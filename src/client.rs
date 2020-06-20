use super::address::*;
use super::chunker;
use super::crypto;
use super::fsutil;
use super::htree;
use super::hydrogen;
use super::itemset;
use super::keys;
use super::protocol::*;
use super::querycache;
use super::repository;
use super::rollsum;
use super::sendlog;
use super::statcache;
use failure::Fail;
use std::collections::HashMap;
use std::convert::{From, TryFrom, TryInto};
use std::os::unix::fs::MetadataExt;

#[derive(Debug, Fail)]
pub enum ClientError {
    #[fail(display = "corrupt or tampered data")]
    CorruptOrTamperedDataError,
}

pub fn handle_server_info(r: &mut dyn std::io::Read) -> Result<ServerInfo, failure::Error> {
    match read_packet(r)? {
        Packet::ServerInfo(info) => {
            if info.protocol != "repo-0" {
                failure::bail!("remote protocol version mismatch");
            };
            Ok(info)
        }
        _ => failure::bail!("protocol error, expected server info packet"),
    }
}

struct FilteredConnection<'a, 'b> {
    tx: &'a mut sendlog::SendLogTx<'b>,
    w: &'a mut dyn std::io::Write,
}

impl<'a, 'b> htree::Sink for FilteredConnection<'a, 'b> {
    fn add_chunk(
        &mut self,
        addr: &Address,
        data: std::vec::Vec<u8>,
    ) -> std::result::Result<(), failure::Error> {
        if self.tx.has_address(addr)? {
            return Ok(());
        }
        write_packet(
            self.w,
            &Packet::Chunk(Chunk {
                address: *addr,
                data: data,
            }),
        )?;
        self.tx.add_address(addr)?;
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub struct SendOptions {
    pub compression: bool,
}

pub enum SendSource {
    Readable(Box<dyn std::io::Read>),
    Directory((statcache::StatCache, std::path::PathBuf)),
}

pub fn send(
    opts: SendOptions,
    key: &keys::Key,
    send_log: &mut sendlog::SendLog,
    r: &mut dyn std::io::Read,
    w: &mut dyn std::io::Write,
    tags: &HashMap<String, Option<String>>,
    data: SendSource,
) -> Result<i64, failure::Error> {
    /* Create the various crypto contexts first so we can error early on bad keys */
    let hash_ctx = crypto::KeyedHashContext::try_from(key)?;
    let metadata_ctx = crypto::EncryptContext::metadata_context(&key);
    let data_ctx = crypto::EncryptContext::data_context(&key)?;

    write_packet(w, &Packet::BeginSend(BeginSend {}))?;

    let gc_generation = match read_packet(r)? {
        Packet::AckSend(ack) => ack.gc_generation,
        _ => failure::bail!("protocol error, expected begin ack packet"),
    };

    let mut send_log_tx = send_log.transaction(&gc_generation)?;
    let mut filtered_conn = FilteredConnection {
        tx: &mut send_log_tx,
        w: w,
    };
    let min_size = 1024;
    let max_size = 8 * 1024 * 1024;
    let chunk_mask = 0x000f_ffff;
    // XXX TODO these chunk parameters need to be investigated and tuned.
    let rs = rollsum::Rollsum::new_with_chunk_mask(chunk_mask);
    let mut chunker = chunker::RollsumChunker::new(rs, min_size, max_size);
    let mut tw = htree::TreeWriter::new(&mut filtered_conn, max_size, chunk_mask);

    match data {
        SendSource::Readable(mut data) => {
            send_chunks(
                &opts,
                &data_ctx,
                &hash_ctx,
                &mut chunker,
                &mut tw,
                &mut data,
                None,
            )?;
            ()
        }
        SendSource::Directory((mut stat_cache, path)) => {
            let mut stat_cache_tx = stat_cache.transaction(&gc_generation)?;
            send_dir(
                &opts,
                &data_ctx,
                &hash_ctx,
                &mut chunker,
                &mut tw,
                &mut stat_cache_tx,
                &path,
            )?;
            stat_cache_tx.commit()?;
        }
    }

    let chunk_data = chunker.finish();
    let addr = hash_ctx.content_address(&chunk_data);
    tw.add(&addr, data_ctx.encrypt_data(opts.compression, chunk_data))?;
    let (tree_height, tree_address) = tw.finish()?;

    let (hk_2a, hk_2b) = match key {
        keys::Key::MasterKeyV1(k) => (k.hash_key_part_2a, k.hash_key_part_2b),
        keys::Key::SendKeyV1(k) => (k.hash_key_part_2a, k.hash_key_part_2b),
        _ => panic!("unreachable"), /* We wouldn't be able to have a HashContext in these cases */
    };

    write_packet(
        filtered_conn.w,
        &Packet::LogOp(itemset::LogOp::AddItem(itemset::VersionedItemMetadata::V1(
            itemset::ItemMetadata {
                tree_height,
                address: tree_address,
                master_key_id: key.master_key_id(),
                hash_key_part_2a: hk_2a,
                hash_key_part_2b: hk_2b,
                encrypted_tags: metadata_ctx.encrypt_data(true, bincode::serialize(&tags)?),
            },
        ))),
    )?;

    match read_packet(r)? {
        Packet::AckLogOp(id) => {
            send_log_tx.commit()?;
            Ok(id)
        }
        _ => failure::bail!("protocol error, expected ack packet"),
    }
}

fn send_chunks(
    opts: &SendOptions,
    data_ctx: &crypto::EncryptContext,
    hash_ctx: &crypto::KeyedHashContext,
    chunker: &mut chunker::RollsumChunker,
    tw: &mut htree::TreeWriter,
    data: &mut dyn std::io::Read,
    mut on_chunk: Option<&mut dyn FnMut(&Address) -> ()>,
) -> Result<usize, failure::Error> {
    let mut buf: Vec<u8> = vec![0; 1024 * 1024];
    let mut n_written: usize = 0;
    loop {
        match data.read(&mut buf) {
            Ok(0) => {
                return Ok(n_written);
            }
            Ok(n_read) => {
                let mut n_chunked = 0;
                while n_chunked != n_read {
                    let (n, c) = chunker.add_bytes(&buf[n_chunked..n_read]);
                    n_chunked += n;
                    if let Some(chunk_data) = c {
                        let addr = hash_ctx.content_address(&chunk_data);
                        let encrypted_chunk = data_ctx.encrypt_data(opts.compression, chunk_data);
                        if let Some(ref mut on_chunk) = on_chunk {
                            on_chunk(&addr);
                        }
                        tw.add(&addr, encrypted_chunk)?;
                    }
                }
                n_written += n_read;
            }
            Err(err) => return Err(err.into()),
        }
    }
}

fn send_dir(
    opts: &SendOptions,
    data_ctx: &crypto::EncryptContext,
    hash_ctx: &crypto::KeyedHashContext,
    chunker: &mut chunker::RollsumChunker,
    tw: &mut htree::TreeWriter,
    stat_cache_tx: &mut statcache::StatCacheTx,
    path: &std::path::PathBuf,
) -> Result<(), failure::Error> {
    let mut addresses: Vec<u8> = Vec::with_capacity(1024 * 128);
    let path = fsutil::absolute_path(&path)?;

    for entry in walkdir::WalkDir::new(&path) {
        let mut hash = hydrogen::Hash::init(*b"statcach", Some(&hash_ctx.hash_key));
        let entry = entry?;
        let entry_path = fsutil::absolute_path(entry.path())?;
        let mut short_entry_path = entry_path.strip_prefix(&path)?.to_path_buf();
        short_entry_path = if short_entry_path.to_str().unwrap_or("").len() == 0 {
            std::path::PathBuf::from(".")
        } else {
            short_entry_path
        };
        let metadata = entry.metadata()?;
        let ft = metadata.file_type();
        let mut hdr = tar::Header::new_ustar();
        hdr.set_path(&short_entry_path)?;
        hdr.set_uid(metadata.uid().into());
        hdr.set_gid(metadata.gid().into());
        hdr.set_mtime(metadata.mtime().try_into()?);
        hdr.set_mode(metadata.mode());
        if ft.is_file() {
            hdr.set_entry_type(tar::EntryType::Regular);
            hdr.set_size(metadata.len());
        } else if ft.is_dir() {
            hdr.set_entry_type(tar::EntryType::Directory);
            hdr.set_size(0);
        } else if ft.is_symlink() {
            hdr.set_entry_type(tar::EntryType::Symlink);
            hdr.set_size(0);
            let target = std::fs::read_link(entry.path())?;
            hdr.set_link_name(target)?;
        } else {
            failure::bail!("unsupported file entry at {}", entry.path().display());
        }
        hdr.set_cksum();
        let hdr_bytes = hdr.as_bytes();
        let hdr_bytes = &hdr_bytes[..];

        hash.update(&hdr_bytes);
        let mut hash_buf = [0; hydrogen::HASH_BYTES];
        hash.finish(&mut hash_buf[..]);

        match stat_cache_tx.lookup(&entry_path, &hash_buf)? {
            Some(cached_addresses) => {
                debug_assert!(cached_addresses.len() % ADDRESS_SZ == 0);
                let mut address = Address::default();
                for cached_address in cached_addresses.chunks(ADDRESS_SZ) {
                    address.bytes[..].clone_from_slice(cached_address);
                    tw.add_addr(0, &address)?;
                }
            }
            None => {
                let mut on_chunk = |addr: &Address| -> () {
                    addresses.extend_from_slice(&addr.bytes[..]);
                };

                let mut hdr_cursor = std::io::Cursor::new(hdr_bytes);
                send_chunks(
                    opts,
                    data_ctx,
                    hash_ctx,
                    chunker,
                    tw,
                    &mut hdr_cursor,
                    Some(&mut on_chunk),
                )?;

                if ft.is_file() {
                    let mut f = std::fs::File::open(&entry_path)?;
                    let len = send_chunks(
                        opts,
                        data_ctx,
                        hash_ctx,
                        chunker,
                        tw,
                        &mut f,
                        Some(&mut on_chunk),
                    )?;
                    /* Tar entries are rounded to 512 bytes */
                    let remaining = 512 - (len % 512);
                    if remaining < 512 {
                        let buf = [0; 512];
                        let mut hdr_cursor = std::io::Cursor::new(&buf[..remaining as usize]);
                        send_chunks(
                            opts,
                            data_ctx,
                            hash_ctx,
                            chunker,
                            tw,
                            &mut hdr_cursor,
                            Some(&mut on_chunk),
                        )?;
                    }
                    if len != metadata.len() as usize {
                        failure::bail!(
                            "file length of {} changed while sending data",
                            entry.path().display()
                        );
                    }
                }

                if let Some(chunk_data) = chunker.force_split() {
                    let addr = hash_ctx.content_address(&chunk_data);
                    on_chunk(&addr);
                    tw.add(&addr, data_ctx.encrypt_data(opts.compression, chunk_data))?
                }

                stat_cache_tx.add(&entry_path, &hash_buf[..], &addresses)?;
            }
        }

        addresses.clear();
    }
    let buf = [0; 1024];
    let mut trailer_cursor = std::io::Cursor::new(&buf[..]);
    send_chunks(
        opts,
        data_ctx,
        hash_ctx,
        chunker,
        tw,
        &mut trailer_cursor,
        None,
    )?;
    Ok(())
}

struct StreamVerifier<'a> {
    r: &'a mut dyn std::io::Read,
}

impl<'a> htree::Source for StreamVerifier<'a> {
    fn get_chunk(&mut self, addr: &Address) -> Result<Vec<u8>, failure::Error> {
        match read_packet(self.r)? {
            Packet::Chunk(chunk) => {
                if *addr != chunk.address {
                    return Err(ClientError::CorruptOrTamperedDataError.into());
                }
                return Ok(chunk.data);
            }
            _ => failure::bail!("protocol error, expected begin chunk packet"),
        }
    }
}

pub fn request_data_stream(
    key: &keys::MasterKey,
    id: i64,
    r: &mut dyn std::io::Read,
    w: &mut dyn std::io::Write,
    out: &mut dyn std::io::Write,
) -> Result<(), failure::Error> {
    write_packet(w, &Packet::RequestData(RequestData { id }))?;

    let metadata = match read_packet(r)? {
        Packet::AckRequestData(req) => match req.metadata {
            Some(metadata) => metadata,
            None => failure::bail!("no stored items with the requested id"),
        },
        _ => failure::bail!("protocol error, expected ack request packet"),
    };

    match metadata {
        itemset::VersionedItemMetadata::V1(metadata) => {
            if key.id != metadata.master_key_id {
                failure::bail!("decryption key does not match master key used for encryption");
            }

            let hash_ctx = crypto::KeyedHashContext::from(key);
            let mut decrypt_ctx =
                crypto::DecryptContext::data_context(&keys::Key::MasterKeyV1(key.clone()))?;
            let mut sv = StreamVerifier { r: r };
            let mut tr = htree::TreeReader::new(metadata.tree_height, &metadata.address);

            loop {
                match tr.next_chunk(&mut sv)? {
                    Some((addr, encrypted_chunk_data)) => {
                        let data = decrypt_ctx.decrypt_data(&encrypted_chunk_data)?;
                        if addr != hash_ctx.content_address(&data) {
                            return Err(ClientError::CorruptOrTamperedDataError.into());
                        }
                        out.write_all(&data)?;
                    }
                    None => break,
                }
            }

            out.flush()?;
            Ok(())
        }
    }
}

pub fn gc(
    r: &mut dyn std::io::Read,
    w: &mut dyn std::io::Write,
) -> Result<repository::GCStats, failure::Error> {
    write_packet(w, &Packet::StartGC(StartGC {}))?;
    let stats = match read_packet(r)? {
        Packet::GCComplete(gccomplete) => gccomplete.stats,
        _ => failure::bail!("protocol error, expected gc complete packet"),
    };
    Ok(stats)
}

pub fn sync(
    query_cache: &mut querycache::QueryCache,
    r: &mut dyn std::io::Read,
    w: &mut dyn std::io::Write,
) -> Result<(), failure::Error> {
    let mut tx = query_cache.transaction()?;

    let after = tx.last_log_op()?;
    let gc_generation = tx.current_gc_generation()?;

    write_packet(
        w,
        &Packet::RequestItemSync(RequestItemSync {
            after,
            gc_generation,
        }),
    )?;

    let gc_generation = match read_packet(r)? {
        Packet::AckItemSync(ack) => ack.gc_generation,
        _ => failure::bail!("protocol error, expected items packet"),
    };

    tx.start_sync(gc_generation)?;

    loop {
        match read_packet(r)? {
            Packet::SyncLogOps(ops) => {
                if ops.is_empty() {
                    break;
                }
                for (id, op) in ops {
                    tx.sync_op(id, op)?;
                }
            }
            _ => failure::bail!("protocol error, expected items packet"),
        }
    }

    tx.commit()?;
    Ok(())
}

pub fn remove(
    ids: Vec<i64>,
    r: &mut dyn std::io::Read,
    w: &mut dyn std::io::Write,
) -> Result<(), failure::Error> {
    write_packet(w, &Packet::LogOp(itemset::LogOp::RemoveItems(ids)))?;
    match read_packet(r)? {
        Packet::AckLogOp(_) => {}
        _ => failure::bail!("protocol error, expected ack log op packet"),
    }
    Ok(())
}

pub fn hangup(w: &mut dyn std::io::Write) -> Result<(), failure::Error> {
    write_packet(w, &Packet::EndOfTransmission)?;
    Ok(())
}
