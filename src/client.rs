use super::address::*;
use super::chunker;
use super::crypto;
use super::fsutil;
use super::htree;
use super::itemset;
use super::keys;
use super::protocol::*;
use super::querycache;
use super::repository;
use super::rollsum;
use super::sendlog;
use super::statcache;
use failure::Fail;
use std::collections::BTreeMap;
use std::convert::{From, TryInto};
use std::os::unix::fs::MetadataExt;

#[derive(Debug, Fail)]
pub enum ClientError {
    #[fail(display = "corrupt or tampered data")]
    CorruptOrTamperedDataError,
}

pub fn handle_server_info(r: &mut dyn std::io::Read) -> Result<ServerInfo, failure::Error> {
    match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
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
    pub compression: crypto::DataCompression,
}

pub enum SendSource {
    Readable(Box<dyn std::io::Read>),
    Directory((statcache::StatCache, std::path::PathBuf)),
}

pub fn send(
    opts: SendOptions,
    master_key_id: &[u8; keys::KEYID_SZ],
    hash_key: &crypto::HashKey,
    data_ectx: &mut crypto::EncryptionContext,
    metadata_ectx: &mut crypto::EncryptionContext,
    send_log: &mut sendlog::SendLog,
    r: &mut dyn std::io::Read,
    w: &mut dyn std::io::Write,
    tags: BTreeMap<String, Option<String>>,
    data: SendSource,
) -> Result<i64, failure::Error> {
    write_packet(w, &Packet::TBeginSend(TBeginSend {}))?;

    let gc_generation = match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
        Packet::RBeginSend(ack) => ack.gc_generation,
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
                hash_key,
                data_ectx,
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
                hash_key,
                data_ectx,
                &mut chunker,
                &mut tw,
                &mut stat_cache_tx,
                &path,
            )?;
            stat_cache_tx.commit()?;
        }
    }

    let chunk_data = chunker.finish();
    let addr = crypto::keyed_content_address(&chunk_data, hash_key);
    tw.add(&addr, data_ectx.encrypt_data(chunk_data, opts.compression))?;
    let (tree_height, address) = tw.finish()?;

    let plain_text_metadata = itemset::PlainTextItemMetadata {
        master_key_id: *master_key_id,
        tree_height,
        address,
    };

    let e_metadata = itemset::EncryptedItemMetadata {
        plain_text_hash: plain_text_metadata.hash(),
        hash_key_part_2: hash_key.part2.clone(),
        tags,
    };

    write_packet(
        w,
        &Packet::TLogOp(itemset::LogOp::AddItem(itemset::VersionedItemMetadata::V1(
            itemset::ItemMetadata {
                plain_text_metadata,
                encrypted_metadata: metadata_ectx.encrypt_data(
                    bincode::serialize(&e_metadata)?,
                    crypto::DataCompression::Zstd,
                ),
            },
        ))),
    )?;

    match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
        Packet::RLogOp(id) => {
            send_log_tx.commit()?;
            Ok(id)
        }
        _ => failure::bail!("protocol error, expected ack packet"),
    }
}

fn send_chunks(
    opts: &SendOptions,
    hash_key: &crypto::HashKey,
    data_ectx: &mut crypto::EncryptionContext,
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
                        let addr = crypto::keyed_content_address(&chunk_data, &hash_key);
                        let encrypted_chunk = data_ectx.encrypt_data(chunk_data, opts.compression);
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
    hash_key: &crypto::HashKey,
    data_ectx: &mut crypto::EncryptionContext,
    chunker: &mut chunker::RollsumChunker,
    tw: &mut htree::TreeWriter,
    stat_cache_tx: &mut statcache::StatCacheTx,
    path: &std::path::PathBuf,
) -> Result<(), failure::Error> {
    let mut addresses: Vec<u8> = Vec::with_capacity(1024 * 128);
    let path = fsutil::absolute_path(&path)?;

    for entry in walkdir::WalkDir::new(&path) {
        let mut hash_state = crypto::HashState::new(Some(&hash_key));
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

        hash_state.update(&hdr_bytes);
        let hash = hash_state.finish();

        match stat_cache_tx.lookup(&entry_path, &hash)? {
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
                    hash_key,
                    data_ectx,
                    chunker,
                    tw,
                    &mut hdr_cursor,
                    Some(&mut on_chunk),
                )?;

                if ft.is_file() {
                    let mut f = std::fs::File::open(&entry_path)?;
                    let len = send_chunks(
                        opts,
                        hash_key,
                        data_ectx,
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
                            hash_key,
                            data_ectx,
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
                    let addr = crypto::keyed_content_address(&chunk_data, hash_key);
                    on_chunk(&addr);
                    tw.add(&addr, data_ectx.encrypt_data(chunk_data, opts.compression))?
                }

                stat_cache_tx.add(&entry_path, &hash[..], &addresses)?;
            }
        }

        addresses.clear();
    }
    let buf = [0; 1024];
    let mut trailer_cursor = std::io::Cursor::new(&buf[..]);
    send_chunks(
        opts,
        hash_key,
        data_ectx,
        chunker,
        tw,
        &mut trailer_cursor,
        None,
    )?;
    Ok(())
}

pub fn request_data_stream(
    master_key_id: &[u8; keys::KEYID_SZ],
    hash_key_part_1: &crypto::PartialHashKey,
    data_dctx: &mut crypto::DecryptionContext,
    metadata_dctx: &mut crypto::DecryptionContext,
    id: i64,
    r: &mut dyn std::io::Read,
    w: &mut dyn std::io::Write,
    out: &mut dyn std::io::Write,
) -> Result<(), failure::Error> {
    write_packet(w, &Packet::TRequestData(TRequestData { id }))?;

    let metadata = match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
        Packet::RRequestData(req) => match req.metadata {
            Some(metadata) => metadata,
            None => failure::bail!("no stored items with the requested id"),
        },
        _ => failure::bail!("protocol error, expected ack request packet"),
    };

    match metadata {
        itemset::VersionedItemMetadata::V1(metadata) => {
            if *master_key_id != metadata.plain_text_metadata.master_key_id {
                failure::bail!("decryption key does not match master key used for encryption");
            }

            let encrypted_metadata = metadata.decrypt_metadata(metadata_dctx)?;
            let plain_text_metadata = metadata.plain_text_metadata;

            let hash_key =
                crypto::derive_hash_key(&hash_key_part_1, &encrypted_metadata.hash_key_part_2);

            let mut tr = htree::TreeReader::new(
                plain_text_metadata.tree_height,
                &plain_text_metadata.address,
            );

            loop {
                match tr.next_addr()? {
                    Some((height, addr)) => {
                        let data = match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
                            Packet::Chunk(chunk) => {
                                if addr != chunk.address {
                                    return Err(ClientError::CorruptOrTamperedDataError.into());
                                }
                                chunk.data
                            }
                            _ => failure::bail!("protocol error, expected begin chunk packet"),
                        };

                        if height == 0 {
                            let data = data_dctx.decrypt_data(data)?;
                            if addr != crypto::keyed_content_address(&data, &hash_key) {
                                return Err(ClientError::CorruptOrTamperedDataError.into());
                            }
                            out.write_all(&data)?;
                        } else {
                            if addr != htree::tree_block_address(&data) {
                                return Err(ClientError::CorruptOrTamperedDataError.into());
                            }
                            tr.push_level(height - 1, data)?;
                        }
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
    write_packet(w, &Packet::TGc(TGc {}))?;
    let stats = match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
        Packet::RGc(rgc) => rgc.stats,
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
        &Packet::TRequestItemSync(TRequestItemSync {
            after,
            gc_generation,
        }),
    )?;

    let gc_generation = match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
        Packet::RRequestItemSync(ack) => ack.gc_generation,
        _ => failure::bail!("protocol error, expected items packet"),
    };

    tx.start_sync(gc_generation)?;

    loop {
        match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
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
    write_packet(w, &Packet::TLogOp(itemset::LogOp::RemoveItems(ids)))?;
    match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
        Packet::RLogOp(_) => {}
        _ => failure::bail!("protocol error, expected ack log op packet"),
    }
    Ok(())
}

pub fn hangup(w: &mut dyn std::io::Write) -> Result<(), failure::Error> {
    write_packet(w, &Packet::EndOfTransmission)?;
    Ok(())
}
