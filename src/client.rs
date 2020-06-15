use super::address::*;
use super::chunker;
use super::crypto;
use super::htree;
use super::itemset;
use super::keys;
use super::protocol::*;
use super::querycache;
use super::repository;
use super::rollsum;
use super::sendlog;
use std::convert::{From, TryFrom};

use failure::Fail;
use std::collections::HashMap;

#[derive(Debug, Fail)]
pub enum ClientError {
    #[fail(display = "corrupt or tampered data")]
    CorruptOrTamperedDataError,
}

pub fn handle_server_info(r: &mut dyn std::io::Read) -> Result<ServerInfo, failure::Error> {
    match read_packet(r)? {
        Packet::ServerInfo(info) => {
            if info.protocol != "0" {
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
    Directory(std::path::PathBuf),
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
    /* Create the various crypto contexts first so we can error early */
    let hash_ctx = crypto::KeyedHashContext::try_from(key)?;
    let metadata_ctx = crypto::EncryptContext::metadata_context(&key);
    let data_ctx = crypto::EncryptContext::data_context(&key)?;

    write_packet(w, &Packet::BeginSend(BeginSend {}))?;

    let gc_generation = match read_packet(r)? {
        Packet::AckSend(ack) => ack.gc_generation,
        _ => failure::bail!("protocol error, expected begin ack packet"),
    };

    let send_result: Result<i64, failure::Error>;
    let mut send_log_tx = send_log.transaction(&gc_generation)?;
    {
        let mut filtered_conn = FilteredConnection {
            tx: &mut send_log_tx,
            w: w,
        };
        // XXX We divide send up into two parts to make the
        // lifetime easier to deal. Theres a good chance
        // it can be factored better, but this works for now.
        send_result = send2(
            opts,
            key,
            &hash_ctx,
            &metadata_ctx,
            &data_ctx,
            r,
            &mut filtered_conn,
            tags,
            data,
        );
    }

    let id = match send_result {
        Ok(id) => {
            send_log_tx.commit()?;
            id
        }
        Err(err) => return Err(err.into()),
    };
    Ok(id)
}

fn send2(
    opts: SendOptions,
    key: &keys::Key,
    hash_ctx: &crypto::KeyedHashContext,
    metadata_ctx: &crypto::EncryptContext,
    data_ctx: &crypto::EncryptContext,
    r: &mut dyn std::io::Read,
    filtered_conn: &mut FilteredConnection,
    tags: &HashMap<String, Option<String>>,
    data: SendSource,
) -> Result<i64, failure::Error> {
    let min_size = 1024;
    let max_size = 8 * 1024 * 1024;
    let chunk_mask = 0x000f_ffff;
    // XXX TODO these chunk parameters need to be investigated and tuned.
    let rs = rollsum::Rollsum::new_with_chunk_mask(chunk_mask);
    let mut chunker = chunker::RollsumChunker::new(rs, min_size, max_size);
    let mut tw = htree::TreeWriter::new(filtered_conn, max_size, chunk_mask);

    match data {
        SendSource::Readable(mut data) => {
            send_chunks(&opts, data_ctx, hash_ctx, &mut chunker, &mut tw, &mut data)?
        }
        SendSource::Directory(_path) => panic!("todo"),
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
        Packet::AckLogOp(id) => Ok(id),
        _ => failure::bail!("protocol error, expected begin ack packet"),
    }
}

fn send_chunks(
    opts: &SendOptions,
    data_ctx: &crypto::EncryptContext,
    hash_ctx: &crypto::KeyedHashContext,
    chunker: &mut chunker::RollsumChunker,
    tw: &mut htree::TreeWriter,
    data: &mut dyn std::io::Read,
) -> Result<(), failure::Error> {
    let mut buf: Vec<u8> = vec![0; 1024 * 1024];

    loop {
        match data.read(&mut buf) {
            Ok(0) => {
                return Ok(());
            }
            Ok(n_read) => {
                let mut n_chunked = 0;
                while n_chunked != n_read {
                    let (n, c) = chunker.add_bytes(&buf[n_chunked..n_read]);
                    n_chunked += n;
                    if let Some(chunk_data) = c {
                        let addr = hash_ctx.content_address(&chunk_data);
                        tw.add(&addr, data_ctx.encrypt_data(opts.compression, chunk_data))?;
                    }
                }
            }
            Err(err) => return Err(err.into()),
        }
    }
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
