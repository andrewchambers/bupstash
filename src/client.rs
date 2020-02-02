use super::address::*;
use super::chunker;
use super::crypto;
use super::htree;
use super::keys;
use super::protocol::*;
use super::repository;
use super::rollsum;
use super::sendlog;

use failure::Fail;
use std::collections::HashMap;

#[derive(Debug, Fail)]
pub enum ClientError {
    #[fail(display = "corrupt or tampered data")]
    CorruptOrTamperedDataError,
}

fn handle_server_info(r: &mut dyn std::io::Read) -> Result<(), failure::Error> {
    match read_packet(r)? {
        Packet::ServerInfo(info) => {
            if info.protocol != "0" {
                failure::bail!("remote protocol version mismatch");
            };
        }
        _ => failure::bail!("protocol error, expected server info packet"),
    }
    Ok(())
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

pub fn send(
    opts: SendOptions,
    ctx: &crypto::EncryptContext,
    send_log: Option<std::path::PathBuf>,
    r: &mut dyn std::io::Read,
    w: &mut dyn std::io::Write,
    tags: &HashMap<String, Option<String>>,
    data: &mut dyn std::io::Read,
) -> Result<i64, failure::Error> {
    handle_server_info(r)?;
    write_packet(w, &Packet::BeginSend(BeginSend {}))?;

    let mut send_log = match read_packet(r)? {
        Packet::AckSend(ack) => {
            if let Some(send_log) = send_log {
                sendlog::SendLog::open(&send_log, &ack.gc_generation)?
            } else {
                sendlog::SendLog::open(&std::path::PathBuf::from(":memory:"), &ack.gc_generation)?
            }
        }
        _ => failure::bail!("protocol error, expected begin ack packet"),
    };

    let send_result: Result<i64, failure::Error>;
    {
        let mut send_log_tx = send_log.transaction()?;
        {
            let mut filtered_conn = FilteredConnection {
                tx: &mut send_log_tx,
                w: w,
            };
            // XXX We divide send up into two parts to make the
            // lifetime easier to deal. Theres a good chance
            // it can be factored better, but this works for now.
            send_result = send2(opts, ctx, r, &mut filtered_conn, tags, data);
        }

        match send_result {
            Ok(id) => {
                send_log_tx.commit()?;
                Ok(id)
            }
            Err(err) => Err(err),
        }
    }
}

fn send2(
    opts: SendOptions,
    ctx: &crypto::EncryptContext,
    r: &mut dyn std::io::Read,
    filtered_conn: &mut FilteredConnection,
    tags: &HashMap<String, Option<String>>,
    data: &mut dyn std::io::Read,
) -> Result<i64, failure::Error> {
    let tree_height: usize;
    let root_address: Address;

    let min_size = 1024;
    let max_size = 8 * 1024 * 1024;
    let chunk_mask = 0x000f_ffff;
    // XXX TODO these chunk parameters need to be investigated and tuned.
    let rs = rollsum::Rollsum::new_with_chunk_mask(chunk_mask);
    let mut chunker = chunker::RollsumChunker::new(rs, min_size, max_size);
    let mut tw = htree::TreeWriter::new(filtered_conn, max_size, chunk_mask);
    let mut buf: Vec<u8> = vec![0; 1024 * 1024];

    loop {
        match data.read(&mut buf) {
            Ok(0) => {
                let chunk_data = chunker.finish();
                let addr = ctx.keyed_content_address(&chunk_data);
                tw.add(&addr, ctx.encrypt_data(opts.compression, chunk_data))?;
                let (height, address) = tw.finish()?;
                tree_height = height;
                root_address = address;
                break;
            }
            Ok(n_read) => {
                let mut n_chunked = 0;
                while n_chunked != n_read {
                    let (n, c) = chunker.add_bytes(&buf[n_chunked..n_read]);
                    n_chunked += n;
                    if let Some(chunk_data) = c {
                        let addr = ctx.keyed_content_address(&chunk_data);
                        tw.add(&addr, ctx.encrypt_data(opts.compression, chunk_data))?;
                    }
                }
            }
            Err(err) => return Err(err.into()),
        }
    }

    write_packet(
        filtered_conn.w,
        &Packet::CommitSend(CommitSend {
            metadata: repository::ItemMetadata {
                address: root_address,
                tree_height,
                encrypt_header: ctx.encryption_header(),
                encrypted_tags: ctx
                    .encrypt_data(true, serde_json::to_string(&tags)?.as_bytes().to_vec()),
            },
        }),
    )?;

    match read_packet(r)? {
        Packet::AckCommit(ack) => Ok(ack.id),
        _ => failure::bail!("protocol error, expected begin ack packet"),
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
    handle_server_info(r)?;

    write_packet(w, &Packet::RequestData(RequestData { id }))?;

    let metadata = match read_packet(r)? {
        Packet::AckRequestData(req) => match req.item {
            Some(item) => item.metadata,
            None => failure::bail!("no stored items with the requested address"),
        },
        _ => failure::bail!("protocol error, expected ack request packet"),
    };

    if key.id != metadata.encrypt_header.master_key_id() {
        failure::bail!("decryption key does not match master key used for encryption");
    }

    let ctx = crypto::DecryptContext::open(key, &metadata.encrypt_header)?;
    let mut sv = StreamVerifier { r: r };
    let mut tr = htree::TreeReader::new(&mut sv, metadata.tree_height, &metadata.address);

    loop {
        match tr.next_chunk()? {
            Some((addr, encrypted_chunk_data)) => {
                let data = ctx.decrypt_data(&encrypted_chunk_data)?;
                if addr != ctx.keyed_content_address(&data) {
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

pub fn gc(
    r: &mut dyn std::io::Read,
    w: &mut dyn std::io::Write,
) -> Result<repository::GCStats, failure::Error> {
    handle_server_info(r)?;
    write_packet(w, &Packet::StartGC(StartGC {}))?;
    match read_packet(r)? {
        Packet::GCComplete(gccomplete) => Ok(gccomplete.stats),
        _ => failure::bail!("protocol error, expected gc complete packet"),
    }
}

pub fn all_items(
    r: &mut dyn std::io::Read,
    w: &mut dyn std::io::Write,
    f: &mut dyn FnMut(Vec<repository::Item>) -> Result<(), failure::Error>,
) -> Result<(), failure::Error> {
    handle_server_info(r)?;
    write_packet(w, &Packet::RequestAllItems(RequestAllItems {}))?;

    loop {
        match read_packet(r)? {
            Packet::Items(items) => {
                if items.is_empty() {
                    break;
                }
                f(items)?;
            }
            _ => failure::bail!("protocol error, expected items packet"),
        }
    }

    Ok(())
}
