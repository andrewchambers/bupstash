use super::address::*;
use super::chunker;
use super::crypto;
use super::htree;
use super::keys;
use super::protocol::*;
use super::repository;
use super::rollsum;
use super::sendlog;

const CHUNK_FOOTER_NO_COMPRESSION: u8 = 0;
const CHUNK_FOOTER_ZSTD_COMPRESSED: u8 = 1;

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
    data: &mut dyn std::io::Read,
) -> Result<Address, failure::Error> {
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

    let send_result: Result<Address, failure::Error>;
    {
        let mut send_log_tx = send_log.transaction()?;
        {
            let mut filtered_conn = FilteredConnection {
                tx: &mut send_log_tx,
                w: w,
            };
            // We divide send up into two parts to make the
            // lifetime easier to deal. Theres a good chance
            // it can be factored better, but this works for now.
            send_result = send2(opts, ctx, r, &mut filtered_conn, data);
        }

        match send_result {
            Ok(root_address) => {
                send_log_tx.commit()?;
                Ok(root_address)
            }
            Err(err) => Err(err),
        }
    }
}

fn compress_chunk(mut data: Vec<u8>) -> Vec<u8> {
    // Our max chunk size means this should never happen.
    assert!(data.len() <= 0xffffffff);
    let mut compressed_data = zstd::block::compress(&data, 0).unwrap();
    if (compressed_data.len() + 4) >= data.len() {
        data.push(CHUNK_FOOTER_NO_COMPRESSION);
        data
    } else {
        compressed_data.reserve(5);
        let sz = data.len() as u32;
        compressed_data.push(((sz & 0xff000000) >> 24) as u8);
        compressed_data.push(((sz & 0x00ff0000) >> 16) as u8);
        compressed_data.push(((sz & 0x0000ff00) >> 8) as u8);
        compressed_data.push((sz & 0x000000ff) as u8);
        compressed_data.push(CHUNK_FOOTER_ZSTD_COMPRESSED);
        compressed_data
    }
}

fn encrypt_chunk(
    opts: SendOptions,
    ctx: &crypto::EncryptContext,
    mut data: Vec<u8>,
) -> Result<Vec<u8>, failure::Error> {
    let to_encrypt = if opts.compression {
        compress_chunk(data)
    } else {
        data.push(CHUNK_FOOTER_NO_COMPRESSION);
        data
    };

    Ok(ctx.encrypt_chunk(&to_encrypt))
}

fn send2(
    opts: SendOptions,
    ctx: &crypto::EncryptContext,
    r: &mut dyn std::io::Read,
    filtered_conn: &mut FilteredConnection,
    data: &mut dyn std::io::Read,
) -> Result<Address, failure::Error> {
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
                tw.add(&addr, encrypt_chunk(opts, ctx, chunk_data)?)?;
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
                        tw.add(&addr, encrypt_chunk(opts, ctx, chunk_data)?)?;
                    }
                }
            }
            Err(err) => return Err(err.into()),
        }
    }

    write_packet(
        filtered_conn.w,
        &Packet::CommitSend(CommitSend {
            address: root_address,
            metadata: repository::ItemMetadata {
                tree_height,
                encrypt_header: ctx.encryption_header(),
            },
        }),
    )?;

    match read_packet(r)? {
        Packet::AckCommit(_) => (),
        _ => failure::bail!("protocol error, expected begin ack packet"),
    };

    Ok(root_address)
}

struct StreamVerifier<'a> {
    r: &'a mut dyn std::io::Read,
}

impl<'a> htree::Source for StreamVerifier<'a> {
    fn get_chunk(&mut self, addr: &Address) -> Result<Vec<u8>, failure::Error> {
        match read_packet(self.r)? {
            Packet::Chunk(chunk) => {
                if *addr != chunk.address {
                    return Err(htree::HTreeError::CorruptOrTamperedDataError.into());
                }
                return Ok(chunk.data);
            }
            _ => failure::bail!("protocol error, expected begin chunk packet"),
        }
    }
}

pub fn request_data_stream(
    key: &keys::MasterKey,
    root_address: Address,
    r: &mut dyn std::io::Read,
    w: &mut dyn std::io::Write,
    out: &mut dyn std::io::Write,
) -> Result<(), failure::Error> {
    handle_server_info(r)?;

    write_packet(w, &Packet::RequestData(RequestData { root: root_address }))?;

    let metadata = match read_packet(r)? {
        Packet::AckRequestData(req) => match req.metadata {
            Some(metadata) => metadata,
            None => failure::bail!("no stored items with the requested address"),
        },
        _ => failure::bail!("protocol error, expected ack request packet"),
    };

    if key.id != metadata.encrypt_header.master_key_id() {
        failure::bail!("decryption key does not match master key used for encryption");
    }

    let ctx = crypto::DecryptContext::open(key, &metadata.encrypt_header)?;
    let mut sv = StreamVerifier { r: r };
    let mut tr = htree::TreeReader::new(&mut sv, metadata.tree_height, root_address);

    loop {
        match tr.next_chunk()? {
            Some((addr, encrypted_chunk_data)) => {
                match ctx.decrypt_chunk(&encrypted_chunk_data) {
                    Some(mut decrypted_chunk_data) => {
                        if decrypted_chunk_data.is_empty() {
                            return Err(htree::HTreeError::CorruptOrTamperedDataError.into());
                        }
                        match decrypted_chunk_data[decrypted_chunk_data.len() - 1] {
                            footer if footer == CHUNK_FOOTER_NO_COMPRESSION => {
                                decrypted_chunk_data.pop();
                                if addr != ctx.keyed_content_address(&decrypted_chunk_data) {
                                    return Err(
                                        htree::HTreeError::CorruptOrTamperedDataError.into()
                                    );
                                }
                                out.write_all(&decrypted_chunk_data)?;
                            }
                            footer if footer == CHUNK_FOOTER_ZSTD_COMPRESSED => {
                                decrypted_chunk_data.pop();
                                if decrypted_chunk_data.len() < 4 {
                                    return Err(
                                        htree::HTreeError::CorruptOrTamperedDataError.into()
                                    );
                                }
                                let dlen = decrypted_chunk_data.len();
                                let decompressed_sz = ((decrypted_chunk_data[dlen - 4] as u32)
                                    << 24)
                                    | ((decrypted_chunk_data[dlen - 3] as u32) << 16)
                                    | ((decrypted_chunk_data[dlen - 2] as u32) << 8)
                                    | (decrypted_chunk_data[dlen - 1] as u32);
                                decrypted_chunk_data.truncate(decrypted_chunk_data.len() - 4);
                                let decompressed_chunk_data = zstd::block::decompress(
                                    &decrypted_chunk_data,
                                    decompressed_sz as usize,
                                )?;
                                if addr != ctx.keyed_content_address(&decompressed_chunk_data) {
                                    return Err(
                                        htree::HTreeError::CorruptOrTamperedDataError.into()
                                    );
                                }
                                out.write_all(&decompressed_chunk_data)?;
                            }
                            _ => return Err(htree::HTreeError::CorruptOrTamperedDataError.into()),
                        };
                    }
                    None => return Err(htree::HTreeError::CorruptOrTamperedDataError.into()),
                };
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
