use super::address;
use super::chunker;
use super::crypto;
use super::htree;
use super::keys;
use super::protocol::*;
use super::rollsum;
use super::store;

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

pub fn send(
    ctx: &crypto::EncryptContext,
    r: &mut dyn std::io::Read,
    w: &mut dyn std::io::Write,
    data: &mut dyn std::io::Read,
) -> Result<address::Address, failure::Error> {
    handle_server_info(r)?;
    write_packet(w, &Packet::BeginSend(BeginSend {}))?;

    match read_packet(r)? {
        Packet::AckSend(_) => {
            // XXX TODO check gc generation matches.
            // abort send if the gc generation does not match.
            // We must restart transmission after resetting our send log.
        }
        _ => failure::bail!("protocol error, expected begin ack packet"),
    }

    let mut sendfn = |address, data| -> std::result::Result<(), failure::Error> {
        write_packet(w, &Packet::Chunk(Chunk { address, data }))?;
        Ok(())
    };

    let min_size = 1024;
    let max_size = 8 * 1024 * 1024;
    let chunk_mask = 0x000f_ffff;
    // XXX TODO these chunk parameters need to be investigated and tuned.
    let rs = rollsum::Rollsum::new_with_chunk_mask(chunk_mask);
    let mut chunker = chunker::RollsumChunker::new(rs, min_size, max_size);
    let mut tw = htree::TreeWriter::new(&mut sendfn, max_size, chunk_mask);

    let mut buf: Vec<u8> = vec![0; 1024 * 1024];

    let tree_height: usize;
    let root_address: address::Address;

    loop {
        match data.read(&mut buf) {
            Ok(0) => {
                let chunk_data = chunker.finish();
                let addr = ctx.keyed_content_address(&chunk_data);
                let encrypted_chunk_data = ctx.encrypt_chunk(&chunk_data);
                tw.add(addr, encrypted_chunk_data)?;
                let (height, address) = tw.finish()?;
                tree_height = height;
                root_address = address;
                write_packet(
                    w,
                    &Packet::CommitSend(CommitSend {
                        address: root_address,
                        metadata: store::ItemMetadata {
                            tree_height,
                            encrypt_header: ctx.encryption_header(),
                        },
                    }),
                )?;
                break;
            }
            Ok(n_read) => {
                let mut n_chunked = 0;
                while n_chunked != n_read {
                    let (n, c) = chunker.add_bytes(&buf[n_chunked..n_read]);
                    n_chunked += n;
                    if let Some(chunk_data) = c {
                        let addr = ctx.keyed_content_address(&chunk_data);
                        let encrypted_chunk_data = ctx.encrypt_chunk(&chunk_data);
                        tw.add(addr, encrypted_chunk_data)?;
                    }
                }
            }
            Err(err) => return Err(err.into()),
        }
    }

    match read_packet(r)? {
        Packet::AckCommit(_) => Ok(root_address),
        _ => failure::bail!("protocol error, expected begin ack packet"),
    }
}

struct StreamVerifier<'a> {
    r: &'a mut dyn std::io::Read,
}

impl<'a> htree::Source for StreamVerifier<'a> {
    fn get_chunk(&mut self, addr: address::Address) -> Result<Vec<u8>, failure::Error> {
        match read_packet(self.r)? {
            Packet::Chunk(chunk) => {
                if addr != chunk.address {
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
    root_address: address::Address,
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
                let decrypted_chunk_data = match ctx.decrypt_chunk(&encrypted_chunk_data) {
                    Some(decrypted_chunk_data) => {
                        if addr != ctx.keyed_content_address(&decrypted_chunk_data) {
                            return Err(htree::HTreeError::CorruptOrTamperedDataError.into());
                        }
                        decrypted_chunk_data
                    }
                    None => return Err(htree::HTreeError::CorruptOrTamperedDataError.into()),
                };
                out.write_all(&decrypted_chunk_data)?
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
) -> Result<store::GCStats, failure::Error> {
    handle_server_info(r)?;
    write_packet(w, &Packet::StartGC(StartGC {}))?;
    match read_packet(r)? {
        Packet::GCComplete(gccomplete) => Ok(gccomplete.stats),
        _ => failure::bail!("protocol error, expected gc complete packet"),
    }
}
