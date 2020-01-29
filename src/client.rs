use super::chunker;
use super::crypto;
use super::htree;
use super::protocol::*;
use super::rollsum;

pub fn send(
    ctx: &crypto::EncryptContext,
    r: &mut dyn std::io::Read,
    w: &mut dyn std::io::Write,
    data: &mut dyn std::io::Read,
) -> Result<(), failure::Error> {
    match read_packet(r)? {
        Packet::ServerInfo(info) => {
            if info.protocol != "0" {
                failure::bail!("remote protocol version mismatch");
            };
        }
        _ => failure::bail!("protocol error, expected server info packet"),
    }

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
    let chunk_mask = 0xffff_fff0;
    // XXX TODO these chunk parameters need to be investigated and tuned.
    let rs = rollsum::Rollsum::new_with_chunk_mask(chunk_mask);
    let mut chunker = chunker::RollsumChunker::new(rs, min_size, max_size);
    let mut tw = htree::TreeWriter::new(&mut sendfn, max_size, chunk_mask);

    let mut buf: Vec<u8> = vec![0; 1024 * 1024];

    loop {
        match data.read(&mut buf) {
            Ok(0) => {
                let root_address = tw.finish()?;
                write_packet(
                    w,
                    &Packet::CommitSend(CommitSend {
                        root: root_address,
                        header: ctx.encryption_header(),
                    }),
                )?;
                break;
            }
            Ok(n_read) => {
                let mut n_chunked = 0;
                while n_chunked != n_read {
                    let (n, c) = chunker.add_bytes(&buf[n_chunked..n_read]);
                    n_chunked += n;
                    if let Some(c) = c {
                        let addr = ctx.keyed_content_address(&c);

                        // XXX TODO, chunk compression.

                        tw.add(addr, c)?;
                    }
                }
            }
            Err(err) => return Err(err.into()),
        }
    }

    match read_packet(r)? {
        Packet::AckCommit(_) => Ok(()),
        _ => failure::bail!("protocol error, expected begin ack packet"),
    }
}
