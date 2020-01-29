use super::address;
use super::htree;
use super::protocol::*;
use super::store;

pub struct ServerConfig {
    pub store_path: std::path::PathBuf,
}

pub fn serve(
    cfg: ServerConfig,
    r: &mut dyn std::io::Read,
    w: &mut dyn std::io::Write,
) -> Result<(), failure::Error> {
    write_packet(
        w,
        &Packet::ServerInfo(ServerInfo {
            protocol: "0".to_string(),
        }),
    )?;

    match read_packet(r)? {
        Packet::BeginSend(_) => {
            let mut store = store::Store::open(&cfg.store_path)?;
            recv(&mut store, r, w)
        }
        Packet::RequestData(req) => {
            let mut store = store::Store::open(&cfg.store_path)?;
            send(&mut store, req.root, w)
        }
        _ => Err(failure::format_err!(
            "protocol error, unexpected packet kind"
        )),
    }
}

fn recv(
    store: &mut store::Store,
    r: &mut dyn std::io::Read,
    w: &mut dyn std::io::Write,
) -> Result<(), failure::Error> {
    write_packet(
        w,
        &Packet::AckSend(AckSend {
            gc_generation: store.gc_generation.clone(),
        }),
    )?;

    loop {
        match read_packet(r)? {
            Packet::Chunk(chunk) => {
                store.add_chunk(chunk.address, chunk.data)?;
            }
            Packet::CommitSend(commit) => {
                store.sync()?;
                store.add_item(commit.root, commit.header)?;
                write_packet(w, &Packet::AckCommit(AckCommit {}))?;
                break;
            }
            _ => {
                return Err(failure::format_err!(
                    "protocol error, unexpected packet kind"
                ))
            }
        }
    }

    Ok(())
}

fn send(
    store: &mut store::Store,
    address: address::Address,
    w: &mut dyn std::io::Write,
) -> Result<(), failure::Error> {
    match store.lookup_item_by_address(address)? {
        Some(hdr) => write_packet(
            w,
            &Packet::AckRequestData(AckRequestData { header: Some(hdr) }),
        )?,
        None => {
            write_packet(w, &Packet::AckRequestData(AckRequestData { header: None }))?;
            return Ok(());
        }
    };

    let mut tr = htree::TreeReader::new(store);
    tr.push_addr(address)?;

    loop {
        match tr.next_addr()? {
            Some((addr, _)) => {
                let chunk_data = tr.get_chunk(&addr)?;
                write_packet(
                    w,
                    &Packet::Chunk(Chunk {
                        address: addr,
                        data: chunk_data,
                    }),
                )?;
            }
            None => break,
        }
    }

    Ok(())
}
