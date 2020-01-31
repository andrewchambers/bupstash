use super::address;
use super::htree;
use super::protocol::*;
use super::repository;

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
            let mut store = repository::Repo::open(&cfg.store_path, repository::OpenMode::Shared)?;
            recv(&mut store, r, w)
        }
        Packet::RequestData(req) => {
            let mut store = repository::Repo::open(&cfg.store_path, repository::OpenMode::Shared)?;
            send(&mut store, req.root, w)
        }
        Packet::StartGC(_) => {
            let mut store =
                repository::Repo::open(&cfg.store_path, repository::OpenMode::Exclusive)?;
            gc(&mut store, w)
        }
        _ => Err(failure::format_err!(
            "protocol error, unexpected packet kind"
        )),
    }
}

fn recv(
    store: &mut repository::Repo,
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
                store.add_chunk(&chunk.address, chunk.data)?;
            }
            Packet::CommitSend(commit) => {
                store.sync()?;
                store.add_item(commit.address, commit.metadata)?;
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
    store: &mut repository::Repo,
    address: address::Address,
    w: &mut dyn std::io::Write,
) -> Result<(), failure::Error> {
    let metadata = match store.lookup_item_by_address(address)? {
        Some(metadata) => {
            write_packet(
                w,
                &Packet::AckRequestData(AckRequestData {
                    metadata: Some(metadata.clone()),
                }),
            )?;
            metadata
        }
        None => {
            let no_metadata: Option<repository::ItemMetadata> = None;
            write_packet(
                w,
                &Packet::AckRequestData(AckRequestData {
                    metadata: no_metadata,
                }),
            )?;
            return Ok(());
        }
    };

    let mut tr = htree::TreeReader::new(store, metadata.tree_height, address);

    loop {
        match tr.next_addr()? {
            Some((height, chunk_address)) => {
                if height != 0 {
                    tr.push_addr(height - 1, &chunk_address)?;
                }
                let chunk_data = tr.get_chunk(&chunk_address)?;
                write_packet(
                    w,
                    &Packet::Chunk(Chunk {
                        address: chunk_address,
                        data: chunk_data,
                    }),
                )?;
            }
            None => break,
        }
    }

    Ok(())
}

fn gc(store: &mut repository::Repo, w: &mut dyn std::io::Write) -> Result<(), failure::Error> {
    let stats = store.gc()?;
    write_packet(w, &Packet::GCComplete(GCComplete { stats }))?;
    Ok(())
}
