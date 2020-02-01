use super::address;
use super::htree;
use super::protocol::*;
use super::repository;

pub struct ServerConfig {
    pub repo_path: std::path::PathBuf,
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
            let mut repo = repository::Repo::open(&cfg.repo_path, repository::OpenMode::Shared)?;
            recv(&mut repo, r, w)
        }
        Packet::RequestData(req) => {
            let mut repo = repository::Repo::open(&cfg.repo_path, repository::OpenMode::Shared)?;
            send(&mut repo, req.id, w)
        }
        Packet::StartGC(_) => {
            let mut repo = repository::Repo::open(&cfg.repo_path, repository::OpenMode::Exclusive)?;
            gc(&mut repo, w)
        }
        Packet::RequestAllItems(_) => {
            let mut repo = repository::Repo::open(&cfg.repo_path, repository::OpenMode::Shared)?;
            all_items(&mut repo, w)
        }
        _ => Err(failure::format_err!(
            "protocol error, unexpected packet kind"
        )),
    }
}

fn recv(
    repo: &mut repository::Repo,
    r: &mut dyn std::io::Read,
    w: &mut dyn std::io::Write,
) -> Result<(), failure::Error> {
    write_packet(
        w,
        &Packet::AckSend(AckSend {
            gc_generation: repo.gc_generation.clone(),
        }),
    )?;

    loop {
        match read_packet(r)? {
            Packet::Chunk(chunk) => {
                repo.add_chunk(&chunk.address, chunk.data)?;
            }
            Packet::CommitSend(commit) => {
                repo.sync()?;
                let id = repo.add_item(commit.metadata)?;
                write_packet(w, &Packet::AckCommit(AckCommit { id }))?;
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
    repo: &mut repository::Repo,
    id: i64,
    w: &mut dyn std::io::Write,
) -> Result<(), failure::Error> {
    let item = match repo.lookup_item_by_id(id)? {
        Some(item) => {
            write_packet(
                w,
                &Packet::AckRequestData(AckRequestData {
                    item: Some(item.clone()),
                }),
            )?;
            item
        }
        None => {
            let no_item: Option<repository::Item> = None;
            write_packet(w, &Packet::AckRequestData(AckRequestData { item: no_item }))?;
            return Ok(());
        }
    };

    let mut tr = htree::TreeReader::new(
        repo,
        item.metadata.tree_height,
        address::Address::from_bytes(&item.metadata.address),
    );

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

fn gc(repo: &mut repository::Repo, w: &mut dyn std::io::Write) -> Result<(), failure::Error> {
    let stats = repo.gc()?;
    write_packet(w, &Packet::GCComplete(GCComplete { stats }))?;
    Ok(())
}

fn all_items(
    repo: &mut repository::Repo,
    w: &mut dyn std::io::Write,
) -> Result<(), failure::Error> {
    repo.walk_all_items(&mut |items| {
        write_packet(w, &Packet::Items(items))?;
        Ok(())
    })?;

    write_packet(w, &Packet::Items(vec![]))?;
    Ok(())
}
