use super::htree;
use super::protocol::*;
use super::repository;

pub struct ServerConfig {
    pub repo_path: std::path::PathBuf,
    pub allow_gc: bool,
    pub allow_read: bool,
    pub allow_add: bool,
    pub allow_edit: bool,
}

pub fn serve(
    cfg: ServerConfig,
    r: &mut dyn std::io::Read,
    w: &mut dyn std::io::Write,
) -> Result<(), failure::Error> {
    let mut repo = repository::Repo::open(&cfg.repo_path, repository::OpenMode::Shared)?;
    write_packet(
        w,
        &Packet::ServerInfo(ServerInfo {
            repo_id: repo.id()?,
            protocol: "0".to_string(),
        }),
    )?;

    match read_packet(r)? {
        Packet::BeginSend(_) => {
            if !cfg.allow_add {
                failure::bail!("server has add writing data for this client")
            }
            recv(&mut repo, r, w)
        }
        Packet::RequestData(req) => {
            if !cfg.allow_read {
                failure::bail!("server has disabled reading data for this client")
            }
            send(&mut repo, req.id, w)
        }
        Packet::StartGC(_) => {
            drop(repo);
            repo = repository::Repo::open(&cfg.repo_path, repository::OpenMode::Exclusive)?;
            if !cfg.allow_gc {
                failure::bail!("server has disabled garbage collection for this client")
            }
            gc(&mut repo, w)
        }
        Packet::RequestAllItems(_) => {
            if !cfg.allow_read {
                failure::bail!("server has disabled query and search for this client")
            }
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
            gc_generation: repo.gc_generation()?,
        }),
    )?;

    let mut store_engine = repo.storage_engine()?;

    loop {
        match read_packet(r)? {
            Packet::Chunk(chunk) => {
                store_engine.add_chunk(&chunk.address, chunk.data)?;
            }
            Packet::CommitSend(commit) => {
                store_engine.sync()?;
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

    let mut storage_engine = repo.storage_engine()?;

    let mut tr = htree::TreeReader::new(
        &mut storage_engine,
        item.metadata.tree_height,
        &item.metadata.address,
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
