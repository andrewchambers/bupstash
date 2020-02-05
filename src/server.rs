use super::htree;
use super::itemset;
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
        Packet::RequestItemSync(req) => {
            if !cfg.allow_read {
                failure::bail!("server has disabled query and search for this client")
            }
            item_sync(&mut repo, req.after, req.gc_generation, w)
        }
        Packet::LogOp(op) => {
            if !cfg.allow_edit {
                failure::bail!("server has disabled delete/edit for this client")
            }
            let id = repo.do_op(op)?;
            write_packet(w, &Packet::AckLogOp(id))?;
            Ok(())
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
            Packet::LogOp(op) => {
                store_engine.sync()?;
                match op {
                    itemset::LogOp::AddItem(_) => {
                        let id = repo.do_op(op)?;
                        write_packet(w, &Packet::AckLogOp(id))?;
                    }
                    _ => failure::bail!("protocol error, expected add item log op"),
                }
                break;
            }
            _ => failure::bail!("protocol error, unexpected packet"),
        }
    }

    Ok(())
}

fn send(
    repo: &mut repository::Repo,
    id: i64,
    w: &mut dyn std::io::Write,
) -> Result<(), failure::Error> {
    let metadata = match repo.lookup_item_by_id(id)? {
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
            write_packet(
                w,
                &Packet::AckRequestData(AckRequestData { metadata: None }),
            )?;
            return Ok(());
        }
    };

    let mut storage_engine = repo.storage_engine()?;

    let mut tr =
        htree::TreeReader::new(&mut storage_engine, metadata.tree_height, &metadata.address);

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

fn item_sync(
    repo: &mut repository::Repo,
    after: i64,
    request_gc_generation: Option<String>,
    w: &mut dyn std::io::Write,
) -> Result<(), failure::Error> {
    let current_generation = repo.gc_generation()?;

    let after = match request_gc_generation {
        Some(request_gc_generation) if request_gc_generation == current_generation => after,
        _ => -1,
    };

    write_packet(
        w,
        &Packet::AckItemSync(AckItemSync {
            gc_generation: current_generation,
        }),
    )?;

    let mut logops = Vec::new();

    repo.walk_log(after, &mut |id, op| {
        logops.push((id, op));
        if logops.len() >= 64 {
            let mut v = Vec::new();
            std::mem::swap(&mut v, &mut logops);
            write_packet(w, &Packet::SyncLogOps(v))?;
        }
        Ok(())
    })?;
    if !logops.is_empty() {
        write_packet(w, &Packet::SyncLogOps(logops))?;
    }
    write_packet(w, &Packet::SyncLogOps(vec![]))?;
    Ok(())
}
