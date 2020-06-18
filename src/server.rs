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
    let mut repo = repository::Repo::open(&cfg.repo_path)?;
    write_packet(
        w,
        &Packet::Identify(Identify {
            ident: repo.id()?,
            protocol: "repo-0".to_string(),
        }),
    )?;

    loop {
        match read_packet(r)? {
            Packet::BeginSend(_) => {
                if !cfg.allow_add {
                    failure::bail!("server has add writing data for this client")
                }
                recv(&mut repo, r, w)?;
            }
            Packet::RequestData(req) => {
                if !cfg.allow_read {
                    failure::bail!("server has disabled reading data for this client")
                }
                send(&mut repo, req.id, w)?;
            }
            Packet::StartGC(_) => {
                if !cfg.allow_gc {
                    failure::bail!("server has disabled garbage collection for this client")
                }
                gc(&mut repo, w)?;
            }
            Packet::RequestItemSync(req) => {
                if !cfg.allow_read {
                    failure::bail!("server has disabled query and search for this client")
                }
                item_sync(&mut repo, req.after, req.gc_generation, w)?;
            }
            Packet::LogOp(op) => {
                if !cfg.allow_edit {
                    failure::bail!("server has disabled delete/edit for this client")
                }
                let id = repo.do_op(op)?;
                write_packet(w, &Packet::AckLogOp(id))?;
            }
            Packet::EndOfTransmission => break Ok(()),
            _ => failure::bail!("protocol error, unexpected packet kind"),
        }
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

    match metadata {
        itemset::VersionedItemMetadata::V1(metadata) => {
            let mut tr = htree::TreeReader::new(metadata.tree_height, &metadata.address);

            // Here we send using a pipeline. The idea is we lookahead and use a worker to prefetch
            // the next data chunk in the stream, this eliminates some of the problems with latency
            // when fetching from a slow storage engine.

            let (height, chunk_address) = tr.next_addr()?.unwrap();
            let mut next_in_pipeline = (
                height,
                chunk_address,
                storage_engine.get_chunk_async(&chunk_address),
            );

            // Idea:
            // we could use a queue with N values, initially filled with noops to utilize N workers
            // worth of lookahead. The tradeoff is we can have a peak memory usage of N*MaxChunkSize.
            loop {
                let (height, chunk_address, pending_chunk) = next_in_pipeline;
                let chunk_data = pending_chunk.recv()??;
                if height != 0 {
                    tr.push_level(height - 1, chunk_data.clone())?;
                }

                match tr.next_addr()? {
                    Some((height, chunk_address)) => {
                        next_in_pipeline = (
                            height,
                            chunk_address,
                            storage_engine.get_chunk_async(&chunk_address),
                        );
                    }
                    None => {
                        write_packet(
                            w,
                            &Packet::Chunk(Chunk {
                                address: chunk_address,
                                data: chunk_data,
                            }),
                        )?;
                        return Ok(());
                    }
                }

                write_packet(
                    w,
                    &Packet::Chunk(Chunk {
                        address: chunk_address,
                        data: chunk_data,
                    }),
                )?;
            }
        }
    }
}

fn gc(repo: &mut repository::Repo, w: &mut dyn std::io::Write) -> Result<(), failure::Error> {
    repo.alter_gc_lock_mode(repository::GCLockMode::Exclusive);
    let stats = repo.gc();
    repo.alter_gc_lock_mode(repository::GCLockMode::Shared);
    let stats = stats?;
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
