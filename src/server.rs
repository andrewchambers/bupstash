use super::htree;
use super::itemset;
use super::protocol::*;
use super::repository;
use super::xid::*;

pub struct ServerConfig {
    pub repo_connect: String,
    pub allow_init: bool,
    pub allow_gc: bool,
    pub allow_get: bool,
    pub allow_put: bool,
    pub allow_remove: bool,
}

pub fn serve(
    cfg: ServerConfig,
    r: &mut dyn std::io::Read,
    w: &mut dyn std::io::Write,
) -> Result<(), failure::Error> {
    match serve2(cfg, r, w) {
        Ok(()) => Ok(()),
        Err(err) => write_packet(
            w,
            &Packet::Abort(Abort {
                message: format!("{}", err),
            }),
        ),
    }
}

fn serve2(
    cfg: ServerConfig,
    r: &mut dyn std::io::Read,
    w: &mut dyn std::io::Write,
) -> Result<(), failure::Error> {
    match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
        Packet::ClientInfo(info) => {
            if info.protocol != "0" {
                failure::bail!("Client/Server version mismatch, expected protocol version 0")
            }

            let clock_skew = chrono::Utc::now().signed_duration_since(info.now);
            const MAX_SKEW: i64 = 30;
            if clock_skew > chrono::Duration::minutes(MAX_SKEW)
                || clock_skew < chrono::Duration::minutes(-MAX_SKEW)
            {
                // This helps protect against inaccurate item timestamps, which protects users from unintentionally
                // deleting important backups when deleting based on timestamp queries. Instead they will be notified
                // of the clock mismatch as soon as we know about it.
                failure::bail!("server and client have clock skew larger than {} minutes, refusing connection.", MAX_SKEW);
            }
        }
        _ => failure::bail!("expected client info"),
    }

    match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
        Packet::TInitRepository(_engine) => {
            failure::bail!("server has disabled init for this client")
        }
        mut current_packet => {
            let mut repo = repository::Repo::open(&cfg.repo_connect)?;
            loop {
                match current_packet {
                    Packet::TInitRepository(_) => {
                        failure::bail!(
                            "protocol error, repository initialization must be the first request"
                        );
                    }
                    Packet::TBeginSend(begin) => {
                        if !cfg.allow_put {
                            failure::bail!("server has disabled put for this client")
                        }
                        recv(&mut repo, begin, r, w)?;
                    }
                    Packet::TRequestData(req) => {
                        if !cfg.allow_get {
                            failure::bail!("server has disabled get for this client")
                        }
                        send(&mut repo, req.id, w)?;
                    }
                    Packet::TGc(_) => {
                        if !cfg.allow_gc {
                            failure::bail!("server has disabled garbage collection for this client")
                        }
                        gc(&mut repo, w)?;
                    }
                    Packet::TRequestItemSync(req) => {
                        if !cfg.allow_get && !cfg.allow_remove {
                            failure::bail!("server has disabled query and search for this client")
                        }
                        item_sync(&mut repo, req.after, req.gc_generation, w)?;
                    }
                    Packet::TRmItems(items) => {
                        if !cfg.allow_remove {
                            failure::bail!("server has disabled remove for this client")
                        }
                        if !items.is_empty() {
                            repo.remove_items(items)?;
                        }
                        write_packet(w, &Packet::RRmItems)?;
                    }
                    Packet::EndOfTransmission => return Ok(()),
                    _ => failure::bail!("protocol error, unexpected packet kind"),
                };
                current_packet = read_packet(r, DEFAULT_MAX_PACKET_SIZE)?;
            }
        }
    };
}

fn recv(
    repo: &mut repository::Repo,
    begin: TBeginSend,
    r: &mut dyn std::io::Read,
    w: &mut dyn std::io::Write,
) -> Result<(), failure::Error> {
    write_packet(
        w,
        &Packet::RBeginSend(RBeginSend {
            gc_generation: repo.gc_generation()?,
            has_delta_id: if let Some(delta_id) = begin.delta_id {
                repo.has_item_with_id(&delta_id)?
            } else {
                false
            },
        }),
    )?;

    let mut store_engine = repo.storage_engine()?;

    loop {
        match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
            Packet::Chunk(chunk) => {
                store_engine.add_chunk(&chunk.address, chunk.data)?;
            }
            Packet::TSendSync => {
                store_engine.sync()?;
                write_packet(w, &Packet::RSendSync)?;
            }
            Packet::TAddItem(add_item) => {
                /*
                  We explicitly check the gc_generation again matches what it was
                  when we started, this is not strictly needed with our current locking
                  rules, but it easy to imagine a situation with flock failing on a network
                  file system that uses leases. Essentially gc_generation is a fence token
                  preventing gc and upload in parallel in the case exclusive locking failed.

                  Since the protocol supports this fencing, we could potentially add optimisitc concurrency
                  in the future with looser locking semantics.
                */
                if add_item.gc_generation != repo.gc_generation()? {
                    failure::bail!("gc generation changed during send, aborting");
                }

                store_engine.sync()?;

                let item_id = repo.add_item(add_item.item)?;
                write_packet(w, &Packet::RAddItem(item_id))?;
                break;
            }
            _ => failure::bail!("protocol error, unexpected packet"),
        }
    }

    Ok(())
}

fn send(
    repo: &mut repository::Repo,
    id: Xid,
    w: &mut dyn std::io::Write,
) -> Result<(), failure::Error> {
    let metadata = match repo.lookup_item_by_id(&id)? {
        Some(metadata) => {
            write_packet(
                w,
                &Packet::RRequestData(RRequestData {
                    metadata: Some(metadata.clone()),
                }),
            )?;
            metadata
        }
        None => {
            write_packet(w, &Packet::RRequestData(RRequestData { metadata: None }))?;
            return Ok(());
        }
    };

    let mut storage_engine = repo.storage_engine()?;

    match metadata {
        itemset::VersionedItemMetadata::V1(metadata) => {
            let mut tr = htree::TreeReader::new(
                metadata.plain_text_metadata.tree_height,
                &metadata.plain_text_metadata.address,
            );

            // The idea is we fetch the next chunk while we are sending the current chunk.
            // to mitigate some of the problems with latency when fetching from a slow storage engine.

            let (height, chunk_address) = tr.next_addr()?.unwrap();
            let mut next = (
                height,
                chunk_address,
                storage_engine.get_chunk_async(&chunk_address),
            );

            loop {
                let (height, chunk_address, pending_chunk) = next;
                let chunk_data = pending_chunk.recv()??;
                if height != 0 {
                    tr.push_level(height - 1, chunk_data.clone())?;
                }

                match tr.next_addr()? {
                    Some((height, chunk_address)) => {
                        next = (
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

                // Write the chunk out while the async worker fetches the next one.
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
    let mut update_progress_msg = |msg| {
        write_packet(w, &Packet::Progress(Progress::SetMessage(msg)))?;
        Ok(())
    };

    let stats = repo.gc(&mut update_progress_msg)?;

    write_packet(w, &Packet::RGc(RGc { stats }))?;
    Ok(())
}

fn item_sync(
    repo: &mut repository::Repo,
    after: i64,
    request_gc_generation: Option<Xid>,
    w: &mut dyn std::io::Write,
) -> Result<(), failure::Error> {
    let current_generation = repo.gc_generation()?;

    let after = match request_gc_generation {
        Some(request_gc_generation) if request_gc_generation == current_generation => after,
        _ => -1,
    };

    write_packet(
        w,
        &Packet::RRequestItemSync(RRequestItemSync {
            gc_generation: current_generation,
        }),
    )?;

    let mut logops = Vec::new();

    repo.walk_log(after, &mut |op_id, item_id, op| {
        logops.push((op_id, item_id, op));
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
