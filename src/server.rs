use super::address;
use super::htree;
use super::index;
use super::itemset;
use super::protocol::*;
use super::repository;
use super::xid::*;

pub struct ServerConfig {
    pub repo_path: std::path::PathBuf,
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
                code: None,
            }),
        ),
    }
}

fn serve2(
    cfg: ServerConfig,
    r: &mut dyn std::io::Read,
    w: &mut dyn std::io::Write,
) -> Result<(), failure::Error> {
    loop {
        match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
            Packet::TOpenRepository(req) => {
                if req.repository_protocol_version != "1" {
                    failure::bail!(
                        "server does not support bupstash protocol version {}",
                        req.repository_protocol_version
                    )
                }

                let mut repo = repository::Repo::open(&cfg.repo_path)?;

                match req.lock_hint {
                    LockHint::Read => repo.alter_lock_mode(repository::LockMode::None)?,
                    LockHint::Write => repo.alter_lock_mode(repository::LockMode::Write)?,
                    LockHint::Gc => repo.alter_lock_mode(repository::LockMode::Write)?,
                }

                write_packet(
                    w,
                    &Packet::ROpenRepository(ROpenRepository {
                        now: chrono::Utc::now(),
                    }),
                )?;

                return serve_repository(cfg, &mut repo, r, w);
            }

            Packet::TInitRepository(engine) => {
                if !cfg.allow_init {
                    failure::bail!("server has disabled init for this client")
                }
                repository::Repo::init(std::path::Path::new(&cfg.repo_path), engine)?;
                write_packet(w, &Packet::RInitRepository)?;
            }

            Packet::EndOfTransmission => return Ok(()),
            _ => failure::bail!("expected client info"),
        }
    }
}

fn serve_repository(
    cfg: ServerConfig,
    repo: &mut repository::Repo,
    r: &mut dyn std::io::Read,
    w: &mut dyn std::io::Write,
) -> Result<(), failure::Error> {
    loop {
        match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
            Packet::TInitRepository(_) => {
                failure::bail!(
                    "protocol error, repository initialization must be the first request"
                );
            }
            Packet::TBeginSend(begin) => {
                if !cfg.allow_put {
                    failure::bail!("server has disabled put for this client")
                }
                repo.alter_lock_mode(repository::LockMode::Write)?;
                recv(repo, begin, r, w)?;
            }
            Packet::TRequestData(req) => {
                if !cfg.allow_get {
                    failure::bail!("server has disabled get for this client")
                }
                repo.alter_lock_mode(repository::LockMode::None)?;
                send(repo, req.id, req.ranges, w)?;
            }
            Packet::TRequestIndex(req) => {
                if !cfg.allow_get {
                    failure::bail!("server has disabled get for this client")
                }
                repo.alter_lock_mode(repository::LockMode::None)?;
                send_index(repo, req.id, w)?;
            }
            Packet::TGc(_) => {
                if !cfg.allow_gc {
                    failure::bail!("server has disabled garbage collection for this client")
                }
                repo.alter_lock_mode(repository::LockMode::Write)?;
                gc(repo, w)?;
            }
            Packet::TRequestItemSync(req) => {
                if !cfg.allow_get && !cfg.allow_remove {
                    failure::bail!("server has disabled query and search for this client")
                }
                repo.alter_lock_mode(repository::LockMode::None)?;
                item_sync(repo, req.after, req.gc_generation, w)?;
            }
            Packet::TRmItems(items) => {
                if !cfg.allow_remove {
                    failure::bail!("server has disabled remove for this client")
                }
                repo.alter_lock_mode(repository::LockMode::Write)?;
                if !items.is_empty() {
                    repo.remove_items(items)?;
                }
                write_packet(w, &Packet::RRmItems)?;
            }
            Packet::TRestoreRemoved => {
                if !cfg.allow_put || !cfg.allow_get {
                    failure::bail!("server has disabled restore for this client (restore requires get and put permissions).")
                }
                repo.alter_lock_mode(repository::LockMode::Write)?;
                let n_restored = repo.restore_removed()?;
                write_packet(w, &Packet::RRestoreRemoved(RRestoreRemoved { n_restored }))?;
            }
            Packet::EndOfTransmission => return Ok(()),
            _ => failure::bail!("protocol error, unexpected packet kind"),
        };
    }
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
                store_engine.sync()?;
                let item_id = repo.add_item(add_item.gc_generation, add_item.item)?;
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
    ranges: Option<Vec<index::HTreeDataRange>>,
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

    match metadata {
        itemset::VersionedItemMetadata::V1(metadata) => {
            let mut tr = htree::TreeReader::new(
                metadata.plain_text_metadata.data_tree.height,
                &metadata.plain_text_metadata.data_tree.address,
            );

            if let Some(ranges) = ranges {
                send_partial_htree(repo, &mut tr, ranges, w)?;
            } else {
                send_htree(repo, &mut tr, w)?;
            }
        }
    }

    Ok(())
}

fn send_index(
    repo: &mut repository::Repo,
    id: Xid,
    w: &mut dyn std::io::Write,
) -> Result<(), failure::Error> {
    let metadata = match repo.lookup_item_by_id(&id)? {
        Some(metadata) => {
            write_packet(
                w,
                &Packet::RRequestIndex(RRequestIndex {
                    metadata: Some(metadata.clone()),
                }),
            )?;
            metadata
        }
        None => {
            write_packet(w, &Packet::RRequestIndex(RRequestIndex { metadata: None }))?;
            return Ok(());
        }
    };

    match metadata {
        itemset::VersionedItemMetadata::V1(metadata) => {
            if let Some(index_tree) = metadata.plain_text_metadata.index_tree {
                let mut tr = htree::TreeReader::new(index_tree.height, &index_tree.address);
                send_htree(repo, &mut tr, w)?;
            }
        }
    }

    Ok(())
}

fn send_htree(
    repo: &mut repository::Repo,
    tr: &mut htree::TreeReader,
    w: &mut dyn std::io::Write,
) -> Result<(), failure::Error> {
    let mut storage_engine = repo.storage_engine()?;
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

fn send_partial_htree(
    repo: &mut repository::Repo,
    tr: &mut htree::TreeReader,
    ranges: Vec<index::HTreeDataRange>,
    w: &mut dyn std::io::Write,
) -> Result<(), failure::Error> {
    // The ranges are sent from the client, first validate them.
    for (i, r) in ranges.iter().enumerate() {
        if r.start_idx > r.end_idx {
            failure::bail!("malformed htree fetch range, start point after end");
        }

        match ranges.get(i + 1) {
            Some(next) if next.start_idx == r.end_idx => {
                failure::bail!("malformed htree fetch range, not in minimal form")
            }
            Some(next) if next.start_idx < r.end_idx => {
                failure::bail!("malformed htree fetch range, not in sorted order")
            }
            _ => (),
        }
    }

    // Mostly the same as the less complicated send_htree function, but we filter out unwanted chunks and exit early.

    let mut storage_engine = repo.storage_engine()?;

    let (height, chunk_address) = tr.next_addr()?.unwrap();
    let mut next = (
        height,
        chunk_address,
        storage_engine.get_chunk_async(&chunk_address),
    );

    let mut range_idx: usize = 0;
    let mut current_data_chunk_idx: u64 = 0;

    loop {
        let (height, chunk_address, pending_chunk) = next;
        let chunk_data = pending_chunk.recv()??;

        if height == 1 {
            let mut filtered_chunk_data = Vec::with_capacity(chunk_data.len());

            for addr_bytes in chunk_data.chunks(address::ADDRESS_SZ) {
                if let Some(current_range) = ranges.get(range_idx) {
                    if current_data_chunk_idx >= current_range.start_idx
                        && current_data_chunk_idx <= current_range.end_idx
                    {
                        filtered_chunk_data.extend_from_slice(addr_bytes);
                    }
                    current_data_chunk_idx += 1;
                    if current_data_chunk_idx > current_range.end_idx {
                        range_idx += 1;
                    }
                }
            }

            tr.push_level(height - 1, filtered_chunk_data)?;
        } else if ranges.get(range_idx).is_some() {
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

        write_packet(
            w,
            &Packet::Chunk(Chunk {
                address: chunk_address,
                data: chunk_data,
            }),
        )?;
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
    repo.item_sync(after, request_gc_generation, &mut |event| match event {
        repository::ItemSyncEvent::Start(gc_generation) => {
            write_packet(
                w,
                &Packet::RRequestItemSync(RRequestItemSync { gc_generation }),
            )?;
            Ok(())
        }
        repository::ItemSyncEvent::LogOps(ops) => {
            write_packet(w, &Packet::SyncLogOps(ops))?;
            Ok(())
        }
        repository::ItemSyncEvent::End => {
            write_packet(w, &Packet::SyncLogOps(vec![]))?;
            Ok(())
        }
    })?;
    Ok(())
}
