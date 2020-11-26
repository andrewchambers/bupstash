use super::address;
use super::compression;
use super::htree;
use super::index;
use super::itemset;
use super::protocol::*;
use super::repository;
use super::xid::*;
use std::convert::TryInto;

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
) -> Result<(), anyhow::Error> {
    loop {
        match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
            Packet::TOpenRepository(req) => {
                if req.repository_protocol_version != "4" {
                    anyhow::bail!(
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
                    anyhow::bail!("server has disabled init for this client")
                }
                repository::Repo::init(std::path::Path::new(&cfg.repo_path), engine)?;
                write_packet(w, &Packet::RInitRepository)?;
            }

            Packet::EndOfTransmission => return Ok(()),
            _ => anyhow::bail!("expected client info"),
        }
    }
}

fn serve_repository(
    cfg: ServerConfig,
    repo: &mut repository::Repo,
    r: &mut dyn std::io::Read,
    w: &mut dyn std::io::Write,
) -> Result<(), anyhow::Error> {
    loop {
        match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
            Packet::TInitRepository(_) => {
                anyhow::bail!(
                    "protocol error, repository initialization must be the first request"
                );
            }
            Packet::TBeginSend(begin) => {
                if !cfg.allow_put {
                    anyhow::bail!("server has disabled put for this client")
                }
                repo.alter_lock_mode(repository::LockMode::Write)?;
                recv(repo, begin, r, w)?;
            }
            Packet::TRequestMetadata(req) => {
                if !cfg.allow_get {
                    anyhow::bail!("server has disabled get for this client")
                }
                repo.alter_lock_mode(repository::LockMode::None)?;
                send_metadata(repo, req.id, w)?;
            }
            Packet::RequestData(req) => {
                if !cfg.allow_get {
                    anyhow::bail!("server has disabled get for this client")
                }
                repo.alter_lock_mode(repository::LockMode::None)?;
                send(repo, req.id, req.ranges, w)?;
            }
            Packet::RequestIndex(req) => {
                if !cfg.allow_get {
                    anyhow::bail!("server has disabled get for this client")
                }
                repo.alter_lock_mode(repository::LockMode::None)?;
                send_index(repo, req.id, w)?;
            }
            Packet::TGc(_) => {
                if !cfg.allow_gc {
                    anyhow::bail!("server has disabled garbage collection for this client")
                }
                repo.alter_lock_mode(repository::LockMode::Write)?;
                gc(repo, w)?;
            }
            Packet::TRequestItemSync(req) => {
                if !cfg.allow_get && !cfg.allow_remove {
                    anyhow::bail!("server has disabled query and search for this client")
                }
                repo.alter_lock_mode(repository::LockMode::None)?;
                item_sync(repo, req.after, req.gc_generation, w)?;
            }
            Packet::TRmItems(items) => {
                if !cfg.allow_remove {
                    anyhow::bail!("server has disabled remove for this client")
                }
                repo.alter_lock_mode(repository::LockMode::Write)?;
                if !items.is_empty() {
                    repo.remove_items(items)?;
                }
                write_packet(w, &Packet::RRmItems)?;
            }
            Packet::TRestoreRemoved => {
                if !cfg.allow_put || !cfg.allow_get {
                    anyhow::bail!("server has disabled restore for this client (restore requires get and put permissions).")
                }
                repo.alter_lock_mode(repository::LockMode::Write)?;
                let n_restored = repo.restore_removed()?;
                write_packet(
                    w,
                    &Packet::RRestoreRemoved(RRestoreRemoved {
                        n_restored: serde_bare::Uint(n_restored),
                    }),
                )?;
            }
            Packet::EndOfTransmission => return Ok(()),
            _ => anyhow::bail!("protocol error, unexpected packet kind"),
        };
    }
}

fn recv(
    repo: &mut repository::Repo,
    begin: TBeginSend,
    r: &mut dyn std::io::Read,
    w: &mut dyn std::io::Write,
) -> Result<(), anyhow::Error> {
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
            _ => anyhow::bail!("protocol error, unexpected packet"),
        }
    }

    Ok(())
}

fn send_metadata(
    repo: &mut repository::Repo,
    id: Xid,
    w: &mut dyn std::io::Write,
) -> Result<(), anyhow::Error> {
    match repo.lookup_item_by_id(&id)? {
        Some(metadata) => {
            write_packet(
                w,
                &Packet::RRequestMetadata(RRequestMetadata {
                    metadata: Some(metadata),
                }),
            )?;
            Ok(())
        }
        None => {
            write_packet(
                w,
                &Packet::RRequestMetadata(RRequestMetadata { metadata: None }),
            )?;
            Ok(())
        }
    }
}

fn send(
    repo: &mut repository::Repo,
    id: Xid,
    ranges: Option<Vec<index::HTreeDataRange>>,
    w: &mut dyn std::io::Write,
) -> Result<(), anyhow::Error> {
    let metadata = match repo.lookup_item_by_id(&id)? {
        Some(metadata) => metadata,
        None => anyhow::bail!("client requested missing item"),
    };

    match metadata {
        itemset::VersionedItemMetadata::V1(metadata) => {
            let mut tr = htree::TreeReader::new(
                metadata.plain_text_metadata.data_tree.height.try_into()?,
                metadata.plain_text_metadata.data_tree.data_chunk_count,
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
) -> Result<(), anyhow::Error> {
    let metadata = match repo.lookup_item_by_id(&id)? {
        Some(metadata) => metadata,
        None => anyhow::bail!("client requested index for missing item"),
    };

    match metadata {
        itemset::VersionedItemMetadata::V1(metadata) => {
            if let Some(index_tree) = metadata.plain_text_metadata.index_tree {
                let mut tr = htree::TreeReader::new(
                    index_tree.height.try_into()?,
                    index_tree.data_chunk_count,
                    &index_tree.address,
                );
                send_htree(repo, &mut tr, w)?;
            } else {
                anyhow::bail!("requested item does not have an index");
            }
        }
    }

    Ok(())
}

const HTREE_SEND_PIPELINE_LEN: usize = 5;

fn send_htree(
    repo: &mut repository::Repo,
    tr: &mut htree::TreeReader,
    w: &mut dyn std::io::Write,
) -> Result<(), anyhow::Error> {
    let mut storage_engine = repo.storage_engine()?;

    loop {
        match tr.current_height() {
            Some(0) => {
                let mut chunk_address = address::Address::default();
                let mut pipeline = std::collections::VecDeque::new();

                for ent_slice in tr.pop_level().unwrap().chunks(8 + address::ADDRESS_SZ) {
                    let address_slice = &ent_slice[8..];
                    chunk_address.bytes.clone_from_slice(&address_slice);
                    pipeline.push_back((
                        chunk_address,
                        storage_engine.get_chunk_async(&chunk_address),
                    ));

                    if pipeline.len() >= HTREE_SEND_PIPELINE_LEN {
                        let (chunk_address, chunk_data) = pipeline.pop_front().unwrap();
                        write_chunk(w, &chunk_address, &chunk_data.recv()??)?;
                    }
                }

                while let Some((chunk_address, chunk_data)) = pipeline.pop_front() {
                    write_chunk(w, &chunk_address, &chunk_data.recv()??)?;
                }
            }
            Some(_) => {
                if let Some((height, chunk_address)) = tr.next_addr() {
                    let chunk_data = storage_engine.get_chunk(&chunk_address)?;
                    write_chunk(w, &chunk_address, &chunk_data)?;
                    let chunk_data = compression::unauthenticated_decompress(chunk_data)?;
                    tr.push_level(height - 1, chunk_data)?;
                }
            }
            None => break,
        }
    }

    Ok(())
}

fn send_partial_htree(
    repo: &mut repository::Repo,
    tr: &mut htree::TreeReader,
    ranges: Vec<index::HTreeDataRange>,
    w: &mut dyn std::io::Write,
) -> Result<(), anyhow::Error> {
    if ranges.is_empty() {
        anyhow::bail!("malformed tree fetch range, range is empty")
    }

    // The ranges are sent from the client, first validate them.
    for (i, r) in ranges.iter().enumerate() {
        if r.start_idx > r.end_idx {
            anyhow::bail!("malformed htree fetch range, start point after end");
        }

        match ranges.get(i + 1) {
            Some(next) if next.start_idx == r.end_idx => {
                anyhow::bail!("malformed htree fetch range, not in minimal form")
            }
            Some(next) if next.start_idx < r.end_idx => {
                anyhow::bail!("malformed htree fetch range, not in sorted order")
            }
            _ => (),
        }
    }

    let mut range_idx: usize = 0;
    let mut storage_engine = repo.storage_engine()?;
    let mut current_data_chunk_idx: u64 = 0;
    let start_chunk_idx = ranges[range_idx].start_idx;

    // Use the offset data in the htree to efficiently seek to the first data chunk.
    loop {
        let height = match tr.current_height() {
            Some(v) => v,
            None => anyhow::bail!("htree is corrupt, pick data not found"),
        };

        if height == 0 {
            break;
        }

        let (_, address) = tr.next_addr().unwrap();

        let chunk_data = storage_engine.get_chunk(&address)?;
        write_chunk(w, &address, &chunk_data)?;
        let mut chunk_data = compression::unauthenticated_decompress(chunk_data)?;

        let mut level_data_chunk_idx = current_data_chunk_idx;
        let mut skip_count = 0;
        for ent_slice in chunk_data.chunks(8 + address::ADDRESS_SZ) {
            let data_chunk_count = u64::from_le_bytes(ent_slice[..8].try_into()?);
            if level_data_chunk_idx + data_chunk_count > start_chunk_idx {
                break;
            }
            level_data_chunk_idx += data_chunk_count;
            skip_count += 1;
        }
        current_data_chunk_idx = level_data_chunk_idx;
        chunk_data.drain(0..(skip_count * (8 + address::ADDRESS_SZ)));
        tr.push_level(height - 1, chunk_data)?;
    }

    if current_data_chunk_idx != start_chunk_idx {
        anyhow::bail!("htree is corrupt, seek went too far");
    }

    // Mostly the same as the less complicated send_htree function, but we filter out unwanted chunks and exit early.
    loop {
        match tr.current_height() {
            Some(0) => {
                let mut chunk_address = address::Address::default();
                let mut pipeline = std::collections::VecDeque::new();
                let level_chunk = tr.pop_level().unwrap();
                for ent_slice in level_chunk.chunks(8 + address::ADDRESS_SZ) {
                    let address_slice = &ent_slice[8..];
                    match ranges.get(range_idx) {
                        Some(current_range) => {
                            chunk_address.bytes.clone_from_slice(&address_slice);
                            if current_data_chunk_idx >= current_range.start_idx
                                && current_data_chunk_idx <= current_range.end_idx
                            {
                                pipeline.push_back((
                                    chunk_address,
                                    storage_engine.get_chunk_async(&chunk_address),
                                ));

                                if pipeline.len() >= HTREE_SEND_PIPELINE_LEN {
                                    let (chunk_address, chunk_data) = pipeline.pop_front().unwrap();
                                    write_chunk(w, &chunk_address, &chunk_data.recv()??)?;
                                }
                            }

                            current_data_chunk_idx += 1;
                            if current_data_chunk_idx > current_range.end_idx {
                                range_idx += 1;
                            }
                        }
                        None => break,
                    }
                }

                while let Some((chunk_address, chunk_data)) = pipeline.pop_front() {
                    write_chunk(w, &chunk_address, &chunk_data.recv()??)?;
                }
            }
            Some(_) if ranges.get(range_idx).is_some() => {
                if let Some((height, chunk_address)) = tr.next_addr() {
                    let chunk_data = storage_engine.get_chunk(&chunk_address)?;
                    write_chunk(w, &chunk_address, &chunk_data)?;
                    let chunk_data = compression::unauthenticated_decompress(chunk_data)?;
                    tr.push_level(height - 1, chunk_data)?;
                }
            }
            _ => break,
        }
    }

    Ok(())
}

fn gc(repo: &mut repository::Repo, w: &mut dyn std::io::Write) -> Result<(), anyhow::Error> {
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
) -> Result<(), anyhow::Error> {
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
