use super::acache;
use super::address;
use super::compression;
use super::htree;
use super::oplog;
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
    pub allow_list: bool,
    pub allow_sync: bool,
}

pub fn serve(
    cfg: ServerConfig,
    r: &mut dyn std::io::Read,
    w: &mut dyn std::io::Write,
) -> Result<(), anyhow::Error> {
    loop {
        match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
            Packet::TOpenRepository(req) => {
                if req.protocol_version != CURRENT_REPOSITORY_PROTOCOL_VERSION {
                    anyhow::bail!(
                        "client and server protocol versions are incompatible, got {}, wanted {}",
                        req.protocol_version,
                        CURRENT_REPOSITORY_PROTOCOL_VERSION,
                    )
                }

                let open_lock_mode = match req.open_mode {
                    OpenMode::Read => repository::RepoLockMode::None,
                    OpenMode::ReadWrite => repository::RepoLockMode::Shared,
                    OpenMode::Gc => repository::RepoLockMode::Shared,
                };

                let mut repo = repository::Repo::open(&cfg.repo_path, open_lock_mode)?;

                write_packet(
                    w,
                    &Packet::ROpenRepository(ROpenRepository {
                        unix_now_millis: chrono::Utc::now().timestamp_millis() as u64,
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
                recv(repo, begin, r, w)?;
            }
            Packet::TRequestMetadata(req) => {
                if !cfg.allow_list {
                    anyhow::bail!("server has disabled listing for this client")
                }
                send_metadata(repo, req.id, w)?;
            }
            Packet::RequestData(req) => {
                if !cfg.allow_get {
                    anyhow::bail!("server has disabled get for this client")
                }
                send(repo, req.id, req.partial, r, w)?;
            }
            Packet::RequestIndex(req) => {
                if !cfg.allow_list {
                    anyhow::bail!("server has disabled listing for this client")
                }
                send_index(repo, req.id, w)?;
            }
            Packet::TGc(_) => {
                if !cfg.allow_gc {
                    anyhow::bail!("server has disabled garbage collection for this client")
                }
                gc(repo, w)?;
            }
            Packet::TRequestOpLogSync(req) => {
                if !cfg.allow_list {
                    anyhow::bail!("server has disabled query and search for this client")
                }
                oplog_sync(repo, req.after.map(|x| x.0), req.gc_generation, w)?;
            }
            Packet::TRmItems(items) => {
                if !cfg.allow_remove {
                    anyhow::bail!("server has disabled remove for this client")
                }
                let n_removed = repo.remove_items(items)?;
                write_packet(w, &Packet::RRmItems(serde_bare::Uint(n_removed)))?;
            }
            Packet::TRecoverRemoved => {
                if !cfg.allow_get || !cfg.allow_put || !cfg.allow_list {
                    anyhow::bail!("server has disabled recover-removed for this client (recover-removed requires get, put and list permissions).")
                }
                let n_recovered = repo.recover_removed()?;
                write_packet(
                    w,
                    &Packet::RRecoverRemoved(RRecoverRemoved {
                        n_recovered: serde_bare::Uint(n_recovered),
                    }),
                )?;
            }
            Packet::TBeginItemSyncPush => {
                if !cfg.allow_sync {
                    anyhow::bail!("server has disabled sync push for this client")
                }
                item_sync_push(repo, r, w)?;
            }
            Packet::TBeginItemSyncPull => {
                if !cfg.allow_get {
                    anyhow::bail!(
                        "server has disabled get (and therefore sync pull) for this client"
                    )
                }
                item_sync_pull(repo, r, w)?;
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
    // Prevent any garbage collection from taking place during send.
    repo.alter_lock_mode(repository::RepoLockMode::Shared)?;

    let item_id = Xid::new();
    let gc_generation = repo.gc_generation()?;

    write_packet(
        w,
        &Packet::RBeginSend(RBeginSend {
            item_id,
            gc_generation,
            has_delta_id: if let Some(delta_id) = begin.delta_id {
                repo.has_complete_data(&delta_id)?
            } else {
                false
            },
        }),
    )?;

    loop {
        match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
            Packet::Chunk(chunk) => {
                repo.add_chunk(&chunk.address, chunk.data)?;
            }
            Packet::TFlush => {
                let stats = repo.flush()?;
                write_packet(w, &Packet::RFlush(stats))?;
            }
            Packet::TAddItem(add_item) => {
                match add_item.item {
                    oplog::VersionedItemMetadata::V3(ref md) => {
                        let item_skew = (md.plain_text_metadata.unix_timestamp_millis as i64)
                            - chrono::Utc::now().timestamp_millis();
                        const MAX_SKEW_MINS: i64 = 15;
                        const MAX_SKEW_MILLIS: i64 = MAX_SKEW_MINS * 60 * 1000;
                        if !(-MAX_SKEW_MILLIS..=MAX_SKEW_MILLIS).contains(&item_skew) {
                            // This check prevents the client from spoofing times without also controlling the server.
                            // The client is protected from server spoofed times by the metadata hash.
                            anyhow::bail!("added item has timestamp skew larger than {} minutes, refusing new item.", MAX_SKEW_MINS);
                        }
                    }

                    _ => anyhow::bail!("server refusing new item with outdated metadata version"),
                }

                repo.add_item(item_id, add_item.item)?;
                write_packet(w, &Packet::RAddItem)?;
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
    partial: bool,
    r: &mut dyn std::io::Read,
    w: &mut dyn std::io::Write,
) -> Result<(), anyhow::Error> {
    let metadata = match repo.lookup_item_by_id(&id)? {
        Some(metadata) => metadata,
        None => anyhow::bail!("client requested missing item"),
    };

    let data_tree = metadata.data_tree();

    let mut tr = htree::TreeReader::new(
        data_tree.height.0.try_into()?,
        data_tree.data_chunk_count.0,
        &data_tree.address,
    );

    if partial {
        send_partial_htree(repo, &mut tr, r, w)?;
    } else {
        send_htree(repo, &mut tr, w)?;
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

    if let Some(index_tree) = metadata.index_tree() {
        let mut tr = htree::TreeReader::new(
            index_tree.height.0.try_into()?,
            index_tree.data_chunk_count.0,
            &index_tree.address,
        );
        send_htree(repo, &mut tr, w)?;
    } else {
        anyhow::bail!("requested item does not have an index");
    }

    Ok(())
}

fn send_htree(
    repo: &mut repository::Repo,
    tr: &mut htree::TreeReader,
    w: &mut dyn std::io::Write,
) -> Result<(), anyhow::Error> {
    let mut on_chunk = |addr: &address::Address, data: &[u8]| -> Result<(), anyhow::Error> {
        write_chunk(w, addr, data)?;
        Ok(())
    };

    loop {
        match tr.current_height() {
            Some(0) => {
                let mut address_buf = tr.pop_level().unwrap();
                let n_addresses = address_buf.len() / (8 + address::ADDRESS_SZ);
                // Shift addresses to contiguous part of buffer.
                for i in 0..n_addresses {
                    let src_offset = 8 + i * (8 + address::ADDRESS_SZ);
                    let src_range = src_offset..(src_offset + address::ADDRESS_SZ);
                    address_buf.copy_within(src_range, i * address::ADDRESS_SZ);
                }
                let addresses =
                    address::bytes_to_addresses(&address_buf[0..n_addresses * address::ADDRESS_SZ]);
                repo.pipelined_get_chunks(addresses, &mut on_chunk)?;
            }
            Some(_) => {
                if let Some((height, chunk_address)) = tr.next_addr() {
                    let chunk_data = repo.get_chunk(&chunk_address)?;
                    on_chunk(&chunk_address, &chunk_data)?;
                    let decompressed = compression::unauthenticated_decompress(chunk_data)?;
                    tr.push_level(height - 1, decompressed)?;
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
    r: &mut dyn std::io::Read,
    w: &mut dyn std::io::Write,
) -> Result<(), anyhow::Error> {
    let mut data_addresses = Vec::with_capacity(64);
    let mut range_idx: usize = 0;
    let mut current_data_chunk_idx: u64 = 0;

    let mut ranges = match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
        Packet::RequestDataRanges(ranges) if !ranges.is_empty() => ranges,
        _ => anyhow::bail!("protocol error, expected RequestDataRanges with non empty ranges"),
    };

    let mut on_chunk = |addr: &address::Address, data: &[u8]| -> Result<(), anyhow::Error> {
        write_chunk(w, addr, data)?;
        Ok(())
    };

    loop {
        // Get the current range.
        let range = match ranges.get(range_idx) {
            Some(range) => {
                if current_data_chunk_idx > range.end_idx.0 {
                    range_idx += 1;
                    continue;
                }
                range
            }
            None => {
                range_idx = 0;
                ranges = match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
                    Packet::RequestDataRanges(ranges) => ranges,
                    _ => anyhow::bail!("protocol error, expected RequestDataRanges"),
                };
                if ranges.is_empty() {
                    return Ok(());
                }
                continue;
            }
        };

        // Fast forward until we are at the correct data chunk boundary.
        loop {
            let num_skipped = tr.fast_forward(range.start_idx.0 - current_data_chunk_idx)?;
            current_data_chunk_idx += num_skipped;
            if let Some(height) = tr.current_height() {
                if height == 0 && current_data_chunk_idx >= range.start_idx.0 {
                    break;
                } else {
                    let (_, chunk_addr) = tr.next_addr().unwrap();
                    let chunk_data = repo.get_chunk(&chunk_addr)?;
                    on_chunk(&chunk_addr, &chunk_data)?;
                    let chunk_data = compression::unauthenticated_decompress(chunk_data)?;
                    tr.push_level(height - 1, chunk_data)?;
                }
            } else {
                anyhow::bail!("hash tree ended before requested range");
            }
        }

        if current_data_chunk_idx != range.start_idx.0 {
            anyhow::bail!(
                "requested data ranges do not match hash tree accounting, seek overshoot detected"
            )
        }

        while current_data_chunk_idx + (data_addresses.len() as u64) <= range.end_idx.0 {
            match tr.current_height() {
                Some(0) => match tr.next_addr() {
                    Some((0, chunk_addr)) => {
                        data_addresses.push(chunk_addr);
                    }
                    _ => unreachable!(),
                },
                _ => break,
            }
        }
        repo.pipelined_get_chunks(&data_addresses, &mut on_chunk)?;
        current_data_chunk_idx += data_addresses.len() as u64;
        data_addresses.clear();
    }
}

fn gc(repo: &mut repository::Repo, w: &mut dyn std::io::Write) -> Result<(), anyhow::Error> {
    let mut update_progress_msg = |msg| {
        write_packet(w, &Packet::GcProgress(msg))?;
        Ok(())
    };
    let stats = repo.gc(&mut update_progress_msg)?;
    write_packet(w, &Packet::RGc(RGc { stats }))?;
    Ok(())
}

fn oplog_sync(
    repo: &mut repository::Repo,
    after: Option<u64>,
    request_gc_generation: Option<Xid>,
    w: &mut dyn std::io::Write,
) -> Result<(), anyhow::Error> {
    repo.oplog_sync(after, request_gc_generation, &mut |event| match event {
        repository::OpLogSyncEvent::Start(gc_generation) => {
            write_packet(
                w,
                &Packet::RRequestOpLogSync(RRequestOpLogSync { gc_generation }),
            )?;
            Ok(())
        }
        repository::OpLogSyncEvent::LogOps(ops) => {
            write_packet(w, &Packet::SyncLogOps(ops))?;
            Ok(())
        }
        repository::OpLogSyncEvent::End => {
            write_packet(w, &Packet::SyncLogOps(vec![]))?;
            Ok(())
        }
    })?;
    Ok(())
}

fn item_sync_push(
    repo: &mut repository::Repo,
    r: &mut dyn std::io::Read,
    w: &mut dyn std::io::Write,
) -> Result<(), anyhow::Error> {
    repo.alter_lock_mode(repository::RepoLockMode::Shared)?;

    write_packet(
        w,
        &Packet::RBeginItemSyncPush(RBeginItemSyncPush {
            gc_generation: repo.gc_generation()?,
        }),
    )?;

    loop {
        match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
            Packet::ItemSyncFilterItems(items) => {
                let mut on_progress = |progress| {
                    write_packet(
                      w,
                      &Packet::ItemSyncFilterItemsProgress(serde_bare::Uint(progress)),
                    )
                };
                let items = repo.filter_items_with_complete_data(&mut on_progress, items)?;
                write_packet(w, &Packet::ItemSyncItems(items))?;
            }
            Packet::ItemSyncFilterExisting(mut addresses) => {
                let mut on_progress = |progress| {
                    write_packet(
                      w,
                      &Packet::ItemSyncFilterExistingProgress(serde_bare::Uint(progress)),
                    )
                };
                addresses = repo.filter_existing_chunks(&mut on_progress, addresses)?;
                write_item_sync_addresses(w, &addresses)?;
            }
            Packet::Chunk(chunk) => {
                repo.add_chunk(&chunk.address, chunk.data)?;
            }
            Packet::TFlush => {
                let stats = repo.flush()?;
                write_packet(w, &Packet::RFlush(stats))?;
            }
            Packet::ItemSyncAddItems(items) => {
                repo.import_items(items)?;
            }
            Packet::TEndItemSyncPush => {
                write_packet(w, &Packet::REndItemSyncPush)?;
                break;
            }
            _ => anyhow::bail!("expected TItemSyncFilterItems, ItemSyncAddresses, Chunk, TFlush, ItemSyncAddItems or TEndItemSyncPush packet"),
        }
    }

    Ok(())
}

fn item_sync_pull(
    repo: &mut repository::Repo,
    r: &mut dyn std::io::Read,
    w: &mut dyn std::io::Write,
) -> Result<(), anyhow::Error> {
    repo.alter_lock_mode(repository::RepoLockMode::Shared)?;

    write_packet(w, &Packet::RBeginItemSyncPull)?;

    let mut address_cache = acache::ACache::new(1048576);

    loop {
        match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
            Packet::ItemSyncRequestMetadata(item_ids) => {
                for metadata in item_ids
                    .chunks(128)
                    .map(|item_ids| repo.batch_read_items(item_ids))
                {
                    write_packet(w, &Packet::ItemSyncMetadata(metadata?))?;
                }
            }
            Packet::ItemSyncRequestAddresses(item_ids) => {
                const ADDRESSES_PER_PACKET: usize = DEFAULT_MAX_PACKET_SIZE / address::ADDRESS_SZ;
                let mut address_batch = Vec::with_capacity(4096);

                for id in item_ids {
                    let item_metadata = match repo.lookup_item_by_id(&id)? {
                        Some(md) => md,
                        None => anyhow::bail!("sync failed, requested item no longer exists"),
                    };

                    let data_tree = item_metadata.data_tree();

                    let trees = if let Some(index_tree) = item_metadata.index_tree() {
                        vec![data_tree, index_tree]
                    } else {
                        vec![data_tree]
                    };

                    for tree in trees {
                        let mut tr = htree::TreeReader::new(
                            tree.height.0.try_into()?,
                            tree.data_chunk_count.0,
                            &tree.address,
                        );

                        while let Some((height, addr)) = tr.next_addr() {
                            let new_address = address_cache.add(&addr);

                            if new_address {
                                address_batch.push(addr);
                                // Send a batch of addresses periodically if things are slow,
                                // this lets us show progress to the user at more pleasant intervals.
                                if address_batch.len() == ADDRESSES_PER_PACKET
                                    || (height != 0 && (address_batch.len() > 5000))
                                {
                                    write_item_sync_addresses(w, &address_batch)?;
                                    address_batch.truncate(0);
                                }
                            }

                            if height != 0 && new_address {
                                let data = repo.get_chunk(&addr)?;
                                let data = compression::unauthenticated_decompress(data)?;
                                tr.push_level(height - 1, data)?;
                            }
                        }
                    }
                }
                if !address_batch.is_empty() {
                    write_item_sync_addresses(w, &address_batch)?;
                }
                write_item_sync_addresses(w, &[])?;
            }
            Packet::ItemSyncAddresses(addresses) => {
                repo.pipelined_get_chunks(&addresses, &mut |address, data| {
                    write_chunk(w, address, data)?;
                    Ok(())
                })?;
            }
            Packet::TEndItemSyncPull => {
                write_packet(w, &Packet::REndItemSyncPull)?;
                break;
            }
            _ => anyhow::bail!(
                "Expected ItemSyncRequestAddresses, ItemSyncAddresses or TEndItemSyncPull",
            ),
        }
    }

    Ok(())
}
