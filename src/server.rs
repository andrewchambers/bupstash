use super::address;
use super::compression;
use super::htree;
use super::index;
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
}

pub fn serve(
    cfg: ServerConfig,
    r: &mut dyn std::io::Read,
    w: &mut dyn std::io::Write,
) -> Result<(), anyhow::Error> {
    loop {
        match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
            Packet::TOpenRepository(req) => {
                if req.protocol_version != "8" {
                    anyhow::bail!(
                        "server does not support bupstash protocol version {}",
                        req.protocol_version
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
                send(repo, req.id, req.ranges, w)?;
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
            Packet::TRequestItemSync(req) => {
                if !cfg.allow_list {
                    anyhow::bail!("server has disabled query and search for this client")
                }
                item_sync(repo, req.after.map(|x| x.0), req.gc_generation, w)?;
            }
            Packet::TRmItems(items) => {
                if !cfg.allow_remove {
                    anyhow::bail!("server has disabled remove for this client")
                }
                if !items.is_empty() {
                    repo.remove_items(items)?;
                }
                write_packet(w, &Packet::RRmItems)?;
            }
            Packet::TRestoreRemoved => {
                if !cfg.allow_get || !cfg.allow_put || !cfg.allow_list {
                    anyhow::bail!("server has disabled restore for this client (restore requires get, put and list permissions).")
                }
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
    // Prevent any garbage collection from taking place during send.
    repo.alter_lock_mode(repository::RepoLockMode::Shared)?;

    let gc_generation = repo.gc_generation()?;

    write_packet(
        w,
        &Packet::RBeginSend(RBeginSend {
            gc_generation,
            has_delta_id: if let Some(delta_id) = begin.delta_id {
                repo.has_item_with_id(&delta_id)?
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
            Packet::TSendSync => {
                let stats = repo.sync()?;
                write_packet(w, &Packet::RSendSync(stats))?;
            }
            Packet::TAddItem(add_item) => {
                // This is an extra check that is not currently used, but may be
                // used for optimistic concurrency such that we do not need to hold repository locks.
                if add_item.gc_generation != gc_generation {
                    anyhow::bail!("client sent an unexpected gc_generation");
                }

                match add_item.item {
                    oplog::VersionedItemMetadata::V2(ref md) => {
                        let item_skew = (md.plain_text_metadata.unix_timestamp_millis as i64)
                            - chrono::Utc::now().timestamp_millis();
                        const MAX_SKEW_MINS: i64 = 15;
                        const MAX_SKEW_MILLIS: i64 = MAX_SKEW_MINS * 60 * 1000;
                        if item_skew > MAX_SKEW_MILLIS || item_skew < -MAX_SKEW_MILLIS {
                            // This check prevents the client from spoofing times without also controlling the server.
                            // The client is protected from server spoofed times by the metadata hash.
                            anyhow::bail!("added item has timestamp skew larger than {} minutes, refusing new item.", MAX_SKEW_MINS);
                        }
                    }

                    _ => anyhow::bail!("server refusing item with incorrect metadata version"),
                }

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

    let data_tree = metadata.data_tree();

    let mut tr = htree::TreeReader::new(
        data_tree.height.0.try_into()?,
        data_tree.data_chunk_count.0,
        &data_tree.address,
    );

    if let Some(ranges) = ranges {
        send_partial_htree(repo, &mut tr, ranges, w)?;
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
    ranges: Vec<index::HTreeDataRange>,
    w: &mut dyn std::io::Write,
) -> Result<(), anyhow::Error> {
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
    let mut current_data_chunk_idx: u64 = 0;
    let start_chunk_idx = match ranges.get(0) {
        Some(range) => range.start_idx,
        None => serde_bare::Uint(0),
    };

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

        let chunk_data = repo.get_chunk(&address)?;
        write_chunk(w, &address, &chunk_data)?;
        let mut chunk_data = compression::unauthenticated_decompress(chunk_data)?;

        let mut level_data_chunk_idx = current_data_chunk_idx;
        let mut skip_count = 0;
        for ent_slice in chunk_data.chunks(8 + address::ADDRESS_SZ) {
            let data_chunk_count = u64::from_le_bytes(ent_slice[..8].try_into()?);
            if level_data_chunk_idx + data_chunk_count > start_chunk_idx.0 {
                break;
            }
            level_data_chunk_idx += data_chunk_count;
            skip_count += 1;
        }
        current_data_chunk_idx = level_data_chunk_idx;
        chunk_data.drain(0..(skip_count * (8 + address::ADDRESS_SZ)));
        tr.push_level(height - 1, chunk_data)?;
    }

    if current_data_chunk_idx != start_chunk_idx.0 {
        anyhow::bail!("htree is corrupt, seek went too far");
    }

    let mut on_chunk = |addr: &address::Address, data: &[u8]| -> Result<(), anyhow::Error> {
        write_chunk(w, addr, data)?;
        Ok(())
    };

    // Mostly the same as the less complicated send_htree function, but we filter out unwanted chunks and exit early.
    loop {
        match tr.current_height() {
            Some(0) => {
                let address_buf = tr.pop_level().unwrap();
                let mut filtered_addresses =
                    Vec::with_capacity(address_buf.len() / (8 + address::ADDRESS_SZ) / 4);

                // XXX This could be an iterator, but it wasn't easy to write nicely,
                // I think when rust gets generators on stable we should use it here.
                for addr in address_buf
                    .chunks(8 + address::ADDRESS_SZ)
                    .map(|x| address::Address::from_slice(&x[8..]).unwrap())
                {
                    match ranges.get(range_idx) {
                        Some(current_range) => {
                            if current_data_chunk_idx >= current_range.start_idx.0
                                && current_data_chunk_idx <= current_range.end_idx.0
                            {
                                filtered_addresses.push(addr)
                            }

                            current_data_chunk_idx += 1;
                            if current_data_chunk_idx > current_range.end_idx.0 {
                                range_idx += 1;
                            }
                        }
                        None => break,
                    }
                }

                repo.pipelined_get_chunks(&filtered_addresses, &mut on_chunk)?;
            }
            Some(_) if ranges.get(range_idx).is_some() => {
                if let Some((height, chunk_address)) = tr.next_addr() {
                    let chunk_data = repo.get_chunk(&chunk_address)?;
                    on_chunk(&chunk_address, &chunk_data)?;
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
    after: Option<u64>,
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
