use super::address::*;
use super::compression;
use super::crypto;
use super::fsutil;
use super::htree;
use super::index;
use super::indexer;
use super::ioutil;
use super::oplog;
use super::protocol::*;
use super::put;
use super::querycache;
use super::repository;
use super::rollsum;
use super::sendlog;
use super::xid::*;
use super::xtar;
use itertools::Itertools;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::convert::TryInto;
use std::ffi::OsStr;
use std::io::{Read, Seek, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("corrupt or tampered data")]
    CorruptOrTamperedData,
}

pub fn open_repository(
    w: &mut dyn Write,
    r: &mut dyn Read,
    open_mode: OpenMode,
) -> Result<(), anyhow::Error> {
    write_packet(
        w,
        &Packet::TOpenRepository(TOpenRepository {
            open_mode,
            protocol_version: CURRENT_REPOSITORY_PROTOCOL_VERSION.to_string(),
        }),
    )?;

    match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
        Packet::ROpenRepository(resp) => {
            let clock_skew = (resp.unix_now_millis as i64) - chrono::Utc::now().timestamp_millis();
            const MAX_SKEW_MINS: i64 = 15;
            const MAX_SKEW_MILLIS: i64 = MAX_SKEW_MINS * 60 * 1000;
            if !(-MAX_SKEW_MILLIS..=MAX_SKEW_MILLIS).contains(&clock_skew) {
                // This helps protect against inaccurate item timestamps, which protects users from unintentionally
                // deleting important backups when deleting based on timestamp queries. Instead they will be notified
                // of the clock mismatch as soon as we know about it.
                anyhow::bail!("server and client have clock skew larger than {} minutes, refusing connection.", MAX_SKEW_MINS);
            }
        }
        _ => anyhow::bail!("protocol error, expected begin ack packet"),
    }

    Ok(())
}

pub fn init_repository(
    r: &mut dyn Read,
    w: &mut dyn Write,
    storage_spec: Option<repository::StorageEngineSpec>,
) -> Result<(), anyhow::Error> {
    write_packet(w, &Packet::TInitRepository(storage_spec))?;
    match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
        Packet::RInitRepository => Ok(()),
        _ => anyhow::bail!("protocol error, expected begin ack packet"),
    }
}

pub enum DataSource {
    Subprocess(Vec<String>),
    Readable {
        description: String,
        data: Box<dyn Read>,
    },
    Filesystem {
        paths: Vec<std::path::PathBuf>,
        exclusions: globset::GlobSet,
        exclusion_markers: std::collections::HashSet<std::ffi::OsString>,
    },
}

pub struct PutContext {
    pub progress: indicatif::ProgressBar,
    pub compression: compression::Scheme,
    pub primary_key_id: Xid,
    pub send_key_id: Xid,
    pub data_hash_key: crypto::HashKey,
    pub data_ectx: crypto::EncryptionContext,
    pub idx_hash_key: crypto::HashKey,
    pub idx_ectx: crypto::EncryptionContext,
    pub metadata_ectx: crypto::EncryptionContext,
    pub gear_tab: rollsum::GearTab,
    pub checkpoint_seconds: u64,
    pub want_xattrs: bool,
    pub use_stat_cache: bool,
    pub one_file_system: bool,
    pub ignore_permission_errors: bool,
    pub send_log: Option<sendlog::SendLog>,
    pub file_action_log_fn: Option<Arc<index::FileActionLogFn>>,
    pub indexer_threads: usize,
    pub threads: usize,
}

pub fn put(
    mut ctx: PutContext,
    r: &mut (dyn Read + Send),
    w: &mut (dyn Write + Send),
    tags: BTreeMap<String, String>,
    data: DataSource,
) -> Result<(Xid, put::SendStats), anyhow::Error> {
    let send_id = match ctx.send_log {
        Some(ref mut send_log) => send_log.last_send_id()?,
        None => None,
    };

    write_packet(w, &Packet::TBeginSend(TBeginSend { delta_id: send_id }))?;

    let ack = match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
        Packet::RBeginSend(ack) => ack,
        _ => anyhow::bail!("protocol error, expected begin ack packet"),
    };

    let send_log_session = match ctx.send_log {
        Some(ref mut send_log) => Some(Arc::new(Mutex::new(send_log.session(ack.gc_generation)?))),
        None => None,
    };

    if let Some(ref send_log_session) = send_log_session {
        send_log_session
            .lock()
            .unwrap()
            .perform_cache_invalidations(ack.has_delta_id)?;
    }

    let send_pipeline_ctx = put::PutContext {
        progress: put::ProgressTracker::new(ctx.progress.clone()),
        compression: ctx.compression,
        data_hash_key: ctx.data_hash_key.clone(),
        data_ectx: ctx.data_ectx.clone(),
        idx_hash_key: ctx.idx_hash_key.clone(),
        idx_ectx: ctx.idx_ectx.clone(),
        gear_tab: ctx.gear_tab,
        checkpoint_seconds: ctx.checkpoint_seconds,
        want_xattrs: ctx.want_xattrs,
        use_stat_cache: ctx.use_stat_cache,
        one_file_system: ctx.one_file_system,
        ignore_permission_errors: ctx.ignore_permission_errors,
        send_log_session: send_log_session.clone(),
        file_action_log_fn: ctx.file_action_log_fn.clone(),
        indexer_threads: ctx.indexer_threads,
        threads: ctx.threads,
    };

    let (data_tree, index_tree, stats) = match data {
        DataSource::Subprocess(args) => {
            let quoted_args: Vec<String> =
                args.iter().map(|x| shlex::quote(x).to_string()).collect();
            ctx.progress
                .set_message(format!("exec: {}", quoted_args.join(" ")));

            let mut child = std::process::Command::new(args[0].clone())
                .args(&args[1..])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .spawn()?;

            let mut data = child.stdout.as_mut().unwrap();

            let (data_tree, stats) = put::put_data(send_pipeline_ctx, r, w, &mut data)?;

            let status = child.wait()?;
            if !status.success() {
                anyhow::bail!("child failed with status {}", status.code().unwrap());
            }

            (data_tree, None, stats)
        }
        DataSource::Readable {
            description,
            mut data,
        } => {
            ctx.progress.set_message(description);
            let (data_tree, stats) = put::put_data(send_pipeline_ctx, r, w, &mut data)?;
            (data_tree, None, stats)
        }
        DataSource::Filesystem {
            paths,
            exclusions,
            exclusion_markers,
        } => {
            let indexer = indexer::FsIndexer::new(
                &paths,
                indexer::FsIndexerOptions {
                    one_file_system: ctx.one_file_system,
                    want_xattrs: ctx.want_xattrs,
                    want_sparseness: true,
                    want_hash: false,
                    ignore_permission_errors: ctx.ignore_permission_errors,
                    exclusions,
                    exclusion_markers,
                    file_action_log_fn: ctx.file_action_log_fn.clone(),
                    threads: ctx.indexer_threads,
                },
            )?;
            let (data_tree, index_tree, stats) = put::put_files(send_pipeline_ctx, r, w, indexer)?;
            (data_tree, Some(index_tree), stats)
        }
    };

    let plain_text_metadata = oplog::V3PlainTextItemMetadata {
        primary_key_id: ctx.primary_key_id,
        unix_timestamp_millis: chrono::Utc::now().timestamp_millis().try_into()?,
        data_tree,
        index_tree,
    };

    let e_metadata = oplog::V3SecretItemMetadata {
        plain_text_hash: plain_text_metadata.hash(&ack.item_id),
        send_key_id: ctx.send_key_id,
        index_hash_key_part_2: ctx.idx_hash_key.part2.clone(),
        data_hash_key_part_2: ctx.data_hash_key.part2.clone(),
        data_size: serde_bare::Uint(stats.uncompressed_data_size),
        index_size: serde_bare::Uint(stats.uncompressed_index_size),
        tags,
    };

    let versioned_metadata = oplog::VersionedItemMetadata::V3(oplog::V3ItemMetadata {
        plain_text_metadata,
        encrypted_metadata: ctx.metadata_ectx.encrypt_data(compression::compress(
            compression::Scheme::Zstd { level: 3 },
            serde_bare::to_vec(&e_metadata)?,
        )),
    });

    write_packet(
        w,
        &Packet::TAddItem(AddItem {
            item: versioned_metadata,
        }),
    )?;

    match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
        Packet::RAddItem => {
            if let Some(ref send_log_session) = send_log_session {
                send_log_session.lock().unwrap().commit(&ack.item_id)?;
            }
            Ok((ack.item_id, stats))
        }
        _ => anyhow::bail!("protocol error, expected an RAddItem packet"),
    }
}

pub fn request_metadata(
    id: Xid,
    r: &mut dyn Read,
    w: &mut dyn Write,
) -> Result<oplog::VersionedItemMetadata, anyhow::Error> {
    write_packet(w, &Packet::TRequestMetadata(TRequestMetadata { id }))?;

    match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
        Packet::RRequestMetadata(resp) => match resp.metadata {
            Some(metadata) => Ok(metadata),
            None => anyhow::bail!("no stored items with the requested id"),
        },
        _ => anyhow::bail!("protocol error, expected ack request packet"),
    }
}

pub struct DataRequestContext {
    pub primary_key_id: Xid,
    pub data_hash_key_part_1: crypto::PartialHashKey,
    pub data_dctx: crypto::DecryptionContext,
    pub metadata_dctx: crypto::DecryptionContext,
}

#[allow(clippy::too_many_arguments)]
pub fn request_data_stream(
    mut ctx: DataRequestContext,
    id: Xid,
    metadata: &oplog::VersionedItemMetadata,
    data_map: Option<index::DataMap>,
    index: Option<index::CompressedIndex>,
    r: &mut dyn Read,
    w: &mut dyn Write,
    out: &mut dyn Write,
) -> Result<(), anyhow::Error> {
    // It makes little sense to ask the server for an empty pick.
    if let Some(ref data_map) = data_map {
        if data_map.data_chunk_ranges.is_empty() {
            if let Some(ref index) = index {
                return write_indexed_data_as_tarball(&mut || Ok(None), index, out);
            } else {
                return Ok(());
            }
        }
    }

    if ctx.primary_key_id != *metadata.primary_key_id() {
        anyhow::bail!("decryption key does not match key used for encryption");
    }

    let decrypted_metadata = metadata.decrypt_metadata(&id, &mut ctx.metadata_dctx)?;
    let data_tree = metadata.data_tree();

    let hash_key = crypto::derive_hash_key(
        &ctx.data_hash_key_part_1,
        &decrypted_metadata.data_hash_key_part_2,
    );

    let mut tr = htree::TreeReader::new(
        data_tree.height.0.try_into()?,
        data_tree.data_chunk_count.0,
        &data_tree.address,
    );

    match data_map {
        Some(data_map) => {
            write_packet(w, &Packet::RequestData(RequestData { id, partial: true }))?;
            receive_partial_htree(
                &mut ctx.data_dctx,
                &hash_key,
                r,
                w,
                &mut tr,
                data_map,
                index,
                out,
            )?;
        }
        None => {
            write_packet(w, &Packet::RequestData(RequestData { id, partial: false }))?;

            match index {
                Some(index) => receive_indexed_htree_as_tarball(
                    &mut ctx.data_dctx,
                    &hash_key,
                    r,
                    &mut tr,
                    &index,
                    out,
                )?,
                None => {
                    let bytes_received =
                        receive_htree(None, &mut ctx.data_dctx, &hash_key, r, &mut tr, out)?;
                    if bytes_received != decrypted_metadata.data_size.0 {
                        anyhow::bail!("expected data size does not match actual data size, possible corruption detected");
                    };
                }
            }
        }
    }

    out.flush()?;
    Ok(())
}

pub struct IndexRequestContext {
    pub primary_key_id: Xid,
    pub idx_hash_key_part_1: crypto::PartialHashKey,
    pub idx_dctx: crypto::DecryptionContext,
    pub metadata_dctx: crypto::DecryptionContext,
}

pub fn request_index(
    progress: &indicatif::ProgressBar,
    mut ctx: IndexRequestContext,
    id: Xid,
    metadata: &oplog::VersionedItemMetadata,
    r: &mut dyn Read,
    w: &mut dyn Write,
) -> Result<index::CompressedIndex, anyhow::Error> {
    if ctx.primary_key_id != *metadata.primary_key_id() {
        anyhow::bail!("decryption key does not match key used for encryption");
    }

    let decrypted_metadata = metadata.decrypt_metadata(&id, &mut ctx.metadata_dctx)?;

    let hash_key = crypto::derive_hash_key(
        &ctx.idx_hash_key_part_1,
        &decrypted_metadata.index_hash_key_part_2,
    );

    let index_tree = match metadata.index_tree() {
        Some(index_tree) => index_tree,
        None => anyhow::bail!("requested item missing an index"),
    };

    let mut tr = htree::TreeReader::new(
        index_tree.height.0.try_into()?,
        index_tree.data_chunk_count.0,
        &index_tree.address,
    );

    // Estimate based off experiments, perhaps something other than vec would work better
    // to avoid resizing and also guessing incorrectly.
    let estimated_compressed_size = (decrypted_metadata.index_size.0 / 2).try_into().unwrap();
    let mut index_data = lz4::EncoderBuilder::new()
        .checksum(lz4::ContentChecksum::NoChecksum)
        .build(std::io::Cursor::new(Vec::with_capacity(
            estimated_compressed_size,
        )))?;

    progress.set_message("fetching content index");
    progress.set_position(0);
    progress.set_length(decrypted_metadata.index_size.0);
    progress.set_style(
        indicatif::ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {msg} [{wide_bar}] {bytes}/{total_bytes}")
            .progress_chars("=> "),
    );

    write_packet(w, &Packet::RequestIndex(RequestIndex { id }))?;
    let bytes_received = receive_htree(
        Some(progress),
        &mut ctx.idx_dctx,
        &hash_key,
        r,
        &mut tr,
        &mut index_data,
    )?;
    if bytes_received != decrypted_metadata.index_size.0 {
        anyhow::bail!(
            "expected index size does not match actual index size, possible corruption detected"
        );
    }

    let (index_cursor, compress_result) = index_data.finish();
    compress_result?;
    let compressed_index = index_cursor.into_inner();
    Ok(index::CompressedIndex::from_vec(compressed_index))
}

fn receive_and_authenticate_htree_chunk(
    r: &mut dyn Read,
    address: Address,
) -> Result<Vec<u8>, anyhow::Error> {
    let data = match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
        Packet::Chunk(chunk) => {
            if address != chunk.address {
                return Err(ClientError::CorruptOrTamperedData.into());
            }
            chunk.data
        }
        _ => anyhow::bail!("protocol error, expected chunk packet"),
    };
    let data = compression::unauthenticated_decompress(data)?;
    if address != htree::tree_block_address(&data) {
        return Err(ClientError::CorruptOrTamperedData.into());
    }
    Ok(data)
}

fn receive_htree(
    progress: Option<&indicatif::ProgressBar>,
    dctx: &mut crypto::DecryptionContext,
    hash_key: &crypto::HashKey,
    r: &mut dyn Read,
    tr: &mut htree::TreeReader,
    out: &mut dyn Write,
) -> Result<u64, anyhow::Error> {
    let mut n_copied: u64 = 0;
    while let Some((height, addr)) = tr.next_addr() {
        if height == 0 {
            let data = match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
                Packet::Chunk(chunk) => {
                    if addr != chunk.address {
                        return Err(ClientError::CorruptOrTamperedData.into());
                    }
                    chunk.data
                }
                _ => anyhow::bail!("protocol error, expected begin chunk packet"),
            };
            let data = compression::decompress(dctx.decrypt_data(data)?)?;
            if addr != crypto::keyed_content_address(&data, hash_key) {
                return Err(ClientError::CorruptOrTamperedData.into());
            }
            out.write_all(&data)?;
            if let Some(progress) = progress {
                progress.inc(data.len() as u64);
            }
            n_copied += data.len() as u64;
        } else {
            let data = receive_and_authenticate_htree_chunk(r, addr)?;
            tr.push_level(height - 1, data)?;
        }
    }

    out.flush()?;
    Ok(n_copied)
}

fn write_indexed_data_as_tarball(
    read_data: &mut dyn FnMut() -> Result<Option<Vec<u8>>, anyhow::Error>,
    index: &index::CompressedIndex,
    out: &mut dyn Write,
) -> Result<(), anyhow::Error> {
    let mut buffered = vec![];
    let mut buffer_index: usize = 0;
    let mut copy_out_and_hash =
        |out: &mut dyn Write, mut n: u64| -> Result<blake3::Hash, anyhow::Error> {
            let mut hasher = blake3::Hasher::new();
            'read: while n != 0 {
                let mut remaining;
                loop {
                    remaining = buffered.len() - buffer_index;
                    if remaining != 0 {
                        break;
                    }

                    match read_data()? {
                        Some(b) => {
                            buffer_index = 0;
                            buffered = b;
                        }
                        None => {
                            break 'read;
                        }
                    }
                }
                let write_range =
                    buffer_index..buffer_index + std::cmp::min(remaining as u64, n) as usize;
                let to_write = &buffered[write_range];
                out.write_all(to_write)?;
                hasher.write_all(to_write)?;
                let n_written = to_write.len();
                buffer_index += n_written;
                n -= n_written as u64;
            }

            if n != 0 {
                anyhow::bail!("data stream corrupt, unexpected end of data");
            }

            Ok(hasher.finalize())
        };

    let mut hardlinks: std::collections::HashMap<(u64, u64), PathBuf> =
        std::collections::HashMap::new();

    for ent in index.iter() {
        let ent = ent?;
        if matches!(ent.kind(), index::IndexEntryKind::Other) {
            // We can't convert this to a tar header, so just discard the
            // data and skip it.
            copy_out_and_hash(&mut std::io::sink(), ent.size.0)?;
            continue;
        }

        let hardlink = if !ent.is_dir() && ent.nlink.0 > 1 {
            let dev_ino = (ent.norm_dev.0, ent.ino.0);
            match hardlinks.get(&dev_ino) {
                None => {
                    hardlinks.insert(dev_ino, ent.path.clone());
                    None
                }
                l => l,
            }
        } else {
            None
        };

        out.write_all(&xtar::index_entry_to_tarheader(&ent, hardlink)?)?;

        if hardlink.is_none() {
            let hash = copy_out_and_hash(out, ent.size.0)?;
            let hash_bytes: [u8; 32] = hash.into();

            match ent.data_hash {
                index::ContentCryptoHash::None => (), // XXX we don't currently require this, but we should for 1.0.
                index::ContentCryptoHash::Blake3(expected_hash) => {
                    if hash_bytes != expected_hash {
                        anyhow::bail!("entry {} content hash differs from index hash, possible corruption detected.", ent.path.to_string_lossy());
                    }
                }
            }
            /* Tar entries are rounded to 512 bytes */
            let remaining = 512 - (ent.size.0 % 512);
            if remaining < 512 {
                let buf = [0; 512];
                out.write_all(&buf[..remaining as usize])?;
            }
        } else {
            /* Hardlinks are uploaded as normal files, so we just skip the data. */
            copy_out_and_hash(&mut std::io::sink(), ent.size.0)?;
        }
    }

    let buf = [0; 1024];
    out.write_all(&buf[..])?;

    out.flush()?;

    // Do the remaining reads to coordinate the end of stream with the server.
    while let Some(data) = read_data()? {
        if !data.is_empty() {
            anyhow::bail!("possibly corrupt index, expected end of data")
        }
    }

    Ok(())
}

fn receive_indexed_htree_as_tarball(
    dctx: &mut crypto::DecryptionContext,
    hash_key: &crypto::HashKey,
    r: &mut dyn Read,
    tr: &mut htree::TreeReader,
    index: &index::CompressedIndex,
    out: &mut dyn Write,
) -> Result<(), anyhow::Error> {
    let mut read_data = || -> Result<Option<Vec<u8>>, anyhow::Error> {
        while let Some((height, addr)) = tr.next_addr() {
            if height == 0 {
                let data = match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
                    Packet::Chunk(chunk) => {
                        if addr != chunk.address {
                            return Err(ClientError::CorruptOrTamperedData.into());
                        }
                        chunk.data
                    }
                    _ => anyhow::bail!("protocol error, expected begin chunk packet"),
                };

                let data = compression::decompress(dctx.decrypt_data(data)?)?;
                if addr != crypto::keyed_content_address(&data, hash_key) {
                    return Err(ClientError::CorruptOrTamperedData.into());
                }
                return Ok(Some(data));
            } else {
                let data = receive_and_authenticate_htree_chunk(r, addr)?;
                tr.push_level(height - 1, data)?;
            }
        }

        Ok(None)
    };

    write_indexed_data_as_tarball(&mut read_data, index, out)
}

#[allow(clippy::too_many_arguments)]
fn receive_partial_htree(
    dctx: &mut crypto::DecryptionContext,
    hash_key: &crypto::HashKey,
    r: &mut dyn Read,
    w: &mut dyn Write,
    tr: &mut htree::TreeReader,
    data_map: index::DataMap,
    index: Option<index::CompressedIndex>,
    out: &mut dyn Write,
) -> Result<(), anyhow::Error> {
    // This is avoided before we make a server request.
    assert!(!data_map.data_chunk_ranges.is_empty());

    let mut data_addresses = VecDeque::with_capacity(64);
    let mut current_data_chunk_idx: u64 = 0;
    let mut range_idx: usize = 0;

    // We send ranges in groups to keep a bound on server memory usage.
    let mut range_groups = data_map
        .data_chunk_ranges
        // Test harsher range splits in debug mode.
        .chunks(if cfg!(debug_assertions) { 2 } else { 100000 });

    let mut ranges = range_groups.next().unwrap();
    write_request_data_ranges(w, ranges)?;

    // This logic is mirroring the send logic
    // on the server side, only the chunks are coming from the remote.
    // We must also verify all the chunk addresses match what we expect.

    let mut read_data = || -> Result<Option<Vec<u8>>, anyhow::Error> {
        loop {
            if let Some(chunk_addr) = data_addresses.pop_front() {
                let data = match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
                    Packet::Chunk(chunk) => {
                        if chunk_addr != chunk.address {
                            return Err(ClientError::CorruptOrTamperedData.into());
                        }
                        chunk.data
                    }
                    _ => anyhow::bail!("protocol error, expected chunk packet"),
                };
                let data = compression::decompress(dctx.decrypt_data(data)?)?;
                if chunk_addr != crypto::keyed_content_address(&data, hash_key) {
                    return Err(ClientError::CorruptOrTamperedData.into());
                }
                let data = match data_map.incomplete_data_chunks.get(&current_data_chunk_idx) {
                    Some(byte_ranges) => {
                        let mut filtered_data = Vec::with_capacity(data.len() / 2);

                        for byte_range in byte_ranges.iter() {
                            filtered_data.extend_from_slice(
                                &data[byte_range.start..std::cmp::min(data.len(), byte_range.end)],
                            );
                        }

                        filtered_data
                    }
                    None => data,
                };
                current_data_chunk_idx += 1;
                return Ok(Some(data));
            }

            let range = loop {
                match ranges.get(range_idx) {
                    Some(range) => {
                        if current_data_chunk_idx > range.end_idx.0 {
                            range_idx += 1;
                            continue;
                        }
                        break range;
                    }
                    None => match range_groups.next() {
                        Some(new_ranges) => {
                            range_idx = 0;
                            ranges = new_ranges;
                            write_request_data_ranges(w, ranges)?;
                            continue;
                        }
                        None => {
                            // Signal end of ranges.
                            write_request_data_ranges(w, &[])?;
                            return Ok(None);
                        }
                    },
                }
            };

            loop {
                if current_data_chunk_idx < range.start_idx.0 {
                    let num_skipped =
                        tr.fast_forward(range.start_idx.0 - current_data_chunk_idx)?;
                    current_data_chunk_idx += num_skipped;
                }
                if let Some(height) = tr.current_height() {
                    if height == 0 && current_data_chunk_idx >= range.start_idx.0 {
                        break;
                    } else {
                        let (_, chunk_addr) = tr.next_addr().unwrap();
                        let chunk_data = receive_and_authenticate_htree_chunk(r, chunk_addr)?;
                        tr.push_level(height - 1, chunk_data)?;
                    }
                } else {
                    anyhow::bail!("hash tree ended before requested range");
                }
            }

            while current_data_chunk_idx + (data_addresses.len() as u64) <= range.end_idx.0 {
                match tr.current_height() {
                    Some(0) => match tr.next_addr() {
                        Some((0, chunk_addr)) => data_addresses.push_back(chunk_addr),
                        _ => unreachable!(),
                    },
                    _ => break,
                }
            }
        }
    };

    if let Some(ref index) = index {
        write_indexed_data_as_tarball(&mut read_data, index, out)?;
    } else {
        while let Some(data) = read_data()? {
            out.write_all(&data)?;
        }
    }

    Ok(())
}

pub fn recover_removed(
    progress: indicatif::ProgressBar,
    r: &mut dyn Read,
    w: &mut dyn Write,
) -> Result<u64, anyhow::Error> {
    progress.set_message("recovering items...");

    write_packet(w, &Packet::TRecoverRemoved)?;
    match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
        Packet::RRecoverRemoved(RRecoverRemoved { n_recovered }) => Ok(n_recovered.0),
        _ => anyhow::bail!("protocol error, expected restore packet response or progress packet",),
    }
}

pub fn gc(
    progress: indicatif::ProgressBar,
    r: &mut dyn Read,
    w: &mut dyn Write,
) -> Result<repository::GcStats, anyhow::Error> {
    progress.set_message("collecting garbage...");

    write_packet(w, &Packet::TGc(TGc {}))?;
    loop {
        match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
            Packet::GcProgress(msg) => {
                progress.set_message(msg);
            }
            Packet::RGc(rgc) => return Ok(rgc.stats),
            _ => anyhow::bail!("protocol error, expected gc packet or progress packe."),
        };
    }
}

pub fn sync_query_cache(
    progress: indicatif::ProgressBar,
    query_cache: &mut querycache::QueryCache,
    r: &mut dyn Read,
    w: &mut dyn Write,
) -> Result<(), anyhow::Error> {
    progress.set_message("fetching remote metadata...");

    let mut tx = query_cache.transaction()?;

    let after = tx.last_log_op_offset()?;
    let gc_generation = tx.current_gc_generation()?;

    write_packet(
        w,
        &Packet::TRequestOpLogSync(TRequestOpLogSync {
            after: after.map(serde_bare::Uint),
            gc_generation,
        }),
    )?;

    let gc_generation = match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
        Packet::RRequestOpLogSync(ack) => ack.gc_generation,
        _ => anyhow::bail!("protocol error, expected items packet"),
    };

    tx.start_oplog_sync(gc_generation)?;

    loop {
        match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
            Packet::SyncLogOps(ops) => {
                if ops.is_empty() {
                    break;
                }
                for op in ops {
                    tx.sync_op(op)?;
                }
            }
            _ => anyhow::bail!("protocol error, expected items packet"),
        }
    }

    tx.commit()?;
    Ok(())
}

pub fn remove(
    progress: indicatif::ProgressBar,
    ids: Vec<Xid>,
    r: &mut dyn Read,
    w: &mut dyn Write,
) -> Result<u64, anyhow::Error> {
    progress.set_message("removing items...");

    let mut n_removed = 0;

    for chunked_ids in ids.chunks(4096) {
        let ids = chunked_ids.to_vec();
        write_packet(w, &Packet::TRmItems(ids))?;
        match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
            Packet::RRmItems(n) => n_removed += n.0,
            _ => anyhow::bail!("protocol error, expected RRmItems"),
        }
    }
    Ok(n_removed)
}

pub struct RestoreContext {
    pub data_ctx: DataRequestContext,
    pub item_id: Xid,
    pub metadata: oplog::VersionedItemMetadata,
    pub restore_xattrs: bool,
    pub restore_ownership: bool,
    pub indexer_threads: usize,
}

#[allow(clippy::too_many_arguments)]
pub fn restore_to_local_dir(
    progress: &indicatif::ProgressBar,
    ctx: RestoreContext,
    content_index: index::CompressedIndex,
    pick: Option<PathBuf>,
    serve_out: &mut dyn Read,
    serve_in: &mut dyn Write,
    to_dir: &Path,
) -> Result<(), anyhow::Error> {
    let sub_index = match pick {
        Some(ref pick) => {
            progress.set_message("building pick index...");
            Some(index::pick_dir_without_data(pick, &content_index)?)
        }
        None => None,
    };

    let index_to_diff = match sub_index {
        Some(ref sub_index) => sub_index,
        None => &content_index,
    };

    // Initially reset the permissions and groups on everything
    // so we don't need to worry about read only files or other access.
    progress.set_message("preparing directory...");
    let uid = nix::unistd::Uid::effective();
    let gid = nix::unistd::Gid::effective();
    for dir_ent in walkdir::WalkDir::new(to_dir) {
        let dir_ent = dir_ent?;
        let metadata = dir_ent.path().symlink_metadata()?;
        if metadata.uid() != libc::uid_t::from(uid) || metadata.gid() != libc::uid_t::from(gid) {
            match nix::unistd::fchownat(
                None,
                dir_ent.path(),
                Some(uid),
                Some(gid),
                nix::unistd::FchownatFlags::NoFollowSymlink,
            ) {
                Ok(_) => (),
                Err(err) => anyhow::bail!("failed to chown {}: {}", dir_ent.path().display(), err),
            };
        }

        // Make any read only files writable for the later code...
        if !metadata.file_type().is_symlink() && (metadata.permissions().mode() & 0o200 == 0) {
            match nix::sys::stat::fchmodat(
                None,
                dir_ent.path(),
                // What we use here doesn't really matter for sync, it gets fixed later...
                nix::sys::stat::Mode::from_bits_truncate(0o700),
                nix::sys::stat::FchmodatFlags::FollowSymlink,
            ) {
                Ok(_) => (),
                Err(err) => anyhow::bail!(
                    "failed to set permissions of {}: {}",
                    dir_ent.path().display(),
                    err
                ),
            };
        }
    }

    let to_dir_index = {
        progress.set_message(format!("indexing {}...", to_dir.to_string_lossy()));
        let mut ciw = index::CompressedIndexWriter::new();
        for ent in indexer::FsIndexer::new(
            &[to_dir.to_owned()],
            indexer::FsIndexerOptions {
                exclusions: globset::GlobSet::empty(),
                exclusion_markers: HashSet::new(),
                want_sparseness: false,
                want_xattrs: false,
                want_hash: true,
                one_file_system: false,
                ignore_permission_errors: false,
                file_action_log_fn: None,
                threads: ctx.indexer_threads,
            },
        )? {
            ciw.add(&ent?.1);
        }
        ciw.finish()
    };

    progress.set_message("calculating content diff...");
    let mut to_remove = Vec::with_capacity(512);
    let mut new_dirs = Vec::with_capacity(512);
    let mut create_path_set = HashSet::with_capacity(512);
    let mut create_index_writer = index::CompressedIndexWriter::new();
    let mut download_index_path_set = HashSet::with_capacity(512);
    let mut downloads = Vec::with_capacity(512);

    {
        let download_path_prefix: PathBuf = match pick {
            Some(ref pick) if pick == Path::new(".") => "".into(),
            Some(ref pick) => fsutil::path_raw_join(pick, Path::new("/")),
            None => "".into(),
        };

        index::diff(
            &to_dir_index,
            index_to_diff,
            !(index::INDEX_COMPARE_MASK_TYPE
                | index::INDEX_COMPARE_MASK_LINK_TARGET
                | index::INDEX_COMPARE_MASK_DEVNOS
                | index::INDEX_COMPARE_MASK_DATA_HASH),
            &mut |ds: index::DiffStat, e: &index::IndexEntry| -> Result<(), anyhow::Error> {
                match ds {
                    index::DiffStat::Unchanged => (),
                    index::DiffStat::Removed => {
                        to_remove.push((PathBuf::from(&e.path), e.kind()));
                    }
                    index::DiffStat::Added => {
                        if e.is_dir() {
                            new_dirs.push(PathBuf::from(&e.path));
                        } else if e.is_file() {
                            let mapped_path = fsutil::path_raw_join(&download_path_prefix, &e.path);
                            download_index_path_set.insert(mapped_path);
                            downloads.push((e.path.clone(), e.size.0, e.data_hash, e.sparse));
                        } else {
                            create_path_set.insert(e.path.clone());
                            create_index_writer.add(e);
                        }
                    }
                }

                Ok(())
            },
        )?;
    }

    progress.set_message("removing extra files...");
    to_remove.reverse();
    if !to_remove.is_empty() {
        for (path, kind) in to_remove.drain(..) {
            let mut to_delete = to_dir.to_owned();
            to_delete.push(path);

            match if kind.is_dir() {
                std::fs::remove_dir(&to_delete)
            } else {
                std::fs::remove_file(&to_delete)
            } {
                Ok(_) => (),
                Err(err) => anyhow::bail!("failed to remove {}: {}", to_delete.display(), err),
            }
        }
    }
    std::mem::drop(to_remove);

    if !new_dirs.is_empty() {
        progress.set_message("creating new directories...");
        for dir_path in new_dirs.drain(..) {
            let mut to_create = to_dir.to_owned();
            to_create.push(dir_path);
            std::fs::create_dir(to_create)?;
        }
    }
    std::mem::drop(new_dirs);

    if !download_index_path_set.is_empty() {
        progress.set_message("calculating fetch set...");

        let fetch_data_map = index::data_map_for_predicate(&content_index, &|e| {
            download_index_path_set.contains(&e.path)
        })?;

        std::mem::drop(download_index_path_set);

        progress.set_message("fetching files...");

        let (mut r, mut w) = ioutil::buffered_pipe(3 * 1024 * 1024); // Sized to cover most packets in one allocation.

        let to_dir = to_dir.to_owned();
        let worker = std::thread::spawn(move || -> std::io::Result<()> {
            let r = &mut r;
            for (path, size, hash, sparse) in downloads.drain(..) {
                let mut to_create = to_dir.to_owned();
                to_create.push(&path);
                let mut f = std::fs::OpenOptions::new()
                    .write(true)
                    .read(true)
                    .create(true)
                    .open(to_create)?;

                let n_copied = if sparse {
                    fsutil::copy_as_sparse_file(&mut r.take(size), &mut f)?
                } else {
                    std::io::copy(&mut r.take(size), &mut f)?
                };

                if n_copied != size {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!(
                            "content of {} is smaller than expected",
                            path.to_string_lossy()
                        ),
                    ));
                }

                f.seek(std::io::SeekFrom::Start(0))?;

                match hash {
                    index::ContentCryptoHash::None => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!("{} in content index missing hash", path.to_string_lossy()),
                        ))
                    }
                    index::ContentCryptoHash::Blake3(expected_hash) => {
                        let mut hasher = blake3::Hasher::new();
                        std::io::copy(&mut f, &mut hasher)?;
                        let actual_hash: [u8; 32] = hasher.finalize().into();
                        if expected_hash != actual_hash {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                format!(
                                    "content of {} did not match expected hash",
                                    path.to_string_lossy()
                                ),
                            ));
                        }
                    }
                }
            }
            Ok(())
        });
        let download_err = request_data_stream(
            ctx.data_ctx,
            ctx.item_id,
            &ctx.metadata,
            Some(fetch_data_map),
            None,
            serve_out,
            serve_in,
            &mut w,
        );
        let file_err = worker.join().unwrap();
        match file_err {
            Ok(()) => {
                download_err?;
            }
            // Copying to the files failed, the error must be a download error.
            Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
                download_err?;
            }
            Err(err) => return Err(err.into()),
        };
    }

    if !create_path_set.is_empty() {
        progress.set_message("creating special files and devices...");
        for ent in create_index_writer.finish().iter() {
            let ent = ent?;
            if !create_path_set.contains(&ent.path) {
                continue;
            }
            let mut to_create = to_dir.to_owned();
            to_create.push(&ent.path);

            match ent.kind() {
                index::IndexEntryKind::Symlink => {
                    if ent.link_target.is_none() {
                        anyhow::bail!("{} is missing a link target", ent.path.to_string_lossy());
                    }
                    match std::os::unix::fs::symlink(ent.link_target.unwrap(), &to_create) {
                        Ok(_) => (),
                        Err(err) => anyhow::bail!(
                            "failed to make symlink at {}: {}",
                            to_create.display(),
                            err
                        ),
                    }
                }
                index::IndexEntryKind::Fifo => {
                    match nix::unistd::mkfifo(&to_create, nix::sys::stat::Mode::S_IRWXU) {
                        Ok(_) => (),
                        Err(err) => {
                            anyhow::bail!("failed to make fifo at {}: {}", to_create.display(), err)
                        }
                    }
                }
                index::IndexEntryKind::Block => match nix::sys::stat::mknod(
                    &to_create,
                    nix::sys::stat::SFlag::S_IFBLK,
                    nix::sys::stat::Mode::S_IRWXU,
                    fsutil::makedev(ent.dev_major.0, ent.dev_minor.0),
                ) {
                    Ok(_) => (),
                    Err(err) => anyhow::bail!(
                        "failed to make block device at {}: {}",
                        to_create.display(),
                        err
                    ),
                },
                index::IndexEntryKind::Char => match nix::sys::stat::mknod(
                    &to_create,
                    nix::sys::stat::SFlag::S_IFCHR,
                    nix::sys::stat::Mode::S_IRWXU,
                    fsutil::makedev(ent.dev_major.0, ent.dev_minor.0),
                ) {
                    Ok(_) => (),
                    Err(err) => anyhow::bail!(
                        "failed to make char device at {}: {}",
                        to_create.display(),
                        err
                    ),
                },
                _ => (),
            }
        }
    }
    std::mem::drop(create_path_set);

    let restore_ownership = ctx.restore_ownership;
    let restore_xattrs = ctx.restore_xattrs;

    let apply_ent_attrs = |to_ch: &Path, ent: &index::IndexEntry| -> Result<(), anyhow::Error> {
        if restore_xattrs && (ent.is_file() || ent.is_dir()) {
            match xattr::list(to_ch) {
                Ok(attrs) => {
                    for attr in attrs {
                        match xattr::remove(to_ch, attr) {
                            Ok(()) => (),
                            Err(err) => anyhow::bail!(
                                "failed to list remove xattr from {}: {}",
                                to_ch.display(),
                                err
                            ),
                        }
                    }
                }
                Err(err) => anyhow::bail!("failed to list xattrs for {}: {}", to_ch.display(), err),
            }
            if let Some(ref xattrs) = ent.xattrs {
                for (attr, value) in xattrs.iter() {
                    match xattr::set(to_ch, OsStr::from_bytes(attr), value) {
                        Ok(()) => (),
                        Err(err) => anyhow::bail!(
                            "failed to list remove xattr {} from {}: {}",
                            String::from_utf8_lossy(attr),
                            to_ch.display(),
                            err
                        ),
                    }
                }
            }
        }

        if restore_ownership {
            match nix::unistd::fchownat(
                None,
                to_ch,
                Some(nix::unistd::Uid::from_raw(ent.uid.0 as u32)),
                Some(nix::unistd::Gid::from_raw(ent.gid.0 as u32)),
                nix::unistd::FchownatFlags::NoFollowSymlink,
            ) {
                Ok(_) => (),
                Err(err) => anyhow::bail!("failed to chown {}: {}", to_ch.display(), err),
            };
        }

        if !ent.is_symlink() {
            match nix::sys::stat::fchmodat(
                None,
                to_ch,
                nix::sys::stat::Mode::from_bits_truncate(ent.mode.0 as libc::mode_t),
                nix::sys::stat::FchmodatFlags::FollowSymlink,
            ) {
                Ok(_) => (),
                Err(err) => {
                    anyhow::bail!("failed to set permissions of {}: {}", to_ch.display(), err)
                }
            };
        }

        if let (Ok(tv_sec), Ok(tv_nsec)) = (ent.mtime.0.try_into(), ent.mtime_nsec.0.try_into()) {
            match nix::sys::stat::utimensat(
                None,
                to_ch,
                &nix::sys::time::TimeSpec::from(libc::timespec {
                    tv_sec: 0,
                    tv_nsec: libc::UTIME_OMIT,
                }),
                &nix::sys::time::TimeSpec::from(libc::timespec { tv_sec, tv_nsec }),
                nix::sys::stat::UtimensatFlags::NoFollowSymlink,
            ) {
                Ok(_) => (),
                Err(err) => anyhow::bail!("failed to set mtime of {}: {}", to_ch.display(), err),
            };
        }

        Ok(())
    };

    let mut dirs_to_alter = Vec::with_capacity(512);
    let mut hardlinks: HashMap<(u64, u64), PathBuf> = HashMap::new();

    progress.set_message("setting file attributes...");
    {
        index::diff(
            &to_dir_index,
            index_to_diff,
            !(index::INDEX_COMPARE_MASK_PERMS
                | index::INDEX_COMPARE_MASK_XATTRS
                | index::INDEX_COMPARE_MASK_MTIME),
            &mut |ds: index::DiffStat, ent: &index::IndexEntry| -> Result<(), anyhow::Error> {
                if matches!(ds, index::DiffStat::Removed) {
                    // Nothing to do, removals already processed.
                    return Ok(());
                }

                match ds {
                    index::DiffStat::Unchanged | index::DiffStat::Added => {
                        // Handle any hard links, we are a little dumb and just
                        // recreate them each time even if they are unchanged,
                        // but hard links are relatively rare we can improve this later if needed.
                        if !ent.is_dir() && ent.nlink.0 > 1 {
                            let mut to_ch = to_dir.to_owned();
                            to_ch.push(&ent.path);
                            let dev_ino = (ent.norm_dev.0, ent.ino.0);
                            match hardlinks.get(&dev_ino) {
                                None => {
                                    hardlinks.insert(dev_ino, to_ch);
                                }
                                Some(first_path) => match std::fs::remove_file(&to_ch) {
                                    Ok(_) => match std::fs::hard_link(first_path, &to_ch) {
                                        Ok(_) => (),
                                        Err(err) => anyhow::bail!(
                                            "failed to hard link {} as {}: {}",
                                            to_ch.display(),
                                            first_path.display(),
                                            err
                                        ),
                                    },
                                    Err(err) => {
                                        anyhow::bail!(
                                            "failed to remove {}: {}",
                                            to_ch.display(),
                                            err
                                        )
                                    }
                                },
                            }
                        }

                        if matches!(ds, index::DiffStat::Added) {
                            // Set the attributes of anything that changed.
                            let mut to_ch = to_dir.to_owned();
                            to_ch.push(&ent.path);
                            if ent.is_dir() {
                                dirs_to_alter.push((to_ch, ent.clone()));
                            } else {
                                apply_ent_attrs(&to_ch, ent)?;
                            }
                        }
                    }
                    index::DiffStat::Removed => (),
                }

                Ok(())
            },
        )?;
    }

    // Process dirs in reverse order to account for read only permissions.
    while let Some((to_ch, ent)) = dirs_to_alter.pop() {
        apply_ent_attrs(&to_ch, &ent)?
    }
    std::mem::drop(dirs_to_alter);

    Ok(())
}

pub fn repo_sync(
    progress: &indicatif::ProgressBar,
    item_ids: Vec<Xid>,
    ids_to_metadata: Option<HashMap<Xid, oplog::VersionedItemMetadata>>,
    source_serve_out: &mut (dyn Read + Send),
    source_serve_in: &mut (dyn Write + Send),
    dest_serve_out: &mut (dyn Read + Send),
    dest_serve_in: &mut (dyn Write + Send),
) -> Result<(), anyhow::Error> {
    write_packet(dest_serve_in, &Packet::TBeginItemSyncPush)?;

    match read_packet(dest_serve_out, DEFAULT_MAX_PACKET_SIZE)? {
        Packet::RBeginItemSyncPush(_) => (),
        _ => anyhow::bail!("expected RBeginItemSyncPush packet"),
    }

    let mut missing_item_ids = Vec::with_capacity(256);

    const ITEM_BATCH_SIZE: usize = DEFAULT_MAX_PACKET_SIZE / XID_SZ;
    // Iterate in chunks that will fit the max packet size.
    progress.set_message(format!("computing item send set 0/{}...", item_ids.len()));
    let mut items_processed: u64 = 0;
    for item_batch in item_ids.chunks(ITEM_BATCH_SIZE) {
        write_item_sync_filter_items(dest_serve_in, item_batch)?;
        let mut batch_progress = 0;
        loop {
            match read_packet(dest_serve_out, DEFAULT_MAX_PACKET_SIZE)? {
                Packet::ItemSyncFilterItemsProgress(n) => {
                    batch_progress += n.0;
                    items_processed += n.0;
                    progress.set_message(format!(
                        "computing item send set {}/{}...",
                        items_processed,
                        item_ids.len(),
                    ));
                }
                Packet::ItemSyncItems(mut missing) => {
                    missing_item_ids.append(&mut missing);
                    items_processed += (item_batch.len() as u64) - batch_progress;
                    break;
                }
                _ => anyhow::bail!("expected RBeginRepoSyncPush packet"),
            }
        }
    }

    write_packet(source_serve_in, &Packet::TBeginItemSyncPull)?;

    match read_packet(source_serve_out, DEFAULT_MAX_PACKET_SIZE)? {
        Packet::RBeginItemSyncPull => (),
        _ => anyhow::bail!("expected RBeginItemSyncPush packet"),
    }

    let all_chunks: Vec<Address> = {
        progress.set_message("counting chunks...");
        let mut all_chunks = HashSet::with_capacity(16 * 1024);
        for missing_item_ids in missing_item_ids.chunks(ITEM_BATCH_SIZE) {
            write_item_sync_request_addresses(source_serve_in, missing_item_ids)?;
            loop {
                let addresses = match read_packet(source_serve_out, DEFAULT_MAX_PACKET_SIZE)? {
                    Packet::ItemSyncAddresses(addresses) => addresses,
                    _ => anyhow::bail!("expected ItemSyncAddresses packet"),
                };
                for address in addresses.iter() {
                    all_chunks.insert(*address);
                }
                progress.set_message(format!("counting chunks, {} found...", all_chunks.len(),));
                if addresses.is_empty() {
                    break;
                }
            }
        }
        all_chunks.into_iter().collect()
    };

    let mut all_missing_chunks = Vec::with_capacity(all_chunks.len() / 10);
    {
        let mut chunks_processed: u64 = 0;
        progress.set_message("computing chunk send set...");
        // Gather the missing chunks, doing the requests in large batches.
        for chunk_batch in all_chunks.chunks(DEFAULT_MAX_PACKET_SIZE / ADDRESS_SZ) {
            write_item_sync_filter_existing(dest_serve_in, chunk_batch)?;
            let mut batch_progress = 0;
            loop {
                match read_packet(dest_serve_out, DEFAULT_MAX_PACKET_SIZE)? {
                    Packet::ItemSyncFilterExistingProgress(n) => {
                        batch_progress += n.0;
                        chunks_processed += n.0;
                        progress.set_message(format!(
                            "computing chunk send set {}/{}...",
                            chunks_processed,
                            all_chunks.len(),
                        ));
                    }
                    Packet::ItemSyncAddresses(mut missing) => {
                        all_missing_chunks.append(&mut missing);
                        chunks_processed += (chunk_batch.len() as u64) - batch_progress;
                        break;
                    }
                    _ => anyhow::bail!("expected ItemSyncAddresses or Process packet"),
                };
            }
        }
    }

    std::mem::drop(all_chunks);

    progress.set_message("copying chunks");
    progress.set_position(0);
    progress.set_length(all_missing_chunks.len().try_into().unwrap());
    progress.set_style(
        indicatif::ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {msg} [{wide_bar}] {pos:>10}/{len}")
            .progress_chars("=> "),
    );

    let n_chunks_to_copy = all_missing_chunks.len();
    // Read chunks in a thread so we are always reading and writing chunks in parallel.
    crossbeam_utils::thread::scope(|tscope| -> Result<(), anyhow::Error> {
        let (chunk_tx, chunk_rx) = crossbeam_channel::bounded(0);
        let copy_chunk_worker: crossbeam_utils::thread::ScopedJoinHandle<
            Result<(), anyhow::Error>,
        > = tscope.spawn(|_| {
            let mut n_chunks_to_copy = n_chunks_to_copy;
            let chunk_tx = chunk_tx;
            while n_chunks_to_copy != 0 {
                match read_packet(source_serve_out, DEFAULT_MAX_PACKET_SIZE)? {
                    Packet::Chunk(chunk) => {
                        chunk_tx.send(chunk)?;
                        n_chunks_to_copy -= 1;
                    }
                    _ => anyhow::bail!("expected Chunk packet"),
                };
            }
            Ok(())
        });

        for addresses in all_missing_chunks.chunks(DEFAULT_MAX_PACKET_SIZE / ADDRESS_SZ) {
            write_item_sync_addresses(source_serve_in, addresses)?;
            for _ in 0..addresses.len() {
                match chunk_rx.recv() {
                    Ok(chunk) => {
                        write_chunk(dest_serve_in, &chunk.address, &chunk.data)?;
                        progress.inc(1);
                    }
                    Err(_) => {
                        copy_chunk_worker.join().unwrap()?;
                        unreachable!();
                    }
                }
            }
        }

        copy_chunk_worker.join().unwrap()?;
        Ok(())
    })
    .unwrap()?;

    // XXX indicatif doesn't provide a way to save and then restore the previous style,
    // so we just use our knowledge of what it was to reset it.
    progress.set_style(
        indicatif::ProgressStyle::default_spinner().template("[{elapsed_precise}] {wide_msg}"),
    );

    write_packet(dest_serve_in, &Packet::TFlush)?;
    match read_packet(dest_serve_out, DEFAULT_MAX_PACKET_SIZE)? {
        Packet::RFlush(_) => (),
        _ => anyhow::bail!("protocol error, expected RSentSync packet"),
    }

    let mut missing_item_metadata = Vec::with_capacity(missing_item_ids.len());
    if let Some(ids_to_metadata) = ids_to_metadata {
        for id in missing_item_ids.iter() {
            match ids_to_metadata.get(id) {
                Some(md) => missing_item_metadata.push(md.clone()),
                None => anyhow::bail!("metadata missing for {}", id.to_string()),
            }
        }
    } else {
        progress.set_message(format!(
            "fetching item metadata from source 0/{}...",
            missing_item_ids.len(),
        ));
        for missing_item_ids in missing_item_ids.chunks(ITEM_BATCH_SIZE) {
            write_packet(
                source_serve_in,
                &Packet::ItemSyncRequestMetadata(missing_item_ids.to_vec()),
            )?;
            while missing_item_metadata.len() != missing_item_ids.len() {
                match read_packet(source_serve_out, DEFAULT_MAX_PACKET_SIZE)? {
                    Packet::ItemSyncMetadata(mut md) => {
                        progress.set_message(format!(
                            "fetching item metadata from source {}/{}...",
                            missing_item_metadata.len(),
                            missing_item_ids.len(),
                        ));
                        missing_item_metadata.append(&mut md);
                    }
                    _ => anyhow::bail!("protocol error, expected ItemSyncMetadata packet"),
                }
            }
        }
    }

    progress.set_message("adding new items...");
    for packet in missing_item_ids
        .into_iter()
        .zip(missing_item_metadata.into_iter())
        .chunks(128) // Small enough to avoid max packet size even with large metadata.
        .into_iter()
        .map(|it| Packet::ItemSyncAddItems(it.collect()))
    {
        write_packet(dest_serve_in, &packet)?;
    }

    write_packet(source_serve_in, &Packet::TEndItemSyncPull)?;
    match read_packet(source_serve_out, DEFAULT_MAX_PACKET_SIZE)? {
        Packet::REndItemSyncPull => (),
        _ => anyhow::bail!("expected REndItemSyncPull packet"),
    };

    write_packet(dest_serve_in, &Packet::TEndItemSyncPush)?;
    match read_packet(dest_serve_out, DEFAULT_MAX_PACKET_SIZE)? {
        Packet::REndItemSyncPush => (),
        _ => anyhow::bail!("expected REndItemSyncPush packet"),
    };

    Ok(())
}

pub fn hangup(w: &mut dyn Write) -> Result<(), anyhow::Error> {
    write_packet(w, &Packet::EndOfTransmission)?;
    Ok(())
}
