use super::acache;
use super::address::*;
use super::chunker;
use super::compression;
use super::crypto;
use super::fsutil;
use super::htree;
use super::index;
use super::itemset;
use super::protocol::*;
use super::querycache;
use super::repository;
use super::rollsum;
use super::sendlog;
use super::xid::*;
use super::xtar;
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashMap};
use std::convert::TryInto;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;

cfg_if::cfg_if! {
    if #[cfg(target_os = "linux")] {
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::io::AsRawFd;
    }
}

// These chunk parameters could be investigated and tuned.
pub const CHUNK_MIN_SIZE: usize = 256 * 1024;
pub const CHUNK_MAX_SIZE: usize = 8 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("corrupt or tampered data")]
    CorruptOrTamperedData,
}

pub fn open_repository(
    w: &mut dyn std::io::Write,
    r: &mut dyn std::io::Read,
    open_mode: OpenMode,
) -> Result<(), anyhow::Error> {
    write_packet(
        w,
        &Packet::TOpenRepository(TOpenRepository {
            open_mode,
            protocol_version: "7".to_string(),
        }),
    )?;

    match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
        Packet::ROpenRepository(resp) => {
            let clock_skew = (resp.unix_now_millis as i64) - chrono::Utc::now().timestamp_millis();
            const MAX_SKEW_MINS: i64 = 15;
            const MAX_SKEW_MILLIS: i64 = MAX_SKEW_MINS * 60 * 1000;
            if clock_skew > MAX_SKEW_MILLIS || clock_skew < -MAX_SKEW_MILLIS {
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
    r: &mut dyn std::io::Read,
    w: &mut dyn std::io::Write,
    storage_spec: Option<repository::StorageEngineSpec>,
) -> Result<(), anyhow::Error> {
    write_packet(w, &Packet::TInitRepository(storage_spec))?;
    match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
        Packet::RInitRepository => Ok(()),
        _ => anyhow::bail!("protocol error, expected begin ack packet"),
    }
}

#[derive(Clone)]
pub struct SendContext {
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
    pub checkpoint_bytes: u64,
    pub want_xattrs: bool,
    pub use_stat_cache: bool,
    pub one_file_system: bool,
}

struct SendSession<'a, 'b, 'c> {
    ctx: SendContext,
    start_time: chrono::DateTime<chrono::Utc>,
    dirty_bytes: u64,
    transferred_chunks: u64,
    transferred_bytes: u64,
    added_chunks: u64,
    added_bytes: u64,
    // Ownership is slightly tricky because the stat cache and query cache share a transaction.
    send_log_session: &'a mut Option<RefCell<sendlog::SendLogSession<'b>>>,
    acache: acache::ACache,
    data_chunker: chunker::RollsumChunker,
    idx_chunker: chunker::RollsumChunker,
    // Can we structure this code so this is not needed?
    data_tw: Cell<Option<Box<htree::TreeWriter>>>,
    idx_tw: Cell<Option<Box<htree::TreeWriter>>>,
    idx_size: u64,
    data_size: u64,
    r: &'c mut dyn std::io::Read,
    w: &'c mut dyn std::io::Write,
}

impl<'a, 'b, 'c> htree::Sink for SendSession<'a, 'b, 'c> {
    fn add_htree_chunk(
        &mut self,
        addr: &Address,
        data: std::vec::Vec<u8>,
    ) -> Result<(), anyhow::Error> {
        if !self.acache.add(addr) {
            return Ok(());
        }

        match self.send_log_session {
            Some(ref send_log_session) => {
                if send_log_session.borrow_mut().add_address(addr)? {
                    self.write_chunk(addr, data)?;
                }
                Ok(())
            }
            None => {
                self.write_chunk(addr, data)?;
                Ok(())
            }
        }
    }
}

impl<'a, 'b, 'c> SendSession<'a, 'b, 'c> {
    fn write_chunk(
        &mut self,
        addr: &Address,
        data: std::vec::Vec<u8>,
    ) -> Result<(), anyhow::Error> {
        write_chunk(self.w, addr, &data)?;
        self.dirty_bytes += data.len() as u64;
        self.transferred_bytes += data.len() as u64;
        self.transferred_chunks += 1;
        if self.dirty_bytes > self.ctx.checkpoint_bytes {
            self.sync()?;
        }
        Ok(())
    }

    fn encrypt_and_write_data_chunk(
        &mut self,
        addr: &Address,
        data: std::vec::Vec<u8>,
    ) -> Result<(), anyhow::Error> {
        let data = self.ctx.data_ectx.encrypt_data(data, self.ctx.compression);
        self.write_chunk(&addr, data)
    }

    fn encrypt_and_write_idx_chunk(
        &mut self,
        addr: &Address,
        data: std::vec::Vec<u8>,
    ) -> Result<(), anyhow::Error> {
        // unconditionally compress index chunks, there is little reason not to.
        let data = self
            .ctx
            .idx_ectx
            .encrypt_data(data, compression::Scheme::Lz4);
        self.write_chunk(&addr, data)
    }

    fn add_data_chunk(&mut self, data: std::vec::Vec<u8>) -> Result<Address, anyhow::Error> {
        let addr = crypto::keyed_content_address(&data, &self.ctx.data_hash_key);

        let mut tw = self.data_tw.take().unwrap();
        tw.add_data_addr(self, &addr)?;
        self.data_tw.set(Some(tw));
        self.data_size += data.len() as u64;
        self.ctx.progress.inc(data.len() as u64);

        if !self.acache.add(&addr) {
            return Ok(addr);
        }

        match self.send_log_session {
            Some(ref send_log_session) => {
                if send_log_session.borrow_mut().add_address(&addr)? {
                    self.encrypt_and_write_data_chunk(&addr, data)?;
                }
                Ok(addr)
            }
            None => {
                self.encrypt_and_write_data_chunk(&addr, data)?;
                Ok(addr)
            }
        }
    }

    fn add_idx_chunk(&mut self, data: std::vec::Vec<u8>) -> Result<Address, anyhow::Error> {
        let addr = crypto::keyed_content_address(&data, &self.ctx.idx_hash_key);
        let mut tw = self.idx_tw.take().unwrap();
        tw.add_data_addr(self, &addr)?;
        self.idx_tw.set(Some(tw));
        self.idx_size += data.len() as u64;
        self.ctx.progress.inc(data.len() as u64);

        if !self.acache.add(&addr) {
            return Ok(addr);
        }

        match self.send_log_session {
            Some(ref send_log_session) => {
                if send_log_session.borrow_mut().add_address(&addr)? {
                    self.encrypt_and_write_idx_chunk(&addr, data)?;
                }
                Ok(addr)
            }
            None => {
                self.encrypt_and_write_idx_chunk(&addr, data)?;
                Ok(addr)
            }
        }
    }

    fn write_data(
        &mut self,
        data: &mut dyn std::io::Read,
        on_chunk: &mut dyn FnMut(&Address, usize),
    ) -> Result<u64, anyhow::Error> {
        let mut buf: [u8; 512 * 1024] = unsafe { std::mem::MaybeUninit::uninit().assume_init() };
        let mut n_written: u64 = 0;
        loop {
            match data.read(&mut buf) {
                Ok(0) => {
                    return Ok(n_written);
                }
                Ok(n_read) => {
                    let mut n_chunked = 0;
                    while n_chunked != n_read {
                        let (n, c) = self.data_chunker.add_bytes(&buf[n_chunked..n_read]);
                        n_chunked += n;
                        if let Some(chunk_data) = c {
                            let data_len = chunk_data.len();
                            let addr = self.add_data_chunk(chunk_data)?;
                            on_chunk(&addr, data_len);
                        }
                    }
                    n_written += n_read as u64;
                }
                Err(err) => return Err(err.into()),
            }
        }
    }

    fn write_idx_ent(&mut self, ent: &index::VersionedIndexEntry) -> Result<(), anyhow::Error> {
        let buf = serde_bare::to_vec(ent)?;
        let mut n_chunked = 0;
        while n_chunked != buf.len() {
            let (n, c) = self.idx_chunker.add_bytes(&buf[n_chunked..]);
            n_chunked += n;
            if let Some(chunk_data) = c {
                self.add_idx_chunk(chunk_data)?;
            }
        }
        Ok(())
    }

    fn send_dir(
        &mut self,
        base: &std::path::Path,
        paths: &[std::path::PathBuf],
        exclusions: &[glob::Pattern],
    ) -> Result<(), anyhow::Error> {
        let use_stat_cache = self.ctx.use_stat_cache;

        let mut dev_normalizer = DevNormalizer::new();

        let metadata = std::fs::metadata(&base).map_err(|err| {
            anyhow::format_err!("unable to fetch metadata for {}: {}", base.display(), err)
        })?;

        if !metadata.is_dir() {
            anyhow::bail!("{} is not a directory", base.display());
        }

        let ent = index::VersionedIndexEntry::V2(
            dir_ent_to_index_ent(
                &mut dev_normalizer,
                &base,
                &std::path::PathBuf::from("."),
                &metadata,
                self.ctx.want_xattrs,
            )
            .map_err(|err| {
                anyhow::format_err!("unable build index entry for {}: {}", base.display(), err)
            })?,
        );

        self.write_idx_ent(&ent)?;

        let mut work_list = std::collections::VecDeque::new();

        let mut initial_paths = std::collections::HashSet::new();
        for p in paths {
            let initial_md = std::fs::metadata(&p).map_err(|err| {
                anyhow::format_err!("unable to fetch metadata for {}: {}", p.display(), err)
            })?;
            if !initial_md.is_dir() {
                // We should be able to lift this restriction in the future.
                anyhow::bail!(
                    "{} is not a directory, files cannot be part of multi-dir put",
                    p.display()
                );
            }
            work_list.push_back((p.clone(), initial_md));
            if p != base {
                initial_paths.insert(p.clone());
            }
        }

        while let Some((cur_dir, cur_dir_md)) = work_list.pop_front() {
            assert!(cur_dir_md.is_dir());
            self.ctx.progress.set_message(&cur_dir.to_string_lossy());

            // These inital paths do not have a parent who will add an index entry
            // for them, so we add before we process the dir contents.
            if !initial_paths.is_empty() && initial_paths.contains(&cur_dir) {
                initial_paths.remove(&cur_dir);
                let index_path = cur_dir.strip_prefix(&base).unwrap().to_path_buf();
                let ent = index::VersionedIndexEntry::V2(
                    dir_ent_to_index_ent(
                        &mut dev_normalizer,
                        &cur_dir,
                        &index_path,
                        &cur_dir_md,
                        self.ctx.want_xattrs,
                    )
                    .map_err(|err| {
                        anyhow::format_err!(
                            "unable build index entry for {}: {}",
                            cur_dir.display(),
                            err
                        )
                    })?,
                );
                self.write_idx_ent(&ent)?;
            }

            let mut hash_state = crypto::HashState::new(Some(&self.ctx.idx_hash_key));

            // Incorporate the absolute dir in our cache key.
            hash_state.update(cur_dir.as_os_str().as_bytes());
            // Null byte marks the end of path in the hash space.
            hash_state.update(&[0]);

            let mut dir_ents = match fsutil::read_dirents(&cur_dir) {
                Ok(dir_ents) => dir_ents,
                // If the directory was deleted from under us, treat it as empty.
                Err(err) if likely_smear_error(&err) => vec![],
                Err(err) => anyhow::bail!("unable list {}: {}", cur_dir.display(), err),
            };

            // Note sorting by extension or reverse filename might give better compression,
            // but we should not add this without checking how it affects the diff command.
            dir_ents.sort_by(|l, r| {
                index::path_cmp(
                    &l.file_name().to_string_lossy(),
                    &r.file_name().to_string_lossy(),
                )
            });

            let mut index_ents = Vec::new();

            'collect_dir_ents: for entry in dir_ents {
                let ent_path = entry.path();

                for excl in exclusions {
                    if excl.matches_path(&ent_path) {
                        continue 'collect_dir_ents;
                    }
                }

                let metadata = match entry.metadata() {
                    Ok(metadata) => metadata,
                    // If the entry was deleted from under us, treat it as if it was excluded.
                    Err(err) if likely_smear_error(&err) => continue 'collect_dir_ents,
                    Err(err) => anyhow::bail!(
                        "unable to fetch metadata for {}: {}",
                        ent_path.display(),
                        err
                    ),
                };

                // There is no meaningful way to backup a unix socket.
                if metadata.file_type().is_socket() {
                    continue 'collect_dir_ents;
                }

                let index_path = ent_path.strip_prefix(&base).unwrap().to_path_buf();
                let index_ent = match dir_ent_to_index_ent(
                    &mut dev_normalizer,
                    &ent_path,
                    &index_path,
                    &metadata,
                    self.ctx.want_xattrs,
                ) {
                    Ok(ent) => ent,
                    // The entry was removed while we were it's metadata
                    // in a way that was unrecoverable. For example a symlink was removed so
                    // we cannot do a valid readlink.
                    Err(err) if likely_smear_error(&err) => continue 'collect_dir_ents,
                    Err(err) => anyhow::bail!(
                        "unable build index entry for {}: {}",
                        ent_path.display(),
                        err
                    ),
                };

                if metadata.is_dir()
                    && ((cur_dir_md.dev() == metadata.dev()) || !self.ctx.one_file_system)
                {
                    work_list.push_back((ent_path.clone(), metadata));
                }

                if use_stat_cache {
                    hash_state.update(&serde_bare::to_vec(&index_ent).unwrap());
                }

                index_ents.push((ent_path, index_ent));
            }

            let hash = hash_state.finish();

            let cache_lookup = if self.send_log_session.is_some() && use_stat_cache {
                self.send_log_session
                    .as_ref()
                    .unwrap()
                    .borrow_mut()
                    .stat_cache_lookup(&hash)?
            } else {
                None
            };

            match cache_lookup {
                Some(cache_entry) => {
                    let dir_data_chunk_idx =
                        self.data_tw.get_mut().as_ref().unwrap().data_chunk_count();

                    let mut data_tw = self.data_tw.take().unwrap();
                    for addr in &cache_entry.addresses {
                        data_tw.add_data_addr(self, &addr)?;
                    }
                    self.data_tw.set(Some(data_tw));
                    self.data_size += cache_entry.total_size;
                    self.ctx.progress.inc(cache_entry.total_size);

                    assert!(cache_entry.base_offsets.len() == index_ents.len());
                    assert!(cache_entry.hashes.len() == index_ents.len());

                    for (i, (_, mut index_ent)) in index_ents.drain(..).enumerate() {
                        index_ent.data_hash = cache_entry.hashes[i];
                        index_ent.offsets = cache_entry.base_offsets[i];
                        index_ent.offsets.data_chunk_idx.0 += dir_data_chunk_idx;
                        index_ent.offsets.data_chunk_end_idx.0 += dir_data_chunk_idx;
                        self.write_idx_ent(&index::VersionedIndexEntry::V2(index_ent))?;
                    }

                    // Re-add the cache entry so it isn't invalidated.
                    self.send_log_session
                        .as_ref()
                        .unwrap()
                        .borrow_mut()
                        .add_stat_cache_data(&hash[..], &cache_entry)?;
                }
                None => {
                    let mut dir_data_size: u64 = 0;
                    let mut addresses = Vec::new();

                    let mut on_data_chunk = |addr: &Address, chunk_len: usize| {
                        dir_data_size += chunk_len as u64;
                        if use_stat_cache {
                            addresses.push(*addr);
                        }
                    };

                    let cache_vec_capacity = if use_stat_cache { index_ents.len() } else { 0 };

                    let mut dir_index_offsets: Vec<index::IndexEntryOffsets> =
                        Vec::with_capacity(cache_vec_capacity);

                    let mut content_hashes: Vec<index::ContentCryptoHash> =
                        Vec::with_capacity(cache_vec_capacity);

                    let dir_data_chunk_idx =
                        self.data_tw.get_mut().as_ref().unwrap().data_chunk_count();

                    'add_dir_ents: for (ent_path, mut index_ent) in index_ents.drain(..) {
                        let ent_data_chunk_idx =
                            self.data_tw.get_mut().as_ref().unwrap().data_chunk_count();
                        let ent_data_chunk_offset = self.data_chunker.buffered_count() as u64;

                        let mut ent_data_chunk_end_idx = ent_data_chunk_idx;
                        let mut ent_data_chunk_end_offset = ent_data_chunk_offset;

                        if index_ent.is_file() {
                            let mut f = match open_file_for_sending(&ent_path) {
                                Ok(f) => TeeHashFileReader::new(f),
                                // The file was deleted, treat it like it did not exist.
                                // It's unlikely this stat cache entry will hit again as
                                // the ctime definitely would change in this case.
                                Err(err) if likely_smear_error(&err) => continue 'add_dir_ents,
                                Err(err) => {
                                    anyhow::bail!("unable to read {}: {}", ent_path.display(), err)
                                }
                            };

                            let file_len = self.write_data(&mut f, &mut on_data_chunk)?;

                            // The true size is just what we read from disk. In the case
                            // of snapshotting an modified file we can't guarantee consistency anyway.
                            index_ent.size.0 = file_len;
                            index_ent.data_hash = index::ContentCryptoHash::Blake3(f.finalize());
                            ent_data_chunk_end_idx =
                                self.data_tw.get_mut().as_ref().unwrap().data_chunk_count();
                            ent_data_chunk_end_offset = self.data_chunker.buffered_count() as u64;
                        }

                        let cur_offsets = index::IndexEntryOffsets {
                            data_chunk_idx: serde_bare::Uint(
                                ent_data_chunk_idx - dir_data_chunk_idx,
                            ),
                            data_chunk_end_idx: serde_bare::Uint(
                                ent_data_chunk_end_idx - dir_data_chunk_idx,
                            ),
                            data_chunk_offset: serde_bare::Uint(ent_data_chunk_offset),
                            data_chunk_end_offset: serde_bare::Uint(ent_data_chunk_end_offset),
                        };

                        if use_stat_cache {
                            dir_index_offsets.push(cur_offsets);
                            content_hashes.push(index_ent.data_hash)
                        }

                        index_ent.offsets = cur_offsets;
                        index_ent.offsets.data_chunk_idx.0 += dir_data_chunk_idx;
                        index_ent.offsets.data_chunk_end_idx.0 += dir_data_chunk_idx;

                        self.write_idx_ent(&index::VersionedIndexEntry::V2(index_ent))?;
                    }

                    if let Some(boundary_chunk) = self.data_chunker.force_split() {
                        let boundary_chunk_len = boundary_chunk.len();
                        let addr = self.add_data_chunk(boundary_chunk)?;
                        on_data_chunk(&addr, boundary_chunk_len);
                    }

                    if self.send_log_session.is_some() && use_stat_cache {
                        self.send_log_session
                            .as_ref()
                            .unwrap()
                            .borrow_mut()
                            .add_stat_cache_data(
                                &hash[..],
                                &sendlog::StatCacheEntry {
                                    addresses,
                                    total_size: dir_data_size,
                                    base_offsets: dir_index_offsets,
                                    hashes: content_hashes,
                                },
                            )?;
                    }
                }
            }
        }

        Ok(())
    }

    fn sync(&mut self) -> Result<(), anyhow::Error> {
        write_packet(self.w, &Packet::TSendSync)?;
        match read_packet(self.r, DEFAULT_MAX_PACKET_SIZE)? {
            Packet::RSendSync(stats) => {
                self.added_bytes += stats.added_bytes;
                self.added_chunks += stats.added_chunks;
            }
            _ => anyhow::bail!("protocol error, expected RSentSync packet"),
        }
        match self.send_log_session {
            Some(ref mut send_log_session) => send_log_session.borrow_mut().checkpoint()?,
            None => (),
        }
        self.dirty_bytes = 0;
        Ok(())
    }

    fn finish(
        mut self,
    ) -> Result<
        (
            itemset::HTreeMetadata,
            Option<itemset::HTreeMetadata>,
            SendStats,
        ),
        anyhow::Error,
    > {
        let buffered_data = self.data_chunker.take_buffered();
        self.add_data_chunk(buffered_data)?;
        let data_tw = self.data_tw.take().unwrap();
        let data_tree_meta = data_tw.finish(&mut self)?;
        let mut idx_tree_meta = None;
        let buffered_idx = self.idx_chunker.take_buffered();
        if !buffered_idx.is_empty() {
            self.add_idx_chunk(buffered_idx)?;
        }
        if self.idx_size != 0 {
            let idx_tw = self.idx_tw.take().unwrap();
            idx_tree_meta = Some(idx_tw.finish(&mut self)?);
        }

        self.ctx.progress.set_message("syncing storage...");
        self.sync()?;

        let stats = SendStats {
            start_time: self.start_time,
            end_time: chrono::Utc::now(),
            uncompressed_index_size: self.idx_size,
            uncompressed_data_size: self.data_size,
            total_chunks: data_tree_meta.total_chunk_count
                + if let Some(ref idx_tree_meta) = idx_tree_meta {
                    idx_tree_meta.total_chunk_count
                } else {
                    0
                },
            transferred_bytes: self.transferred_bytes,
            transferred_chunks: self.transferred_chunks,
            added_bytes: self.added_bytes,
            added_chunks: self.added_chunks,
        };

        let data_tree_meta = itemset::HTreeMetadata {
            height: serde_bare::Uint(data_tree_meta.height as u64),
            data_chunk_count: serde_bare::Uint(data_tree_meta.data_chunk_count),
            address: data_tree_meta.address,
        };

        let idx_tree_meta = if let Some(ref idx_tree_meta) = idx_tree_meta {
            Some(itemset::HTreeMetadata {
                height: serde_bare::Uint(idx_tree_meta.height as u64),
                data_chunk_count: serde_bare::Uint(idx_tree_meta.data_chunk_count),
                address: idx_tree_meta.address,
            })
        } else {
            None
        };

        Ok((data_tree_meta, idx_tree_meta, stats))
    }
}

pub enum DataSource {
    Subprocess(Vec<String>),
    Readable {
        description: String,
        data: Box<dyn std::io::Read>,
    },
    Filesystem {
        base: std::path::PathBuf,
        paths: Vec<std::path::PathBuf>,
        exclusions: Vec<glob::Pattern>,
    },
}

pub struct SendStats {
    // send start time.
    pub start_time: chrono::DateTime<chrono::Utc>,
    // send end time.
    pub end_time: chrono::DateTime<chrono::Utc>,
    // Total number of chunks processed.
    pub total_chunks: u64,
    // Size of uncompressed index stream.
    pub uncompressed_index_size: u64,
    // Size of uncompressed data stream.
    pub uncompressed_data_size: u64,
    // Number of chunks actually sent to the remote after caching.
    pub transferred_chunks: u64,
    // Data actually sent after compression/caching.
    pub transferred_bytes: u64,
    // Number of chunks added to the remote server.
    pub added_chunks: u64,
    // Number of bytes added to the remote server.
    pub added_bytes: u64,
}

pub fn send(
    ctx: &mut SendContext,
    r: &mut dyn std::io::Read,
    w: &mut dyn std::io::Write,
    mut send_log: Option<sendlog::SendLog>,
    tags: BTreeMap<String, String>,
    data: &mut DataSource,
) -> Result<(Xid, SendStats), anyhow::Error> {
    let start_time = chrono::Utc::now();

    let send_id = match send_log {
        Some(ref mut send_log) => send_log.last_send_id()?,
        None => None,
    };

    write_packet(w, &Packet::TBeginSend(TBeginSend { delta_id: send_id }))?;

    let ack = match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
        Packet::RBeginSend(ack) => ack,
        _ => anyhow::bail!("protocol error, expected begin ack packet"),
    };

    let mut send_log_session = match send_log {
        Some(ref mut send_log) => Some(RefCell::new(send_log.session(ack.gc_generation)?)),
        None => None,
    };

    if let Some(ref send_log_session) = send_log_session {
        send_log_session
            .borrow_mut()
            .perform_cache_invalidations(ack.has_delta_id)?;
    }

    let min_size = CHUNK_MIN_SIZE;
    let max_size = CHUNK_MAX_SIZE;

    let mut session = SendSession {
        ctx: ctx.clone(),
        start_time,
        dirty_bytes: 0,
        transferred_bytes: 0,
        transferred_chunks: 0,
        added_chunks: 0,
        added_bytes: 0,
        send_log_session: &mut send_log_session,
        acache: acache::ACache::new(32768),
        data_chunker: chunker::RollsumChunker::new(ctx.gear_tab, min_size, max_size),
        data_tw: Cell::new(Some(Box::new(htree::TreeWriter::new(min_size, max_size)))),
        idx_chunker: chunker::RollsumChunker::new(ctx.gear_tab, min_size, max_size),
        idx_tw: Cell::new(Some(Box::new(htree::TreeWriter::new(min_size, max_size)))),
        idx_size: 0,
        data_size: 0,
        w,
        r,
    };

    match data {
        DataSource::Subprocess(args) => {
            let quoted_args: Vec<String> =
                args.iter().map(|x| shlex::quote(x).to_string()).collect();
            ctx.progress
                .set_message(&format!("exec: {}", quoted_args.join(" ")));

            let mut child = std::process::Command::new(args[0].clone())
                .args(&args[1..])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .spawn()?;
            let mut data = child.stdout.as_mut().unwrap();
            session.write_data(&mut data, &mut |_: &Address, _: usize| {})?;
            let status = child.wait()?;
            if !status.success() {
                anyhow::bail!("child failed with status {}", status.code().unwrap());
            }
        }
        DataSource::Readable {
            description,
            ref mut data,
        } => {
            ctx.progress.set_message(&description);
            session.write_data(data, &mut |_: &Address, _: usize| {})?;
        }
        DataSource::Filesystem {
            base,
            paths,
            exclusions,
        } => {
            session.send_dir(base, paths, exclusions)?;
        }
    }

    let (data_tree, index_tree, stats) = session.finish()?;

    let plain_text_metadata = itemset::V2PlainTextItemMetadata {
        primary_key_id: ctx.primary_key_id,
        unix_timestamp_millis: chrono::Utc::now().timestamp_millis().try_into()?,
        data_tree,
        index_tree,
    };

    let e_metadata = itemset::V2SecretItemMetadata {
        plain_text_hash: plain_text_metadata.hash(),
        send_key_id: ctx.send_key_id,
        index_hash_key_part_2: ctx.idx_hash_key.part2.clone(),
        data_hash_key_part_2: ctx.data_hash_key.part2.clone(),
        data_size: serde_bare::Uint(stats.uncompressed_data_size),
        index_size: serde_bare::Uint(stats.uncompressed_index_size),
        tags,
    };

    let versioned_metadata = itemset::VersionedItemMetadata::V2(itemset::V2ItemMetadata {
        plain_text_metadata,
        encrypted_metadata: ctx
            .metadata_ectx
            .encrypt_data(serde_bare::to_vec(&e_metadata)?, compression::Scheme::Lz4),
    });

    write_packet(
        w,
        &Packet::TAddItem(AddItem {
            gc_generation: ack.gc_generation,
            item: versioned_metadata,
        }),
    )?;

    match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
        Packet::RAddItem(id) => {
            if let Some(send_log_session) = send_log_session {
                send_log_session.into_inner().commit(&id)?;
            }
            Ok((id, stats))
        }
        _ => anyhow::bail!("protocol error, expected an RAddItem packet"),
    }
}

// A smear error is an error likely caused by the filesystem being altered
// by a concurrent process as we are making a snapshot.
fn likely_smear_error(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::NotFound | std::io::ErrorKind::InvalidInput
    )
}

cfg_if::cfg_if! {
    if #[cfg(target_os = "linux")] {

        fn dev_major(dev: u64) -> u32 {
            (((dev >> 32) & 0xffff_f000) |
             ((dev >>  8) & 0x0000_0fff)) as u32
        }

        fn dev_minor(dev: u64) -> u32 {
            (((dev >> 12) & 0xffff_ff00) |
             ((dev      ) & 0x0000_00ff)) as u32
        }

    } else if #[cfg(target_os = "openbsd")] {

        fn dev_major(dev: u64) -> u32 {
            ((dev >> 8) & 0x0000_00ff) as u32
        }

        fn dev_minor(dev: u64) -> u32 {
            ((dev & 0x0000_00ff) | ((dev & 0xffff_0000) >> 8)) as u32
        }

    } else {

        fn dev_major(_dev: u64) -> u32 {
            panic!("unable to get device major number on this platform (file a bug report)");
        }

        fn dev_minor(_dev: u64) -> u32 {
            panic!("unable to get device minor number on this platform (file a bug report)");
        }

    }
}

pub struct DevNormalizer {
    count: u64,
    tab: HashMap<u64, u64>,
}

impl DevNormalizer {
    fn new() -> Self {
        DevNormalizer {
            count: 0,
            tab: HashMap::new(),
        }
    }

    fn normalize(&mut self, dev: u64) -> u64 {
        match self.tab.get(&dev) {
            Some(nd) => *nd,
            None => {
                let nd = self.count;
                self.count += 1;
                self.tab.insert(dev, nd);
                nd
            }
        }
    }
}

fn dir_ent_to_index_ent(
    dev_normalizer: &mut DevNormalizer,
    full_path: &std::path::Path,
    short_path: &std::path::Path,
    metadata: &std::fs::Metadata,
    want_xattrs: bool,
) -> Result<index::IndexEntry, std::io::Error> {
    // TODO XXX it seems we should not be using to_string_lossy and throwing away user data...
    // how best to handle this?

    let t = metadata.file_type();

    let (dev_major, dev_minor) = if t.is_block_device() || t.is_char_device() {
        (dev_major(metadata.rdev()), dev_minor(metadata.rdev()))
    } else {
        (0, 0)
    };

    let mut xattrs = None;

    if want_xattrs && (t.is_file() || t.is_dir()) {
        match xattr::list(full_path) {
            Ok(attrs) => {
                for attr in attrs {
                    match xattr::get(full_path, &attr) {
                        Ok(Some(value)) => {
                            if xattrs.is_none() {
                                xattrs = Some(std::collections::BTreeMap::new())
                            }
                            match xattrs {
                                Some(ref mut xattrs) => {
                                    xattrs.insert(attr.to_string_lossy().to_string(), value);
                                }
                                _ => unreachable!(),
                            }
                        }
                        Ok(None) => (), // The file had it's xattr removed, assume it never had it.
                        Err(err) if likely_smear_error(&err) => (), // The file was modified, assume it never had this xattr.
                        Err(err) => return Err(err),
                    }
                }
            }
            Err(err) if likely_smear_error(&err) => (), // The file was modified, assume no xattrs for what we have.
            Err(err) => return Err(err),
        }
    }

    Ok(index::IndexEntry {
        path: short_path.to_string_lossy().to_string(),
        size: serde_bare::Uint(if metadata.is_file() {
            metadata.size()
        } else {
            0
        }),
        uid: serde_bare::Uint(metadata.uid() as u64),
        gid: serde_bare::Uint(metadata.gid() as u64),
        mode: serde_bare::Uint(metadata.permissions().mode() as u64),
        ctime: serde_bare::Uint(metadata.ctime() as u64),
        ctime_nsec: serde_bare::Uint(metadata.ctime_nsec() as u64),
        mtime: serde_bare::Uint(metadata.mtime() as u64),
        mtime_nsec: serde_bare::Uint(metadata.mtime_nsec() as u64),
        nlink: serde_bare::Uint(metadata.nlink()),
        link_target: if t.is_symlink() {
            Some(
                std::fs::read_link(&full_path)?
                    .to_string_lossy() // XXX Avoid this lossy conversion?
                    .to_string(),
            )
        } else {
            None
        },
        dev_major: serde_bare::Uint(dev_major as u64),
        dev_minor: serde_bare::Uint(dev_minor as u64),
        norm_dev: serde_bare::Uint(dev_normalizer.normalize(metadata.dev())),
        ino: serde_bare::Uint(metadata.ino()),
        xattrs,
        offsets: index::IndexEntryOffsets {
            data_chunk_idx: serde_bare::Uint(0),
            data_chunk_end_idx: serde_bare::Uint(0),
            data_chunk_offset: serde_bare::Uint(0),
            data_chunk_end_offset: serde_bare::Uint(0),
        },
        data_hash: index::ContentCryptoHash::None, // Set by caller.
    })
}

// Read a file while also blake3 hashing any data.
struct TeeHashFileReader {
    f: std::fs::File,
    h: blake3::Hasher,
}

impl TeeHashFileReader {
    fn new(f: std::fs::File) -> Self {
        TeeHashFileReader {
            f,
            h: blake3::Hasher::new(),
        }
    }

    fn finalize(self) -> [u8; 32] {
        self.h.finalize().into()
    }
}

impl std::io::Read for TeeHashFileReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self.f.read(buf) {
            Ok(n) => {
                self.h.update(&buf[0..n]);
                Ok(n)
            }
            err => err,
        }
    }
}

cfg_if::cfg_if! {
    if #[cfg(target_os = "linux")] {

        fn open_file_for_sending(fpath: &std::path::Path) -> Result<std::fs::File, std::io::Error> {
            // Try with O_NOATIME first; if it fails, e.g. because the user we
            // run as is not the file owner, retry without. See #106.
            let f = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOATIME)
                .open(fpath)
                .or_else(|error| {
                    match error.kind() {
                        std::io::ErrorKind::PermissionDenied => {
                            std::fs::OpenOptions::new()
                                .read(true)
                                .open(fpath)
                        }
                        _ => Err(error)
                    }
                })?;

            // For linux at least, shift file pages to the tail of the page cache, allowing
            // the kernel to quickly evict these pages. This works well for the case of system
            // backups, where we don't to trash the users current cache.
            // One source on how linux treats this hint - https://lwn.net/Articles/449420
            match nix::fcntl::posix_fadvise(
                f.as_raw_fd(),
                0,
                0,
                nix::fcntl::PosixFadviseAdvice::POSIX_FADV_NOREUSE,
            ) {
                Ok(_) => (),
                Err(err) => return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("fadvise failed: {}", err))),
            };

            Ok(f)
        }

    // XXX More platforms should support NOATIME or at the very least POSIX_FADV_NOREUSE
    } else {

        fn open_file_for_sending(fpath: &std::path::Path) -> Result<std::fs::File, std::io::Error> {
            let f = std::fs::OpenOptions::new()
                .read(true)
                .open(fpath)?;
            Ok(f)
        }
    }
}

pub fn request_metadata(
    id: Xid,
    r: &mut dyn std::io::Read,
    w: &mut dyn std::io::Write,
) -> Result<itemset::VersionedItemMetadata, anyhow::Error> {
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
    metadata: &itemset::VersionedItemMetadata,
    pick: Option<index::PickMap>,
    index: Option<index::CompressedIndex>,
    r: &mut dyn std::io::Read,
    w: &mut dyn std::io::Write,
    out: &mut dyn std::io::Write,
) -> Result<(), anyhow::Error> {
    // It makes little sense to ask the server for an empty pick.
    if let Some(ref pick) = pick {
        if !pick.is_subtar && pick.data_chunk_ranges.is_empty() {
            return Ok(());
        }
    }

    if ctx.primary_key_id != *metadata.primary_key_id() {
        anyhow::bail!("decryption key does not match key used for encryption");
    }

    let decrypted_metadata = metadata.decrypt_metadata(&mut ctx.metadata_dctx)?;
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

    match pick {
        Some(pick) => {
            write_packet(
                w,
                &Packet::RequestData(RequestData {
                    id,
                    ranges: Some(pick.data_chunk_ranges.clone()),
                }),
            )?;
            receive_partial_htree(&mut ctx.data_dctx, &hash_key, r, &mut tr, pick, out)?;
        }
        None => {
            write_packet(w, &Packet::RequestData(RequestData { id, ranges: None }))?;

            match index {
                Some(index) => receive_indexed_htree_as_tarball(
                    &mut ctx.data_dctx,
                    &hash_key,
                    r,
                    &mut tr,
                    &index,
                    out,
                )?,
                None => receive_htree(&mut ctx.data_dctx, &hash_key, r, &mut tr, out)?,
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
    mut ctx: IndexRequestContext,
    id: Xid,
    metadata: &itemset::VersionedItemMetadata,
    r: &mut dyn std::io::Read,
    w: &mut dyn std::io::Write,
) -> Result<index::CompressedIndex, anyhow::Error> {
    if ctx.primary_key_id != *metadata.primary_key_id() {
        anyhow::bail!("decryption key does not match key used for encryption");
    }

    let decrypted_metadata = metadata.decrypt_metadata(&mut ctx.metadata_dctx)?;

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

    write_packet(w, &Packet::RequestIndex(RequestIndex { id }))?;
    receive_htree(&mut ctx.idx_dctx, &hash_key, r, &mut tr, &mut index_data)?;

    let (index_cursor, compress_result) = index_data.finish();
    compress_result?;
    let compressed_index = index_cursor.into_inner();
    Ok(index::CompressedIndex::from_vec(compressed_index))
}

fn receive_and_authenticate_htree_chunk(
    r: &mut dyn std::io::Read,
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
    dctx: &mut crypto::DecryptionContext,
    hash_key: &crypto::HashKey,
    r: &mut dyn std::io::Read,
    tr: &mut htree::TreeReader,
    out: &mut dyn std::io::Write,
) -> Result<(), anyhow::Error> {
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

            let data = dctx.decrypt_data(data)?;
            if addr != crypto::keyed_content_address(&data, &hash_key) {
                return Err(ClientError::CorruptOrTamperedData.into());
            }
            out.write_all(&data)?;
        } else {
            let data = receive_and_authenticate_htree_chunk(r, addr)?;
            tr.push_level(height - 1, data)?;
        }
    }

    out.flush()?;
    Ok(())
}

fn write_index_as_tarball(
    read_data: &mut dyn FnMut() -> Result<Option<Vec<u8>>, anyhow::Error>,
    index: &index::CompressedIndex,
    out: &mut dyn std::io::Write,
) -> Result<(), anyhow::Error> {
    let mut buffered = vec![];
    let mut buffer_index: usize = 0;
    let mut copy_n = |out: &mut dyn std::io::Write, mut n: u64| -> Result<(), anyhow::Error> {
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
            let n_written = out.write(&buffered[write_range])?;
            buffer_index += n_written;
            n -= n_written as u64;
        }

        if n != 0 {
            anyhow::bail!("data stream corrupt, unexpected end of data");
        }

        Ok(())
    };

    let mut hardlinks: std::collections::HashMap<(u64, u64), String> =
        std::collections::HashMap::new();

    for ent in index.iter() {
        let ent = ent?;
        if matches!(ent.kind(), index::IndexEntryKind::Other) {
            // We can't convert this to a tar header, so just discard the
            // data and skip it.
            copy_n(&mut std::io::sink(), ent.size.0)?;
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
            copy_n(out, ent.size.0)?;
            /* Tar entries are rounded to 512 bytes */
            let remaining = 512 - (ent.size.0 % 512);
            if remaining < 512 {
                let buf = [0; 512];
                out.write_all(&buf[..remaining as usize])?;
            }
        } else {
            /* Hardlinks are uploaded as normal files, so we just skip the data. */
            copy_n(&mut std::io::sink(), ent.size.0)?;
        }
    }

    let buf = [0; 1024];
    out.write_all(&buf[..])?;

    out.flush()?;
    Ok(())
}

fn receive_indexed_htree_as_tarball(
    dctx: &mut crypto::DecryptionContext,
    hash_key: &crypto::HashKey,
    r: &mut dyn std::io::Read,
    tr: &mut htree::TreeReader,
    index: &index::CompressedIndex,
    out: &mut dyn std::io::Write,
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

                let data = dctx.decrypt_data(data)?;
                if addr != crypto::keyed_content_address(&data, &hash_key) {
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

    write_index_as_tarball(&mut read_data, index, out)
}

fn receive_partial_htree(
    dctx: &mut crypto::DecryptionContext,
    hash_key: &crypto::HashKey,
    r: &mut dyn std::io::Read,
    tr: &mut htree::TreeReader,
    pick: index::PickMap,
    out: &mut dyn std::io::Write,
) -> Result<(), anyhow::Error> {
    let mut range_idx: usize = 0;
    let mut current_data_chunk_idx: u64 = 0;

    // This complicated logic is mirroring the send logic
    // on the server side, only the chunks are coming from the remote.
    // We must also verify all the chunk addresses match what we expect.

    let start_chunk_idx = match pick.data_chunk_ranges.get(0) {
        Some(range) => range.start_idx.0,
        None => 0,
    };

    loop {
        let height = match tr.current_height() {
            Some(v) => v,
            None => anyhow::bail!("htree is corrupt, pick data not found"),
        };

        if height == 0 {
            break;
        }

        let (_, address) = tr.next_addr().unwrap();

        let mut chunk_data = receive_and_authenticate_htree_chunk(r, address)?;
        let mut level_data_chunk_idx = current_data_chunk_idx;
        let mut skip_count = 0;
        for ent_slice in chunk_data.chunks(8 + ADDRESS_SZ) {
            let data_chunk_count = u64::from_le_bytes(ent_slice[..8].try_into()?);
            if level_data_chunk_idx + data_chunk_count > start_chunk_idx {
                break;
            }
            level_data_chunk_idx += data_chunk_count;
            skip_count += 1;
        }
        current_data_chunk_idx = level_data_chunk_idx;
        chunk_data.drain(0..(skip_count * (8 + ADDRESS_SZ)));
        tr.push_level(height - 1, chunk_data)?;
    }

    if current_data_chunk_idx != start_chunk_idx {
        anyhow::bail!("htree is corrupt, seek went too far");
    };

    let mut read_data = || -> Result<Option<Vec<u8>>, anyhow::Error> {
        loop {
            match tr.current_height() {
                Some(0) => {
                    let (_, chunk_address) = tr.next_addr().unwrap();

                    match pick.data_chunk_ranges.get(range_idx) {
                        Some(current_range) => {
                            let mut to_output = None;

                            if current_data_chunk_idx >= current_range.start_idx.0
                                && current_data_chunk_idx <= current_range.end_idx.0
                            {
                                let data = match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
                                    Packet::Chunk(chunk) => {
                                        if chunk_address != chunk.address {
                                            return Err(ClientError::CorruptOrTamperedData.into());
                                        }
                                        chunk.data
                                    }
                                    _ => anyhow::bail!("protocol error, expected chunk packet"),
                                };

                                let data = dctx.decrypt_data(data)?;
                                if chunk_address != crypto::keyed_content_address(&data, &hash_key)
                                {
                                    return Err(ClientError::CorruptOrTamperedData.into());
                                }

                                match pick.incomplete_data_chunks.get(&current_data_chunk_idx) {
                                    Some(ranges) => {
                                        let mut filtered_data = Vec::with_capacity(data.len() / 2);

                                        for range in ranges.iter() {
                                            filtered_data.extend_from_slice(
                                                &data[range.start
                                                    ..std::cmp::min(data.len(), range.end)],
                                            );
                                        }

                                        to_output = Some(filtered_data);
                                    }
                                    None => {
                                        to_output = Some(data);
                                    }
                                }
                            }

                            current_data_chunk_idx += 1;
                            if current_data_chunk_idx > current_range.end_idx.0 {
                                range_idx += 1;
                            }

                            if to_output.is_some() {
                                return Ok(to_output);
                            }
                        }
                        None => break,
                    }
                }
                Some(_) if pick.data_chunk_ranges.get(range_idx).is_some() => {
                    match tr.next_addr() {
                        Some((height, address)) => {
                            let data = receive_and_authenticate_htree_chunk(r, address)?;
                            tr.push_level(height - 1, data)?;
                        }
                        None => break,
                    }
                }
                _ => break,
            }
        }

        Ok(None)
    };

    if pick.is_subtar {
        write_index_as_tarball(&mut read_data, &pick.index, out)?;
    } else {
        while let Some(data) = read_data()? {
            out.write_all(&data)?;
        }
    }

    Ok(())
}

pub fn restore_removed(
    progress: indicatif::ProgressBar,
    r: &mut dyn std::io::Read,
    w: &mut dyn std::io::Write,
) -> Result<u64, anyhow::Error> {
    progress.set_message("restoring items...");

    write_packet(w, &Packet::TRestoreRemoved)?;
    match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
        Packet::RRestoreRemoved(RRestoreRemoved { n_restored }) => Ok(n_restored.0),
        _ => anyhow::bail!("protocol error, expected restore packet response or progress packet",),
    }
}

pub fn gc(
    progress: indicatif::ProgressBar,
    r: &mut dyn std::io::Read,
    w: &mut dyn std::io::Write,
) -> Result<repository::GcStats, anyhow::Error> {
    progress.set_message("collecting garbage...");

    write_packet(w, &Packet::TGc(TGc {}))?;
    loop {
        match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
            Packet::Progress(Progress::Notice(msg)) => {
                progress.println(&msg);
            }
            Packet::Progress(Progress::SetMessage(msg)) => {
                progress.set_message(&msg);
            }
            Packet::RGc(rgc) => return Ok(rgc.stats),
            _ => anyhow::bail!("protocol error, expected gc packet or progress packe."),
        };
    }
}

pub fn sync(
    progress: indicatif::ProgressBar,
    query_cache: &mut querycache::QueryCache,
    r: &mut dyn std::io::Read,
    w: &mut dyn std::io::Write,
) -> Result<(), anyhow::Error> {
    progress.set_message("fetching remote metadata...");

    let mut tx = query_cache.transaction()?;

    let after = tx.last_log_op()?;
    let gc_generation = tx.current_gc_generation()?;

    write_packet(
        w,
        &Packet::TRequestItemSync(TRequestItemSync {
            after,
            gc_generation,
        }),
    )?;

    let gc_generation = match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
        Packet::RRequestItemSync(ack) => ack.gc_generation,
        _ => anyhow::bail!("protocol error, expected items packet"),
    };

    tx.start_sync(gc_generation)?;

    loop {
        match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
            Packet::SyncLogOps(ops) => {
                if ops.is_empty() {
                    break;
                }
                for (opid, item_id, op) in ops {
                    tx.sync_op(opid, item_id, op)?;
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
    r: &mut dyn std::io::Read,
    w: &mut dyn std::io::Write,
) -> Result<(), anyhow::Error> {
    progress.set_message("removing items...");

    for chunked_ids in ids.chunks(4096) {
        let ids = chunked_ids.to_vec();
        write_packet(w, &Packet::TRmItems(ids))?;
        match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
            Packet::RRmItems => {}
            _ => anyhow::bail!("protocol error, expected RRmItems"),
        }
    }
    Ok(())
}

pub fn hangup(w: &mut dyn std::io::Write) -> Result<(), anyhow::Error> {
    write_packet(w, &Packet::EndOfTransmission)?;
    Ok(())
}
