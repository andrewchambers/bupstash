use super::acache;
use super::address::*;
use super::chunker;
use super::compression;
use super::crypto;
use super::fprefetch;
use super::fsutil::likely_smear_error;
use super::htree;
use super::index;
use super::indexer;
use super::oplog;
use super::protocol::*;
use super::querycache;
use super::repository;
use super::rollsum;
use super::sendlog;
use super::xid::*;
use super::xtar;
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, VecDeque};
use std::convert::TryInto;
use std::os::unix::ffi::OsStrExt;

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
            protocol_version: CURRENT_REPOSITORY_PROTOCOL_VERSION.to_string(),
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
    scratch_buf: Vec<u8>,
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
        let mut n_written: u64 = 0;
        loop {
            match data.read(&mut self.scratch_buf[..]) {
                Ok(0) => {
                    return Ok(n_written);
                }
                Ok(n_read) => {
                    let mut n_chunked = 0;
                    while n_chunked != n_read {
                        let (n, c) = self
                            .data_chunker
                            .add_bytes(&self.scratch_buf[n_chunked..n_read]);
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
        paths: Vec<std::path::PathBuf>,
        exclusions: Vec<glob::Pattern>,
    ) -> Result<(), anyhow::Error> {
        let use_stat_cache = self.ctx.use_stat_cache;

        let mut file_opener = fprefetch::ReadaheadFileOpener::new();

        let indexer = indexer::FsIndexer::new(
            &paths,
            indexer::FsIndexerOptions {
                one_file_system: self.ctx.one_file_system,
                want_xattrs: self.ctx.want_xattrs,
                want_hash: false,
                exclusions,
            },
        )?
        .background();

        for indexed_dir in indexer {
            let mut indexed_dir = indexed_dir?;

            self.ctx
                .progress
                .set_message(indexed_dir.dir_path.to_string_lossy().to_string());

            let mut hash_state = crypto::HashState::new(Some(&self.ctx.idx_hash_key));

            if use_stat_cache {
                // Incorporate the absolute dir in our cache key.
                hash_state.update(indexed_dir.dir_path.as_os_str().as_bytes());
                // Null byte marks the end of path in the hash space.
                hash_state.update(&[0]);
                for ent in indexed_dir.index_ents.iter() {
                    hash_state.update(&serde_bare::to_vec(ent).unwrap());
                }
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
                    let mut data_tw = self.data_tw.take().unwrap();
                    for addr in &cache_entry.addresses {
                        data_tw.add_data_addr(self, &addr)?;
                    }
                    self.data_tw.set(Some(data_tw));
                    self.data_size += cache_entry.total_size;
                    self.ctx.progress.inc(cache_entry.total_size);

                    assert!(cache_entry.hashes.len() == indexed_dir.index_ents.len());

                    for (i, mut index_ent) in indexed_dir.index_ents.drain(..).enumerate() {
                        index_ent.data_hash = cache_entry.hashes[i];
                        index_ent.data_cursor = cache_entry.data_cursors[i];
                        self.write_idx_ent(&index::VersionedIndexEntry::V3(index_ent))?;
                    }
                }
                None => {
                    let mut smear_detected = false;
                    let mut dir_data_size: u64 = 0;
                    let mut addresses = Vec::new();

                    let mut on_data_chunk = |addr: &Address, chunk_len: usize| {
                        dir_data_size += chunk_len as u64;
                        if use_stat_cache {
                            addresses.push(*addr);
                        }
                    };

                    let n_idx_ents = indexed_dir.index_ents.len();

                    let cache_vec_capacity = if use_stat_cache { n_idx_ents } else { 0 };

                    let mut data_cursors: Vec<index::RelativeDataCursor> =
                        Vec::with_capacity(cache_vec_capacity);

                    let mut content_hashes: Vec<index::ContentCryptoHash> =
                        Vec::with_capacity(cache_vec_capacity);

                    // Setup the file readahead immediately.
                    for (_, ent_path) in indexed_dir
                        .index_ents
                        .iter()
                        .zip(indexed_dir.ent_paths.drain(..))
                        .filter(|x| x.0.is_file())
                    {
                        file_opener.add_to_queue(ent_path);
                    }

                    'add_dir_ents: for (i, mut index_ent) in
                        indexed_dir.index_ents.drain(..).enumerate()
                    {
                        let ent_data_chunk_start_idx =
                            self.data_tw.get_mut().as_ref().unwrap().data_chunk_count();
                        let ent_start_byte_offset = self.data_chunker.buffered_count() as u64;

                        if index_ent.is_file() {
                            let mut f = match file_opener.next_file().unwrap() {
                                (_, Ok(f)) => TeeHashFileReader::new(f),

                                (_, Err(err)) if likely_smear_error(&err) => {
                                    // This can happen if the file was deleted,
                                    // or the filesystem was unmounted during upload.
                                    // We simply skip this entry but don't cache the result.
                                    smear_detected = true;
                                    continue 'add_dir_ents;
                                }
                                (ent_path, Err(err)) => {
                                    anyhow::bail!("unable to read {}: {}", ent_path.display(), err)
                                }
                            };

                            let file_len = self.write_data(&mut f, &mut on_data_chunk)?;

                            if file_len != index_ent.size.0 {
                                // Don't cache a smeared entry that is immediately invalidated by ctime.
                                smear_detected = true;
                                // The true size is what we read from disk.
                                index_ent.size.0 = file_len;
                            }

                            index_ent.data_hash = index::ContentCryptoHash::Blake3(f.finalize());
                        }

                        if i == n_idx_ents - 1 {
                            // Force a new chunk for the final directory entry so we can
                            // cache whole directories as a single block.
                            if let Some(boundary_chunk) = self.data_chunker.force_split() {
                                let boundary_chunk_len = boundary_chunk.len();
                                let addr = self.add_data_chunk(boundary_chunk)?;
                                on_data_chunk(&addr, boundary_chunk_len);
                            }
                        }

                        let ent_data_chunk_end_idx =
                            self.data_tw.get_mut().as_ref().unwrap().data_chunk_count();
                        let ent_end_byte_offset = self.data_chunker.buffered_count() as u64;

                        index_ent.data_cursor = index::RelativeDataCursor {
                            chunk_delta: serde_bare::Uint(
                                ent_data_chunk_end_idx - ent_data_chunk_start_idx,
                            ),
                            start_byte_offset: serde_bare::Uint(ent_start_byte_offset),
                            end_byte_offset: serde_bare::Uint(ent_end_byte_offset),
                        };

                        if use_stat_cache {
                            data_cursors.push(index_ent.data_cursor);
                            content_hashes.push(index_ent.data_hash)
                        }

                        self.write_idx_ent(&index::VersionedIndexEntry::V3(index_ent))?;
                    }

                    if self.send_log_session.is_some()
                        && use_stat_cache
                        && !smear_detected
                        && !addresses.is_empty()
                    {
                        self.send_log_session
                            .as_ref()
                            .unwrap()
                            .borrow_mut()
                            .add_stat_cache_data(
                                &hash[..],
                                &sendlog::StatCacheEntry {
                                    addresses,
                                    data_cursors,
                                    total_size: dir_data_size,
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
            oplog::HTreeMetadata,
            Option<oplog::HTreeMetadata>,
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

        self.ctx.progress.set_message("flushing storage...");
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

        let data_tree_meta = oplog::HTreeMetadata {
            height: serde_bare::Uint(data_tree_meta.height as u64),
            data_chunk_count: serde_bare::Uint(data_tree_meta.data_chunk_count),
            address: data_tree_meta.address,
        };

        let idx_tree_meta = idx_tree_meta
            .as_ref()
            .map(|idx_tree_meta| oplog::HTreeMetadata {
                height: serde_bare::Uint(idx_tree_meta.height as u64),
                data_chunk_count: serde_bare::Uint(idx_tree_meta.data_chunk_count),
                address: idx_tree_meta.address,
            });

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
    mut ctx: SendContext,
    r: &mut dyn std::io::Read,
    w: &mut dyn std::io::Write,
    mut send_log: Option<sendlog::SendLog>,
    tags: BTreeMap<String, String>,
    data: DataSource,
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
        scratch_buf: vec![0; 512 * 1024],
    };

    match data {
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
            session.write_data(&mut data, &mut |_: &Address, _: usize| {})?;
            let status = child.wait()?;
            if !status.success() {
                anyhow::bail!("child failed with status {}", status.code().unwrap());
            }
        }
        DataSource::Readable {
            description,
            mut data,
        } => {
            ctx.progress.set_message(description);
            session.write_data(&mut data, &mut |_: &Address, _: usize| {})?;
        }
        DataSource::Filesystem { paths, exclusions } => {
            session.send_dir(paths, exclusions)?;
        }
    }

    let (data_tree, index_tree, stats) = session.finish()?;

    let plain_text_metadata = oplog::V2PlainTextItemMetadata {
        primary_key_id: ctx.primary_key_id,
        unix_timestamp_millis: chrono::Utc::now().timestamp_millis().try_into()?,
        data_tree,
        index_tree,
    };

    let e_metadata = oplog::V2SecretItemMetadata {
        plain_text_hash: plain_text_metadata.hash(),
        send_key_id: ctx.send_key_id,
        index_hash_key_part_2: ctx.idx_hash_key.part2.clone(),
        data_hash_key_part_2: ctx.data_hash_key.part2.clone(),
        data_size: serde_bare::Uint(stats.uncompressed_data_size),
        index_size: serde_bare::Uint(stats.uncompressed_index_size),
        tags,
    };

    let versioned_metadata = oplog::VersionedItemMetadata::V2(oplog::V2ItemMetadata {
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

pub fn request_metadata(
    id: Xid,
    r: &mut dyn std::io::Read,
    w: &mut dyn std::io::Write,
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
    r: &mut dyn std::io::Read,
    w: &mut dyn std::io::Write,
    out: &mut dyn std::io::Write,
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
    metadata: &oplog::VersionedItemMetadata,
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

fn write_indexed_data_as_tarball(
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

    write_indexed_data_as_tarball(&mut read_data, index, out)
}

#[allow(clippy::too_many_arguments)]
fn receive_partial_htree(
    dctx: &mut crypto::DecryptionContext,
    hash_key: &crypto::HashKey,
    r: &mut dyn std::io::Read,
    w: &mut dyn std::io::Write,
    tr: &mut htree::TreeReader,
    data_map: index::DataMap,
    index: Option<index::CompressedIndex>,
    out: &mut dyn std::io::Write,
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
        .chunks(if cfg!(debug_assertions) { 1 } else { 100000 });

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
                let data = dctx.decrypt_data(data)?;
                if chunk_addr != crypto::keyed_content_address(&data, &hash_key) {
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

            // Fast forward until we are at the correct data chunk boundary.
            loop {
                let num_skipped = tr.fast_forward(range.start_idx.0 - current_data_chunk_idx)?;
                current_data_chunk_idx += num_skipped;
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

            if current_data_chunk_idx != range.start_idx.0 {
                anyhow::bail!("requested data ranges do not match hash tree accounting, seek overshoot detected")
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
                progress.set_message(msg);
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

    let after = tx.last_log_op_offset()?;
    let gc_generation = tx.current_gc_generation()?;

    write_packet(
        w,
        &Packet::TRequestItemSync(TRequestItemSync {
            after: after.map(serde_bare::Uint),
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
