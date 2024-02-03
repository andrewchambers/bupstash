// This file contains the put pipeline which is responsible
// for the parallel chunking, hashing and sending of
// client side data to the server side.
//
// There are currently two pipelines:
//  - Uploading files from the filesystem into indexed data streams.
//  - Uploading raw data from single files, stdin,
//

use super::acache;
use super::address::Address;
use super::chunker;
use super::compression;
use super::crypto;
use super::fprefetch;
use super::fsutil;
use super::htree;
use super::index;
use super::indexer;
use super::ioutil;
use super::oplog;
use super::protocol;
use super::rollsum;
use super::sendlog;
use anyhow::Context;
use plmap::{PipelineMap, ScopedPipelineMap};
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

enum PathDisplayState {
    Pending,
    Visible,
}

struct ProgressTrackerInner {
    checkpoint_in_progress: bool,
    in_progress: BTreeMap<PathBuf, PathDisplayState>,
}

#[derive(Clone)]
pub struct ProgressTracker {
    hidden: bool,
    progress_bar: indicatif::ProgressBar,

    // Tracking and displaying progress for multi threaded uploads
    // requires a bit of state. We want to know which files are
    // being uploaded and when one finishes we want to display
    // another in progress upload that has already been started.
    inner: Arc<Mutex<ProgressTrackerInner>>,
}

impl ProgressTracker {
    pub fn new(progress_bar: indicatif::ProgressBar) -> ProgressTracker {
        let hidden = progress_bar.is_hidden();
        ProgressTracker {
            progress_bar,
            hidden,
            inner: Arc::new(Mutex::new(ProgressTrackerInner {
                checkpoint_in_progress: false,
                in_progress: BTreeMap::new(),
            })),
        }
    }

    fn path_in_progress(&self, p: &Path) {
        if self.hidden {
            return;
        }

        let p = p.to_path_buf();
        let mut inner = self.inner.lock().unwrap();
        if inner.in_progress.is_empty() && !inner.checkpoint_in_progress {
            self.progress_bar
                .set_message(p.to_string_lossy().to_string());
            inner.in_progress.insert(p, PathDisplayState::Visible);
        } else {
            inner.in_progress.insert(p, PathDisplayState::Pending);
        }
        drop(inner);
    }

    fn path_done(&self, p: &PathBuf) {
        if self.hidden {
            return;
        }

        let mut inner = self.inner.lock().unwrap();
        if let Some(PathDisplayState::Visible) = inner.in_progress.remove(p) {
            if !inner.checkpoint_in_progress {
                let mut iter = inner.in_progress.iter_mut(); // XXX .first_entry() in unstable rust would be better.
                if let Some((next_p, state)) = iter.next() {
                    *state = PathDisplayState::Visible;
                    self.progress_bar
                        .set_message(next_p.to_string_lossy().to_string());
                }
            }
        };
        drop(inner);
    }

    fn inc(&self, v: u64) {
        if self.hidden {
            return;
        }
        self.progress_bar.inc(v);
    }

    fn checkpoint_in_progress(&self) {
        if self.hidden {
            return;
        }
        let mut inner = self.inner.lock().unwrap();
        if !inner.checkpoint_in_progress {
            // Mark all paths as pending display, possibly
            // inefficient, but checkpoints do not happen frequently.
            // it probably costs less than copying the currently displayed path.
            for (_, v) in inner.in_progress.iter_mut() {
                *v = PathDisplayState::Pending;
            }
            self.progress_bar.set_message("checkpointing progress...");
            inner.checkpoint_in_progress = true;
        }
        drop(inner);
    }

    fn checkpoint_done(&self) {
        if self.hidden {
            return;
        }
        let mut inner = self.inner.lock().unwrap();
        if inner.checkpoint_in_progress {
            // Choose a path to display from those currently in progress.
            let mut iter = inner.in_progress.iter_mut(); // XXX .first_entry() in unstable rust would be better.
            if let Some((next_p, state)) = iter.next() {
                *state = PathDisplayState::Visible;
                self.progress_bar
                    .set_message(next_p.to_string_lossy().to_string());
            }
            inner.checkpoint_in_progress = false;
        }
        drop(inner);
    }
}

struct EntBatcher {
    indexer: indexer::FsIndexer,
    buffered: Option<(PathBuf, index::IndexEntry)>,
}

impl EntBatcher {
    pub fn new(indexer: indexer::FsIndexer) -> EntBatcher {
        EntBatcher {
            indexer,
            buffered: None,
        }
    }

    fn buffered_next(&mut self) -> Option<Result<(PathBuf, index::IndexEntry), anyhow::Error>> {
        match self.buffered.take() {
            Some(v) => Some(Ok(v)),
            None => self.indexer.next(),
        }
    }
}

impl Iterator for EntBatcher {
    type Item = Result<Vec<(PathBuf, index::IndexEntry)>, anyhow::Error>;

    fn next(&mut self) -> Option<Result<Vec<(PathBuf, index::IndexEntry)>, anyhow::Error>> {
        const MAX_BATCH_BYTES: u64 = 1024 * 1024 * 128;
        const MAX_BATCH_ENTRIES: usize = 128;

        let empty_path = PathBuf::from("");
        let mut current_dir = PathBuf::new();
        let mut batch_bytes: u64 = 0;
        let mut batch = Vec::with_capacity(512);

        loop {
            if batch_bytes >= MAX_BATCH_BYTES || batch.len() >= MAX_BATCH_ENTRIES {
                break;
            }

            match self.buffered_next() {
                Some(Ok((abs_path, ent))) => {
                    let entry_dir = match abs_path.parent() {
                        Some(entry_dir) => entry_dir,
                        None => &empty_path,
                    };

                    if batch.is_empty() {
                        current_dir = entry_dir.to_path_buf();
                    }

                    if entry_dir != current_dir {
                        self.buffered = Some((abs_path, ent));
                        break;
                    }

                    batch_bytes += ent.size.0;
                    batch.push((abs_path, ent));
                }
                Some(Err(err)) => return Some(Err(err)),
                None => break,
            }
        }

        if batch.is_empty() {
            None
        } else {
            Some(Ok(batch))
        }
    }
}

pub struct ChunkIter<'a> {
    data: &'a mut dyn Read,
    chunker: chunker::RollsumChunker,
    buffer: Vec<u8>,
    n_chunked: usize,
    n_read: usize,
    done: bool,
}

impl<'a> ChunkIter<'a> {
    pub fn new(chunker: chunker::RollsumChunker, data: &'a mut dyn Read) -> ChunkIter<'a> {
        ChunkIter {
            data,
            chunker,
            buffer: vec![0; 512 * 1024 * 1024],
            n_chunked: 0,
            n_read: 0,
            done: false,
        }
    }
}

impl<'a> Iterator for ChunkIter<'a> {
    type Item = Result<Vec<u8>, anyhow::Error>;

    fn next(&mut self) -> Option<Result<Vec<u8>, anyhow::Error>> {
        if self.done {
            return None;
        }

        loop {
            if self.n_chunked == self.n_read {
                self.n_chunked = 0;
                self.n_read = 0;
                // XXX If we could read directly into the chunkers
                // buffer we could eliminate the copy from this buffer.
                self.n_read = match self.data.read(&mut self.buffer) {
                    Ok(n) => n,
                    Err(err) => return Some(Err(err.into())),
                }
            }

            if self.n_read == 0 {
                self.done = true;
                let last = self.chunker.take_buffered();
                if !last.is_empty() {
                    return Some(Ok(last));
                }
                return None;
            }

            let (n, maybe_chunk) = self
                .chunker
                .add_bytes(&self.buffer[self.n_chunked..self.n_read]);

            self.n_chunked += n;

            if let Some(chunk) = maybe_chunk {
                return Some(Ok(chunk));
            }
        }
    }
}

struct ServerConn<'a> {
    r: &'a mut (dyn Read + Send),
    w: &'a mut (dyn Write + Send),

    transferred_chunks: u64,
    transferred_bytes: u64,

    added_chunks: u64,
    added_bytes: u64,

    next_checkpoint: std::time::Instant,
}

impl<'a> ServerConn<'a> {
    fn write_chunk(
        &mut self,
        addr: &Address,
        data: std::vec::Vec<u8>,
    ) -> Result<(), anyhow::Error> {
        self.transferred_bytes += data.len() as u64;
        self.transferred_chunks += 1;
        protocol::write_chunk(self.w, addr, &data)?;
        Ok(())
    }

    fn flush(&mut self) -> Result<(), anyhow::Error> {
        protocol::write_packet(self.w, &protocol::Packet::TFlush)?;
        match protocol::read_packet(self.r, protocol::DEFAULT_MAX_PACKET_SIZE)? {
            protocol::Packet::RFlush(stats) => {
                self.added_bytes += stats.added_bytes;
                self.added_chunks += stats.added_chunks;
            }
            _ => anyhow::bail!("protocol error, expected RFlush packet"),
        }
        Ok(())
    }
}

struct Sender<'a, 'b> {
    progress: ProgressTracker,
    acache: Mutex<acache::ACache>,
    conn: Mutex<ServerConn<'a>>,
    send_log_session: Option<Arc<Mutex<sendlog::SendLogSession<'b>>>>,
    checkpoint_seconds: u64,
}

impl<'a, 'b> Sender<'a, 'b> {
    fn write_chunk(&self, addr: &Address, data: std::vec::Vec<u8>) -> Result<(), anyhow::Error> {
        {
            let mut acache = self.acache.lock().unwrap();
            if !acache.add(addr) {
                return Ok(());
            }
        }

        match &self.send_log_session {
            Some(session) => {
                {
                    let session = session.lock().unwrap();
                    if session.add_address_if_cached(addr)? {
                        // The address was already cached and so
                        // has already been flushed, nothing more to do.
                        return Ok(());
                    }
                }

                {
                    let mut conn = self.conn.lock().unwrap();

                    conn.write_chunk(addr, data)?;

                    if (conn.transferred_chunks % 64 == 0)
                        && std::time::Instant::now() > conn.next_checkpoint
                    {
                        let mut session = session.lock().unwrap();
                        self.progress.checkpoint_in_progress();
                        // Flush all data chunks that have already been written to the wire.
                        conn.flush()?;
                        // Once flushed, it is ok to flush to the send log.
                        session.checkpoint()?;
                        self.progress.checkpoint_done();
                        conn.next_checkpoint = std::time::Instant::now()
                            + std::time::Duration::from_secs(self.checkpoint_seconds);
                        drop(session);
                    }
                }

                {
                    // Ensure we add the address to the sendlog AFTER it has
                    // been written to the connection so checkpoints
                    // won't incorrectly mark a chunk as sent when it
                    // hasnt been confirmed by a corresponding flush.
                    let session = session.lock().unwrap();
                    session.add_address(addr)?;
                }
            }
            None => {
                let mut conn = self.conn.lock().unwrap();
                conn.write_chunk(addr, data)?;
                drop(conn);
            }
        }

        Ok(())
    }
}

impl<'a, 'b> htree::Sink for Sender<'a, 'b> {
    fn add_htree_chunk(
        &mut self,
        addr: &Address,
        data: std::vec::Vec<u8>,
    ) -> Result<(), anyhow::Error> {
        self.write_chunk(addr, data)
    }
}

impl<'a, 'b> htree::Sink for Arc<Sender<'a, 'b>> {
    fn add_htree_chunk(
        &mut self,
        addr: &Address,
        data: std::vec::Vec<u8>,
    ) -> Result<(), anyhow::Error> {
        self.write_chunk(addr, data)
    }
}

#[derive(Clone)]
pub struct PutContext<'a> {
    pub progress: ProgressTracker,
    pub compression: compression::Scheme,
    pub data_hash_key: crypto::HashKey,
    pub data_ectx: crypto::EncryptionContext,
    pub idx_hash_key: crypto::HashKey,
    pub idx_ectx: crypto::EncryptionContext,
    pub gear_tab: rollsum::GearTab,
    pub checkpoint_seconds: u64,
    pub want_xattrs: bool,
    pub use_stat_cache: bool,
    pub one_file_system: bool,
    pub ignore_permission_errors: bool,
    pub send_log_session: Option<Arc<Mutex<sendlog::SendLogSession<'a>>>>,
    pub file_action_log_fn: Option<Arc<index::FileActionLogFn>>,
    pub indexer_threads: usize,
    pub threads: usize,
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

pub const CHUNK_MIN_SIZE: usize = 256 * 1024;
pub const CHUNK_MAX_SIZE: usize = 20 * 1024 * 1024;
const ACACHE_SIZE: usize = 32768;

pub fn put_data(
    mut ctx: PutContext,
    r: &mut (dyn Read + Send),
    w: &mut (dyn Write + Send),
    data: &mut dyn Read,
) -> Result<(oplog::HTreeMetadata, SendStats), anyhow::Error> {
    let start_time = chrono::Utc::now();
    let mut data_htree = htree::TreeWriter::new(CHUNK_MIN_SIZE, CHUNK_MAX_SIZE);
    let data_chunker =
        chunker::RollsumChunker::new(ctx.gear_tab.clone(), CHUNK_MIN_SIZE, CHUNK_MAX_SIZE);

    let mut sender = Sender {
        acache: Mutex::new(acache::ACache::new(ACACHE_SIZE)),
        conn: Mutex::new(ServerConn {
            r,
            w,
            transferred_chunks: 0,
            transferred_bytes: 0,
            added_chunks: 0,
            added_bytes: 0,
            next_checkpoint: std::time::Instant::now()
                + std::time::Duration::from_secs(ctx.checkpoint_seconds),
        }),
        progress: ctx.progress.clone(),
        checkpoint_seconds: ctx.checkpoint_seconds,
        send_log_session: ctx.send_log_session.clone(),
    };

    let chunks = ChunkIter::new(data_chunker, data);

    let data_hash_key = ctx.data_hash_key.clone();
    let compression = ctx.compression;
    let mut data_ectx = ctx.data_ectx.clone();

    let pipeline_threads = ctx.threads;
    let addressing_pipeline_len = pipeline_threads / 3;
    let mut compressing_pipeline_len = pipeline_threads / 3;
    let mut encrypting_pipeline_len = pipeline_threads / 3;

    match pipeline_threads % 3 {
        1 => {
            compressing_pipeline_len += 1;
        }
        2 => {
            compressing_pipeline_len += 1;
            encrypting_pipeline_len += 1;
        }
        _ => (),
    };

    let addressed_chunks = chunks.plmap(
        addressing_pipeline_len,
        move |chunk: Result<Vec<u8>, anyhow::Error>| {
            let chunk = chunk?;
            let address = crypto::keyed_content_address(&chunk, &data_hash_key);
            Ok::<_, anyhow::Error>((address, chunk))
        },
    );

    let mut uncompressed_data_size: u64 = 0;

    let addressed_and_compressed_chunks = addressed_chunks.plmap(
        compressing_pipeline_len,
        move |chunk: Result<(Address, Vec<u8>), anyhow::Error>| {
            let (address, chunk) = chunk?;
            let chunk_len = chunk.len();
            let chunk = compression::compress(compression, chunk);
            Ok::<_, anyhow::Error>((address, chunk_len as u64, chunk))
        },
    );

    let addressed_and_encrypted_chunks = addressed_and_compressed_chunks.plmap(
        encrypting_pipeline_len,
        move |chunk: Result<(Address, u64, Vec<u8>), anyhow::Error>| {
            let (address, chunk_len, chunk) = chunk?;
            let chunk = data_ectx.encrypt_data(chunk);
            Ok::<_, anyhow::Error>((address, chunk_len, chunk))
        },
    );

    for chunk in addressed_and_encrypted_chunks {
        let (address, chunk_len, chunk) = chunk?;
        sender.write_chunk(&address, chunk)?;
        data_htree.add_data_addr(&mut sender, &address)?;
        uncompressed_data_size += chunk_len;
        ctx.progress.inc(chunk_len);
    }

    // We always need at least one chunk, so fill in the empty chunk.
    if uncompressed_data_size == 0 {
        let chunk = Vec::new();
        let address = crypto::keyed_content_address(&chunk, &ctx.data_hash_key);
        let chunk = compression::compress(ctx.compression, chunk);
        let chunk = ctx.data_ectx.encrypt_data(chunk);
        sender.write_chunk(&address, chunk)?;
        data_htree.add_data_addr(&mut sender, &address)?;
    }

    let data_tree_meta = data_htree.finish(&mut sender)?;

    let mut conn = sender.conn.lock().unwrap();
    conn.flush()?;

    Ok((
        oplog::HTreeMetadata {
            height: serde_bare::Uint(data_tree_meta.height as u64),
            data_chunk_count: serde_bare::Uint(data_tree_meta.data_chunk_count),
            address: data_tree_meta.address,
        },
        SendStats {
            start_time,
            end_time: chrono::Utc::now(),
            uncompressed_data_size,
            uncompressed_index_size: 0,
            total_chunks: data_tree_meta.total_chunk_count,
            transferred_bytes: conn.transferred_bytes,
            transferred_chunks: conn.transferred_chunks,
            added_bytes: conn.added_bytes,
            added_chunks: conn.added_chunks,
        },
    ))
}

#[derive(Clone)]
struct BatchFileProcessor<'a, 'b> {
    ctx: PutContext<'b>,
    sender: Arc<Sender<'a, 'b>>,
    data_chunker: chunker::RollsumChunker,
    scratch_buf: Vec<u8>,
}

impl<'a, 'b> plmap::Mapper<Result<Vec<(PathBuf, index::IndexEntry)>, anyhow::Error>>
    for BatchFileProcessor<'a, 'b>
{
    type Out = Result<(Vec<(PathBuf, index::IndexEntry)>, Vec<Address>), anyhow::Error>;
    fn apply(
        &mut self,
        file_batch: Result<Vec<(PathBuf, index::IndexEntry)>, anyhow::Error>,
    ) -> Self::Out {
        self.process_batch(file_batch.context("received `Err` batch for processing")?)
            .context("failed to process a batch")
    }
}

impl<'a, 'b> BatchFileProcessor<'a, 'b> {
    fn log_file_action(
        &mut self,
        action_char: char,
        kind_char: char,
        p: &Path,
    ) -> Result<(), anyhow::Error> {
        if let Some(ref file_action_log_fn) = self.ctx.file_action_log_fn {
            file_action_log_fn(action_char, kind_char, p)?;
        }
        Ok(())
    }

    fn chunk_and_hash_file_data(
        &mut self,
        f: std::fs::File,
        data_addresses: &mut Vec<Address>,
        ent: &mut index::IndexEntry,
    ) -> Result<(), anyhow::Error> {
        let mut f = ioutil::TeeReader::new(f, blake3::Hasher::new());
        let mut file_len = 0;

        loop {
            match f.read(&mut self.scratch_buf) {
                Ok(0) => break,
                Ok(n_read) => {
                    file_len += n_read as u64;
                    let mut to_chunk = &self.scratch_buf[..n_read];
                    while !to_chunk.is_empty() {
                        let (n_chunked, maybe_chunk) = self.data_chunker.add_bytes(to_chunk);
                        to_chunk = &to_chunk[n_chunked..];
                        if let Some(chunk) = maybe_chunk {
                            let chunk_len = chunk.len() as u64;
                            let address =
                                crypto::keyed_content_address(&chunk, &self.ctx.data_hash_key);
                            let chunk = compression::compress(self.ctx.compression, chunk);
                            let chunk = self.ctx.data_ectx.encrypt_data(chunk);
                            self.sender.write_chunk(&address, chunk)?;
                            data_addresses.push(address);
                            self.ctx.progress.inc(chunk_len);
                        }
                    }
                }
                Err(err) => return Err(err.into()),
            }
        }

        // The size might have changed since the first stat.
        ent.size.0 = file_len;

        let (_, file_hasher) = f.into_inner();
        ent.data_hash = index::ContentCryptoHash::Blake3(file_hasher.finalize().into());
        Ok(())
    }

    #[allow(clippy::type_complexity)]
    fn process_batch(
        &mut self,
        mut file_batch: Vec<(PathBuf, index::IndexEntry)>,
    ) -> Result<(Vec<(PathBuf, index::IndexEntry)>, Vec<Address>), anyhow::Error> {
        let mut stat_cache_key = None;

        let cache_lookup = if self.ctx.use_stat_cache && self.ctx.send_log_session.is_some() {
            let mut hash_state = crypto::HashState::new(Some(&self.ctx.idx_hash_key));
            let mut hash_buf = Vec::with_capacity(1024);
            for (path, ent) in file_batch.iter() {
                hash_buf.truncate(0);
                hash_buf.write_all(path.as_os_str().as_bytes()).unwrap();
                serde_bare::to_writer(&mut hash_buf, ent).unwrap();
                hash_state.update(&hash_buf);
            }
            stat_cache_key = Some(hash_state.finish());
            self.ctx
                .send_log_session
                .as_ref()
                .unwrap()
                .lock()
                .unwrap()
                .stat_cache_lookup_and_update(&stat_cache_key.unwrap())
                .context("failed to update stat cache")?
        } else {
            None
        };

        let data_addresses = match cache_lookup {
            Some(cache_entry) => {
                let mut uncompressed_data_size = 0;
                for (i, (ref path, ref mut ent)) in file_batch.iter_mut().enumerate() {
                    uncompressed_data_size += ent.size.0;
                    self.log_file_action('~', ent.type_display_char(), path)
                        .with_context(|| {
                            format!("failed to log file action for {}", path.display())
                        })?;
                    ent.data_hash = cache_entry.hashes[i];
                    ent.data_cursor = cache_entry.data_cursors[i];
                }
                self.ctx.progress.inc(uncompressed_data_size);
                cache_entry.addresses.into_owned()
            }
            None => {
                let mut file_opener = fprefetch::ReadaheadFileOpener::new();
                let mut bad_cache_ent = false;

                let mut data_cursors: Vec<index::RelativeDataCursor> =
                    Vec::with_capacity(file_batch.len());
                let mut content_hashes: Vec<index::ContentCryptoHash> =
                    Vec::with_capacity(file_batch.len());
                let mut data_addresses = Vec::with_capacity(file_batch.len());

                // Setup the file readahead immediately.
                for (path, _) in file_batch.iter().filter(|x| x.1.is_file()) {
                    file_opener.add_to_queue(path.to_path_buf());
                }

                let file_batch_len = file_batch.len();

                for (i, (ref path, ref mut ent)) in file_batch.iter_mut().enumerate() {
                    self.log_file_action('+', ent.type_display_char(), path)
                        .context("failed to log file action")?;

                    let ent_data_chunk_start_idx = data_addresses.len() as u64;
                    let ent_start_byte_offset = self.data_chunker.buffered_count() as u64;

                    if ent.is_file() {
                        match file_opener.next_file().unwrap() {
                            (ent_path, Ok(f)) => {
                                let stat_size = ent.size.0;
                                self.chunk_and_hash_file_data(f, &mut data_addresses, ent)
                                    .with_context(|| {
                                        format!(
                                            "failed to process file data of {}",
                                            ent_path.display()
                                        )
                                    })?;
                                if stat_size != ent.size.0 {
                                    // The files size changed, don't cache
                                    // this result in the stat cache.
                                    bad_cache_ent = true;
                                }
                            }
                            (_, Err(err))
                                if fsutil::likely_smear_error(&err)
                                    || (self.ctx.ignore_permission_errors
                                        && err.kind() == std::io::ErrorKind::PermissionDenied) =>
                            {
                                // This can happen if the file was deleted,
                                // the filesystem was unmounted during upload,
                                // or the file permissions were changed changed.
                                // We simply skip this entry and don't cache the result.
                                bad_cache_ent = true;
                                // It is simpler to keep the file but assume it has zero size
                                // rather than attempt to repair the previous chunk offsets.
                                ent.size.0 = 0;
                            }
                            (ent_path, Err(err)) => {
                                anyhow::bail!("unable to read {}: {}", ent_path.display(), err)
                            }
                        };
                    }

                    if i == file_batch_len - 1 {
                        // Force a new chunk for the final entry so we can
                        // cache batches as a single block.
                        if let Some(chunk) = self.data_chunker.force_split() {
                            let chunk_len = chunk.len() as u64;
                            let address =
                                crypto::keyed_content_address(&chunk, &self.ctx.data_hash_key);
                            let chunk = compression::compress(self.ctx.compression, chunk);
                            let chunk = self.ctx.data_ectx.encrypt_data(chunk);
                            self.sender
                                .write_chunk(&address, chunk)
                                .context("failed to write chunk")?;
                            data_addresses.push(address);
                            self.ctx.progress.inc(chunk_len);
                        }
                    }

                    let ent_data_chunk_end_idx = data_addresses.len() as u64;
                    let ent_end_byte_offset = self.data_chunker.buffered_count() as u64;

                    ent.data_cursor = index::RelativeDataCursor {
                        chunk_delta: serde_bare::Uint(
                            ent_data_chunk_end_idx - ent_data_chunk_start_idx,
                        ),
                        start_byte_offset: serde_bare::Uint(ent_start_byte_offset),
                        end_byte_offset: serde_bare::Uint(ent_end_byte_offset),
                    };

                    data_cursors.push(ent.data_cursor);
                    content_hashes.push(ent.data_hash);
                }

                if self.ctx.send_log_session.is_some() && self.ctx.use_stat_cache && !bad_cache_ent
                {
                    // It is important to note that every chunk in the stat cache entry
                    // has already been written to the wire, these chunks will be flushed
                    // before any checkpoint that commits this cache entry.
                    self.ctx
                        .send_log_session
                        .as_ref()
                        .unwrap()
                        .lock()
                        .unwrap()
                        .add_stat_cache_data(
                            &stat_cache_key.unwrap()[..],
                            &sendlog::StatCacheEntry {
                                addresses: Cow::Borrowed(&data_addresses),
                                data_cursors: Cow::Borrowed(&data_cursors),
                                hashes: Cow::Borrowed(&content_hashes),
                            },
                        )
                        .context("failed to add stat cache data")?;
                }

                data_addresses
            }
        };

        Ok((file_batch, data_addresses))
    }
}

pub fn put_files(
    mut ctx: PutContext,
    r: &mut (dyn Read + Send),
    w: &mut (dyn Write + Send),
    files: indexer::FsIndexer,
) -> Result<(oplog::HTreeMetadata, oplog::HTreeMetadata, SendStats), anyhow::Error> {
    let start_time = chrono::Utc::now();
    let mut data_htree = htree::TreeWriter::new(CHUNK_MIN_SIZE, CHUNK_MAX_SIZE);

    let mut index_htree = htree::TreeWriter::new(CHUNK_MIN_SIZE, CHUNK_MAX_SIZE);
    let mut index_chunker =
        chunker::RollsumChunker::new(ctx.gear_tab.clone(), CHUNK_MIN_SIZE, CHUNK_MAX_SIZE);
    // The index is highly compressible, there is no reason to ever avoid compressing it.
    let index_compression_scheme = compression::Scheme::Zstd { level: 3 };

    let mut sender = Arc::new(Sender {
        acache: Mutex::new(acache::ACache::new(ACACHE_SIZE)),
        conn: Mutex::new(ServerConn {
            r,
            w,
            transferred_chunks: 0,
            transferred_bytes: 0,
            added_chunks: 0,
            added_bytes: 0,
            next_checkpoint: std::time::Instant::now()
                + std::time::Duration::from_secs(ctx.checkpoint_seconds),
        }),
        progress: ctx.progress.clone(),
        send_log_session: ctx.send_log_session.clone(),
        checkpoint_seconds: ctx.checkpoint_seconds,
    });

    let mut uncompressed_data_size = 0;
    let mut uncompressed_index_size = 0;

    let batch_processor = BatchFileProcessor {
        ctx: ctx.clone(),
        sender: sender.clone(),
        data_chunker: chunker::RollsumChunker::new(
            ctx.gear_tab.clone(),
            CHUNK_MIN_SIZE,
            CHUNK_MAX_SIZE,
        ),
        scratch_buf: vec![0; 256 * 1024],
    };

    let batch_progress = ctx.progress.clone();

    let file_batches = EntBatcher::new(files).map(move |file_batch| {
        if let Ok(file_batch) = &file_batch {
            if let Some(first) = file_batch.first() {
                batch_progress.path_in_progress(&first.0);
            }
        }
        file_batch
    });

    crossbeam_utils::thread::scope(|ts| -> Result<(), anyhow::Error> {
        for processed_file_batch in file_batches.scoped_plmap(ts, ctx.threads, batch_processor) {
            let (mut file_batch, data_addresses) = processed_file_batch?;

            if let Some((p, _)) = file_batch.first() {
                ctx.progress.path_done(p);
            }

            for addr in data_addresses.iter() {
                data_htree.add_data_addr(&mut sender, addr)?;
            }

            let mut ent_buf = Vec::with_capacity(file_batch.len() * 64);
            for (_, ent) in file_batch.drain(..) {
                uncompressed_data_size += ent.size.0;
                serde_bare::to_writer(&mut ent_buf, &index::VersionedIndexEntry::V5(ent))?;
            }
            uncompressed_index_size += ent_buf.len() as u64;

            let mut to_chunk = &ent_buf[..];
            while !to_chunk.is_empty() {
                let (n, maybe_chunk) = index_chunker.add_bytes(to_chunk);
                to_chunk = &to_chunk[n..];
                if let Some(chunk) = maybe_chunk {
                    let chunk_len = chunk.len() as u64;
                    let address = crypto::keyed_content_address(&chunk, &ctx.idx_hash_key);
                    let chunk = compression::compress(index_compression_scheme, chunk);
                    let chunk = ctx.idx_ectx.encrypt_data(chunk);
                    sender.write_chunk(&address, chunk)?;
                    index_htree.add_data_addr(&mut sender, &address)?;
                    ctx.progress.inc(chunk_len);
                }
            }
        }

        Ok(())
    })
    .expect("unable to create thread scope")?;

    // We always need at least one chunk, so fill in the empty chunk.
    if uncompressed_data_size == 0 {
        let chunk = Vec::new();
        let address = crypto::keyed_content_address(&chunk, &ctx.data_hash_key);
        let chunk = compression::compress(ctx.compression, chunk);
        let chunk = ctx.data_ectx.encrypt_data(chunk);
        sender.write_chunk(&address, chunk)?;
        data_htree.add_data_addr(&mut sender, &address)?;
    }
    let data_tree_meta = data_htree.finish(&mut sender)?;

    {
        let chunk = index_chunker.finish();
        if uncompressed_index_size == 0 || !chunk.is_empty() {
            let address = crypto::keyed_content_address(&chunk, &ctx.idx_hash_key);
            let chunk = compression::compress(index_compression_scheme, chunk);
            let chunk = ctx.idx_ectx.encrypt_data(chunk);
            sender.write_chunk(&address, chunk)?;
            index_htree.add_data_addr(&mut sender, &address)?;
        }
    }
    let index_tree_meta = index_htree.finish(&mut sender)?;

    if index_tree_meta.data_chunk_count == 0 {
        // This could in theory happen when the base dir is temporarily inaccessible.
        anyhow::bail!("refusing to create an empty snapshot");
    }

    let mut conn = sender.conn.lock().unwrap();
    conn.flush()?;

    Ok((
        oplog::HTreeMetadata {
            height: serde_bare::Uint(data_tree_meta.height as u64),
            data_chunk_count: serde_bare::Uint(data_tree_meta.data_chunk_count),
            address: data_tree_meta.address,
        },
        oplog::HTreeMetadata {
            height: serde_bare::Uint(index_tree_meta.height as u64),
            data_chunk_count: serde_bare::Uint(index_tree_meta.data_chunk_count),
            address: index_tree_meta.address,
        },
        SendStats {
            start_time,
            end_time: chrono::Utc::now(),
            uncompressed_data_size,
            uncompressed_index_size,
            total_chunks: data_tree_meta.total_chunk_count + index_tree_meta.total_chunk_count,
            transferred_bytes: conn.transferred_bytes,
            transferred_chunks: conn.transferred_chunks,
            added_bytes: conn.added_bytes,
            added_chunks: conn.added_chunks,
        },
    ))
}
