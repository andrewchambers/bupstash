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
use super::indexer2;
use super::ioutil;
use super::oplog;
use super::protocol;
use super::rollsum;
use super::sendlog;
use super::xid::Xid;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::{Arc, Mutex};

pub struct EntBatcher {
    indexer: indexer2::FsIndexer,
    buffered: Option<(PathBuf, index::IndexEntry)>,
}

impl EntBatcher {
    pub fn new(indexer: indexer2::FsIndexer) -> EntBatcher {
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
        const MAX_BATCH_BYTES: u64 = 1024 * 1024 * 1024 * 32;
        const MAX_BATCH_ENTRIES: usize = 10000;

        let mut batch_slashes: usize = 0;
        let mut batch_bytes: u64 = 0;
        let mut batch = Vec::with_capacity(512);

        loop {
            if batch_bytes >= MAX_BATCH_BYTES || batch.len() >= MAX_BATCH_ENTRIES {
                break;
            }

            match self.buffered_next() {
                Some(Ok((abs_path, ent))) => {
                    let n_slashes = abs_path
                        .as_os_str()
                        .as_bytes()
                        .iter()
                        .filter(|b| **b == b'/')
                        .count();
                    if batch_slashes == 0 {
                        batch_slashes = n_slashes
                    } else {
                        if n_slashes != batch_slashes {
                            self.buffered = Some((abs_path, ent));
                            break;
                        }
                    };
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
    fn new(chunker: chunker::RollsumChunker, data: &'a mut dyn Read) -> ChunkIter<'a> {
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

struct ServerConn<'a, 'b> {
    r: &'a mut dyn Read,
    w: &'a mut dyn Write,

    transferred_chunks: u64,
    transferred_bytes: u64,

    added_chunks: u64,
    added_bytes: u64,

    next_checkpoint: std::time::Instant,
    checkpoint_seconds: u64,
    send_log_session: Option<Arc<Mutex<sendlog::SendLogSession<'b>>>>,
}

impl<'a, 'b> ServerConn<'a, 'b> {
    fn write_chunk(
        &mut self,
        addr: &Address,
        data: std::vec::Vec<u8>,
    ) -> Result<(), anyhow::Error> {
        self.transferred_bytes += data.len() as u64;
        self.transferred_chunks += 1;

        protocol::write_chunk(self.w, addr, &data)?;

        if self.send_log_session.is_some()
            && (self.transferred_chunks % 16 == 0)
            && std::time::Instant::now() > self.next_checkpoint
        {
            self.checkpoint()?;
        }

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

    fn checkpoint(&mut self) -> Result<(), anyhow::Error> {
        self.flush()?;
        match &self.send_log_session {
            Some(send_log_session) => {
                let mut send_log_session = send_log_session.lock().unwrap();
                send_log_session.checkpoint()?
            }
            None => (),
        }
        self.next_checkpoint =
            std::time::Instant::now() + std::time::Duration::from_secs(self.checkpoint_seconds);
        Ok(())
    }
}

struct Sender<'a, 'b> {
    acache: Mutex<acache::ACache>,
    conn: Mutex<ServerConn<'a, 'b>>,
    send_log_session: Option<Arc<Mutex<sendlog::SendLogSession<'b>>>>,
}

impl<'a, 'b> Sender<'a, 'b> {
    fn write_chunk(&self, addr: &Address, data: std::vec::Vec<u8>) -> Result<(), anyhow::Error> {
        let mut acache = self.acache.lock().unwrap();
        if !acache.add(addr) {
            return Ok(());
        }
        drop(acache);

        match &self.send_log_session {
            Some(session) => {
                let session = session.lock().unwrap();
                if !session.add_address(addr)? {
                    return Ok(());
                }
                drop(session)
            }
            None => (),
        }

        let mut conn = self.conn.lock().unwrap();
        conn.write_chunk(addr, data)?;
        drop(conn);

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

pub type FileActionLogFn = dyn Fn(&str) -> Result<(), anyhow::Error>;

#[derive(Clone)]
pub struct SendContext<'a> {
    pub progress: indicatif::ProgressBar,
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
    pub file_action_log_fn: Option<Rc<FileActionLogFn>>,
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
pub const CHUNK_MAX_SIZE: usize = 8 * 1024 * 1024;
const ACACHE_SIZE: usize = 32768;

pub fn send_data(
    mut ctx: SendContext,
    r: &mut dyn Read,
    w: &mut dyn Write,
    data: &mut dyn Read,
) -> Result<(oplog::HTreeMetadata, SendStats), anyhow::Error> {
    let start_time = chrono::Utc::now();
    let mut data_htree = htree::TreeWriter::new(CHUNK_MIN_SIZE, CHUNK_MAX_SIZE);
    let chunker = chunker::RollsumChunker::new(ctx.gear_tab, CHUNK_MIN_SIZE, CHUNK_MAX_SIZE);

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
            checkpoint_seconds: ctx.checkpoint_seconds,
            send_log_session: None,
        }),
        send_log_session: ctx.send_log_session.clone(),
    };

    let mut uncompressed_data_size = 0;

    for chunk in ChunkIter::new(chunker, data) {
        let chunk = chunk?;
        let data_len = chunk.len() as u64;
        uncompressed_data_size += data_len;
        let address = crypto::keyed_content_address(&chunk, &ctx.data_hash_key);
        let chunk = compression::compress(ctx.compression, chunk);
        let chunk = ctx.data_ectx.encrypt_data2(chunk);
        sender.write_chunk(&address, chunk)?;
        data_htree.add_data_addr(&mut sender, &address)?;
        ctx.progress.inc(data_len);
    }

    // We always need at least one chunk, so fill in the empty chunk.
    if uncompressed_data_size == 0 {
        let chunk = Vec::new();
        let address = crypto::keyed_content_address(&chunk, &ctx.data_hash_key);
        let chunk = compression::compress(ctx.compression, chunk);
        let chunk = ctx.data_ectx.encrypt_data2(chunk);
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

pub fn send_files(
    mut ctx: SendContext,
    r: &mut dyn Read,
    w: &mut dyn Write,
    files: indexer2::FsIndexer,
) -> Result<(oplog::HTreeMetadata, oplog::HTreeMetadata, SendStats), anyhow::Error> {
    let start_time = chrono::Utc::now();
    let mut data_htree = htree::TreeWriter::new(CHUNK_MIN_SIZE, CHUNK_MAX_SIZE);
    let mut index_htree = htree::TreeWriter::new(CHUNK_MIN_SIZE, CHUNK_MAX_SIZE);
    let mut index_chunker =
        chunker::RollsumChunker::new(ctx.gear_tab, CHUNK_MIN_SIZE, CHUNK_MAX_SIZE);
    let mut data_chunker =
        chunker::RollsumChunker::new(ctx.gear_tab, CHUNK_MIN_SIZE, CHUNK_MAX_SIZE);

    let mut file_data_buf = vec![0; 512 * 1024 * 1024];

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
            checkpoint_seconds: ctx.checkpoint_seconds,
            send_log_session: None,
        }),
        send_log_session: ctx.send_log_session.clone(),
    };

    let mut uncompressed_data_size = 0;
    let mut uncompressed_index_size = 0;

    for file_batch in EntBatcher::new(files) {
        let mut file_batch = file_batch?;

        ctx.progress
            .set_message(file_batch.first().unwrap().0.to_string_lossy().to_string());

        let mut stat_cache_key = None;

        let cache_lookup = if ctx.use_stat_cache && ctx.send_log_session.is_some() {
            let mut hash_state = crypto::HashState::new(Some(&ctx.idx_hash_key));
            let mut hash_buf = Vec::with_capacity(1024);
            for (path, ent) in file_batch.iter() {
                hash_buf.truncate(0);
                hash_buf.write_all(path.as_os_str().as_bytes()).unwrap();
                serde_bare::to_writer(&mut hash_buf, ent).unwrap();
                hash_state.update(&hash_buf);
            }
            stat_cache_key = Some(hash_state.finish());
            ctx.send_log_session
                .as_ref()
                .unwrap()
                .lock()
                .unwrap()
                .stat_cache_lookup(&stat_cache_key.unwrap())?
        } else {
            None
        };

        let mut data_addresses;

        match cache_lookup {
            Some(cache_entry) => {
                uncompressed_data_size += cache_entry.total_size;
                ctx.progress.inc(cache_entry.total_size);
                for (i, (ref _path, ref mut index_ent)) in file_batch.iter_mut().enumerate() {
                    // XXX
                    // ctx.log_file_action('~', index_ent.type_display_char(), path)?;
                    index_ent.data_hash = cache_entry.hashes[i];
                    index_ent.data_cursor = cache_entry.data_cursors[i];
                }
                data_addresses = cache_entry.addresses;
            }
            None => {
                let mut file_opener = fprefetch::ReadaheadFileOpener::new();
                let mut bad_cache_ent = false;
                let mut dir_data_size: u64 = 0;
                let mut data_chunk_count: u64 = 0;

                let mut data_cursors: Vec<index::RelativeDataCursor> =
                    Vec::with_capacity(file_batch.len());

                let mut content_hashes: Vec<index::ContentCryptoHash> =
                    Vec::with_capacity(file_batch.len());

                data_addresses = Vec::with_capacity(file_batch.len());

                // Setup the file readahead immediately.
                for (path, _) in file_batch.iter().filter(|x| x.1.is_file()) {
                    file_opener.add_to_queue(path.to_path_buf());
                }

                let file_batch_len = file_batch.len();

                'add_dir_ents: for (i, (ref _path, ref mut index_ent)) in
                    file_batch.iter_mut().enumerate()
                {
                    // XXX
                    // self.log_file_action('+', index_ent.type_display_char(), &path)?;

                    let ent_data_chunk_start_idx = data_chunk_count;
                    let ent_start_byte_offset = data_chunker.buffered_count() as u64;

                    if index_ent.is_file() {
                        let mut f = match file_opener.next_file().unwrap() {
                            (_, Ok(f)) => ioutil::TeeReader::new(f, blake3::Hasher::new()),

                            (_, Err(err)) if fsutil::likely_smear_error(&err) => {
                                // This can happen if the file was deleted,
                                // or the filesystem was unmounted during upload.
                                // We simply skip this entry but don't cache the result.
                                bad_cache_ent = true;
                                continue 'add_dir_ents;
                            }

                            (_, Err(err))
                                if ctx.ignore_permission_errors
                                    && err.kind() == std::io::ErrorKind::PermissionDenied =>
                            {
                                bad_cache_ent = true;
                                continue 'add_dir_ents;
                            }

                            (ent_path, Err(err)) => {
                                anyhow::bail!("unable to read {}: {}", ent_path.display(), err)
                            }
                        };

                        let mut file_len = 0;
                        loop {
                            match f.read(&mut file_data_buf) {
                                Ok(0) => break,
                                Ok(n_read) => {
                                    file_len += n_read as u64;
                                    uncompressed_data_size += n_read as u64;
                                    dir_data_size += n_read as u64;
                                    let mut n_chunked = 0;
                                    while n_chunked != n_read {
                                        let (n, maybe_chunk) = data_chunker
                                            .add_bytes(&file_data_buf[n_chunked..n_read]);
                                        n_chunked += n;
                                        if let Some(chunk) = maybe_chunk {
                                            let data_len = chunk.len() as u64;
                                            data_chunk_count += 1;
                                            let address = crypto::keyed_content_address(
                                                &chunk,
                                                &ctx.data_hash_key,
                                            );
                                            let chunk =
                                                compression::compress(ctx.compression, chunk);
                                            let chunk = ctx.data_ectx.encrypt_data2(chunk);
                                            sender.write_chunk(&address, chunk)?;
                                            data_addresses.push(address);
                                            ctx.progress.inc(data_len);
                                        }
                                    }
                                }
                                Err(err) => return Err(err.into()),
                            }
                        }

                        if file_len != index_ent.size.0 {
                            bad_cache_ent = true;
                            // The true size is what we read from disk.
                            index_ent.size.0 = file_len;
                        }

                        let (_, file_hasher) = f.into_inner();

                        index_ent.data_hash =
                            index::ContentCryptoHash::Blake3(file_hasher.finalize().into());
                    }

                    if i == file_batch_len - 1 {
                        // Force a new chunk for the final entry so we can
                        // cache batches as a single block.
                        if let Some(chunk) = data_chunker.force_split() {
                            let data_len = chunk.len() as u64;
                            uncompressed_data_size += data_len;
                            data_chunk_count += 1;
                            let address = crypto::keyed_content_address(&chunk, &ctx.data_hash_key);
                            let chunk = compression::compress(ctx.compression, chunk);
                            let chunk = ctx.data_ectx.encrypt_data2(chunk);
                            sender.write_chunk(&address, chunk)?;
                            data_addresses.push(address);
                            ctx.progress.inc(data_len);
                        }
                    }

                    let ent_data_chunk_end_idx = data_chunk_count;
                    let ent_end_byte_offset = data_chunker.buffered_count() as u64;

                    index_ent.data_cursor = index::RelativeDataCursor {
                        chunk_delta: serde_bare::Uint(
                            ent_data_chunk_end_idx - ent_data_chunk_start_idx,
                        ),
                        start_byte_offset: serde_bare::Uint(ent_start_byte_offset),
                        end_byte_offset: serde_bare::Uint(ent_end_byte_offset),
                    };

                    data_cursors.push(index_ent.data_cursor);
                    content_hashes.push(index_ent.data_hash)
                }

                if ctx.send_log_session.is_some() && ctx.use_stat_cache && !bad_cache_ent {
                    ctx.send_log_session
                        .as_ref()
                        .unwrap()
                        .lock()
                        .unwrap()
                        .add_stat_cache_data(
                            &stat_cache_key.unwrap()[..],
                            &sendlog::StatCacheEntry {
                                addresses: data_addresses.clone(), // TODO XXX don't clone.
                                data_cursors,
                                total_size: dir_data_size,
                                hashes: content_hashes,
                            },
                        )?;
                }
            }
        };

        for addr in data_addresses.iter() {
            data_htree.add_data_addr(&mut sender, addr)?;
        }

        let mut ent_buf = Vec::with_capacity(file_batch.len() * 64);
        for (_, ent) in file_batch.iter() {
            serde_bare::to_writer(&mut ent_buf, &ent)?;
        }
        uncompressed_index_size += ent_buf.len();

        let mut to_chunk = &ent_buf[..];
        while !to_chunk.is_empty() {
            let (n, maybe_chunk) = index_chunker.add_bytes(to_chunk);
            to_chunk = &to_chunk[n..];
            if let Some(chunk) = maybe_chunk {
                let data_len = chunk.len() as u64;
                let address = crypto::keyed_content_address(&chunk, &ctx.idx_hash_key);
                let chunk = compression::compress(ctx.compression, chunk);
                let chunk = ctx.idx_ectx.encrypt_data2(chunk);
                sender.write_chunk(&address, chunk)?;
                index_htree.add_data_addr(&mut sender, &address)?;
                ctx.progress.inc(data_len);
            }
        }
    }

    // We always need at least one chunk, so fill in the empty chunk.
    if uncompressed_data_size == 0 {
        let chunk = Vec::new();
        let address = crypto::keyed_content_address(&chunk, &ctx.data_hash_key);
        let chunk = compression::compress(ctx.compression, chunk);
        let chunk = ctx.data_ectx.encrypt_data2(chunk);
        sender.write_chunk(&address, chunk)?;
        data_htree.add_data_addr(&mut sender, &address)?;
    }
    let data_tree_meta = data_htree.finish(&mut sender)?;

    {
        let chunk = index_chunker.finish();
        uncompressed_index_size += chunk.len() as u64;
        if !chunk.is_empty() || uncompressed_index_size == 0 {
            let address = crypto::keyed_content_address(&chunk, &ctx.idx_hash_key);
            let chunk = compression::compress(ctx.compression, chunk);
            let chunk = ctx.idx_ectx.encrypt_data2(chunk);
            sender.write_chunk(&address, chunk)?;
            index_htree.add_data_addr(&mut sender, &address)?;
        }
    }
    let index_tree_meta = index_htree.finish(&mut sender)?;

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
            total_chunks: data_tree_meta.total_chunk_count,
            transferred_bytes: conn.transferred_bytes,
            transferred_chunks: conn.transferred_chunks,
            added_bytes: conn.added_bytes,
            added_chunks: conn.added_chunks,
        },
    ))
}
