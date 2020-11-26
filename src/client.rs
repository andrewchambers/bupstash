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
use std::collections::BTreeMap;
use std::convert::TryInto;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("corrupt or tampered data")]
    CorruptOrTamperedDataError,
}

pub fn open_repository(
    w: &mut dyn std::io::Write,
    r: &mut dyn std::io::Read,
    lock_hint: LockHint,
) -> Result<(), anyhow::Error> {
    write_packet(
        w,
        &Packet::TOpenRepository(TOpenRepository {
            repository_protocol_version: "4".to_string(),
            lock_hint,
        }),
    )?;

    match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
        Packet::ROpenRepository(resp) => {
            let clock_skew = chrono::Utc::now().signed_duration_since(resp.now);
            const MAX_SKEW_MINS: i64 = 15;
            if clock_skew > chrono::Duration::minutes(MAX_SKEW_MINS)
                || clock_skew < chrono::Duration::minutes(-MAX_SKEW_MINS)
            {
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

struct ConnectionHtreeSink<'a, 'b> {
    checkpoint_bytes: u64,
    dirty_bytes: u64,
    send_log_session: &'a Option<std::cell::RefCell<sendlog::SendLogSession<'b>>>,
    r: &'a mut dyn std::io::Read,
    w: &'a mut dyn std::io::Write,
}

impl<'a, 'b> htree::Sink for ConnectionHtreeSink<'a, 'b> {
    fn add_chunk(
        &mut self,
        addr: &Address,
        data: std::vec::Vec<u8>,
    ) -> std::result::Result<(), anyhow::Error> {
        match self.send_log_session {
            Some(ref send_log_session) => {
                let mut send_log_session = send_log_session.borrow_mut();
                if send_log_session.cached_address(addr)? {
                    send_log_session.add_address(addr)?;
                } else {
                    self.dirty_bytes += data.len() as u64;
                    write_chunk(self.w, addr, &data)?;
                    send_log_session.add_address(addr)?;
                }

                if self.dirty_bytes >= self.checkpoint_bytes {
                    self.dirty_bytes = 0;
                    write_packet(self.w, &Packet::TSendSync)?;
                    match read_packet(self.r, DEFAULT_MAX_PACKET_SIZE)? {
                        Packet::RSendSync => {
                            send_log_session.checkpoint()?;
                        }
                        _ => anyhow::bail!("protocol error, expected RSentSync packet"),
                    }
                }

                Ok(())
            }
            None => {
                write_chunk(self.w, addr, &data)?;
                Ok(())
            }
        }
    }
}

pub struct SendContext {
    pub progress: indicatif::ProgressBar,
    pub compression: compression::Scheme,
    pub use_stat_cache: bool,
    pub primary_key_id: Xid,
    pub send_key_id: Xid,
    pub hash_key: crypto::HashKey,
    pub data_ectx: crypto::EncryptionContext,
    pub metadata_ectx: crypto::EncryptionContext,
    pub checkpoint_bytes: u64,
}

pub enum DataSource {
    Subprocess(Vec<String>),
    Readable {
        description: String,
        data: Box<dyn std::io::Read>,
    },
    Directory {
        path: std::path::PathBuf,
        exclusions: Vec<glob::Pattern>,
    },
}

pub fn send(
    ctx: &mut SendContext,
    r: &mut dyn std::io::Read,
    w: &mut dyn std::io::Write,
    mut send_log: Option<sendlog::SendLog>,
    tags: BTreeMap<String, String>,
    data: &mut DataSource,
) -> Result<Xid, anyhow::Error> {
    let send_id = match send_log {
        Some(ref mut send_log) => send_log.last_send_id()?,
        None => None,
    };

    write_packet(w, &Packet::TBeginSend(TBeginSend { delta_id: send_id }))?;

    let ack = match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
        Packet::RBeginSend(ack) => ack,
        _ => anyhow::bail!("protocol error, expected begin ack packet"),
    };

    'retry: for _i in 0..256 {
        let mut index_tree = None;

        let send_log_session = match send_log {
            Some(ref mut send_log) => Some(std::cell::RefCell::new(
                send_log.session(ack.gc_generation)?,
            )),
            None => None,
        };

        if let Some(ref send_log_session) = send_log_session {
            send_log_session
                .borrow_mut()
                .perform_cache_invalidations(ack.has_delta_id)?;
        }

        let mut sink = ConnectionHtreeSink {
            checkpoint_bytes: ctx.checkpoint_bytes,
            dirty_bytes: 0,
            send_log_session: &send_log_session,
            w,
            r,
        };

        // XXX TODO these chunk parameters need to be investigated and tuned.
        let min_size = 256 * 1024;
        let max_size = 8 * 1024 * 1024;
        let chunk_mask = 0x000f_ffff;

        let mut chunker = chunker::RollsumChunker::new(
            rollsum::Rollsum::new_with_chunk_mask(chunk_mask),
            min_size,
            max_size,
        );
        let mut tw = htree::TreeWriter::new(max_size, chunk_mask);

        match data {
            DataSource::Subprocess(args) => {
                let quoted_args: Vec<String> =
                    args.iter().map(|x| shlex::quote(x).to_string()).collect();
                ctx.progress
                    .set_message(&("exec: ".to_string() + &quoted_args.join(" ")));

                let mut child = std::process::Command::new(args[0].clone())
                    .args(&args[1..])
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::piped())
                    .spawn()?;
                let mut data = child.stdout.as_mut().unwrap();
                send_chunks(ctx, &mut sink, &mut chunker, &mut tw, &mut data, None)?;
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
                send_chunks(ctx, &mut sink, &mut chunker, &mut tw, data, None)?;
            }
            DataSource::Directory { path, exclusions } => {
                let mut idx_chunker = chunker::RollsumChunker::new(
                    rollsum::Rollsum::new_with_chunk_mask(chunk_mask),
                    min_size,
                    max_size,
                );
                let mut idx_tw = htree::TreeWriter::new(max_size, chunk_mask);

                match send_dir(
                    ctx,
                    &mut sink,
                    &mut chunker,
                    &mut tw,
                    &mut idx_chunker,
                    &mut idx_tw,
                    &send_log_session,
                    &path,
                    &exclusions,
                ) {
                    Ok(()) => {
                        let chunk_data = idx_chunker.finish();
                        let idx_addr = crypto::keyed_content_address(&chunk_data, &ctx.hash_key);
                        idx_tw.add(
                            &mut sink,
                            &idx_addr,
                            ctx.data_ectx.encrypt_data(chunk_data, ctx.compression),
                        )?;

                        let (idx_tree_height, idx_tree_data_chunk_count, idx_address) =
                            idx_tw.finish(&mut sink)?;

                        index_tree = Some(itemset::HTreeMetadata {
                            height: serde_bare::Uint(idx_tree_height as u64),
                            data_chunk_count: serde_bare::Uint(idx_tree_data_chunk_count),
                            address: idx_address,
                        });
                    }
                    Err(SendDirError::FilesystemModified) => {
                        ctx.progress.println(
                            "filesystem modified while sending, restarting send...".to_string(),
                        );
                        if let Some(ref send_log_session) = send_log_session {
                            write_packet(w, &Packet::TSendSync)?;
                            match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
                                Packet::RSendSync => {
                                    send_log_session.borrow_mut().checkpoint()?;
                                }
                                _ => anyhow::bail!("protocol error, expected RSentSync packet"),
                            }
                        }
                        continue 'retry;
                    }
                    Err(SendDirError::Other(err)) => return Err(err),
                }
            }
        }

        let chunk_data = chunker.finish();
        let addr = crypto::keyed_content_address(&chunk_data, &ctx.hash_key);
        tw.add(
            &mut sink,
            &addr,
            ctx.data_ectx.encrypt_data(chunk_data, ctx.compression),
        )?;
        let (data_tree_height, data_tree_data_chunk_count, data_tree_address) =
            tw.finish(&mut sink)?;

        let plain_text_metadata = itemset::PlainTextItemMetadata {
            primary_key_id: ctx.primary_key_id,
            data_tree: itemset::HTreeMetadata {
                height: serde_bare::Uint(data_tree_height as u64),
                data_chunk_count: serde_bare::Uint(data_tree_data_chunk_count),
                address: data_tree_address,
            },
            index_tree,
        };

        let e_metadata = itemset::EncryptedItemMetadata {
            plain_text_hash: plain_text_metadata.hash(),
            send_key_id: ctx.send_key_id,
            hash_key_part_2: ctx.hash_key.part2.clone(),
            timestamp: chrono::Utc::now(),
            tags,
        };

        ctx.progress.set_message("syncing disks...");

        write_packet(
            w,
            &Packet::TAddItem(AddItem {
                gc_generation: ack.gc_generation,
                item: itemset::VersionedItemMetadata::V1(itemset::ItemMetadata {
                    plain_text_metadata,
                    encrypted_metadata: ctx
                        .metadata_ectx
                        .encrypt_data(serde_bare::to_vec(&e_metadata)?, compression::Scheme::Zstd),
                }),
            }),
        )?;

        match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
            Packet::RAddItem(id) => {
                if send_log_session.is_some() {
                    send_log_session.unwrap().into_inner().commit(&id)?;
                }
                return Ok(id);
            }
            _ => anyhow::bail!("protocol error, expected an RAddItem packet"),
        }
    }

    anyhow::bail!("put retried too many times");
}

fn send_chunks(
    ctx: &mut SendContext,
    sink: &mut dyn htree::Sink,
    chunker: &mut chunker::RollsumChunker,
    tw: &mut htree::TreeWriter,
    data: &mut dyn std::io::Read,
    mut on_chunk: Option<&mut dyn FnMut(&Address)>,
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
                    let (n, c) = chunker.add_bytes(&buf[n_chunked..n_read]);
                    n_chunked += n;
                    if let Some(chunk_data) = c {
                        let addr = crypto::keyed_content_address(&chunk_data, &ctx.hash_key);
                        let encrypted_chunk =
                            ctx.data_ectx.encrypt_data(chunk_data, ctx.compression);
                        if let Some(ref mut on_chunk) = on_chunk {
                            on_chunk(&addr);
                        }
                        tw.add(sink, &addr, encrypted_chunk)?;
                    }
                }
                ctx.progress.inc(n_read as u64);
                n_written += n_read as u64;
            }
            Err(err) => return Err(err.into()),
        }
    }
}

#[derive(Debug)]
enum SendDirError {
    FilesystemModified,
    Other(anyhow::Error),
}

impl std::fmt::Display for SendDirError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SendDirError::FilesystemModified => {
                write!(f, "filesystem modified during directory send.")
            }
            SendDirError::Other(err) => err.fmt(f),
        }
    }
}

impl std::error::Error for SendDirError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl From<anyhow::Error> for SendDirError {
    fn from(err: anyhow::Error) -> Self {
        SendDirError::Other(err)
    }
}

impl From<std::io::Error> for SendDirError {
    fn from(err: std::io::Error) -> Self {
        SendDirError::Other(err.into())
    }
}

impl From<nix::Error> for SendDirError {
    fn from(err: nix::Error) -> Self {
        SendDirError::Other(err.into())
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
    if #[cfg(linux)] {

        fn dev_major(dev: u64) -> u32 {
            ((dev >> 32) & 0xffff_f000) |
            ((dev >>  8) & 0x0000_0fff)
        }

        fn dev_minor(dev: u64) -> u32 {
            ((dev >> 12) & 0xffff_ff00) |
            ((dev      ) & 0x0000_00ff)
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

fn dir_ent_to_index_ent(
    full_path: &std::path::PathBuf,
    short_path: &std::path::PathBuf,
    metadata: &std::fs::Metadata,
) -> Result<index::IndexEntry, std::io::Error> {
    // TODO XXX it seems we should not be using to_string_lossy and throwing away user data...
    // how best to handle this?

    let t = metadata.file_type();

    let (dev_major, dev_minor) = if t.is_block_device() || t.is_block_device() {
        (dev_major(metadata.rdev()), dev_minor(metadata.rdev()))
    } else {
        (0, 0)
    };

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
        link_target: if t.is_symlink() {
            Some(
                std::fs::read_link(&full_path)?
                    .to_string_lossy()
                    .to_string(),
            )
        } else {
            None
        },
        dev_major: serde_bare::Uint(dev_major as u64),
        dev_minor: serde_bare::Uint(dev_minor as u64),
        xattrs: None,
        data_chunk_idx: serde_bare::Uint(0),
        data_chunk_end_idx: serde_bare::Uint(0),
        data_chunk_offset: serde_bare::Uint(0),
        data_chunk_end_offset: serde_bare::Uint(0),
    })
}

fn send_dir(
    ctx: &mut SendContext,
    sink: &mut dyn htree::Sink,
    chunker: &mut chunker::RollsumChunker,
    tw: &mut htree::TreeWriter,
    idx_chunker: &mut chunker::RollsumChunker,
    idx_tw: &mut htree::TreeWriter,
    send_log_session: &Option<std::cell::RefCell<sendlog::SendLogSession>>,
    path: &std::path::PathBuf,
    exclusions: &[glob::Pattern],
) -> Result<(), SendDirError> {
    let path = fsutil::absolute_path(&path)?;

    let mut addresses: Vec<u8> = Vec::new();
    let mut work_list = std::collections::VecDeque::new();
    work_list.push_back(path.clone());

    while let Some(cur_dir) = work_list.pop_front() {
        ctx.progress.set_message(&cur_dir.to_string_lossy());
        addresses.clear();
        let mut hash_state = crypto::HashState::new(Some(&ctx.hash_key));
        // Incorporate the absolute dir in our cache key.
        hash_state.update(cur_dir.as_os_str().as_bytes());
        // Null byte marks the end of path in the hash space.
        hash_state.update(&[0]);

        let mut dir_ents = match fsutil::read_dirents(&cur_dir) {
            Ok(dir_ents) => dir_ents,
            Err(err) if likely_smear_error(&err) => return Err(SendDirError::FilesystemModified),
            Err(err) => return Err(SendDirError::Other(err.into())),
        };

        dir_ents.sort_by_key(|a| a.file_name());

        let mut index_ents = Vec::new();

        if cur_dir == path {
            let metadata = std::fs::metadata(&path)?;
            if !metadata.is_dir() {
                return Err(SendDirError::Other(anyhow::format_err!(
                    "{} is not a directory",
                    path.display()
                )));
            }
            let index_path = ".".into();

            let index_ent = match dir_ent_to_index_ent(&path, &index_path, &metadata) {
                Ok(index_ent) => index_ent,
                Err(err) if likely_smear_error(&err) => {
                    return Err(SendDirError::FilesystemModified)
                }
                Err(err) => return Err(SendDirError::Other(err.into())),
            };

            let index_bytes = serde_bare::to_vec(&index_ent).unwrap();

            hash_state.update(&index_bytes);
            index_ents.push((path.clone(), index_ent));
        }

        'collect_dir_ents: for entry in dir_ents {
            let ent_path = entry.path();

            for excl in exclusions {
                if excl.matches_path(&ent_path) {
                    continue 'collect_dir_ents;
                }
            }

            let metadata = match entry.metadata() {
                Ok(metadata) => metadata,
                Err(err) if likely_smear_error(&err) => {
                    return Err(SendDirError::FilesystemModified)
                }
                Err(err) => return Err(SendDirError::Other(err.into())),
            };
            let index_path = ent_path.strip_prefix(&path).unwrap().to_path_buf();
            let index_ent = match dir_ent_to_index_ent(&ent_path, &index_path, &metadata) {
                Ok(index_ent) => index_ent,
                Err(err) if likely_smear_error(&err) => {
                    return Err(SendDirError::FilesystemModified)
                }
                Err(err) => return Err(SendDirError::Other(err.into())),
            };
            let index_bytes = serde_bare::to_vec(&index_ent).unwrap();

            if metadata.is_dir() {
                work_list.push_back(ent_path.clone());
            }

            hash_state.update(&index_bytes);
            index_ents.push((ent_path, index_ent));
        }

        let hash = hash_state.finish();

        let cache_lookup = if send_log_session.is_some() && ctx.use_stat_cache {
            send_log_session
                .as_ref()
                .unwrap()
                .borrow_mut()
                .stat_cache_lookup(&hash)?
        } else {
            None
        };

        match cache_lookup {
            Some((size, cached_addresses, cached_index)) => {
                debug_assert!(cached_addresses.len() % ADDRESS_SZ == 0);

                let dir_data_chunk_idx = tw.data_chunk_count();

                let mut address = Address::default();
                for cached_address in cached_addresses.chunks(ADDRESS_SZ) {
                    address.bytes[..].clone_from_slice(cached_address);
                    tw.add_addr(sink, 0, 1, &address)?;
                }

                let mut dir_index: Vec<index::VersionedIndexEntry> =
                    serde_bare::from_slice(&cached_index).unwrap();

                for index_ent in dir_index.iter_mut() {
                    match index_ent {
                        index::VersionedIndexEntry::V1(ref mut index_ent) => {
                            index_ent.data_chunk_idx.0 += dir_data_chunk_idx;
                            index_ent.data_chunk_end_idx.0 += dir_data_chunk_idx;
                        }
                    }
                    send_chunks(
                        ctx,
                        sink,
                        idx_chunker,
                        idx_tw,
                        &mut std::io::Cursor::new(&serde_bare::to_vec(&index_ent).unwrap()),
                        None,
                    )?;
                }

                ctx.progress.inc(size);

                send_log_session
                    .as_ref()
                    .unwrap()
                    .borrow_mut()
                    .add_stat_cache_data(&hash[..], size, &addresses, &cached_index)?;
            }
            None => {
                let mut total_size: u64 = 0;
                let mut on_chunk = |addr: &Address| {
                    addresses.extend_from_slice(&addr.bytes[..]);
                };

                let mut cache_dir_index: Vec<index::VersionedIndexEntry> =
                    Vec::with_capacity(index_ents.len());
                let dir_data_chunk_idx = tw.data_chunk_count();

                for (ent_path, mut index_ent) in index_ents.drain(..) {
                    ctx.progress.set_message(&ent_path.to_string_lossy());

                    let ent_data_chunk_idx = tw.data_chunk_count();
                    let ent_data_chunk_offset = chunker.buffered_count() as u64;

                    let mut ent_data_chunk_end_idx = ent_data_chunk_idx;
                    let mut ent_data_chunk_end_offset = ent_data_chunk_offset;

                    if index_ent.is_file() && index_ent.size.0 != 0 {
                        let mut f = match std::fs::OpenOptions::new()
                            .read(true)
                            .custom_flags(libc::O_NOATIME)
                            .open(&ent_path)
                        {
                            Ok(f) => f,
                            Err(err) if likely_smear_error(&err) => {
                                return Err(SendDirError::FilesystemModified)
                            }
                            Err(err) => return Err(SendDirError::Other(err.into())),
                        };

                        // For linux at least, shift file pages to the tail of the page cache, allowing
                        // the kernel to quickly evict these pages. This works well for the case of system
                        // backups, where we don't to trash the users current cache.
                        // One source on how linux treats this hint - https://lwn.net/Articles/449420
                        nix::fcntl::posix_fadvise(
                            f.as_raw_fd(),
                            0,
                            0,
                            nix::fcntl::PosixFadviseAdvice::POSIX_FADV_NOREUSE,
                        )?;

                        let file_len =
                            send_chunks(ctx, sink, chunker, tw, &mut f, Some(&mut on_chunk))?;

                        total_size += file_len as u64;

                        ent_data_chunk_end_idx = tw.data_chunk_count();
                        ent_data_chunk_end_offset = chunker.buffered_count() as u64;

                        if file_len != index_ent.size.0 as u64 {
                            return Err(SendDirError::FilesystemModified);
                        }
                    }

                    index_ent.data_chunk_idx =
                        serde_bare::Uint(ent_data_chunk_idx - dir_data_chunk_idx);
                    index_ent.data_chunk_end_idx =
                        serde_bare::Uint(ent_data_chunk_end_idx - dir_data_chunk_idx);

                    index_ent.data_chunk_offset = serde_bare::Uint(ent_data_chunk_offset);
                    index_ent.data_chunk_end_offset = serde_bare::Uint(ent_data_chunk_end_offset);

                    cache_dir_index.push(index::VersionedIndexEntry::V1(index_ent.clone()));

                    index_ent.data_chunk_idx.0 += dir_data_chunk_idx;
                    index_ent.data_chunk_end_idx.0 += dir_data_chunk_idx;

                    send_chunks(
                        ctx,
                        sink,
                        idx_chunker,
                        idx_tw,
                        &mut std::io::Cursor::new(
                            &serde_bare::to_vec(&index::VersionedIndexEntry::V1(index_ent))
                                .unwrap(),
                        ),
                        None,
                    )?;
                }

                if let Some(chunk_data) = chunker.force_split() {
                    let addr = crypto::keyed_content_address(&chunk_data, &ctx.hash_key);
                    on_chunk(&addr);
                    tw.add(
                        sink,
                        &addr,
                        ctx.data_ectx.encrypt_data(chunk_data, ctx.compression),
                    )?
                }

                if send_log_session.is_some() && ctx.use_stat_cache {
                    send_log_session
                        .as_ref()
                        .unwrap()
                        .borrow_mut()
                        .add_stat_cache_data(
                            &hash[..],
                            total_size,
                            &addresses,
                            &serde_bare::to_vec(&cache_dir_index).unwrap(),
                        )?;
                }
            }
        }
    }

    Ok(())
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
    pub hash_key_part_1: crypto::PartialHashKey,
    pub data_dctx: crypto::DecryptionContext,
    pub metadata_dctx: crypto::DecryptionContext,
}

pub fn request_data_stream(
    mut ctx: DataRequestContext,
    id: Xid,
    metadata: &itemset::ItemMetadata,
    pick: Option<index::PickMap>,
    index: Option<Vec<index::VersionedIndexEntry>>,
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

    if ctx.primary_key_id != metadata.plain_text_metadata.primary_key_id {
        anyhow::bail!("decryption key does not match master key used for encryption");
    }

    let encrypted_metadata = metadata.decrypt_metadata(&mut ctx.metadata_dctx)?;
    let plain_text_metadata = &metadata.plain_text_metadata;

    let hash_key =
        crypto::derive_hash_key(&ctx.hash_key_part_1, &encrypted_metadata.hash_key_part_2);

    let mut tr = htree::TreeReader::new(
        plain_text_metadata.data_tree.height.0.try_into()?,
        plain_text_metadata.data_tree.data_chunk_count.0,
        &plain_text_metadata.data_tree.address,
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
            receive_partial_htree(ctx, &hash_key, r, &mut tr, pick, out)?;
        }
        None => {
            write_packet(w, &Packet::RequestData(RequestData { id, ranges: None }))?;

            match index {
                Some(index) => {
                    receive_indexed_htree_as_tarball(ctx, &hash_key, r, &mut tr, &index, out)?
                }
                None => receive_htree(ctx, &hash_key, r, &mut tr, out)?,
            }
        }
    }

    out.flush()?;
    Ok(())
}

pub fn request_index(
    mut ctx: DataRequestContext,
    id: Xid,
    metadata: &itemset::ItemMetadata,
    r: &mut dyn std::io::Read,
    w: &mut dyn std::io::Write,
) -> Result<Vec<index::VersionedIndexEntry>, anyhow::Error> {
    if ctx.primary_key_id != metadata.plain_text_metadata.primary_key_id {
        anyhow::bail!("decryption key does not match master key used for encryption");
    }

    let encrypted_metadata = metadata.decrypt_metadata(&mut ctx.metadata_dctx)?;
    let plain_text_metadata = &metadata.plain_text_metadata;

    let hash_key =
        crypto::derive_hash_key(&ctx.hash_key_part_1, &encrypted_metadata.hash_key_part_2);

    let index_tree = match &plain_text_metadata.index_tree {
        Some(index_tree) => index_tree,
        None => anyhow::bail!("requested item missing an index"),
    };

    let mut tr = htree::TreeReader::new(
        index_tree.height.0.try_into()?,
        index_tree.data_chunk_count.0,
        &index_tree.address,
    );

    let mut index_data = std::io::Cursor::new(Vec::new());

    write_packet(w, &Packet::RequestIndex(RequestIndex { id }))?;
    receive_htree(ctx, &hash_key, r, &mut tr, &mut index_data)?;

    let mut index: Vec<index::VersionedIndexEntry> = Vec::new();

    let index_data_size = index_data.position();
    index_data.set_position(0);
    while index_data.position() != index_data_size {
        match serde_bare::from_reader(&mut index_data) {
            Ok(index_entry) => index.push(index_entry),
            Err(err) => anyhow::bail!("error deserializing index: {}", err),
        }
    }

    Ok(index)
}

fn receive_and_authenticate_htree_chunk(
    r: &mut dyn std::io::Read,
    address: Address,
) -> Result<Vec<u8>, anyhow::Error> {
    let data = match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
        Packet::Chunk(chunk) => {
            if address != chunk.address {
                return Err(ClientError::CorruptOrTamperedDataError.into());
            }
            chunk.data
        }
        _ => anyhow::bail!("protocol error, expected chunk packet"),
    };
    let data = compression::unauthenticated_decompress(data)?;
    if address != htree::tree_block_address(&data) {
        return Err(ClientError::CorruptOrTamperedDataError.into());
    }
    Ok(data)
}

fn receive_htree(
    mut ctx: DataRequestContext,
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
                        return Err(ClientError::CorruptOrTamperedDataError.into());
                    }
                    chunk.data
                }
                _ => anyhow::bail!("protocol error, expected begin chunk packet"),
            };

            let data = ctx.data_dctx.decrypt_data(data)?;
            if addr != crypto::keyed_content_address(&data, &hash_key) {
                return Err(ClientError::CorruptOrTamperedDataError.into());
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
    index: &Vec<index::VersionedIndexEntry>,
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

    for ent in index.iter() {
        match ent {
            index::VersionedIndexEntry::V1(ent) => {
                out.write_all(&xtar::index_entry_to_tarheader(&ent)?)?;

                copy_n(out, ent.size.0)?;
                /* Tar entries are rounded to 512 bytes */
                let remaining = 512 - (ent.size.0 % 512);
                if remaining < 512 {
                    let buf = [0; 512];
                    out.write_all(&buf[..remaining as usize])?;
                }
            }
        }
    }

    let buf = [0; 1024];
    out.write_all(&buf[..])?;

    out.flush()?;
    Ok(())
}

fn receive_indexed_htree_as_tarball(
    mut ctx: DataRequestContext,
    hash_key: &crypto::HashKey,
    r: &mut dyn std::io::Read,
    tr: &mut htree::TreeReader,
    index: &Vec<index::VersionedIndexEntry>,
    out: &mut dyn std::io::Write,
) -> Result<(), anyhow::Error> {
    let mut read_data = || -> Result<Option<Vec<u8>>, anyhow::Error> {
        while let Some((height, addr)) = tr.next_addr() {
            if height == 0 {
                let data = match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
                    Packet::Chunk(chunk) => {
                        if addr != chunk.address {
                            return Err(ClientError::CorruptOrTamperedDataError.into());
                        }
                        chunk.data
                    }
                    _ => anyhow::bail!("protocol error, expected begin chunk packet"),
                };

                let data = ctx.data_dctx.decrypt_data(data)?;
                if addr != crypto::keyed_content_address(&data, &hash_key) {
                    return Err(ClientError::CorruptOrTamperedDataError.into());
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
    mut ctx: DataRequestContext,
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
        Some(range) => range.start_idx,
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

                            if current_data_chunk_idx >= current_range.start_idx
                                && current_data_chunk_idx <= current_range.end_idx
                            {
                                let data = match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
                                    Packet::Chunk(chunk) => {
                                        if chunk_address != chunk.address {
                                            return Err(
                                                ClientError::CorruptOrTamperedDataError.into()
                                            );
                                        }
                                        chunk.data
                                    }
                                    _ => anyhow::bail!("protocol error, expected chunk packet"),
                                };

                                let data = ctx.data_dctx.decrypt_data(data)?;
                                if chunk_address != crypto::keyed_content_address(&data, &hash_key)
                                {
                                    return Err(ClientError::CorruptOrTamperedDataError.into());
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
                            if current_data_chunk_idx > current_range.end_idx {
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
) -> Result<repository::GCStats, anyhow::Error> {
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
    progress.set_message("syncing remote items...");

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
