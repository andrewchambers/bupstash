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
use std::collections::BTreeMap;
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
    CorruptOrTamperedDataError,
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
            protocol_version: "5".to_string(),
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
    acache: acache::ACache,
    r: &'a mut dyn std::io::Read,
    w: &'a mut dyn std::io::Write,
}

impl<'a, 'b> htree::Sink for ConnectionHtreeSink<'a, 'b> {
    fn add_chunk(
        &mut self,
        addr: &Address,
        data: std::vec::Vec<u8>,
    ) -> std::result::Result<(), anyhow::Error> {
        if !self.acache.add(addr) {
            return Ok(());
        }

        match self.send_log_session {
            Some(ref send_log_session) => {
                let mut send_log_session = send_log_session.borrow_mut();

                if send_log_session.add_address(addr)? {
                    self.dirty_bytes += data.len() as u64;
                    write_chunk(self.w, addr, &data)?;
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

    let mut data_ectx = ctx.data_ectx.clone();

    write_packet(w, &Packet::TBeginSend(TBeginSend { delta_id: send_id }))?;

    let ack = match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
        Packet::RBeginSend(ack) => ack,
        _ => anyhow::bail!("protocol error, expected begin ack packet"),
    };

    let mut index_tree = None;
    let mut index_size = 0;

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
        acache: acache::ACache::new(65536),
        w,
        r,
    };

    let min_size = CHUNK_MIN_SIZE;
    let max_size = CHUNK_MAX_SIZE;

    let mut chunker = chunker::RollsumChunker::new(ctx.gear_tab, min_size, max_size);
    let mut tw = htree::TreeWriter::new(min_size, max_size);

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
            send_chunks(
                ctx,
                &mut sink,
                &ctx.data_hash_key,
                &mut data_ectx,
                &mut chunker,
                &mut tw,
                &mut data,
                None,
            )?;
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
            send_chunks(
                ctx,
                &mut sink,
                &ctx.data_hash_key,
                &mut data_ectx,
                &mut chunker,
                &mut tw,
                data,
                None,
            )?;
        }
        DataSource::Filesystem {
            base,
            paths,
            exclusions,
        } => {
            let mut idx_chunker = chunker::RollsumChunker::new(ctx.gear_tab, min_size, max_size);
            let mut idx_tw = htree::TreeWriter::new(min_size, max_size);

            let mut st = SendDirState {
                sink: &mut sink,
                chunker: &mut chunker,
                tw: &mut tw,
                idx_chunker: &mut idx_chunker,
                idx_tw: &mut idx_tw,
                send_log_session: &send_log_session,
            };

            send_dir(ctx, &mut st, &base, paths, &exclusions)?;

            let chunk_data = idx_chunker.finish();
            let data_len = chunk_data.len() as u64;
            let chunk_addr = crypto::keyed_content_address(&chunk_data, &ctx.idx_hash_key);
            idx_tw.add(
                &mut sink,
                &chunk_addr,
                data_len,
                ctx.idx_ectx.encrypt_data(chunk_data, ctx.compression),
            )?;

            let (i_tree_height, i_tree_data_chunk_count, i_size, i_address) =
                idx_tw.finish(&mut sink)?;

            index_tree = Some(itemset::HTreeMetadata {
                height: serde_bare::Uint(i_tree_height as u64),
                data_chunk_count: serde_bare::Uint(i_tree_data_chunk_count),
                address: i_address,
            });
            index_size = i_size;
        }
    }

    let chunk_data = chunker.finish();
    let data_len = chunk_data.len() as u64;
    let addr = crypto::keyed_content_address(&chunk_data, &ctx.data_hash_key);
    tw.add(
        &mut sink,
        &addr,
        data_len,
        ctx.data_ectx.encrypt_data(chunk_data, ctx.compression),
    )?;
    let (data_tree_height, data_tree_data_chunk_count, data_sz, data_tree_address) =
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
        idx_hash_key_part_2: ctx.idx_hash_key.part2.clone(),
        data_hash_key_part_2: ctx.data_hash_key.part2.clone(),
        timestamp: chrono::Utc::now(),
        data_size: serde_bare::Uint(data_sz),
        index_size: serde_bare::Uint(index_size),
        tags,
    };

    ctx.progress.set_message("syncing storage...");

    write_packet(
        w,
        &Packet::TAddItem(AddItem {
            gc_generation: ack.gc_generation,
            item: itemset::VersionedItemMetadata::V1(itemset::ItemMetadata {
                plain_text_metadata,
                encrypted_metadata: ctx
                    .metadata_ectx
                    .encrypt_data(serde_bare::to_vec(&e_metadata)?, compression::Scheme::Lz4),
            }),
        }),
    )?;

    match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
        Packet::RAddItem(id) => {
            if send_log_session.is_some() {
                send_log_session.unwrap().into_inner().commit(&id)?;
            }
            Ok(id)
        }
        _ => anyhow::bail!("protocol error, expected an RAddItem packet"),
    }
}

#[allow(clippy::too_many_arguments)]
fn send_chunks(
    ctx: &SendContext,
    sink: &mut dyn htree::Sink,
    hash_key: &crypto::HashKey,
    ectx: &mut crypto::EncryptionContext,
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
                        let data_len = chunk_data.len() as u64;
                        ctx.progress.inc(data_len);
                        let addr = crypto::keyed_content_address(&chunk_data, &hash_key);
                        let encrypted_chunk = ectx.encrypt_data(chunk_data, ctx.compression);
                        if let Some(ref mut on_chunk) = on_chunk {
                            on_chunk(&addr);
                        }
                        tw.add(sink, &addr, data_len, encrypted_chunk)?;
                    }
                }
                n_written += n_read as u64;
            }
            Err(err) => return Err(err.into()),
        }
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

fn dir_ent_to_index_ent(
    full_path: &std::path::PathBuf,
    short_path: &std::path::PathBuf,
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
        dev: serde_bare::Uint(metadata.dev()),
        ino: serde_bare::Uint(metadata.ino()),
        xattrs,
        offsets: index::IndexEntryOffsets {
            data_chunk_idx: serde_bare::Uint(0),
            data_chunk_end_idx: serde_bare::Uint(0),
            data_chunk_offset: serde_bare::Uint(0),
            data_chunk_end_offset: serde_bare::Uint(0),
        },
    })
}

struct SendDirState<'a, 'b> {
    sink: &'a mut dyn htree::Sink,
    chunker: &'a mut chunker::RollsumChunker,
    tw: &'a mut htree::TreeWriter,
    idx_chunker: &'a mut chunker::RollsumChunker,
    idx_tw: &'a mut htree::TreeWriter,
    send_log_session: &'a Option<std::cell::RefCell<sendlog::SendLogSession<'b>>>,
}

cfg_if::cfg_if! {
    if #[cfg(target_os = "linux")] {

        fn open_file_for_sending(fpath: &std::path::Path) -> Result<std::fs::File, std::io::Error> {
            let f = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOATIME)
                .open(fpath)?;

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

fn send_dir(
    ctx: &SendContext,
    st: &mut SendDirState,
    base: &std::path::PathBuf,
    paths: &[std::path::PathBuf],
    exclusions: &[glob::Pattern],
) -> Result<(), anyhow::Error> {
    let mut data_ectx = ctx.data_ectx.clone();
    let mut idx_ectx = ctx.idx_ectx.clone();

    {
        let metadata = std::fs::metadata(&base)?;
        if !metadata.is_dir() {
            anyhow::bail!("{} is not a directory", base.display());
        }
        let ent = index::VersionedIndexEntry::V1(dir_ent_to_index_ent(
            &base,
            &".".into(),
            &metadata,
            ctx.want_xattrs,
        )?);
        send_chunks(
            ctx,
            st.sink,
            &ctx.idx_hash_key,
            &mut idx_ectx,
            st.idx_chunker,
            st.idx_tw,
            &mut std::io::Cursor::new(&serde_bare::to_vec(&ent).unwrap()),
            None,
        )?;
    }

    let mut addresses: Vec<u8> = Vec::new();
    let mut work_list = Vec::new();

    let mut initial_paths = std::collections::HashSet::new();
    for p in paths {
        let initial_md = std::fs::metadata(&p)?;
        if !initial_md.is_dir() {
            // We should be able to lift this restriction in the future.
            anyhow::bail!(
                "{} is not a directory, files cannot be part of multi-dir put",
                p.display()
            );
        }
        work_list.push((p.clone(), initial_md));
        if p != base {
            initial_paths.insert(p.clone());
        }
    }

    while let Some((cur_dir, cur_dir_md)) = work_list.pop() {
        assert!(cur_dir_md.is_dir());
        ctx.progress.set_message(&cur_dir.to_string_lossy());

        // These inital paths do not have a parent who will add an index entry
        // for them, so we add before we process the dir contents.
        if !initial_paths.is_empty() && initial_paths.contains(&cur_dir) {
            initial_paths.remove(&cur_dir);

            let index_path = cur_dir.strip_prefix(&base).unwrap().to_path_buf();
            let ent = index::VersionedIndexEntry::V1(dir_ent_to_index_ent(
                &cur_dir,
                &index_path,
                &cur_dir_md,
                ctx.want_xattrs,
            )?);

            send_chunks(
                ctx,
                st.sink,
                &ctx.idx_hash_key,
                &mut idx_ectx,
                st.idx_chunker,
                st.idx_tw,
                &mut std::io::Cursor::new(&serde_bare::to_vec(&ent).unwrap()),
                None,
            )?;
        }

        addresses.clear();
        let mut hash_state = crypto::HashState::new(Some(&ctx.idx_hash_key));

        // Incorporate the absolute dir in our cache key.
        hash_state.update(cur_dir.as_os_str().as_bytes());
        // Null byte marks the end of path in the hash space.
        hash_state.update(&[0]);

        let mut dir_ents = match fsutil::read_dirents(&cur_dir) {
            Ok(dir_ents) => dir_ents,
            // If the directory was from under us, treat it as empty.
            Err(err) if likely_smear_error(&err) => vec![],
            Err(err) => return Err(err.into()),
        };

        // XXX sorting by extension or reverse filename might give better compression.
        dir_ents.sort_by_key(|a| a.file_name());

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
                // If the directory was from under us, treat it as if it was excluded.
                Err(err) if likely_smear_error(&err) => continue 'collect_dir_ents,
                Err(err) => return Err(err.into()),
            };

            // There is no meaningful way to backup a unix socket.
            if metadata.file_type().is_socket() {
                continue 'collect_dir_ents;
            }

            let index_path = ent_path.strip_prefix(&base).unwrap().to_path_buf();
            let index_ent =
                match dir_ent_to_index_ent(&ent_path, &index_path, &metadata, ctx.want_xattrs) {
                    Ok(ent) => ent,
                    // The entry was removed while we were it's metadata
                    // in a way that was unrecoverable. For example a symlink was removed so
                    // we cannot do a valid readlink.
                    Err(err) if likely_smear_error(&err) => continue 'collect_dir_ents,
                    Err(err) => return Err(err.into()),
                };

            if metadata.is_dir() && ((cur_dir_md.dev() == metadata.dev()) || !ctx.one_file_system) {
                work_list.push((ent_path.clone(), metadata));
            }

            if ctx.use_stat_cache {
                hash_state.update(&serde_bare::to_vec(&index_ent).unwrap());
            }

            index_ents.push((ent_path, index_ent));
        }

        let hash = hash_state.finish();

        let cache_lookup = if st.send_log_session.is_some() && ctx.use_stat_cache {
            st.send_log_session
                .as_ref()
                .unwrap()
                .borrow_mut()
                .stat_cache_lookup(&hash)?
        } else {
            None
        };

        match cache_lookup {
            Some((total_size, cached_addresses, cached_index_offsets_buf)) => {
                debug_assert!(cached_addresses.len() % ADDRESS_SZ == 0);

                let dir_data_chunk_idx = st.tw.data_chunk_count();

                let mut address = Address::default();
                for cached_address in cached_addresses.chunks(ADDRESS_SZ) {
                    address.bytes[..].clone_from_slice(cached_address);
                    st.tw.add_data_addr(st.sink, &address)?;
                }
                st.tw.add_stream_size(total_size);

                let cached_index_offsets: Vec<index::IndexEntryOffsets> =
                    serde_bare::from_slice(&cached_index_offsets_buf).unwrap();

                assert!(index_ents.len() == cached_index_offsets.len());

                for ((_, mut index_ent), base_offsets) in
                    index_ents.drain(..).zip(cached_index_offsets.iter())
                {
                    index_ent.offsets = *base_offsets;
                    index_ent.offsets.data_chunk_idx.0 += dir_data_chunk_idx;
                    index_ent.offsets.data_chunk_end_idx.0 += dir_data_chunk_idx;
                    send_chunks(
                        ctx,
                        st.sink,
                        &ctx.idx_hash_key,
                        &mut idx_ectx,
                        st.idx_chunker,
                        st.idx_tw,
                        &mut std::io::Cursor::new(
                            &serde_bare::to_vec(&index::VersionedIndexEntry::V1(index_ent))
                                .unwrap(),
                        ),
                        None,
                    )?;
                }

                // Re-add the cache entry so it isn't invalidated.
                st.send_log_session
                    .as_ref()
                    .unwrap()
                    .borrow_mut()
                    .add_stat_cache_data(
                        &hash[..],
                        total_size,
                        &addresses,
                        &cached_index_offsets_buf,
                    )?;

                ctx.progress.inc(total_size);
            }
            None => {
                let mut total_size: u64 = 0;

                let mut on_chunk = |addr: &Address| {
                    if ctx.use_stat_cache {
                        addresses.extend_from_slice(&addr.bytes[..]);
                    }
                };

                let mut dir_index_offsets: Vec<index::IndexEntryOffsets> =
                    Vec::with_capacity(index_ents.len());

                let dir_data_chunk_idx = st.tw.data_chunk_count();

                'add_dir_ents: for (ent_path, mut index_ent) in index_ents.drain(..) {
                    let ent_data_chunk_idx = st.tw.data_chunk_count();
                    let ent_data_chunk_offset = st.chunker.buffered_count() as u64;

                    let mut ent_data_chunk_end_idx = ent_data_chunk_idx;
                    let mut ent_data_chunk_end_offset = ent_data_chunk_offset;

                    if index_ent.is_file() && index_ent.size.0 != 0 {
                        let mut f = match open_file_for_sending(&ent_path) {
                            Ok(f) => f,
                            // The file was deleted, treat it like it did not exist.
                            // It's unlikely this stat cache entry will hit again as
                            // the ctime definitely would change in this case.
                            Err(err) if likely_smear_error(&err) => continue 'add_dir_ents,
                            Err(err) => return Err(err.into()),
                        };

                        let file_len = send_chunks(
                            ctx,
                            st.sink,
                            &ctx.data_hash_key,
                            &mut data_ectx,
                            st.chunker,
                            st.tw,
                            &mut f,
                            Some(&mut on_chunk),
                        )?;

                        // The true size is just what we read from disk. In the case
                        // of snapshotting an modified file we can't guarantee consistency anyway.
                        index_ent.size.0 = file_len;
                        total_size += file_len as u64;

                        ent_data_chunk_end_idx = st.tw.data_chunk_count();
                        ent_data_chunk_end_offset = st.chunker.buffered_count() as u64;
                    }

                    let cur_offsets = index::IndexEntryOffsets {
                        data_chunk_idx: serde_bare::Uint(ent_data_chunk_idx - dir_data_chunk_idx),
                        data_chunk_end_idx: serde_bare::Uint(
                            ent_data_chunk_end_idx - dir_data_chunk_idx,
                        ),
                        data_chunk_offset: serde_bare::Uint(ent_data_chunk_offset),
                        data_chunk_end_offset: serde_bare::Uint(ent_data_chunk_end_offset),
                    };

                    dir_index_offsets.push(cur_offsets);

                    index_ent.offsets = cur_offsets;
                    index_ent.offsets.data_chunk_idx.0 += dir_data_chunk_idx;
                    index_ent.offsets.data_chunk_end_idx.0 += dir_data_chunk_idx;

                    send_chunks(
                        ctx,
                        st.sink,
                        &ctx.idx_hash_key,
                        &mut idx_ectx,
                        st.idx_chunker,
                        st.idx_tw,
                        &mut std::io::Cursor::new(
                            &serde_bare::to_vec(&index::VersionedIndexEntry::V1(index_ent))
                                .unwrap(),
                        ),
                        None,
                    )?;
                }

                if let Some(chunk_data) = st.chunker.force_split() {
                    let data_len = chunk_data.len() as u64;
                    let addr = crypto::keyed_content_address(&chunk_data, &ctx.data_hash_key);
                    on_chunk(&addr);
                    st.tw.add(
                        st.sink,
                        &addr,
                        data_len,
                        data_ectx.encrypt_data(chunk_data, ctx.compression),
                    )?
                }

                if st.send_log_session.is_some() && ctx.use_stat_cache {
                    st.send_log_session
                        .as_ref()
                        .unwrap()
                        .borrow_mut()
                        .add_stat_cache_data(
                            &hash[..],
                            total_size,
                            &addresses,
                            &serde_bare::to_vec(&dir_index_offsets).unwrap(),
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
    pub data_hash_key_part_1: crypto::PartialHashKey,
    pub data_dctx: crypto::DecryptionContext,
    pub metadata_dctx: crypto::DecryptionContext,
}

#[allow(clippy::too_many_arguments)]
pub fn request_data_stream(
    mut ctx: DataRequestContext,
    id: Xid,
    metadata: &itemset::ItemMetadata,
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

    if ctx.primary_key_id != metadata.plain_text_metadata.primary_key_id {
        anyhow::bail!("decryption key does not match key used for encryption");
    }

    let encrypted_metadata = metadata.decrypt_metadata(&mut ctx.metadata_dctx)?;
    let plain_text_metadata = &metadata.plain_text_metadata;

    let hash_key = crypto::derive_hash_key(
        &ctx.data_hash_key_part_1,
        &encrypted_metadata.data_hash_key_part_2,
    );

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
    metadata: &itemset::ItemMetadata,
    r: &mut dyn std::io::Read,
    w: &mut dyn std::io::Write,
) -> Result<index::CompressedIndex, anyhow::Error> {
    if ctx.primary_key_id != metadata.plain_text_metadata.primary_key_id {
        anyhow::bail!("decryption key does not match key used for encryption");
    }

    let encrypted_metadata = metadata.decrypt_metadata(&mut ctx.metadata_dctx)?;
    let plain_text_metadata = &metadata.plain_text_metadata;

    let hash_key = crypto::derive_hash_key(
        &ctx.idx_hash_key_part_1,
        &encrypted_metadata.idx_hash_key_part_2,
    );

    let index_tree = match &plain_text_metadata.index_tree {
        Some(index_tree) => index_tree,
        None => anyhow::bail!("requested item missing an index"),
    };

    let mut tr = htree::TreeReader::new(
        index_tree.height.0.try_into()?,
        index_tree.data_chunk_count.0,
        &index_tree.address,
    );

    let mut index_data = lz4::EncoderBuilder::new()
        .checksum(lz4::ContentChecksum::NoChecksum)
        .build(std::io::Cursor::new(Vec::new()))?;

    write_packet(w, &Packet::RequestIndex(RequestIndex { id }))?;
    receive_htree(&mut ctx.idx_dctx, &hash_key, r, &mut tr, &mut index_data)?;

    let (index_cursor, compress_result) = index_data.finish();
    compress_result?;

    Ok(index::CompressedIndex::from_vec(index_cursor.into_inner()))
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
                        return Err(ClientError::CorruptOrTamperedDataError.into());
                    }
                    chunk.data
                }
                _ => anyhow::bail!("protocol error, expected begin chunk packet"),
            };

            let data = dctx.decrypt_data(data)?;
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
        match ent? {
            index::VersionedIndexEntry::V1(ent) => {
                if matches!(ent.kind(), index::IndexEntryKind::Other) {
                    // We can't convert this to a tar header, so just discard the
                    // data and skip it.
                    copy_n(&mut std::io::sink(), ent.size.0)?;
                    continue;
                }

                let hardlink = if !ent.is_dir() && ent.nlink.0 > 1 {
                    let dev_ino = (ent.dev.0, ent.ino.0);
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
                            return Err(ClientError::CorruptOrTamperedDataError.into());
                        }
                        chunk.data
                    }
                    _ => anyhow::bail!("protocol error, expected begin chunk packet"),
                };

                let data = dctx.decrypt_data(data)?;
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
                                            return Err(
                                                ClientError::CorruptOrTamperedDataError.into()
                                            );
                                        }
                                        chunk.data
                                    }
                                    _ => anyhow::bail!("protocol error, expected chunk packet"),
                                };

                                let data = dctx.decrypt_data(data)?;
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
