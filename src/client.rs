use super::address::*;
use super::chunker;
use super::crypto;
use super::fsutil;
use super::htree;
use super::itemset;
use super::protocol::*;
use super::querycache;
use super::repository;
use super::rollsum;
use super::sendlog;
use super::xid::*;
use super::xtar;
use failure::Fail;
use std::collections::BTreeMap;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::AsRawFd;

#[derive(Debug, Fail)]
pub enum ClientError {
    #[fail(display = "corrupt or tampered data")]
    CorruptOrTamperedDataError,
}

pub fn negotiate_connection(w: &mut dyn std::io::Write) -> Result<(), failure::Error> {
    write_packet(
        w,
        &Packet::ClientInfo(ClientInfo {
            protocol: "0".to_string(),
            now: chrono::Utc::now(),
        }),
    )?;
    Ok(())
}

pub fn init_repository(
    r: &mut dyn std::io::Read,
    w: &mut dyn std::io::Write,
    storage_spec: Option<repository::StorageEngineSpec>,
) -> Result<(), failure::Error> {
    write_packet(w, &Packet::TInitRepository(storage_spec))?;
    match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
        Packet::RInitRepository => Ok(()),
        _ => failure::bail!("protocol error, expected begin ack packet"),
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
    ) -> std::result::Result<(), failure::Error> {
        match self.send_log_session {
            Some(ref send_log_session) => {
                let mut send_log_session = send_log_session.borrow_mut();
                if send_log_session.cached_address(addr)? {
                    send_log_session.add_address(addr)?;
                } else {
                    self.dirty_bytes += data.len() as u64;
                    write_packet(
                        self.w,
                        &Packet::Chunk(Chunk {
                            address: *addr,
                            data,
                        }),
                    )?;
                    send_log_session.add_address(addr)?;
                }

                if self.dirty_bytes >= self.checkpoint_bytes {
                    self.dirty_bytes = 0;
                    write_packet(self.w, &Packet::TSendSync)?;
                    match read_packet(self.r, DEFAULT_MAX_PACKET_SIZE)? {
                        Packet::RSendSync => {
                            send_log_session.checkpoint()?;
                        }
                        _ => failure::bail!("protocol error, expected RSentSync packet"),
                    }
                }

                Ok(())
            }
            None => {
                write_packet(
                    self.w,
                    &Packet::Chunk(Chunk {
                        address: *addr,
                        data,
                    }),
                )?;
                Ok(())
            }
        }
    }
}

pub struct SendContext {
    pub progress: indicatif::ProgressBar,
    pub compression: crypto::DataCompression,
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
    data: DataSource,
) -> Result<Xid, failure::Error> {
    let send_id = match send_log {
        Some(ref mut send_log) => send_log.last_send_id()?,
        None => None,
    };

    write_packet(w, &Packet::TBeginSend(TBeginSend { delta_id: send_id }))?;

    let ack = match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
        Packet::RBeginSend(ack) => ack,
        _ => failure::bail!("protocol error, expected begin ack packet"),
    };

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

    let min_size = 256 * 1024;
    let max_size = 8 * 1024 * 1024;
    let chunk_mask = 0x000f_ffff;
    // XXX TODO these chunk parameters need to be investigated and tuned.
    let rs = rollsum::Rollsum::new_with_chunk_mask(chunk_mask);
    let mut chunker = chunker::RollsumChunker::new(rs, min_size, max_size);
    let mut tw = htree::TreeWriter::new(&mut sink, max_size, chunk_mask);

    match data {
        DataSource::Subprocess(args) => {
            let mut child = std::process::Command::new(args[0].clone())
                .args(&args[1..])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .spawn()?;
            let mut data = child.stdout.as_mut().unwrap();
            send_chunks(ctx, &mut chunker, &mut tw, &mut data, None)?;
            let status = child.wait()?;
            if !status.success() {
                failure::bail!("child failed with status {}", status.code().unwrap());
            }

            let quoted_args: Vec<String> =
                args.iter().map(|x| shlex::quote(x).to_string()).collect();
            ctx.progress
                .set_message(&("exec: ".to_string() + &quoted_args.join(" ")));
        }
        DataSource::Readable {
            description,
            mut data,
        } => {
            ctx.progress.set_message(&description);
            send_chunks(ctx, &mut chunker, &mut tw, &mut data, None)?;
        }
        DataSource::Directory { path, exclusions } => {
            ctx.progress.set_message(&path.to_string_lossy());
            send_dir(
                ctx,
                &mut chunker,
                &mut tw,
                &send_log_session,
                &path,
                &exclusions,
            )?;
        }
    }

    let chunk_data = chunker.finish();
    let addr = crypto::keyed_content_address(&chunk_data, &ctx.hash_key);
    tw.add(
        &addr,
        ctx.data_ectx.encrypt_data(chunk_data, ctx.compression),
    )?;
    let (tree_height, address) = tw.finish()?;

    let plain_text_metadata = itemset::PlainTextItemMetadata {
        primary_key_id: ctx.primary_key_id,
        tree_height,
        address,
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
                encrypted_metadata: ctx.metadata_ectx.encrypt_data(
                    serde_bare::to_vec(&e_metadata)?,
                    crypto::DataCompression::Zstd,
                ),
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
        _ => failure::bail!("protocol error, expected an RAddItem packet"),
    }
}

fn send_chunks(
    ctx: &mut SendContext,
    chunker: &mut chunker::RollsumChunker,
    tw: &mut htree::TreeWriter,
    data: &mut dyn std::io::Read,
    mut on_chunk: Option<&mut dyn FnMut(&Address)>,
) -> Result<usize, failure::Error> {
    let mut buf: Vec<u8> = vec![0; 1024 * 1024];
    let mut n_written: usize = 0;
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
                        tw.add(&addr, encrypted_chunk)?;
                    }
                }
                ctx.progress.inc(n_read as u64);
                n_written += n_read;
            }
            Err(err) => return Err(err.into()),
        }
    }
}

fn send_dir(
    ctx: &mut SendContext,
    chunker: &mut chunker::RollsumChunker,
    tw: &mut htree::TreeWriter,
    send_log_session: &Option<std::cell::RefCell<sendlog::SendLogSession>>,
    path: &std::path::PathBuf,
    exclusions: &[glob::Pattern],
) -> Result<(), failure::Error> {
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
        // Null byte marks the end of path and tar headers in the hash space.
        hash_state.update(&[0]);

        let mut dir_ents = Vec::new();

        for entry in std::fs::read_dir(&cur_dir)? {
            dir_ents.push(entry?);
        }

        dir_ents.sort_by(|a, b| a.file_name().cmp(&b.file_name()));

        let mut tar_dir_ents = Vec::new();

        if cur_dir == path {
            let metadata = std::fs::metadata(&path)?;
            if !metadata.is_dir() {
                failure::bail!("{} is not a directory", path.display());
            }
            let short_path = ".".into();
            let tar_hdr_bytes = xtar::dirent_to_tarheader(&metadata, &path, &short_path)?;
            hash_state.update(&tar_hdr_bytes);
            tar_dir_ents.push((path.clone(), metadata, tar_hdr_bytes));
        }

        'collect_dir_ents: for entry in dir_ents {
            let ent_path = entry.path();

            for excl in exclusions {
                if excl.matches_path(&ent_path) {
                    continue 'collect_dir_ents;
                }
            }

            let metadata = entry.metadata()?;
            let short_path = ent_path.strip_prefix(&path)?.to_path_buf();
            let tar_hdr_bytes = xtar::dirent_to_tarheader(&metadata, &ent_path, &short_path)?;

            if metadata.is_dir() {
                work_list.push_back(ent_path.clone());
            }

            hash_state.update(&tar_hdr_bytes);
            tar_dir_ents.push((ent_path, metadata, tar_hdr_bytes));
        }

        let hash = hash_state.finish();

        let cache_lookup = if send_log_session.is_some() && ctx.use_stat_cache {
            send_log_session
                .as_ref()
                .unwrap()
                .borrow_mut()
                .cached_stat_addresses(&hash)?
        } else {
            None
        };

        match cache_lookup {
            Some((size, cached_addresses)) => {
                debug_assert!(cached_addresses.len() % ADDRESS_SZ == 0);

                let mut address = Address::default();
                for cached_address in cached_addresses.chunks(ADDRESS_SZ) {
                    address.bytes[..].clone_from_slice(cached_address);
                    tw.add_addr(0, &address)?;
                }

                ctx.progress.inc(size);

                send_log_session
                    .as_ref()
                    .unwrap()
                    .borrow_mut()
                    .add_stat_addresses(&hash[..], size, &addresses)?;
            }
            None => {
                let mut total_size: u64 = 0;
                let mut on_chunk = |addr: &Address| {
                    addresses.extend_from_slice(&addr.bytes[..]);
                };

                for (ent_path, metadata, hdr_bytes) in tar_dir_ents.drain(..) {
                    ctx.progress.set_message(&ent_path.to_string_lossy());

                    let mut hdr_cursor = std::io::Cursor::new(hdr_bytes);
                    total_size +=
                        send_chunks(ctx, chunker, tw, &mut hdr_cursor, Some(&mut on_chunk))? as u64;

                    if metadata.is_file() {
                        let mut f = std::fs::File::open(&ent_path)?;

                        // For linux at least, shift file pages to the tail of the page cache, allowing
                        // the kernel to quickly evict these pages. This works well for the case of system
                        // backups, where we don't to trash the users current cache.
                        // One source on how linux treats this hint - https://lwn.net/Articles/449420"
                        nix::fcntl::posix_fadvise(
                            f.as_raw_fd(),
                            0,
                            0,
                            nix::fcntl::PosixFadviseAdvice::POSIX_FADV_NOREUSE,
                        )?;

                        let file_len = send_chunks(ctx, chunker, tw, &mut f, Some(&mut on_chunk))?;
                        total_size += file_len as u64;

                        /* Tar entries are rounded to 512 bytes */
                        let remaining = 512 - (file_len % 512);
                        if remaining < 512 {
                            let buf = [0; 512];
                            let mut hdr_cursor = std::io::Cursor::new(&buf[..remaining as usize]);
                            total_size += send_chunks(
                                ctx,
                                chunker,
                                tw,
                                &mut hdr_cursor,
                                Some(&mut on_chunk),
                            )? as u64;
                        }

                        if file_len != metadata.len() as usize {
                            failure::bail!(
                                "length of {} changed while sending data",
                                ent_path.display()
                            );
                        }
                    }
                }

                if let Some(chunk_data) = chunker.force_split() {
                    let addr = crypto::keyed_content_address(&chunk_data, &ctx.hash_key);
                    on_chunk(&addr);
                    tw.add(
                        &addr,
                        ctx.data_ectx.encrypt_data(chunk_data, ctx.compression),
                    )?
                }

                if send_log_session.is_some() && ctx.use_stat_cache {
                    send_log_session
                        .as_ref()
                        .unwrap()
                        .borrow_mut()
                        .add_stat_addresses(&hash[..], total_size, &addresses)?;
                }
            }
        }
    }

    // The final entry in a tarball is two null files.
    let buf = [0; 1024];
    let mut trailer_cursor = std::io::Cursor::new(&buf[..]);
    send_chunks(ctx, chunker, tw, &mut trailer_cursor, None)?;
    Ok(())
}

pub struct RequestContext {
    pub progress: indicatif::ProgressBar,
    pub primary_key_id: Xid,
    pub hash_key_part_1: crypto::PartialHashKey,
    pub data_dctx: crypto::DecryptionContext,
    pub metadata_dctx: crypto::DecryptionContext,
}

pub fn request_data_stream(
    mut ctx: RequestContext,
    id: Xid,
    r: &mut dyn std::io::Read,
    w: &mut dyn std::io::Write,
    out: &mut dyn std::io::Write,
) -> Result<(), failure::Error> {
    write_packet(w, &Packet::TRequestData(TRequestData { id }))?;

    let metadata = match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
        Packet::RRequestData(req) => match req.metadata {
            Some(metadata) => metadata,
            None => failure::bail!("no stored items with the requested id"),
        },
        _ => failure::bail!("protocol error, expected ack request packet"),
    };

    // We only wanted to show the progress bar until we could start getting
    // messages, at this point we know the repository is unlocked.
    ctx.progress.finish_and_clear();

    match metadata {
        itemset::VersionedItemMetadata::V1(metadata) => {
            if ctx.primary_key_id != metadata.plain_text_metadata.primary_key_id {
                failure::bail!("decryption key does not match master key used for encryption");
            }

            let encrypted_metadata = metadata.decrypt_metadata(&mut ctx.metadata_dctx)?;
            let plain_text_metadata = metadata.plain_text_metadata;

            let hash_key =
                crypto::derive_hash_key(&ctx.hash_key_part_1, &encrypted_metadata.hash_key_part_2);

            let mut tr = htree::TreeReader::new(
                plain_text_metadata.tree_height,
                &plain_text_metadata.address,
            );

            while let Some((height, addr)) = tr.next_addr()? {
                let data = match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
                    Packet::Chunk(chunk) => {
                        if addr != chunk.address {
                            return Err(ClientError::CorruptOrTamperedDataError.into());
                        }
                        chunk.data
                    }
                    _ => failure::bail!("protocol error, expected begin chunk packet"),
                };

                if height == 0 {
                    let data = ctx.data_dctx.decrypt_data(data)?;
                    if addr != crypto::keyed_content_address(&data, &hash_key) {
                        return Err(ClientError::CorruptOrTamperedDataError.into());
                    }
                    out.write_all(&data)?;
                } else {
                    if addr != htree::tree_block_address(&data) {
                        return Err(ClientError::CorruptOrTamperedDataError.into());
                    }
                    tr.push_level(height - 1, data)?;
                }
            }

            out.flush()?;
            Ok(())
        }
    }
}

pub fn gc(
    progress: indicatif::ProgressBar,
    r: &mut dyn std::io::Read,
    w: &mut dyn std::io::Write,
) -> Result<repository::GCStats, failure::Error> {
    write_packet(w, &Packet::TGc(TGc {}))?;

    loop {
        match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
            Packet::Progress(Progress::Notice(msg)) => {
                progress.println(&msg);
            }
            Packet::Progress(Progress::SetMessage(msg)) => {
                progress.set_message(&msg);
            }
            Packet::Progress(_) => (), /* Reserved unused. */
            Packet::RGc(rgc) => return Ok(rgc.stats),
            _ => failure::bail!("protocol error, expected gc pcket or progress packet."),
        };
    }
}

pub fn sync(
    progress: indicatif::ProgressBar,
    query_cache: &mut querycache::QueryCache,
    r: &mut dyn std::io::Read,
    w: &mut dyn std::io::Write,
) -> Result<(), failure::Error> {
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
        _ => failure::bail!("protocol error, expected items packet"),
    };

    // At this point we know we have the remote lock, update message.
    progress.set_message("syncing remote items...");

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
            _ => failure::bail!("protocol error, expected items packet"),
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
) -> Result<(), failure::Error> {
    // If the user is watching, we want to set the progress
    // bar as late as possible so we don't obscure the
    // 'acquiring repository lock...' message. Here we just
    // send an empty RmItems, so that when the server responds
    // we know the repository locks are held and we can
    // start deleting items in batches.
    // One extra round trip in exchange for a far better user debugging experience,
    // but only when we know they are watching.
    if !progress.is_hidden() {
        write_packet(w, &Packet::TRmItems(vec![]))?;
        match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
            Packet::RRmItems => {}
            _ => failure::bail!("protocol error, expected RRmItems"),
        }
    }

    progress.set_message("removing items...");

    for chunked_ids in ids.chunks(4096) {
        let ids = chunked_ids.to_vec();
        write_packet(w, &Packet::TRmItems(ids))?;
        match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
            Packet::RRmItems => {}
            _ => failure::bail!("protocol error, expected RRmItems"),
        }
    }
    Ok(())
}

pub fn hangup(w: &mut dyn std::io::Write) -> Result<(), failure::Error> {
    write_packet(w, &Packet::EndOfTransmission)?;
    Ok(())
}
