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
use failure::Fail;
use std::collections::BTreeMap;
use std::convert::From;
use std::convert::TryInto;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;

#[derive(Debug, Fail)]
pub enum ClientError {
    #[fail(display = "corrupt or tampered data")]
    CorruptOrTamperedDataError,
}

pub fn handle_server_info(r: &mut dyn std::io::Read) -> Result<ServerInfo, failure::Error> {
    match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
        Packet::ServerInfo(info) => {
            if info.protocol != "repo-0" {
                failure::bail!("remote protocol version mismatch");
            };
            Ok(info)
        }
        _ => failure::bail!("protocol error, expected server info packet"),
    }
}

struct ConnectionHtreeSink<'a, 'b> {
    tx: &'a Option<sendlog::SendLogTx<'b>>,
    w: &'a mut dyn std::io::Write,
}

impl<'a, 'b> htree::Sink for ConnectionHtreeSink<'a, 'b> {
    fn add_chunk(
        &mut self,
        addr: &Address,
        data: std::vec::Vec<u8>,
    ) -> std::result::Result<(), failure::Error> {
        match self.tx {
            Some(ref tx) => {
                if tx.has_address(addr)? {
                    tx.add_address(addr)?;
                    Ok(())
                } else {
                    write_packet(
                        self.w,
                        &Packet::Chunk(Chunk {
                            address: *addr,
                            data,
                        }),
                    )?;
                    tx.add_address(addr)?;
                    Ok(())
                }
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
    pub compression: crypto::DataCompression,
    pub use_stat_cache: bool,
    pub primary_key_id: Xid,
    pub hash_key: crypto::HashKey,
    pub data_ectx: crypto::EncryptionContext,
    pub metadata_ectx: crypto::EncryptionContext,
}

pub enum DataSource {
    Subprocess(Vec<String>),
    Readable(Box<dyn std::io::Read>),
    Directory(std::path::PathBuf),
}

pub fn send(
    ctx: &mut SendContext,
    r: &mut dyn std::io::Read,
    w: &mut dyn std::io::Write,
    mut send_log: Option<sendlog::SendLog>,
    tags: BTreeMap<String, Option<String>>,
    data: DataSource,
) -> Result<Xid, failure::Error> {
    let (send_log_tx, send_id) = match send_log {
        Some(ref mut send_log) => {
            let tx = send_log.transaction()?;
            let send_id = tx.send_id()?;
            (Some(tx), send_id)
        }
        None => (None, None),
    };

    write_packet(w, &Packet::TBeginSend(TBeginSend { delta_id: send_id }))?;

    let ack = match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
        Packet::RBeginSend(ack) => ack,
        _ => failure::bail!("protocol error, expected begin ack packet"),
    };

    if let Some(ref tx) = send_log_tx {
        if !ack.has_delta_id {
            tx.clear_log()?;
        }
    }

    let mut sink = ConnectionHtreeSink {
        tx: &send_log_tx,
        w,
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
        }
        DataSource::Readable(mut data) => {
            send_chunks(ctx, &mut chunker, &mut tw, &mut data, None)?;
        }
        DataSource::Directory(path) => {
            send_dir(ctx, &mut chunker, &mut tw, &send_log_tx, &path)?;
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
        hash_key_part_2: ctx.hash_key.part2.clone(),
        tags,
    };

    write_packet(
        w,
        &Packet::TAddItem(itemset::VersionedItemMetadata::V1(itemset::ItemMetadata {
            plain_text_metadata,
            encrypted_metadata: ctx.metadata_ectx.encrypt_data(
                serde_bare::to_vec(&e_metadata)?,
                crypto::DataCompression::Zstd,
            ),
        })),
    )?;

    match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
        Packet::RAddItem(id) => {
            if send_log_tx.is_some() {
                send_log_tx.unwrap().commit(&id)?;
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
                n_written += n_read;
            }
            Err(err) => return Err(err.into()),
        }
    }
}

fn format_pax_extended_record(key: &[u8], value: &[u8]) -> Vec<u8> {
    let mut record_len = 3 + key.len() + value.len();
    let mut record_len_s = format!("{}", record_len);
    // Whoever designed the pax_ext extended header format was a bit crazy.
    // We just loop until we have fixpoint record length.
    loop {
        if record_len_s.len() + 3 + key.len() + value.len() == record_len {
            break;
        }
        record_len = record_len_s.len() + 3 + key.len() + value.len();
        record_len_s = format!("{}", record_len);
    }

    let mut record = Vec::with_capacity(record_len);
    record.extend_from_slice(record_len_s.as_bytes());
    record.extend_from_slice(b" ");
    record.extend_from_slice(key);
    record.extend_from_slice(b"=");
    record.extend_from_slice(value);
    record.extend_from_slice(b"\n");
    debug_assert!(record.len() == record_len);
    record
}

fn send_dir(
    ctx: &mut SendContext,
    chunker: &mut chunker::RollsumChunker,
    tw: &mut htree::TreeWriter,
    send_log_tx: &Option<sendlog::SendLogTx>,
    path: &std::path::PathBuf,
) -> Result<(), failure::Error> {
    let mut addresses: Vec<u8> = Vec::with_capacity(1024 * 128);
    let path = fsutil::absolute_path(&path)?;

    for entry in walkdir::WalkDir::new(&path) {
        let mut hash_state = crypto::HashState::new(Some(&ctx.hash_key));
        let entry = entry?;
        let entry_path = fsutil::absolute_path(entry.path())?;
        let mut short_entry_path = entry_path.strip_prefix(&path)?.to_path_buf();
        short_entry_path = if short_entry_path.to_str().unwrap_or("").is_empty() {
            std::path::PathBuf::from(".")
        } else {
            short_entry_path
        };
        let metadata = entry.metadata()?;

        let mut pax_ext_records = Vec::new();
        let mut ustar_hdr = tar::Header::new_ustar();
        ustar_hdr.set_metadata(&metadata);

        match ustar_hdr.set_path(&short_entry_path) {
            Ok(()) => (),
            Err(e) => {
                /* 100 is more than ustar can handle, this confirms the
                reason for failure... */
                if short_entry_path.as_os_str().len() > 100 {
                    let path_bytes = short_entry_path.as_os_str().as_bytes();
                    let path_record = format_pax_extended_record(b"path", path_bytes);
                    pax_ext_records.extend_from_slice(&path_record);
                } else {
                    return Err(e.into());
                }
            }
        }

        match ustar_hdr.entry_type() {
            tar::EntryType::Char | tar::EntryType::Block => {
                cfg_if::cfg_if! {
                    if #[cfg(linux)] {

                        fn dev_major(dev: u64) -> Result<u32, failure::Error> {
                            ((dev >> 32) & 0xffff_f000) |
                            ((dev >>  8) & 0x0000_0fff)
                        }

                        fn dev_minor(dev: u64) -> Result<u32, failure::Error> {
                            ((dev >> 12) & 0xffff_ff00) |
                            ((dev      ) & 0x0000_00ff)
                        }

                    } else {

                        fn dev_major(_dev: u64) -> Result<u32, failure::Error> {
                            failure::bail!("unable to get device major number on this platform (file a bug report)");
                        }

                        fn dev_minor(_dev: u64) -> Result<u32, failure::Error> {
                            failure::bail!("unable to get device minor number on this platform (file a bug report)");
                        }

                    }
                }

                ustar_hdr.set_device_major(dev_major(metadata.rdev())?)?;
                ustar_hdr.set_device_minor(dev_minor(metadata.rdev())?)?;
            }
            tar::EntryType::Symlink => {
                let target = std::fs::read_link(entry.path())?;

                match ustar_hdr.set_link_name(&target) {
                    Ok(()) => (),
                    Err(e) => {
                        /* 100 is more than ustar can handle, this confirms the
                        reason for failure... */
                        if target.as_os_str().len() > 100 {
                            let target_bytes = target.as_os_str().as_bytes();
                            let target_record =
                                format_pax_extended_record(b"linkpath", target_bytes);
                            pax_ext_records.extend_from_slice(&target_record);
                        } else {
                            return Err(e.into());
                        }
                    }
                }
            }
            _ => (),
        }

        ustar_hdr.set_cksum();

        let mut hdr_bytes = Vec::new();

        if !pax_ext_records.is_empty() {
            let mut pax_ext_hdr = tar::Header::new_ustar();
            pax_ext_hdr.set_entry_type(tar::EntryType::XHeader);
            pax_ext_hdr.set_size(pax_ext_records.len().try_into().unwrap());
            pax_ext_hdr.set_cksum();
            hdr_bytes.extend_from_slice(&pax_ext_hdr.as_bytes()[..]);
            hdr_bytes.extend_from_slice(&pax_ext_records);
            let remaining = 512 - (hdr_bytes.len() % 512);
            if remaining < 512 {
                let buf = [0; 512];
                hdr_bytes.extend_from_slice(&buf[..remaining as usize]);
            }
            debug_assert!(hdr_bytes.len() % 512 == 0);
        }

        hdr_bytes.extend_from_slice(&ustar_hdr.as_bytes()[..]);
        hash_state.update(&hdr_bytes);

        let hash = hash_state.finish();

        let cache_lookup = if send_log_tx.is_some() && ctx.use_stat_cache {
            send_log_tx
                .as_ref()
                .unwrap()
                .lookup_stat(&entry_path, &hash)?
        } else {
            None
        };

        match cache_lookup {
            Some(cached_addresses) => {
                debug_assert!(cached_addresses.len() % ADDRESS_SZ == 0);
                let mut address = Address::default();
                for cached_address in cached_addresses.chunks(ADDRESS_SZ) {
                    address.bytes[..].clone_from_slice(cached_address);
                    tw.add_addr(0, &address)?;
                }
            }
            None => {
                let mut on_chunk = |addr: &Address| {
                    addresses.extend_from_slice(&addr.bytes[..]);
                };

                let mut hdr_cursor = std::io::Cursor::new(hdr_bytes);
                send_chunks(ctx, chunker, tw, &mut hdr_cursor, Some(&mut on_chunk))?;

                if ustar_hdr.entry_type().is_file() {
                    let mut f = std::fs::File::open(&entry_path)?;
                    let len = send_chunks(ctx, chunker, tw, &mut f, Some(&mut on_chunk))?;
                    /* Tar entries are rounded to 512 bytes */
                    let remaining = 512 - (len % 512);
                    if remaining < 512 {
                        let buf = [0; 512];
                        let mut hdr_cursor = std::io::Cursor::new(&buf[..remaining as usize]);
                        send_chunks(ctx, chunker, tw, &mut hdr_cursor, Some(&mut on_chunk))?;
                    }
                    if len != metadata.len() as usize {
                        failure::bail!(
                            "file length of {} changed while sending data",
                            entry.path().display()
                        );
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

                if send_log_tx.is_some() && ctx.use_stat_cache {
                    send_log_tx
                        .as_ref()
                        .unwrap()
                        .add_stat(&entry_path, &hash[..], &addresses)?;
                }
            }
        }

        addresses.clear();
    }
    let buf = [0; 1024];
    let mut trailer_cursor = std::io::Cursor::new(&buf[..]);
    send_chunks(ctx, chunker, tw, &mut trailer_cursor, None)?;
    Ok(())
}

pub struct RequestContext {
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
    r: &mut dyn std::io::Read,
    w: &mut dyn std::io::Write,
) -> Result<repository::GCStats, failure::Error> {
    write_packet(w, &Packet::TGc(TGc {}))?;
    let stats = match read_packet(r, DEFAULT_MAX_PACKET_SIZE)? {
        Packet::RGc(rgc) => rgc.stats,
        _ => failure::bail!("protocol error, expected gc complete packet"),
    };
    Ok(stats)
}

pub fn sync(
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
    ids: Vec<Xid>,
    r: &mut dyn std::io::Read,
    w: &mut dyn std::io::Write,
) -> Result<(), failure::Error> {
    for chunked_ids in ids.chunks(1000000) {
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
