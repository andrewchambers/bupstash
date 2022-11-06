// EXtended tar functionality.

use super::index;
use std::convert::TryInto;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

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

pub fn index_entry_to_tarheader(
    ent: &index::IndexEntry,
    hard_link: Option<&PathBuf>,
) -> Result<Vec<u8>, anyhow::Error> {
    let mut pax_ext_records = Vec::new();
    let mut ustar_hdr = tar::Header::new_ustar();

    let tar_type = match &hard_link {
        Some(hard_link) => match ent.kind() {
            index::IndexEntryKind::Other => {
                anyhow::bail!(
                    "index entry {} has an unknown type",
                    ent.path.to_string_lossy()
                )
            }
            index::IndexEntryKind::Directory => anyhow::bail!(
                "index entry {} is a directory, so can't have a hard link to {}",
                ent.path.to_string_lossy(),
                hard_link.to_string_lossy(),
            ),
            _ => tar::EntryType::Link,
        },

        None => match ent.kind() {
            index::IndexEntryKind::Other => {
                anyhow::bail!(
                    "index entry {} has an unknown type",
                    ent.path.to_string_lossy()
                )
            }
            index::IndexEntryKind::Regular => tar::EntryType::Regular,
            index::IndexEntryKind::Symlink => tar::EntryType::Symlink,
            index::IndexEntryKind::Char => tar::EntryType::Char,
            index::IndexEntryKind::Block => tar::EntryType::Block,
            index::IndexEntryKind::Directory => tar::EntryType::Directory,
            index::IndexEntryKind::Fifo => tar::EntryType::Fifo,
        },
    };

    ustar_hdr.set_entry_type(tar_type);
    ustar_hdr.set_mode(ent.mode.0 as u32);
    ustar_hdr.set_mtime(ent.mtime.0);
    ustar_hdr.set_uid(ent.uid.0);
    ustar_hdr.set_gid(ent.gid.0);
    ustar_hdr.set_size(if hard_link.is_none() { ent.size.0 } else { 0 });
    ustar_hdr.set_device_major(ent.dev_major.0 as u32)?;
    ustar_hdr.set_device_minor(ent.dev_minor.0 as u32)?;

    match ustar_hdr.set_path(&ent.path) {
        Ok(()) => (),
        Err(e) => {
            /* 100 is more than ustar can handle as a path target */
            if ent.path.as_os_str().len() > 100 {
                let path_bytes = ent.path.as_os_str().as_bytes();
                let path_record = format_pax_extended_record(b"path", path_bytes);
                pax_ext_records.extend_from_slice(&path_record);
            } else {
                return Err(e.into());
            }
        }
    };

    if matches!(tar_type, tar::EntryType::Symlink | tar::EntryType::Link) {
        let target = if let Some(ref hard_link) = hard_link {
            hard_link
        } else {
            ent.link_target.as_ref().unwrap()
        };

        match ustar_hdr.set_link_name(target) {
            Ok(()) => (),
            Err(err) => {
                /* 100 is more than ustar can handle as a link target */
                if target.as_os_str().len() > 100 {
                    let target_record =
                        format_pax_extended_record(b"linkpath", target.as_os_str().as_bytes());
                    pax_ext_records.extend_from_slice(&target_record);
                } else {
                    return Err(err.into());
                }
            }
        }
    }

    ustar_hdr.set_cksum();

    match &ent.xattrs {
        Some(xattrs) => {
            let mut key_bytes = Vec::with_capacity(24);
            for (k, v) in xattrs.iter() {
                key_bytes.truncate(0);
                key_bytes.extend_from_slice(b"SCHILY.xattr.");
                key_bytes.extend_from_slice(k);
                pax_ext_records.extend_from_slice(&format_pax_extended_record(&key_bytes, v));
            }
        }
        None => (),
    }

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

    Ok(hdr_bytes)
}
