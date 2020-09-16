// EXtended tar functionality.

use std::convert::TryInto;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;

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

pub fn dirent_to_tarheader(
    metadata: &std::fs::Metadata,
    full_path: &std::path::PathBuf,
    short_path: &std::path::PathBuf,
) -> Result<Vec<u8>, std::io::Error> {
    let mut pax_ext_records = Vec::new();
    let mut ustar_hdr = tar::Header::new_ustar();
    ustar_hdr.set_metadata(&metadata);

    match ustar_hdr.set_path(&short_path) {
        Ok(()) => (),
        Err(e) => {
            /* 100 is more than ustar can handle as a path parget */
            if short_path.as_os_str().len() > 100 {
                let path_bytes = short_path.as_os_str().as_bytes();
                let path_record = format_pax_extended_record(b"path", path_bytes);
                pax_ext_records.extend_from_slice(&path_record);
            } else {
                return Err(e.into());
            }
        }
    }

    match ustar_hdr.entry_type() {
        tar::EntryType::Char | tar::EntryType::Block => {
            ustar_hdr.set_device_major(dev_major(metadata.rdev()))?;
            ustar_hdr.set_device_minor(dev_minor(metadata.rdev()))?;
        }
        tar::EntryType::Symlink => {
            let target = std::fs::read_link(full_path)?;

            match ustar_hdr.set_link_name(&target) {
                Ok(()) => (),
                Err(err) => {
                    /* 100 is more than ustar can handle as a link parget */
                    if target.as_os_str().len() > 100 {
                        let target_bytes = target.as_os_str().as_bytes();
                        let target_record = format_pax_extended_record(b"linkpath", target_bytes);
                        pax_ext_records.extend_from_slice(&target_record);
                    } else {
                        return Err(err.into());
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

    Ok(hdr_bytes)
}
