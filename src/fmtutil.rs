use super::hex;
use super::index;
use std::os::unix::ffi::OsStrExt;

pub fn format_timestamp(ts: &chrono::DateTime<chrono::Utc>, utc_timestamps: bool) -> String {
    let tsfmt = "%Y/%m/%d %T";
    if utc_timestamps {
        ts.format(tsfmt).to_string()
    } else {
        chrono::DateTime::<chrono::Local>::from(*ts)
            .format(tsfmt)
            .to_string()
    }
}

pub fn format_size(n: u64) -> String {
    // Binary units, not SI units.
    const K: u64 = 1024;
    const M: u64 = 1024 * K;
    const G: u64 = 1024 * M;
    const T: u64 = 1024 * G;
    const P: u64 = 1024 * T;

    if n > P {
        format!("{}.{:0>2}PiB", n / P, (n % P) / (P / 100))
    } else if n > T {
        format!("{}.{:0>2}TiB", n / T, (n % T) / (T / 100))
    } else if n > G {
        format!("{}.{:0>2}GiB", n / G, (n % G) / (G / 100))
    } else if n > M {
        format!("{}.{:0>2}MiB", n / M, (n % M) / (M / 100))
    } else if n > K {
        format!("{}.{:0>2}KiB", n / K, (n % K) / (K / 100))
    } else {
        format!("{}B", n)
    }
}

pub struct IndexHumanDisplayWidths {
    pub human_size_digits: usize,
}

pub fn estimate_index_human_display_widths(
    index: &index::CompressedIndex,
) -> Result<IndexHumanDisplayWidths, anyhow::Error> {
    // If the index is large, just assume we have the full range of values.
    // The cost of formatting a huge index perfectly is too large.
    if index.compressed_size() > 512 * 1024 {
        Ok(IndexHumanDisplayWidths {
            human_size_digits: 11, // 'nnnn.nn UUU'
        })
    } else {
        let mut human_size_digits = 0;
        for ent in index.iter() {
            let ent = ent?;
            human_size_digits = human_size_digits.max(format_size(ent.size.0).len())
        }
        Ok(IndexHumanDisplayWidths { human_size_digits })
    }
}

pub fn format_human_content_listing(
    ent: &index::IndexEntry,
    utc_timestamps: bool,
    widths: &IndexHumanDisplayWidths,
) -> String {
    let mut result = String::new();
    std::fmt::write(&mut result, format_args!("{}", ent.display_mode())).unwrap();
    let size = if ent.is_file() {
        format_size(ent.size.0)
    } else {
        "-".to_string()
    };
    let size_padding: String = " ".repeat(widths.human_size_digits - size.len());
    std::fmt::write(&mut result, format_args!(" {}{}", size, size_padding)).unwrap();
    let ts = chrono::NaiveDateTime::from_timestamp(ent.ctime.0 as i64, ent.ctime_nsec.0 as u32);
    let ts = chrono::DateTime::<chrono::Utc>::from_utc(ts, chrono::Utc);
    let ts = format_timestamp(&ts, utc_timestamps);
    std::fmt::write(&mut result, format_args!(" {}", ts)).unwrap();
    std::fmt::write(&mut result, format_args!(" {}", ent.path.to_string_lossy())).unwrap();
    result
}

pub fn format_jsonl1_content_listing(ent: &index::IndexEntry) -> Result<String, anyhow::Error> {
    let mut result = String::with_capacity(512);
    std::fmt::write(&mut result, format_args!("{{"))?;
    std::fmt::write(
        &mut result,
        format_args!("\"mode\":{}", serde_json::to_string(&ent.mode.0)?),
    )?;
    std::fmt::write(&mut result, format_args!(",\"size\":{}", ent.size.0))?;

    match ent.path.to_str() {
        Some(path) => std::fmt::write(
            &mut result,
            format_args!(",\"path\":{}", serde_json::to_string(path)?),
        )?,
        None => {
            let path = ent.path.as_os_str().as_bytes();
            std::fmt::write(
                &mut result,
                format_args!(",\"path\":{}", serde_json::to_string(path)?),
            )?
        }
    }
    std::fmt::write(
        &mut result,
        format_args!(",\"mtime\":{}", serde_json::to_string(&ent.mtime.0)?),
    )?;
    std::fmt::write(
        &mut result,
        format_args!(
            ",\"mtime_nsec\":{}",
            serde_json::to_string(&ent.mtime_nsec.0)?
        ),
    )?;
    std::fmt::write(
        &mut result,
        format_args!(",\"ctime\":{}", serde_json::to_string(&ent.ctime.0)?),
    )?;
    std::fmt::write(
        &mut result,
        format_args!(
            ",\"ctime_nsec\":{}",
            serde_json::to_string(&ent.ctime_nsec.0)?
        ),
    )?;
    std::fmt::write(
        &mut result,
        format_args!(",\"uid\":{}", serde_json::to_string(&ent.uid.0)?),
    )?;
    std::fmt::write(
        &mut result,
        format_args!(",\"gid\":{}", serde_json::to_string(&ent.gid.0)?),
    )?;
    std::fmt::write(
        &mut result,
        format_args!(",\"norm_dev\":{}", serde_json::to_string(&ent.norm_dev.0)?),
    )?;
    std::fmt::write(
        &mut result,
        format_args!(",\"nlink\":{}", serde_json::to_string(&ent.nlink.0)?),
    )?;
    std::fmt::write(
        &mut result,
        format_args!(",\"ino\":{}", serde_json::to_string(&ent.ino.0)?),
    )?;

    if ent.is_dev_node() {
        std::fmt::write(
            &mut result,
            format_args!(
                ",\"dev_major\":{}",
                serde_json::to_string(&ent.dev_major.0)?,
            ),
        )?;
        std::fmt::write(
            &mut result,
            format_args!(
                ",\"dev_minor\":{}",
                serde_json::to_string(&ent.dev_minor.0)?,
            ),
        )?;
    } else {
        result.push_str(",\"dev_major\":null,\"dev_minor\":null");
    }

    if let Some(ref xattrs) = ent.xattrs {
        result.push_str(",\"xattrs\":{");
        let mut first = true;
        for (k, v) in xattrs.iter() {
            let k = if let Some(k) = k.to_str() {
                serde_json::to_string(k)?
            } else {
                serde_json::to_string(k)?
            };

            let v = if let Ok(v) = std::str::from_utf8(v.as_slice()) {
                serde_json::to_string(v)?
            } else {
                serde_json::to_string(v)?
            };

            if first {
                first = false;
            } else {
                result.push(',');
            }

            result.push_str(&k);
            result.push(':');
            result.push_str(&v);
        }
        result.push('}');
    } else {
        result.push_str(",\"xattrs\":null");
    }

    std::fmt::write(&mut result, format_args!(",\"sparse\": {}", ent.sparse))?;

    if let Some(ref link_target) = ent.link_target {
        match link_target.to_str() {
            Some(path) => std::fmt::write(
                &mut result,
                format_args!(",\"link_target\":{}", serde_json::to_string(path)?),
            )?,
            None => {
                let link_target = link_target.as_os_str().as_bytes();
                std::fmt::write(
                    &mut result,
                    format_args!(",\"link_target\":{}", serde_json::to_string(link_target)?),
                )?
            }
        }
    } else {
        result.push_str(",\"link_target\":null");
    }

    match ent.data_hash {
        index::ContentCryptoHash::None => result.push_str(",\"data_hash\":null"),
        index::ContentCryptoHash::Blake3(h) => std::fmt::write(
            &mut result,
            format_args!(
                ",\"data_hash\":{}",
                serde_json::to_string(&format!("blake3:{}", hex::easy_encode_to_string(&h)))?
            ),
        )?,
    };
    std::fmt::write(&mut result, format_args!("}}"))?;
    Ok(result)
}
