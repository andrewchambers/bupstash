use std::convert::TryInto;

pub const COMPRESS_FOOTER_NONE: u8 = 0;
pub const COMPRESS_FOOTER_LZ4: u8 = 1;
pub const COMPRESS_FOOTER_ZSTD: u8 = 2;

pub const COMPRESS_MAX_SIZE: usize = 67108864;

#[derive(Clone, Copy)]
pub enum Scheme {
    None,
    Lz4,
    Zstd { level: i32 },
}

pub fn parse_scheme(s: &str) -> Result<Scheme, anyhow::Error> {
    if s == "none" {
        return Ok(Scheme::None);
    }
    if s == "lz4" {
        return Ok(Scheme::Lz4);
    }
    if s == "zstd" {
        return Ok(Scheme::Zstd { level: 3 });
    }

    if s.starts_with("zstd:") {
        let spec_parts: Vec<&str> = s.split(':').collect();
        if spec_parts.len() != 2 {
            anyhow::bail!("invalid zstd compression level, expected a number");
        }
        match spec_parts[1].parse() {
            Ok(level) => {
                if !(1..=19).contains(&level) {
                    anyhow::bail!("zstd compression level must be in the range 1-19");
                }
                return Ok(Scheme::Zstd { level });
            }
            Err(_) => anyhow::bail!("zstd compression level must be a number"),
        }
    }
    anyhow::bail!("invalid compression scheme, expected one of none, lz4, zstd[:$level]")
}

pub fn compress(scheme: Scheme, mut data: Vec<u8>) -> Vec<u8> {
    assert!(data.len() <= COMPRESS_MAX_SIZE);

    let compressed_data = match scheme {
        Scheme::None => {
            data.push(COMPRESS_FOOTER_NONE);
            return data;
        }
        Scheme::Lz4 => {
            let mut compressed_data = lz4::block::compress(&data, None, false).unwrap();
            compressed_data.reserve(5);
            let sz = data.len() as u32;
            compressed_data.extend_from_slice(&u32::to_le_bytes(sz)[..]);
            compressed_data.push(COMPRESS_FOOTER_LZ4);
            compressed_data
        }
        Scheme::Zstd { level } => {
            let mut compressed_data: Vec<u8> =
                Vec::with_capacity(zstd_safe::compress_bound(data.len()) + 1);
            zstd_safe::compress(&mut compressed_data, &data, level).unwrap();
            compressed_data.push(COMPRESS_FOOTER_ZSTD);
            compressed_data
        }
    };

    if (compressed_data.len()) > data.len() {
        data.push(COMPRESS_FOOTER_NONE);
        return data;
    }

    compressed_data
}

pub fn decompress(mut data: Vec<u8>) -> Result<Vec<u8>, anyhow::Error> {
    match data.pop() {
        Some(COMPRESS_FOOTER_NONE) => Ok(data),
        Some(COMPRESS_FOOTER_LZ4) => {
            if data.len() < 4 {
                anyhow::bail!("data corrupt - compression footer missing decompressed size");
            }
            let data_len = data.len();
            let decompressed_sz =
                u32::from_le_bytes(data[data_len - 4..data_len].try_into().unwrap()) as usize;
            // This limit helps prevent bad actors from causing ooms, bupstash
            // naturally limits chunks and metadata to a max size that is well below this.
            if decompressed_sz > COMPRESS_MAX_SIZE {
                anyhow::bail!("data corrupt - decompressed size is larger than application limits");
            }
            data.truncate(data.len() - 4);
            Ok(lz4::block::decompress(&data, Some(decompressed_sz as i32))?)
        }
        Some(COMPRESS_FOOTER_ZSTD) => {
            let max_decompressed_sz = zstd_safe::decompress_bound(&data)
                .unwrap()
                .try_into()
                .unwrap();
            let mut decompressed: Vec<u8> = Vec::with_capacity(max_decompressed_sz);
            match zstd_safe::decompress(&mut decompressed, &data) {
                Ok(_) => Ok(decompressed),
                Err(_) => anyhow::bail!("error during zstd decompression"),
            }
        }
        Some(_) => anyhow::bail!("unknown decompression footer, don't know how to decompress data"),
        None => anyhow::bail!("data missing compression footer"),
    }
}

pub fn unauthenticated_decompress(data: Vec<u8>) -> Result<Vec<u8>, anyhow::Error> {
    match data.last() {
        None => anyhow::bail!("data buffer too small, missing compression footer"),
        Some(f) if *f == COMPRESS_FOOTER_NONE => decompress(data),
        // Once we are confident in the security/memory safety of our decompression function,
        // we can shift to enabling compression of the unauthenticated data.
        Some(f) => anyhow::bail!(
            "decompression of unauthenticated data is currently disabled (encryption footer is {})",
            *f
        ),
    }
}
