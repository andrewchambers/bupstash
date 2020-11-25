pub const COMPRESS_FOOTER_NO_COMPRESSION: u8 = 0;
pub const COMPRESS_FOOTER_ZSTD_COMPRESSED: u8 = 1;

pub const COMPRESS_MAX_SIZE: usize = 67108864;

#[derive(Clone, Copy)]
pub enum Scheme {
    None,
    Zstd,
}

fn noop_compress_chunk(mut data: Vec<u8>) -> Vec<u8> {
    data.push(COMPRESS_FOOTER_NO_COMPRESSION);
    data
}

fn zstd_compress_chunk(data: Vec<u8>) -> Vec<u8> {
    // Our max chunk and packet sizes means this should never happen.
    assert!(data.len() <= COMPRESS_MAX_SIZE);
    let mut compressed_data = zstd::block::compress(&data, 0).unwrap();
    if (compressed_data.len() + 4) >= data.len() {
        noop_compress_chunk(data)
    } else {
        compressed_data.reserve(5);
        let sz = data.len() as u32;
        compressed_data.push((sz & 0x000000ff) as u8);
        compressed_data.push(((sz & 0x0000ff00) >> 8) as u8);
        compressed_data.push(((sz & 0x00ff0000) >> 16) as u8);
        compressed_data.push(((sz & 0xff000000) >> 24) as u8);
        compressed_data.push(COMPRESS_FOOTER_ZSTD_COMPRESSED);
        compressed_data
    }
}

pub fn compress(scheme: Scheme, data: Vec<u8>) -> Vec<u8> {
    match scheme {
        Scheme::None => noop_compress_chunk(data),
        Scheme::Zstd => zstd_compress_chunk(data),
    }
}

pub fn decompress(mut data: Vec<u8>) -> Result<Vec<u8>, anyhow::Error> {
    if data.is_empty() {
        anyhow::bail!("data buffer too small, missing compression footer");
    }

    let data = match data[data.len() - 1] {
        footer if footer == COMPRESS_FOOTER_NO_COMPRESSION => {
            data.pop();
            data
        }
        footer if footer == COMPRESS_FOOTER_ZSTD_COMPRESSED => {
            data.pop();
            if data.len() < 4 {
                anyhow::bail!("data corrupt - zstd data footer missing decompressed size");
            }
            let data_len = data.len();
            let decompressed_sz = (((data[data_len - 1] as u32) << 24)
                | ((data[data_len - 2] as u32) << 16)
                | ((data[data_len - 3] as u32) << 8)
                | (data[data_len - 4] as u32)) as usize;
            // This limit helps prevent bad actors from causing ooms, bupstash
            // naturally limits chunks and metadata to a max size that is well below this.
            if decompressed_sz > COMPRESS_MAX_SIZE {
                anyhow::bail!("data corrupt - decompressed size is larger than application limits");
            }
            data.truncate(data.len() - 4);
            zstd::block::decompress(&data, decompressed_sz)?
        }
        _ => anyhow::bail!("unknown compression type in footer"),
    };
    Ok(data)
}

pub fn unauthenticated_decompress(data: Vec<u8>) -> Result<Vec<u8>, anyhow::Error> {
    match data.last() {
        None => anyhow::bail!("data buffer too small, missing compression footer"),
        Some(f) if *f == COMPRESS_FOOTER_NO_COMPRESSION => decompress(data),
        // Once we are confident in the security/memory safety of our decompression function,
        // we can shift to enabling compression of the unauthenticated data.
        Some(f) => anyhow::bail!(
            "decompression of unauthenticated data is currently disabled (encryption footer is {})",
            *f
        ),
    }
}
