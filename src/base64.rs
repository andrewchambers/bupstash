use super::sodium;

// We use libsodium base64 as it removes some dependencies
// as we already have a hard dependency on libsodium.

pub fn encode(buf: &[u8]) -> String {
    let max_out_len = unsafe {
        sodium::sodium_base64_encoded_len(buf.len(), sodium::sodium_base64_VARIANT_ORIGINAL as i32)
    };

    let mut out_buf = vec![0; max_out_len];

    unsafe {
        assert!(!sodium::sodium_bin2base64(
            out_buf.as_mut_ptr() as *mut i8,
            out_buf.len(),
            buf.as_ptr(),
            buf.len(),
            sodium::sodium_base64_VARIANT_ORIGINAL as i32,
        )
        .is_null())
    };

    match out_buf.iter().position(|&v| v == 0) {
        Some(idx) => {
            out_buf.truncate(idx);
        }
        None => {
            panic!();
        }
    }

    String::from_utf8(out_buf).unwrap()
}

pub fn decode(data: &str) -> Option<Vec<u8>> {
    let mut out_len = 0;
    let mut out_buf = vec![0; data.len()];

    let rc = unsafe {
        sodium::sodium_base642bin(
            out_buf.as_mut_ptr(),
            out_buf.len(),
            data.as_ptr() as *const i8,
            data.len(),
            std::ptr::null(),
            &mut out_len as *mut usize,
            std::ptr::null_mut::<*const i8>(),
            sodium::sodium_base64_VARIANT_ORIGINAL as i32,
        )
    };

    if rc == 0 {
        assert!(out_len <= out_buf.len());
        out_buf.truncate(out_len);
        Some(out_buf)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode() {
        assert_eq!(encode(b""), "");
        assert_eq!(encode(b"a"), "YQ==");
        assert_eq!(encode(b"ab"), "YWI=");
        assert_eq!(encode(b"abc"), "YWJj");
        assert_eq!(encode(b"abcd"), "YWJjZA==");
        assert_eq!(encode(b"abcde"), "YWJjZGU=");
    }

    #[test]
    fn test_decode() {
        assert_eq!(decode("").unwrap(), b"");
        assert_eq!(decode("YQ==").unwrap(), b"a");
        assert_eq!(decode("YWI=").unwrap(), b"ab");
        assert_eq!(decode("YWJj").unwrap(), b"abc");
        assert_eq!(decode("YWJjZA==").unwrap(), b"abcd");
        assert_eq!(decode("YWJjZGU=").unwrap(), b"abcde");
    }
}
