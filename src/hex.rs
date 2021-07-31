#[derive(Debug, PartialEq, thiserror::Error)]
pub enum HexError {
    #[error("invalid character in hex input")]
    InvalidCharacter,
    #[error("hex padding required")]
    PaddingRequired,
}

#[inline]
fn from_hex_byte(b: u8) -> Result<u8, HexError> {
    match b {
        48..=57 => Ok(b - 48),
        65..=70 => Ok(b - 65 + 10),
        97..=102 => Ok(b - 97 + 10),
        _ => Err(HexError::InvalidCharacter),
    }
}

pub fn decode(from: &[u8], to: &mut [u8]) -> Result<(), HexError> {
    if from.len() % 2 != 0 {
        return Err(HexError::PaddingRequired);
    }

    assert_eq!(from.len(), to.len() * 2);

    for i in 0..to.len() {
        let hi = from[2 * i];
        let lo = from[2 * i + 1];
        to[i] = from_hex_byte(hi)? << 4 | from_hex_byte(lo)?;
    }
    Ok(())
}

pub fn decode_string(from: &str, to: &mut [u8]) -> Result<(), HexError> {
    decode(from.as_bytes(), to)
}

pub fn easy_decode_string(from: &str) -> Result<Vec<u8>, HexError> {
    let n = from.len() / 2;
    let mut v = Vec::<u8>::with_capacity(n);
    // Safe because <u8> is a primitive type.
    // and v definitely has capacity for it's own capacity.
    unsafe { v.set_len(n) };
    match decode_string(from, &mut v) {
        Ok(()) => Ok(v),
        Err(e) => Err(e),
    }
}

#[inline]
fn to_hex_bytes(b: u8) -> (u8, u8) {
    let tab = b"0123456789abcdef";
    let hi = (b & 0xf0) >> 4;
    let lo = b & 0x0f;
    (tab[hi as usize], tab[lo as usize])
}

#[inline]
fn to_hex_chars(b: u8) -> (char, char) {
    let (hi, lo) = to_hex_bytes(b);
    (hi as char, lo as char)
}

// from.len() MUST be exactly half to.len()
pub fn encode(from: &[u8], to: &mut [u8]) {
    assert!(to.len() == 2 * from.len());

    for i in 0..from.len() {
        let (hi, lo) = to_hex_bytes(from[i]);
        to[2 * i] = hi;
        to[2 * i + 1] = lo;
    }
}

pub fn easy_encode_to_string(from: &[u8]) -> String {
    let mut s = String::with_capacity(2 * from.len());
    for b in from {
        let (hi, lo) = to_hex_chars(*b);
        s.push(hi);
        s.push(lo);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode() {
        let buf: [u8; 8] = [18, 52, 86, 120, 154, 188, 222, 240];
        let mut encoded: [u8; 16] = [0; 16];
        encode(&buf, &mut encoded);
        assert_eq!(std::str::from_utf8(&encoded).unwrap(), "123456789abcdef0");
    }

    #[test]
    fn test_easy_encode_to_string() {
        let buf: [u8; 8] = [18, 52, 86, 120, 154, 188, 222, 240];
        assert_eq!(easy_encode_to_string(&buf), "123456789abcdef0");
    }

    #[test]
    fn test_easy_decode_string() {
        let buf: [u8; 8] = [18, 52, 86, 120, 154, 188, 222, 240];
        assert_eq!(
            easy_decode_string("123456789abcdef0").unwrap().as_slice(),
            &buf[..]
        );
        assert_eq!(
            easy_decode_string("123456789ABCDEF0").unwrap().as_slice(),
            &buf[..]
        );
        assert_eq!(
            easy_decode_string("1234!6789ABCDEF0").unwrap_err(),
            HexError::InvalidCharacter
        );
        assert_eq!(
            easy_decode_string("23456789ABCDEF0").unwrap_err(),
            HexError::PaddingRequired
        );
    }
}
