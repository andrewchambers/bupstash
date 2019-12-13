use super::{hex, hydrogen};
use std::fmt;

pub const ADDRESS_SZ: usize = hydrogen::HASH_BYTES;

#[derive(PartialEq, Eq, Hash, Clone, Copy, Debug)]
pub struct Address {
    pub bytes: [u8; ADDRESS_SZ],
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_hex_addr())
    }
}

impl Address {
    pub fn from_bytes(bytes: &[u8; 32]) -> Address {
        Address { bytes: *bytes }
    }

    pub fn as_hex_addr(&self) -> HexAddress {
        let mut result = HexAddress::default();
        hex::encode(&self.bytes, &mut result.bytes);
        result
    }
}

impl Default for Address {
    fn default() -> Address {
        Address::from_bytes(&[0; 32])
    }
}

pub struct HexAddress {
    bytes: [u8; 64],
}

impl<'a> HexAddress {
    pub fn as_str(&'a self) -> &'a str {
        std::str::from_utf8(&self.bytes).unwrap()
    }
}

impl fmt::Display for HexAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", std::str::from_utf8(&self.bytes).unwrap())
    }
}

impl Default for HexAddress {
    fn default() -> HexAddress {
        HexAddress {
            bytes: ['0' as u8; 64],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_addr_to_hex_addr() {
        assert!(Address::default().as_hex_addr().bytes[..] == HexAddress::default().bytes[..]);
    }
}
