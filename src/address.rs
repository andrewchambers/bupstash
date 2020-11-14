use super::hex;
use serde::{Deserialize, Serialize};
use std::fmt;

pub const ADDRESS_SZ: usize = 32;

#[derive(Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Copy, Debug)]
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

    pub fn from_hex_str(s: &str) -> Result<Address, anyhow::Error> {
        if s.len() != ADDRESS_SZ * 2 {
            anyhow::bail!("invalid address '{}', length is not {} ", s, ADDRESS_SZ * 2);
        }
        let mut a = Address::default();
        hex::decode_string(s, &mut a.bytes)?;
        Ok(a)
    }

    pub fn as_hex_addr(&self) -> HexAddress {
        let mut result = HexAddress::default();
        hex::encode(&self.bytes, &mut result.bytes);
        result
    }
}

impl Default for Address {
    fn default() -> Address {
        Address::from_bytes(&[0; ADDRESS_SZ])
    }
}

pub struct HexAddress {
    bytes: [u8; ADDRESS_SZ * 2],
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
            bytes: [b'0'; ADDRESS_SZ * 2],
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
