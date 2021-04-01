use super::crypto;
use super::hex;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
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
    pub fn random() -> Address {
        let mut bytes = [0; ADDRESS_SZ];
        crypto::randombytes(&mut bytes);
        Address { bytes }
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Address {
        Address { bytes: *bytes }
    }

    pub fn from_slice(s: &[u8]) -> Result<Address, anyhow::Error> {
        Ok(Address {
            bytes: s.try_into()?,
        })
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

// Convert a slice of addresses to a slice of bytes without any copying.
pub fn addresses_to_bytes(addresses: &[Address]) -> &[u8] {
    assert!(std::mem::size_of::<Address>() == ADDRESS_SZ);
    let n_bytes = addresses.len() * ADDRESS_SZ;
    unsafe { std::slice::from_raw_parts(addresses.as_ptr() as *const u8, n_bytes) }
}

// Convert a slice of addresses to a slice of bytes without any copying.
// panics if alignment is wrong.
pub fn bytes_to_addresses(bytes: &[u8]) -> &[Address] {
    // We rely on alignment, flag any places our assumption is not true.
    assert!(((bytes.as_ptr() as usize) & (std::mem::align_of::<Address>() - 1)) == 0);
    assert!(std::mem::size_of::<Address>() == ADDRESS_SZ);
    let n_addresses = bytes.len() / ADDRESS_SZ;
    unsafe { std::slice::from_raw_parts(bytes.as_ptr() as *const Address, n_addresses) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_addr_to_hex_addr() {
        assert!(Address::default().as_hex_addr().bytes[..] == HexAddress::default().bytes[..]);
    }

    #[test]
    fn test_addresses_to_bytes() {
        let v = vec![Address::default()];
        let s = addresses_to_bytes(&v);
        assert_eq!(Address::from_slice(s).unwrap(), v[0])
    }

    #[test]
    fn test_bytes_to_addresses() {
        // Try to create an poorly unaligned allocation if it is
        // possible on the current platform.
        for _i in 0..100 {
            let bytes = [0; 64];
            let mut b = Vec::new();
            b.extend_from_slice(&bytes[..]);
            let s = bytes_to_addresses(&b);
            assert_eq!(Address::default(), s[0])
        }
    }
}
