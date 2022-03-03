use super::crypto;
use super::hex;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::fmt;

pub const XID_SZ: usize = 16;

#[derive(Serialize, Debug, Deserialize, Default, PartialEq, Eq, Hash, Clone, Copy)]
pub struct Xid {
    pub bytes: [u8; XID_SZ],
}

// Convert a slice of xids to a slice of bytes without any copying.
pub fn xids_to_bytes(xids: &[Xid]) -> &[u8] {
    assert!(std::mem::size_of::<Xid>() == XID_SZ);
    let n_bytes = xids.len() * XID_SZ;
    unsafe { std::slice::from_raw_parts(xids.as_ptr() as *const u8, n_bytes) }
}

impl Xid {
    pub fn new() -> Self {
        let mut bytes = [0; XID_SZ];
        crypto::randombytes(&mut bytes[..]);
        Xid { bytes }
    }

    pub fn parse(s: &str) -> Result<Xid, anyhow::Error> {
        let mut bytes = [0; XID_SZ];
        let s = s.as_bytes();
        if s.len() != 32 {
            anyhow::bail!("invalid id, should be 32 characters long");
        }
        if hex::decode(s, &mut bytes[..]).is_err() {
            anyhow::bail!("invalid id, should be a hex value");
        }
        Ok(Xid { bytes })
    }

    pub fn as_hex(&self) -> [u8; XID_SZ * 2] {
        let mut buf = [0; XID_SZ * 2];
        hex::encode(&self.bytes[..], &mut buf[..]);
        buf
    }

    pub fn from_slice(s: &[u8]) -> Result<Xid, anyhow::Error> {
        Ok(Xid {
            bytes: s.try_into()?,
        })
    }
}

impl fmt::Display for Xid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let h = self.as_hex();
        write!(f, "{}", std::str::from_utf8(&h[..]).unwrap())
    }
}

impl fmt::LowerHex for Xid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let h = self.as_hex();
        write!(f, "{}", std::str::from_utf8(&h[..]).unwrap())
    }
}

impl rusqlite::types::FromSql for Xid {
    fn column_result(v: rusqlite::types::ValueRef) -> rusqlite::types::FromSqlResult<Self> {
        v.as_blob().map(|b| {
            let mut id = Xid::default();
            id.bytes[..].clone_from_slice(b);
            id
        })
    }
}

impl rusqlite::types::ToSql for Xid {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput> {
        Ok(rusqlite::types::ToSqlOutput::from(&self.bytes[..]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default() {
        let u = Xid::default();
        assert_eq!(
            u.to_string(),
            "00000000000000000000000000000000".to_string()
        );

        assert_eq!(u, Xid::parse("00000000000000000000000000000000").unwrap(),);
    }
}
