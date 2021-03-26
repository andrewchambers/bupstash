use super::crypto;
use super::hex;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Copy)]
pub struct Xid {
    pub bytes: [u8; 16],
}

impl Xid {
    pub fn new() -> Self {
        let mut bytes = [0; 16];
        crypto::randombytes(&mut bytes[..]);
        Xid { bytes }
    }

    pub fn parse(s: &str) -> Result<Xid, anyhow::Error> {
        let mut bytes = [0; 16];
        let s = s.as_bytes();
        if s.len() != 32 {
            anyhow::bail!("invalid id, should be 32 characters long");
        }
        if hex::decode(s, &mut bytes[..]).is_err() {
            anyhow::bail!("invalid id, should be a hex value");
        }
        Ok(Xid { bytes })
    }

    fn as_hex(&self) -> [u8; 32] {
        let mut buf = [0; 32];
        hex::encode(&self.bytes[..], &mut buf[..]);
        buf
    }
}

impl Default for Xid {
    fn default() -> Xid {
        Xid { bytes: [0; 16] }
    }
}

impl fmt::Debug for Xid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let h = self.as_hex();
        write!(f, "ID({})", std::str::from_utf8(&h[..]).unwrap())
    }
}

impl fmt::Display for Xid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let h = self.as_hex();
        write!(f, "{}", std::str::from_utf8(&h[..]).unwrap())
    }
}

impl rusqlite::types::FromSql for Xid {
    fn column_result(v: rusqlite::types::ValueRef) -> rusqlite::types::FromSqlResult<Self> {
        v.as_blob().map(|b| {
            let mut id = Xid::default();
            id.bytes[..].clone_from_slice(&b);
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
