use super::address::*;
use super::xid::*;
use std::path::PathBuf;

pub struct SendLog {
    conn: rusqlite::Connection,
}

pub struct SendLogTx<'a> {
    sequence_number: i64,
    tx: rusqlite::Transaction<'a>,
}

impl SendLog {
    pub fn open(p: &PathBuf) -> Result<SendLog, failure::Error> {
        let mut conn = rusqlite::Connection::open(p)?;
        conn.query_row("pragma journal_mode=WAL;", rusqlite::NO_PARAMS, |_r| Ok(()))?;
        conn.busy_timeout(std::time::Duration::new(600, 0))?;
        let tx = conn.transaction()?;
        tx.execute(
            "create table if not exists LogMeta(Key, Value, unique(Key)); ",
            rusqlite::NO_PARAMS,
        )?;

        match tx.query_row(
            "select Value from LogMeta where Key = 'schema-version';",
            rusqlite::NO_PARAMS,
            |r| {
                let v: i64 = r.get(0)?;
                Ok(v)
            },
        ) {
            Ok(v) => {
                if v != 0 {
                    failure::bail!("send log at {:?} is from a different version of the software and must be removed manually", &p);
                }
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                tx.execute(
                    "insert into LogMeta(Key, Value) values('schema-version', 0);",
                    rusqlite::NO_PARAMS,
                )?;
            }
            Err(err) => return Err(err.into()),
        }

        let sequence_number = match tx.query_row(
            "select Value from LogMeta where Key = 'sequence-number';",
            rusqlite::NO_PARAMS,
            |r| Ok(r.get(0)?),
        ) {
            Ok(n) => n,
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                tx.execute(
                    "insert into LogMeta(Key, Value) values('sequence-number', 1);",
                    rusqlite::NO_PARAMS,
                )?;
                1
            }
            Err(err) => return Err(err.into()),
        };

        tx.execute(
            "create table if not exists Sent(Addr, Seq, unique(Addr)); ",
            rusqlite::NO_PARAMS,
        )?;

        tx.execute(
            "create table if not exists StatCache(Path, Hash, Addresses, Seq, unique(Path)); ",
            rusqlite::NO_PARAMS,
        )?;

        tx.execute(
            "create index if not exists StateCachePathHashIndex on StatCache(Path, Hash);",
            rusqlite::NO_PARAMS,
        )?;

        tx.commit()?;

        /* Simple policy to decide when to defragment our send log. */
        if cfg!(debug_assertions) || sequence_number % 10 == 0 {
            conn.execute("vacuum;", rusqlite::NO_PARAMS)?;
        }

        Ok(SendLog { conn })
    }

    pub fn transaction(self: &mut Self) -> Result<SendLogTx, failure::Error> {
        let tx = self.conn.transaction()?;

        let sequence_number = match tx.query_row(
            "select Value from LogMeta where Key = 'sequence-number';",
            rusqlite::NO_PARAMS,
            |r| Ok(r.get(0)?),
        ) {
            Ok(n) => n,
            Err(err) => return Err(err.into()),
        };

        tx.execute(
            "update LogMeta set Value = Value + 1 where Key = 'sequence-number';",
            rusqlite::NO_PARAMS,
        )?;

        Ok(SendLogTx {
            sequence_number,
            tx,
        })
    }
}

impl<'a> SendLogTx<'a> {
    pub fn send_id(self: &Self) -> Result<Option<Xid>, failure::Error> {
        match self.tx.query_row(
            "select value from LogMeta where key = 'send-id';",
            rusqlite::NO_PARAMS,
            |r| {
                let send_id: Xid = r.get(0)?;
                Ok(send_id)
            },
        ) {
            Ok(send_id) => Ok(Some(send_id)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(err) => Err(err.into()),
        }
    }

    pub fn clear_log(self: &Self) -> Result<(), failure::Error> {
        self.tx
            .execute("delete from StatCache;", rusqlite::NO_PARAMS)?;
        self.tx.execute("delete from Sent;", rusqlite::NO_PARAMS)?;
        self.tx.execute(
            "delete from LogMeta where Key = 'send-id';",
            rusqlite::NO_PARAMS,
        )?;
        Ok(())
    }

    pub fn add_address(self: &Self, addr: &Address) -> Result<(), failure::Error> {
        let mut stmt = self
            .tx
            .prepare_cached("insert or replace into Sent(Addr, Seq) values(?, ?); ")?;
        stmt.execute(rusqlite::params![&addr.bytes[..], self.sequence_number])?;
        Ok(())
    }

    pub fn has_address(self: &Self, addr: &Address) -> Result<bool, failure::Error> {
        let mut stmt = self.tx.prepare_cached("select 1 from Sent where Addr=?;")?;
        match stmt.query_row(&[&addr.bytes[..]], |_r| Ok(())) {
            Ok(_) => Ok(true),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(false),
            Err(err) => Err(err.into()),
        }
    }

    pub fn add_stat(
        &self,
        p: &std::path::Path,
        hash: &[u8],
        addresses: &[u8],
    ) -> Result<(), failure::Error> {
        let p = p.to_str();
        let mut stmt = self.tx.prepare_cached(
            "insert or replace into StatCache(Seq, Path, Hash, Addresses) Values(?, ?, ?, ?);",
        )?;
        stmt.execute(rusqlite::params![self.sequence_number, p, hash, addresses])?;
        Ok(())
    }

    pub fn lookup_stat(
        &self,
        p: &std::path::Path,
        hash: &[u8],
    ) -> Result<Option<Vec<u8>>, failure::Error> {
        let p = p.to_str();

        let mut stmt = self
            .tx
            .prepare_cached("select Addresses from StatCache where Path = ? and Hash = ?;")?;

        let addresses = match stmt.query_row(rusqlite::params![p, hash], |r| Ok(r.get(0)?)) {
            Ok(addresses) => addresses,
            Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
            Err(err) => return Err(err.into()),
        };

        let mut stmt = self
            .tx
            .prepare_cached("update StatCache set Seq = ? where Path = ? and Hash = ?;")?;

        stmt.execute(rusqlite::params![self.sequence_number, p, hash])?;

        Ok(Some(addresses))
    }

    pub fn commit(self: Self, id: &Xid) -> Result<(), failure::Error> {
        self.tx.execute(
            "delete from StatCache where Seq != ?;",
            &[self.sequence_number],
        )?;
        self.tx
            .execute("delete from Sent where Seq != ?;", &[self.sequence_number])?;
        self.tx.execute(
            "insert or replace into LogMeta(Key, Value) Values('send-id', ?);",
            &[id],
        )?;
        self.tx.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_log_sanity_test() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let log_path = {
            let mut d = PathBuf::from(tmp_dir.path());
            d.push("send.log");
            d
        };
        let id1 = Xid::new();
        let id2 = Xid::new();
        // Commit an address
        let mut sendlog = SendLog::open(&log_path).unwrap();
        let addr = Address::default();
        let tx = sendlog.transaction().unwrap();
        assert_eq!(tx.send_id().unwrap(), None);
        tx.add_address(&addr).unwrap();
        assert!(tx.has_address(&addr).unwrap());
        tx.commit(&id1).unwrap();
        drop(sendlog);

        // Ensure address is still present after reopening db.
        let mut sendlog = SendLog::open(&log_path).unwrap();
        let tx = sendlog.transaction().unwrap();
        assert_eq!(tx.send_id().unwrap(), Some(id1));
        assert!(tx.has_address(&addr).unwrap());

        // Drop tx to avoid ab cycling
        tx.commit(&id2).unwrap();
        drop(sendlog);

        let mut sendlog = SendLog::open(&log_path).unwrap();
        let tx = sendlog.transaction().unwrap();
        // Address should have been cycled.
        assert!(!tx.has_address(&addr).unwrap());
    }

    #[test]
    fn stat_cache_sanity_test() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let log_path = {
            let mut d = PathBuf::from(tmp_dir.path());
            d.push("send.log");
            d
        };
        let id1 = Xid::new();
        let id2 = Xid::new();
        let mut sendlog = SendLog::open(&log_path).unwrap();
        let tx = sendlog.transaction().unwrap();
        let hash = &[0; 32][..];
        let addresses = &[0; 64][..];
        tx.add_stat(&PathBuf::from("/foo"), hash, addresses)
            .unwrap();

        let addresses2: &[u8] = &tx
            .lookup_stat(&PathBuf::from("/foo"), hash)
            .unwrap()
            .unwrap();
        assert_eq!(addresses, addresses2);

        tx.commit(&id1).unwrap();

        let tx = sendlog.transaction().unwrap();

        assert!(&tx
            .lookup_stat(&PathBuf::from("/foo"), hash)
            .unwrap()
            .is_some());

        tx.clear_log().unwrap();

        assert!(&tx
            .lookup_stat(&PathBuf::from("/foo"), hash)
            .unwrap()
            .is_none());

        tx.commit(&id2).unwrap();

        drop(sendlog);
    }
}
