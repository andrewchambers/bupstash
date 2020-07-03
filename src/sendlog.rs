use super::address::*;
use std::path::PathBuf;

pub struct SendLog {
    remember: i64,
    conn: rusqlite::Connection,
}

pub struct SendLogTx<'a> {
    remember: i64,
    sequence: i64,
    tx: rusqlite::Transaction<'a>,
}

impl SendLog {
    pub fn open(p: &PathBuf, remember: i64) -> Result<SendLog, failure::Error> {
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
            "select 1 from LogMeta where Key = 'sequence-number';",
            rusqlite::NO_PARAMS,
            |r| Ok(r.get(0)?),
        ) {
            Ok(seq_number) => seq_number,
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

        /* Simple policy to decide when to defragment our send log */
        if cfg!(debug_assertions) || sequence_number % 10 == 0 {
            conn.execute("vacuum;", rusqlite::NO_PARAMS)?;
        }

        Ok(SendLog { conn, remember })
    }

    pub fn transaction<'a>(
        self: &'a mut Self,
        gc_generation: &str,
    ) -> Result<SendLogTx<'a>, failure::Error> {
        let tx = self.conn.transaction()?;

        match tx.query_row(
            "select value from LogMeta where key = 'gc-generation';",
            rusqlite::NO_PARAMS,
            |r| {
                let generation: String = r.get(0)?;
                Ok(generation)
            },
        ) {
            Ok(old_generation) => {
                if gc_generation != old_generation {
                    tx.execute("delete from StatCache;", rusqlite::NO_PARAMS)?;
                    tx.execute("delete from Sent;", rusqlite::NO_PARAMS)?;
                    tx.execute(
                        "update LogMeta set Value = ? where Key = 'gc-generation';",
                        &[&gc_generation],
                    )?;
                }
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                tx.execute(
                    "insert into LogMeta(Key, Value) values('gc-generation', ?);",
                    &[&gc_generation],
                )?;
            }
            Err(err) => return Err(err.into()),
        }

        let sequence = tx.query_row(
            "select Value from LogMeta where Key = 'sequence-number';",
            rusqlite::NO_PARAMS,
            |r| {
                let n: i64 = r.get(0)?;
                Ok(n)
            },
        )?;

        Ok(SendLogTx {
            remember: self.remember,
            sequence,
            tx,
        })
    }
}

impl<'a> SendLogTx<'a> {
    pub fn add_address(self: &Self, addr: &Address) -> Result<(), failure::Error> {
        let mut stmt = self
            .tx
            .prepare_cached("insert or replace into Sent(Addr, Seq) values(?, ?); ")?;
        stmt.execute(rusqlite::params![&addr.bytes[..], self.sequence])?;
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
        stmt.execute(rusqlite::params![self.sequence + 1, p, hash, addresses])?;

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

        stmt.execute(rusqlite::params![self.sequence + 1, p, hash])?;

        Ok(Some(addresses))
    }

    pub fn commit(self: Self) -> Result<(), failure::Error> {
        self.tx.execute(
            "delete from StatCache where Seq <= ? ;",
            &[self.sequence - self.remember],
        )?;
        self.tx.execute(
            "delete from Sent where Seq <= ? ;",
            &[self.sequence - self.remember],
        )?;
        self.tx.execute(
            "update LogMeta set Value = ? where Key = 'sequence-number';",
            &[self.sequence + 1],
        )?;
        self.tx.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gc_generation_change_wipes_log() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let log_path = {
            let mut d = PathBuf::from(tmp_dir.path());
            d.push("send.log");
            d
        };
        // Commit an address
        let mut sendlog = SendLog::open(&log_path, 1).unwrap();
        let addr = Address::default();
        let tx = sendlog.transaction("123").unwrap();
        tx.add_address(&addr).unwrap();
        assert!(tx.has_address(&addr).unwrap());
        tx.commit().unwrap();
        drop(sendlog);

        // Ensure address is still present after reopening db.
        let mut sendlog = SendLog::open(&log_path, 1).unwrap();
        let addr = Address::default();
        let tx = sendlog.transaction("123").unwrap();
        assert!(tx.has_address(&addr).unwrap());
        // Drop tx to avoid ab cycling
        drop(tx);
        drop(sendlog);

        // Since the gc-generation changed, address should not
        // be there anymore.
        let mut sendlog = SendLog::open(&log_path, 1).unwrap();
        let addr = Address::default();
        let tx = sendlog.transaction("345").unwrap();
        assert!(!tx.has_address(&addr).unwrap());
    }

    #[test]
    fn address_cycling() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let log_path = {
            let mut d = PathBuf::from(tmp_dir.path());
            d.push("send.log");
            d
        };
        let mut sendlog = SendLog::open(&log_path, 1).unwrap();
        let addr = Address::default();
        // Commit adding an address
        let tx = sendlog.transaction("123").unwrap();
        assert!(!tx.has_address(&addr).unwrap());
        tx.add_address(&addr).unwrap();
        assert!(tx.has_address(&addr).unwrap());
        tx.commit().unwrap();
        // Start a new tx, ensure we still have that address.
        // then add the address again.
        let tx = sendlog.transaction("123").unwrap();
        assert!(tx.has_address(&addr).unwrap());
        tx.add_address(&addr).unwrap();
        assert!(tx.has_address(&addr).unwrap());
        tx.commit().unwrap();
        // Start a new tx, it should expire
        // when the sequence number hits the limit transaction cycles.
        let tx = sendlog.transaction("123").unwrap();
        tx.commit().unwrap();
        // Verify the value was cycled away.
        let tx = sendlog.transaction("123").unwrap();
        assert!(!tx.has_address(&addr).unwrap());
        tx.commit().unwrap();
    }

    #[test]
    fn stat_cache_sanity_test() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let log_path = {
            let mut d = PathBuf::from(tmp_dir.path());
            d.push("send.log");
            d
        };
        let mut sendlog = SendLog::open(&log_path, 1).unwrap();
        let tx = sendlog.transaction("abc").unwrap();
        let hash = &[0; 32][..];
        let addresses = &[0; 64][..];
        tx.add_stat(&PathBuf::from("/foo"), hash, addresses)
            .unwrap();

        let addresses2: &[u8] = &tx
            .lookup_stat(&PathBuf::from("/foo"), hash)
            .unwrap()
            .unwrap();
        assert_eq!(addresses, addresses2);

        tx.commit().unwrap();
        drop(sendlog);
    }
}
