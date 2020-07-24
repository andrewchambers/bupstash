use super::address::*;
use super::xid::*;
use std::path::PathBuf;

pub struct SendLog {
    conn: rusqlite::Connection,
}

pub struct SendLogSession<'a> {
    gc_generation: Xid,
    session_id: Xid,
    tx_active: bool,
    log: &'a mut SendLog,
}

impl SendLog {
    pub fn open(p: &PathBuf) -> Result<SendLog, failure::Error> {
        let mut conn = rusqlite::Connection::open(p)?;

        conn.busy_timeout(std::time::Duration::new(600, 0))?;
        conn.set_prepared_statement_cache_capacity(8);

        // We rely on exclusive locking for correctness, it is easier to
        // reason about in terms of cache invalidation.
        conn.query_row(
            "pragma locking_mode = EXCLUSIVE;",
            rusqlite::NO_PARAMS,
            |_r| Ok(()),
        )?;
        conn.query_row("pragma journal_mode = WAL;", rusqlite::NO_PARAMS, |_r| {
            Ok(())
        })?;

        let tx = conn.transaction()?;
        tx.execute(
            "create table if not exists LogMeta(Key primary key, Value) without rowid; ",
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
            Ok(n) => {
                tx.execute(
                    "update LogMeta set Value = Value + 1 where Key = 'sequence-number';",
                    rusqlite::NO_PARAMS,
                )?;
                n
            }
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
            "create table if not exists Sent(Address primary key, GCGeneration, LatestSessionId, ItemId) without rowid; ",
            rusqlite::NO_PARAMS,
        )?;

        tx.execute(
            "create table if not exists StatCache(Hash primary key, Addresses, GCGeneration, LatestSessionId, ItemId) without rowid; ",
            rusqlite::NO_PARAMS,
        )?;

        tx.commit()?;

        /* Simple policy to decide when to defragment our send log. */
        if cfg!(debug_assertions) || sequence_number % 10 == 0 {
            conn.execute("vacuum;", rusqlite::NO_PARAMS)?;
        }

        Ok(SendLog { conn })
    }

    pub fn session(self: &mut Self, gc_generation: Xid) -> Result<SendLogSession, failure::Error> {
        // We manually control the sqlite3 transaction so we are able
        // to issue checkpoints and commit part way through a send operation.
        self.conn.execute("begin;", rusqlite::NO_PARAMS)?;

        Ok(SendLogSession {
            gc_generation,
            session_id: Xid::new(),
            log: self,
            tx_active: true,
        })
    }

    pub fn last_send_id(self: &Self) -> Result<Option<Xid>, failure::Error> {
        match self.conn.query_row(
            "select value from LogMeta where key = 'last-send-id';",
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
}

impl<'a> SendLogSession<'a> {
    pub fn last_send_id(self: &Self) -> Result<Option<Xid>, failure::Error> {
        self.log.last_send_id()
    }

    pub fn perform_cache_invalidations(
        self: &Self,
        had_send_id: bool,
    ) -> Result<(), failure::Error> {
        if !self.tx_active {
            panic!()
        };

        let last_send_id = self.log.last_send_id()?;

        if had_send_id {
            self.log.conn.execute(
                "delete from Sent where (GCGeneration != ?) and (ItemId != ?);",
                rusqlite::params![self.gc_generation, last_send_id],
            )?;
            self.log.conn.execute(
                "delete from StatCache where (GCGeneration != ?) and (ItemId != ?);",
                rusqlite::params![self.gc_generation, last_send_id],
            )?;
        } else {
            self.log.conn.execute(
                "delete from Sent where GCGeneration != ?;",
                &[self.gc_generation],
            )?;
            self.log.conn.execute(
                "delete from StatCache where GCGeneration != ?;",
                &[self.gc_generation],
            )?;
        }

        Ok(())
    }

    pub fn add_address(self: &Self, addr: &Address) -> Result<(), failure::Error> {
        if !self.tx_active {
            failure::bail!("no active transaction");
        };

        // We update and not replace so we can keep an old item id if it exists.
        let mut stmt = self.log.conn.prepare_cached(
            "insert into Sent(GCGeneration, LatestSessionId, Address) values($1, $2, $3) \
             on conflict(Address) do update set LatestSessionId = $2;",
        )?;

        stmt.execute(rusqlite::params![
            self.gc_generation,
            self.session_id,
            &addr.bytes[..]
        ])?;
        Ok(())
    }

    pub fn cached_address(self: &Self, addr: &Address) -> Result<bool, failure::Error> {
        let mut stmt = self
            .log
            .conn
            .prepare_cached("select 1 from Sent where Address = ?;")?;

        let hit = match stmt.query_row(&[&addr.bytes[..]], |_r| Ok(())) {
            Ok(_) => true,
            Err(rusqlite::Error::QueryReturnedNoRows) => false,
            Err(err) => return Err(err.into()),
        };

        Ok(hit)
    }

    pub fn add_stat_addresses(&self, hash: &[u8], addresses: &[u8]) -> Result<(), failure::Error> {
        if !self.tx_active {
            failure::bail!("no active transaction");
        };

        // We update and not replace so we can keep an old item id if it exists.
        let mut stmt = self.log.conn.prepare_cached(
            "insert into StatCache(GCGeneration, LatestSessionId, Hash, Addresses) Values($1, $2, $3, $4) \
            on conflict(Hash) do update set LatestSessionId = $2;"
        )?;

        stmt.execute(rusqlite::params![
            self.gc_generation,
            self.session_id,
            hash,
            addresses
        ])?;

        // It's unclear to me if something like the following is worth doing:
        //
        // let mut addr = Address::default();
        // for bytes in addresses.chunks(ADDRESS_SZ) {
        //    addr.bytes[..].clone_from_slice(bytes);
        // }
        // self.add_address(&addr)?;
        //
        // We know the server has these addresses, but the higher level
        // stat cache already skips sending them.

        Ok(())
    }

    pub fn cached_stat_addresses(&self, hash: &[u8]) -> Result<Option<Vec<u8>>, failure::Error> {
        let mut stmt = self
            .log
            .conn
            .prepare_cached("select Addresses from StatCache where Hash = ?;")?;

        let addresses = match stmt.query_row(rusqlite::params![hash], |r| Ok(r.get(0)?)) {
            Ok(addresses) => addresses,
            Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
            Err(err) => return Err(err.into()),
        };

        Ok(Some(addresses))
    }

    pub fn checkpoint(&mut self) -> Result<(), failure::Error> {
        debug_assert!(self.tx_active);

        self.log.conn.execute("commit;", rusqlite::NO_PARAMS)?;
        self.tx_active = false;
        self.log.conn.execute("begin;", rusqlite::NO_PARAMS)?;
        self.tx_active = true;

        Ok(())
    }

    pub fn commit(mut self, id: &Xid) -> Result<(), failure::Error> {
        if !self.tx_active {
            failure::bail!("no active transaction");
        };

        // To keep the cache bounded, delete everything
        // that was not sent or updated during the current session.
        self.log.conn.execute(
            "delete from StatCache where LatestSessionId != ?;",
            &[&self.session_id],
        )?;

        self.log.conn.execute(
            "delete from Sent where LatestSessionId != ?;",
            &[&self.session_id],
        )?;

        self.log.conn.execute(
            "update StatCache set ItemId = ? where LatestSessionId = ?;",
            &[id, &self.session_id],
        )?;

        self.log.conn.execute(
            "update Sent set ItemId = ? where LatestSessionId = ?;",
            &[id, &self.session_id],
        )?;

        self.log.conn.execute(
            "insert or replace into LogMeta(Key, Value) Values('last-send-id', ?);",
            &[id],
        )?;

        self.log.conn.execute("commit;", rusqlite::NO_PARAMS)?;
        self.tx_active = false;
        Ok(())
    }
}

impl<'a> Drop for SendLogSession<'a> {
    fn drop(&mut self) {
        if self.tx_active {
            self.log
                .conn
                .execute("rollback;", rusqlite::NO_PARAMS)
                .unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_address_commit() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let log_path = {
            let mut d = PathBuf::from(tmp_dir.path());
            d.push("send.log");
            d
        };

        let gc_generation = Xid::new();
        let id = Xid::new();

        let addr = Address::default();

        // Commit an address
        let mut sendlog = SendLog::open(&log_path).unwrap();
        {
            let session = sendlog.session(gc_generation).unwrap();

            assert!(!session.cached_address(&addr).unwrap());
            assert!(!session.cached_stat_addresses(&[32; 0]).unwrap().is_some());
            session.add_address(&addr).unwrap();
            session.add_stat_addresses(&[32; 0], &[]).unwrap();
            assert!(session.cached_address(&addr).unwrap());
            assert!(session.cached_stat_addresses(&[32; 0]).unwrap().is_some());
            session.commit(&id).unwrap();
        }
        drop(sendlog);

        let mut sendlog = SendLog::open(&log_path).unwrap();
        {
            let session = sendlog.session(gc_generation).unwrap();
            assert_eq!(session.last_send_id().unwrap(), Some(id));
            session.perform_cache_invalidations(false).unwrap();
            // gc_generation is the same, so we keep cache.
            assert!(session.cached_address(&addr).unwrap());
            assert!(session.cached_stat_addresses(&[32; 0]).unwrap().is_some());
        }
        drop(sendlog);

        let mut sendlog = SendLog::open(&log_path).unwrap();
        {
            let session = sendlog.session(gc_generation).unwrap();
            assert_eq!(session.last_send_id().unwrap(), Some(id));
            session.perform_cache_invalidations(true).unwrap();
            // gc_generation is the same and we have the item id so we keep cache.
            assert!(session.cached_address(&addr).unwrap());
            assert!(session.cached_stat_addresses(&[32; 0]).unwrap().is_some());
        }
        drop(sendlog);

        let mut sendlog = SendLog::open(&log_path).unwrap();
        {
            let session = sendlog.session(Xid::new()).unwrap();
            assert_eq!(session.last_send_id().unwrap(), Some(id));
            session.perform_cache_invalidations(false).unwrap();
            // gc_generation differs, and we do not have the item id so we discard cache.
            assert!(!session.cached_address(&addr).unwrap());
            assert!(!session.cached_stat_addresses(&[32; 0]).unwrap().is_some());
        }
        drop(sendlog);
    }

    #[test]
    fn cache_address_checkpoint() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let log_path = {
            let mut d = PathBuf::from(tmp_dir.path());
            d.push("send.log");
            d
        };

        let gc_generation = Xid::new();
        let addr = Address::default();

        // checkpoint an address
        let mut sendlog = SendLog::open(&log_path).unwrap();
        {
            let mut session = sendlog.session(gc_generation).unwrap();
            session.add_address(&addr).unwrap();
            session.add_stat_addresses(&[32; 0], &[]).unwrap();
            session.checkpoint().unwrap();
        }
        drop(sendlog);

        let mut sendlog = SendLog::open(&log_path).unwrap();
        {
            let session = sendlog.session(gc_generation).unwrap();
            session.perform_cache_invalidations(false).unwrap();
            // gc_generation is the same, so we keep cache.
            assert!(session.cached_address(&addr).unwrap());
            assert!(session.cached_stat_addresses(&[32; 0]).unwrap().is_some());
        }
        drop(sendlog);

        let mut sendlog = SendLog::open(&log_path).unwrap();
        {
            let session = sendlog.session(gc_generation).unwrap();
            session.perform_cache_invalidations(true).unwrap();
            // gc_generation is the same so we keep cache.
            assert!(session.cached_address(&addr).unwrap());
            assert!(session.cached_stat_addresses(&[32; 0]).unwrap().is_some());
        }
        drop(sendlog);

        let mut sendlog = SendLog::open(&log_path).unwrap();
        {
            let session = sendlog.session(Xid::new()).unwrap();
            session.perform_cache_invalidations(false).unwrap();
            // gc_generation differs, so we discard cache.
            assert!(!session.cached_address(&addr).unwrap());
            assert!(!session.cached_stat_addresses(&[32; 0]).unwrap().is_some());
        }
        drop(sendlog);
    }

    #[test]
    fn cache_address_commit_then_checkpoint() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let log_path = {
            let mut d = PathBuf::from(tmp_dir.path());
            d.push("send.log");
            d
        };

        let gc_generation = Xid::new();
        let id = Xid::new();

        let addr = Address::default();

        // Commit an address.
        let mut sendlog = SendLog::open(&log_path).unwrap();
        {
            let session = sendlog.session(gc_generation).unwrap();
            session.add_address(&addr).unwrap();
            session.add_stat_addresses(&[32; 0], &[]).unwrap();
            session.commit(&id).unwrap();
        }
        drop(sendlog);

        // checkpoint that address.
        let mut sendlog = SendLog::open(&log_path).unwrap();
        {
            let mut session = sendlog.session(gc_generation).unwrap();
            session.add_address(&addr).unwrap();
            session.add_stat_addresses(&[32; 0], &[]).unwrap();
            session.checkpoint().unwrap();
        }
        drop(sendlog);

        // checkpoint again, without adding..
        let mut sendlog = SendLog::open(&log_path).unwrap();
        {
            let mut session = sendlog.session(gc_generation).unwrap();
            session.checkpoint().unwrap();
        }
        drop(sendlog);

        // check we still have the cache.
        let mut sendlog = SendLog::open(&log_path).unwrap();
        {
            let session = sendlog.session(gc_generation).unwrap();
            assert!(session.cached_address(&addr).unwrap());
            assert!(session.cached_stat_addresses(&[32; 0]).unwrap().is_some());
            session.perform_cache_invalidations(true).unwrap();
            assert!(session.cached_address(&addr).unwrap());
            assert!(session.cached_stat_addresses(&[32; 0]).unwrap().is_some());
            session.perform_cache_invalidations(false).unwrap();
            assert!(session.cached_address(&addr).unwrap());
            assert!(session.cached_stat_addresses(&[32; 0]).unwrap().is_some());
        }
        drop(sendlog);

        let mut sendlog = SendLog::open(&log_path).unwrap();
        {
            let session = sendlog.session(Xid::new()).unwrap();
            session.perform_cache_invalidations(false).unwrap();
            assert!(!session.cached_address(&addr).unwrap());
            assert!(!session.cached_stat_addresses(&[32; 0]).unwrap().is_some());
        }
        drop(sendlog);
    }
}
