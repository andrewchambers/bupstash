use super::address::*;
use super::index;
use super::xid::*;
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct SendLog {
    db_conn: rusqlite::Connection,
}

pub struct SendLogSession<'a> {
    gc_generation: Xid,
    session_id: Xid,
    tx_active: bool,
    log: &'a mut SendLog,
}

#[derive(Serialize, Deserialize)]
pub struct StatCacheEntry {
    pub total_size: u64,
    pub addresses: Vec<Address>,
    pub data_cursors: Vec<index::RelativeDataCursor>,
    pub hashes: Vec<index::ContentCryptoHash>,
}

const SCHEMA_VERSION: i64 = 4;

impl SendLog {
    pub fn open(p: &Path) -> Result<SendLog, anyhow::Error> {
        let mut db_conn = rusqlite::Connection::open(p)?;

        // Only one put per send log at a time.
        db_conn.query_row("PRAGMA locking_mode = EXCLUSIVE;", [], |_r| Ok(()))?;

        db_conn.busy_timeout(std::time::Duration::new(7 * 24 * 60 * 60, 0))?;

        // Immediate lock with exclusive mode immediately blocks all other writers for the life
        // of this open connection.
        let tx = db_conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.execute(
            "create table if not exists LogMeta(Key primary key, Value) without rowid;",
            [],
        )?;

        let needs_init = match tx.query_row(
            "select Value from LogMeta where Key = 'schema-version';",
            [],
            |r| {
                let v: i64 = r.get(0)?;
                Ok(v)
            },
        ) {
            Ok(v) => v != SCHEMA_VERSION,
            Err(rusqlite::Error::QueryReturnedNoRows) => true,
            Err(err) => return Err(err.into()),
        };

        let sequence_number = match tx.query_row(
            "select Value from LogMeta where Key = 'sequence-number';",
            [],
            |r| r.get(0),
        ) {
            Ok(n) => {
                tx.execute(
                    "update LogMeta set Value = Value + 1 where Key = 'sequence-number';",
                    [],
                )?;
                n
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                tx.execute(
                    "insert into LogMeta(Key, Value) values('sequence-number', 1);",
                    [],
                )?;
                1
            }
            Err(err) => return Err(err.into()),
        };

        tx.commit()?;

        /* Simple policy to decide when to defragment our send log. */
        if cfg!(debug_assertions) || sequence_number % 10 == 0 {
            db_conn.execute("vacuum;", [])?;
        }

        if needs_init {
            let mut tmp_conn = rusqlite::Connection::open(":memory:")?;

            let tx = tmp_conn.transaction()?;

            tx.execute(
                "create table LogMeta(Key primary key, Value) without rowid;",
                [],
            )?;

            tx.execute(
                "insert into LogMeta(Key, Value) values('schema-version', ?);",
                &[&SCHEMA_VERSION],
            )?;

            tx.execute(
                "insert into LogMeta(Key, Value) values('sequence-number', 1);",
                [],
            )?;

            tx.execute(
                "create table Sent(Address primary key, GCGeneration, LatestSessionId, ItemId) without rowid;",
                [],
            )?;

            tx.execute(
                "create table StatCache(Hash primary key, Cached, GCGeneration, LatestSessionId, ItemId) without rowid; ",
                [],
            )?;

            tx.commit()?;

            let backup = rusqlite::backup::Backup::new(&tmp_conn, &mut db_conn)?;
            if backup.step(-1)? != rusqlite::backup::StepResult::Done {
                anyhow::bail!("unable to start send log transaction");
            }
        }

        // On 64 bit platforms use sqlite3 memory mapped io.
        if std::mem::size_of::<usize>() == 8 {
            // 64GiB mmap size, just an estimate of the largest sendlog we are likely to see.
            db_conn.query_row("PRAGMA mmap_size=68719476736;", [], |_r| Ok(()))?;
        }

        // We want a rather large page cache for the send log.
        // default is -2000 which is 2000 * 1024 bytes.
        db_conn.execute("PRAGMA cache_size = -20000;", [])?;

        Ok(SendLog { db_conn })
    }

    pub fn session(&mut self, gc_generation: Xid) -> Result<SendLogSession, anyhow::Error> {
        // We manually control the sqlite3 transaction so we are able
        // to issue checkpoints and commit part way through a send operation.
        self.db_conn.execute("begin immediate;", [])?;

        Ok(SendLogSession {
            gc_generation,
            session_id: Xid::new(),
            log: self,
            tx_active: true,
        })
    }

    pub fn last_send_id(&self) -> Result<Option<Xid>, anyhow::Error> {
        match self.db_conn.query_row(
            "select value from LogMeta where key = 'last-send-id';",
            [],
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
    pub fn last_send_id(&self) -> Result<Option<Xid>, anyhow::Error> {
        self.log.last_send_id()
    }

    pub fn perform_cache_invalidations(&self, had_send_id: bool) -> Result<(), anyhow::Error> {
        if !self.tx_active {
            panic!()
        };

        let last_send_id = self.last_send_id()?;

        if had_send_id {
            self.log.db_conn.execute(
                "delete from Sent where (GCGeneration != ?) and (ItemId != ?);",
                rusqlite::params![self.gc_generation, last_send_id.unwrap()],
            )?;
            self.log.db_conn.execute(
                "delete from StatCache where (GCGeneration != ?) and (ItemId != ?);",
                rusqlite::params![self.gc_generation, last_send_id.unwrap()],
            )?;
        } else {
            self.log.db_conn.execute(
                "delete from Sent where GCGeneration != ?;",
                [self.gc_generation],
            )?;
            self.log.db_conn.execute(
                "delete from StatCache where GCGeneration != ?;",
                [self.gc_generation],
            )?;
        }

        Ok(())
    }

    pub fn add_address(&self, addr: &Address) -> Result<bool, anyhow::Error> {
        if !self.tx_active {
            anyhow::bail!("no active transaction");
        };

        // TODO I think we can do this in one query instead of two.
        let has_address = self.cached_address(addr)?;

        if has_address {
            let mut stmt = self
                .log
                .db_conn
                .prepare_cached("update Sent set LatestSessionId = ? where Address = ?;")?;
            stmt.execute(rusqlite::params![self.session_id, &addr.bytes[..]])?;
        } else {
            let mut stmt = self.log.db_conn.prepare_cached(
                "insert into Sent(GCGeneration, LatestSessionId, Address) values(?, ?, ?);",
            )?;
            stmt.execute(rusqlite::params![
                self.gc_generation,
                self.session_id,
                &addr.bytes[..]
            ])?;
        }

        Ok(!has_address)
    }

    pub fn cached_address(&self, addr: &Address) -> Result<bool, anyhow::Error> {
        let mut stmt = self
            .log
            .db_conn
            .prepare_cached("select 1 from Sent where Address = ?;")?;

        let hit = match stmt.query_row(&[&addr.bytes[..]], |_r| Ok(())) {
            Ok(_) => true,
            Err(rusqlite::Error::QueryReturnedNoRows) => false,
            Err(err) => return Err(err.into()),
        };

        Ok(hit)
    }

    pub fn add_stat_cache_data(
        &self,
        hash: &[u8],
        data: &StatCacheEntry,
    ) -> Result<(), anyhow::Error> {
        if !self.tx_active {
            anyhow::bail!("no active transaction");
        };

        // We update and not replace so we can keep an old item id if it exists.
        let mut stmt = self.log.db_conn.prepare_cached(
            "insert into StatCache(GCGeneration, LatestSessionId, Hash, Cached) Values(?1, ?2, ?3, ?4) \
            on conflict(Hash) do update set LatestSessionId = ?2;"
        )?;

        stmt.execute(rusqlite::params![
            self.gc_generation,
            self.session_id,
            hash,
            serde_bare::to_vec(data)?,
        ])?;

        Ok(())
    }

    pub fn stat_cache_lookup(&self, hash: &[u8]) -> Result<Option<StatCacheEntry>, anyhow::Error> {
        let mut stmt = self
            .log
            .db_conn
            .prepare_cached("select Cached from StatCache where Hash = ?;")?;

        match stmt.query_row(rusqlite::params![hash], |r| {
            let data: Vec<u8> = r.get(0)?;
            Ok(data)
        }) {
            Ok(cached) => Ok(Some(serde_bare::from_slice(&cached)?)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(err) => Err(err.into()),
        }
    }

    pub fn checkpoint(&mut self) -> Result<(), anyhow::Error> {
        if !self.tx_active {
            anyhow::bail!("no active transaction");
        };

        self.log.db_conn.execute("commit;", [])?;
        self.tx_active = false;
        self.log.db_conn.execute("begin immediate;", [])?;
        self.tx_active = true;
        Ok(())
    }

    pub fn commit(mut self, id: &Xid) -> Result<(), anyhow::Error> {
        if !self.tx_active {
            anyhow::bail!("no active transaction");
        };

        // To keep the cache bounded, delete everything
        // that was not sent or updated during the current session.
        self.log.db_conn.execute(
            "delete from StatCache where LatestSessionId != ?;",
            &[&self.session_id],
        )?;

        self.log.db_conn.execute(
            "delete from Sent where LatestSessionId != ?;",
            &[&self.session_id],
        )?;

        self.log.db_conn.execute(
            "update StatCache set ItemId = ? where LatestSessionId = ?;",
            &[id, &self.session_id],
        )?;

        self.log.db_conn.execute(
            "update Sent set ItemId = ? where LatestSessionId = ?;",
            &[id, &self.session_id],
        )?;

        self.log.db_conn.execute(
            "insert or replace into LogMeta(Key, Value) Values('last-send-id', ?);",
            &[id],
        )?;

        self.log.db_conn.execute("commit;", [])?;
        self.tx_active = false;
        Ok(())
    }
}

impl<'a> Drop for SendLogSession<'a> {
    fn drop(&mut self) {
        if self.tx_active {
            self.log.db_conn.execute("rollback;", []).unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn cache_commit() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let log_path = {
            let mut d = std::path::PathBuf::from(tmp_dir.path());
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
            assert!(!session.stat_cache_lookup(&[32; 0]).unwrap().is_some());
            session.add_address(&addr).unwrap();
            session
                .add_stat_cache_data(
                    &[32; 0],
                    &StatCacheEntry {
                        total_size: 123,
                        addresses: vec![],
                        data_cursors: vec![],
                        hashes: vec![],
                    },
                )
                .unwrap();
            assert!(session.cached_address(&addr).unwrap());
            assert!(session.stat_cache_lookup(&[32; 0]).unwrap().is_some());
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
            assert!(session.stat_cache_lookup(&[32; 0]).unwrap().is_some());
        }
        drop(sendlog);

        let mut sendlog = SendLog::open(&log_path).unwrap();
        {
            let session = sendlog.session(gc_generation).unwrap();
            assert_eq!(session.last_send_id().unwrap(), Some(id));
            session.perform_cache_invalidations(true).unwrap();
            // gc_generation is the same and we have the item id so we keep cache.
            assert!(session.cached_address(&addr).unwrap());
            assert!(session.stat_cache_lookup(&[32; 0]).unwrap().is_some());
        }
        drop(sendlog);

        let mut sendlog = SendLog::open(&log_path).unwrap();
        {
            let session = sendlog.session(Xid::new()).unwrap();
            assert_eq!(session.last_send_id().unwrap(), Some(id));
            session.perform_cache_invalidations(false).unwrap();
            // gc_generation differs, and we do not have the item id so we discard cache.
            assert!(!session.cached_address(&addr).unwrap());
            assert!(!session.stat_cache_lookup(&[32; 0]).unwrap().is_some());
        }
        drop(sendlog);
    }

    #[test]
    fn cache_checkpoint() {
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
            session
                .add_stat_cache_data(
                    &[32; 0],
                    &StatCacheEntry {
                        total_size: 123,
                        addresses: vec![],
                        data_cursors: vec![],
                        hashes: vec![],
                    },
                )
                .unwrap();
            session.checkpoint().unwrap();
        }
        drop(sendlog);

        let mut sendlog = SendLog::open(&log_path).unwrap();
        {
            let session = sendlog.session(gc_generation).unwrap();
            session.perform_cache_invalidations(false).unwrap();
            // gc_generation is the same, so we keep cache.
            assert!(session.cached_address(&addr).unwrap());
            assert!(session.stat_cache_lookup(&[32; 0]).unwrap().is_some());
        }
        drop(sendlog);

        let mut sendlog = SendLog::open(&log_path).unwrap();
        {
            let session = sendlog.session(gc_generation).unwrap();
            session.perform_cache_invalidations(false).unwrap();
            // gc_generation is the same so we keep cache.
            assert!(session.cached_address(&addr).unwrap());
            assert!(session.stat_cache_lookup(&[32; 0]).unwrap().is_some());
        }
        drop(sendlog);

        let mut sendlog = SendLog::open(&log_path).unwrap();
        {
            let session = sendlog.session(Xid::new()).unwrap();
            session.perform_cache_invalidations(false).unwrap();
            // gc_generation differs, so we discard cache.
            assert!(!session.cached_address(&addr).unwrap());
            assert!(!session.stat_cache_lookup(&[32; 0]).unwrap().is_some());
        }
        drop(sendlog);
    }

    #[test]
    fn cache_commit_then_checkpoint() {
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
            session
                .add_stat_cache_data(
                    &[32; 0],
                    &StatCacheEntry {
                        total_size: 123,
                        addresses: vec![],
                        data_cursors: vec![],
                        hashes: vec![],
                    },
                )
                .unwrap();
            session.commit(&id).unwrap();
        }
        drop(sendlog);

        // checkpoint that address.
        let mut sendlog = SendLog::open(&log_path).unwrap();
        {
            let mut session = sendlog.session(gc_generation).unwrap();
            session.add_address(&addr).unwrap();
            session
                .add_stat_cache_data(
                    &[32; 0],
                    &StatCacheEntry {
                        total_size: 123,
                        addresses: vec![],
                        data_cursors: vec![],
                        hashes: vec![],
                    },
                )
                .unwrap();
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
            assert!(session.stat_cache_lookup(&[32; 0]).unwrap().is_some());
            session.perform_cache_invalidations(true).unwrap();
            assert!(session.cached_address(&addr).unwrap());
            assert!(session.stat_cache_lookup(&[32; 0]).unwrap().is_some());
            session.perform_cache_invalidations(false).unwrap();
            assert!(session.cached_address(&addr).unwrap());
            assert!(session.stat_cache_lookup(&[32; 0]).unwrap().is_some());
        }
        drop(sendlog);

        let mut sendlog = SendLog::open(&log_path).unwrap();
        {
            let session = sendlog.session(Xid::new()).unwrap();
            session.perform_cache_invalidations(false).unwrap();
            assert!(!session.cached_address(&addr).unwrap());
            assert!(!session.stat_cache_lookup(&[32; 0]).unwrap().is_some());
        }
        drop(sendlog);
    }
}
