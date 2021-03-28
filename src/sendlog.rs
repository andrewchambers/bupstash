use super::address::*;
use super::index;
use super::xid::*;
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct SendLog {
    // We retain two connections, the send log, and an anonymous
    // copy of the send log. Commiting the send log involves copying
    // the temp db over the send log. We do this so the user can do
    // multiple puts without any locks and the last put wins
    // when it comes to what is left on the disk.
    db_conn: rusqlite::Connection,
    tmp_conn: rusqlite::Connection,
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
    pub base_offsets: Vec<index::IndexEntryOffsets>,
    pub hashes: Vec<index::ContentCryptoHash>,
}

const SCHEMA_VERSION: i64 = 4;

impl SendLog {
    pub fn open(p: &Path) -> Result<SendLog, anyhow::Error> {
        let mut db_conn = rusqlite::Connection::open(p)?;

        db_conn.busy_timeout(std::time::Duration::new(600, 0))?;

        let tx = db_conn.transaction()?;
        tx.execute(
            "create table if not exists LogMeta(Key primary key, Value) without rowid;",
            rusqlite::NO_PARAMS,
        )?;

        let needs_init = match tx.query_row(
            "select Value from LogMeta where Key = 'schema-version';",
            rusqlite::NO_PARAMS,
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
            rusqlite::NO_PARAMS,
            |r| r.get(0),
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

        tx.commit()?;

        /* Simple policy to decide when to defragment our send log. */
        if cfg!(debug_assertions) || sequence_number % 10 == 0 {
            db_conn.execute("vacuum;", rusqlite::NO_PARAMS)?;
        }

        let mut tmp_conn = rusqlite::Connection::open("")?;
        tmp_conn.set_prepared_statement_cache_capacity(8);
        // tmp conn does not need fsync, it disappears on os crash.
        tmp_conn.execute("pragma synchronous = OFF;", rusqlite::NO_PARAMS)?;

        if needs_init {
            let tx = tmp_conn.transaction()?;

            tx.execute(
                "create table LogMeta(Key primary key, Value) without rowid;",
                rusqlite::NO_PARAMS,
            )?;

            tx.execute(
                "insert into LogMeta(Key, Value) values('schema-version', $1);",
                &[&SCHEMA_VERSION],
            )?;

            tx.execute(
                "insert into LogMeta(Key, Value) values('sequence-number', 1);",
                rusqlite::NO_PARAMS,
            )?;

            tx.execute(
                "create table Sent(Address primary key, GCGeneration, LatestSessionId, ItemId) without rowid; ",
                rusqlite::NO_PARAMS,
            )?;

            tx.execute(
                "create table StatCache(Hash primary key, Cached, GCGeneration, LatestSessionId, ItemId) without rowid; ",
                rusqlite::NO_PARAMS,
            )?;

            tx.commit()?;
        } else {
            // Copy the persistent send log to the anonymous one.
            let backup = rusqlite::backup::Backup::new(&db_conn, &mut tmp_conn)?;
            if backup.step(-1)? != rusqlite::backup::StepResult::Done {
                anyhow::bail!("unable to start send log transaction");
            }
        }

        Ok(SendLog { db_conn, tmp_conn })
    }

    pub fn session(&mut self, gc_generation: Xid) -> Result<SendLogSession, anyhow::Error> {
        // We manually control the sqlite3 transaction so we are able
        // to issue checkpoints and commit part way through a send operation.
        self.tmp_conn
            .execute("begin immediate;", rusqlite::NO_PARAMS)?;

        Ok(SendLogSession {
            gc_generation,
            session_id: Xid::new(),
            log: self,
            tx_active: true,
        })
    }

    pub fn last_send_id(&self) -> Result<Option<Xid>, anyhow::Error> {
        match self.tmp_conn.query_row(
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
    pub fn last_send_id(&self) -> Result<Option<Xid>, anyhow::Error> {
        self.log.last_send_id()
    }

    pub fn perform_cache_invalidations(&self, had_send_id: bool) -> Result<(), anyhow::Error> {
        if !self.tx_active {
            panic!()
        };

        let last_send_id = self.last_send_id()?;

        if had_send_id {
            self.log.tmp_conn.execute(
                "delete from Sent where (GCGeneration != ?) and (ItemId != ?);",
                rusqlite::params![self.gc_generation, last_send_id.unwrap()],
            )?;
            self.log.tmp_conn.execute(
                "delete from StatCache where (GCGeneration != ?) and (ItemId != ?);",
                rusqlite::params![self.gc_generation, last_send_id.unwrap()],
            )?;
        } else {
            self.log.tmp_conn.execute(
                "delete from Sent where GCGeneration != ?;",
                &[self.gc_generation],
            )?;
            self.log.tmp_conn.execute(
                "delete from StatCache where GCGeneration != ?;",
                &[self.gc_generation],
            )?;
        }

        Ok(())
    }

    pub fn add_address(&self, addr: &Address) -> Result<bool, anyhow::Error> {
        if !self.tx_active {
            anyhow::bail!("no active transaction");
        };

        // There does not seem to be a way to do this in a single query due
        // to the fact that we are using a 'without rowid' table. We can't change this
        // without upgrading the send logs that are out there.
        let has_address = self.cached_address(addr)?;

        if has_address {
            let mut stmt = self
                .log
                .tmp_conn
                .prepare_cached("update Sent set LatestSessionId = $1 where Address = $2;")?;
            stmt.execute(rusqlite::params![self.session_id, &addr.bytes[..]])?;
        } else {
            let mut stmt = self.log.tmp_conn.prepare_cached(
                "insert into Sent(GCGeneration, LatestSessionId, Address) values($1, $2, $3);",
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
            .tmp_conn
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
        let mut stmt = self.log.tmp_conn.prepare_cached(
            "insert into StatCache(GCGeneration, LatestSessionId, Hash, Cached) Values($1, $2, $3, $4) \
            on conflict(Hash) do update set LatestSessionId = $2;"
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
            .tmp_conn
            .prepare_cached("select Cached from StatCache where Hash = $1;")?;

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

        self.log.tmp_conn.execute("commit;", rusqlite::NO_PARAMS)?;
        self.tx_active = false;

        {
            let backup = rusqlite::backup::Backup::new(&self.log.tmp_conn, &mut self.log.db_conn)?;
            if backup.step(-1)? != rusqlite::backup::StepResult::Done {
                anyhow::bail!("unable to checkpoint send log");
            }
        }

        self.log
            .tmp_conn
            .execute("begin immediate;", rusqlite::NO_PARAMS)?;
        self.tx_active = true;

        Ok(())
    }

    pub fn commit(mut self, id: &Xid) -> Result<(), anyhow::Error> {
        if !self.tx_active {
            anyhow::bail!("no active transaction");
        };

        // To keep the cache bounded, delete everything
        // that was not sent or updated during the current session.
        self.log.tmp_conn.execute(
            "delete from StatCache where LatestSessionId != ?;",
            &[&self.session_id],
        )?;

        self.log.tmp_conn.execute(
            "delete from Sent where LatestSessionId != ?;",
            &[&self.session_id],
        )?;

        self.log.tmp_conn.execute(
            "update StatCache set ItemId = ? where LatestSessionId = ?;",
            &[id, &self.session_id],
        )?;

        self.log.tmp_conn.execute(
            "update Sent set ItemId = ? where LatestSessionId = ?;",
            &[id, &self.session_id],
        )?;

        self.log.tmp_conn.execute(
            "insert or replace into LogMeta(Key, Value) Values('last-send-id', ?);",
            &[id],
        )?;

        self.log.tmp_conn.execute("commit;", rusqlite::NO_PARAMS)?;
        self.tx_active = false;

        {
            let backup = rusqlite::backup::Backup::new(&self.log.tmp_conn, &mut self.log.db_conn)?;
            if backup.step(-1)? != rusqlite::backup::StepResult::Done {
                anyhow::bail!("unable to commit send log");
            }
        }

        Ok(())
    }
}

impl<'a> Drop for SendLogSession<'a> {
    fn drop(&mut self) {
        if self.tx_active {
            self.log
                .tmp_conn
                .execute("rollback;", rusqlite::NO_PARAMS)
                .unwrap();
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
                        base_offsets: vec![],
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
                        base_offsets: vec![],
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
                        base_offsets: vec![],
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
                        base_offsets: vec![],
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
