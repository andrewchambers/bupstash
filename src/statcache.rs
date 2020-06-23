use std::path::{Path, PathBuf};

pub struct StatCache {
    conn: rusqlite::Connection,
    remember: i64,
}

pub struct StatCacheTx<'a> {
    tx: rusqlite::Transaction<'a>,
    remember: i64,
    sequence: i64,
}

impl StatCache {
    pub fn open(p: &PathBuf, remember: i64) -> Result<StatCache, failure::Error> {
        let mut conn = rusqlite::Connection::open(p)?;
        conn.query_row("pragma journal_mode=WAL;", rusqlite::NO_PARAMS, |_r| Ok(()))?;

        let tx = conn.transaction()?;

        tx.execute(
            "create table if not exists StatCacheMeta(Key, Value, unique(Key)); ",
            rusqlite::NO_PARAMS,
        )?;

        match tx.query_row(
            "select Value from StatCacheMeta where Key = 'schema-version';",
            rusqlite::NO_PARAMS,
            |r| {
                let v: i64 = r.get(0)?;
                Ok(v)
            },
        ) {
            Ok(v) => {
                if v != 0 {
                    failure::bail!("stat cache at {:?} is from a different version of the software and must be removed manually", &p);
                }
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                tx.execute(
                    "insert into StatCacheMeta(Key, Value) values('schema-version', 0);",
                    rusqlite::NO_PARAMS,
                )?;
            }
            Err(err) => return Err(err.into()),
        }

        match tx.query_row(
            "select 1 from StatCacheMeta where Key = 'sequence-number';",
            rusqlite::NO_PARAMS,
            |_r| Ok(()),
        ) {
            Ok(_) => (),
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                tx.execute(
                    "insert into StatCacheMeta(Key, Value) values('sequence-number', 0);",
                    rusqlite::NO_PARAMS,
                )?;
            }
            Err(err) => return Err(err.into()),
        }

        tx.execute(
            "create table if not exists StatCache(Path, Hash, Addresses, Seq, unique(Path)); ",
            rusqlite::NO_PARAMS,
        )?;

        tx.execute(
            "create index if not exists StateCachePathHashIndex on StatCache(Path, Hash); ",
            rusqlite::NO_PARAMS,
        )?;

        tx.commit()?;

        Ok(StatCache { conn, remember })
    }

    pub fn transaction<'a>(
        self: &'a mut Self,
        gc_generation: &str,
    ) -> Result<StatCacheTx<'a>, failure::Error> {
        let tx = self.conn.transaction()?;

        match tx.query_row(
            "select value from StatCacheMeta where key = 'gc-generation';",
            rusqlite::NO_PARAMS,
            |r| {
                let generation: String = r.get(0)?;
                Ok(generation)
            },
        ) {
            Ok(old_generation) => {
                if gc_generation != old_generation {
                    tx.execute("delete from StatCache;", rusqlite::NO_PARAMS)?;
                    tx.execute(
                        "update StatCacheMeta set Value = ? where Key = 'gc-generation';",
                        &[&gc_generation],
                    )?;
                }
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                tx.execute("delete from StatCache;", rusqlite::NO_PARAMS)?;
                tx.execute(
                    "insert into StatCacheMeta(Key, Value) values('gc-generation', ?);",
                    &[&gc_generation],
                )?;
            }
            Err(err) => return Err(err.into()),
        }

        let sequence = tx.query_row(
            "select Value from StatCacheMeta where Key = 'sequence-number';",
            rusqlite::NO_PARAMS,
            |r| {
                let n: i64 = r.get(0)?;
                Ok(n)
            },
        )?;

        Ok(StatCacheTx {
            remember: self.remember,
            sequence,
            tx,
        })
    }
}

impl<'a> StatCacheTx<'a> {
    pub fn commit(self: Self) -> Result<(), failure::Error> {
        self.tx.execute(
            "delete from StatCache where Seq <= ? ;",
            &[self.sequence - self.remember],
        )?;
        self.tx.execute(
            "update StatCacheMeta set Value = ? where Key = 'sequence-number';",
            &[self.sequence + 1],
        )?;
        self.tx.commit()?;
        Ok(())
    }

    pub fn add(&mut self, p: &Path, hash: &[u8], addresses: &[u8]) -> Result<(), failure::Error> {
        let p = p.to_str();
        let mut stmt = self.tx.prepare_cached(
            "insert or replace into StatCache(Seq, Path, Hash, Addresses) Values(?, ?, ?, ?);",
        )?;
        stmt.execute(rusqlite::params![self.sequence + 1, p, hash, addresses])?;

        Ok(())
    }

    pub fn lookup(&mut self, p: &Path, hash: &[u8]) -> Result<Option<Vec<u8>>, failure::Error> {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_cache_sanity_test() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let log_path = {
            let mut d = PathBuf::from(tmp_dir.path());
            d.push("stat_cache.sqlite3");
            d
        };
        let mut stat_cache = StatCache::open(&log_path, 1).unwrap();
        let mut tx = stat_cache.transaction("abc").unwrap();
        let hash = &[0; 32][..];
        let addresses = &[0; 64][..];
        tx.add(&PathBuf::from("/foo"), hash, addresses).unwrap();

        let addresses2: &[u8] = &tx.lookup(&PathBuf::from("/foo"), hash).unwrap().unwrap();
        assert_eq!(addresses, addresses2);

        tx.commit().unwrap();
        drop(stat_cache);
    }
}
