use super::itemset;
use std::path::PathBuf;

pub struct QueryCache {
    conn: rusqlite::Connection,
}

pub struct QueryCacheTx<'a> {
    tx: rusqlite::Transaction<'a>,
}

impl QueryCache {
    pub fn open(p: &PathBuf) -> Result<QueryCache, failure::Error> {
        let mut conn = rusqlite::Connection::open(p)?;
        conn.query_row("pragma journal_mode=WAL;", rusqlite::NO_PARAMS, |_r| Ok(()))?;

        let mut tx = conn.transaction()?;

        tx.execute(
            "create table if not exists QueryCacheMeta(Key, Value, unique(Key)); ",
            rusqlite::NO_PARAMS,
        )?;

        match tx.query_row(
            "select Value from QueryCacheMeta where Key = 'schema-version';",
            rusqlite::NO_PARAMS,
            |r| {
                let v: i64 = r.get(0)?;
                Ok(v)
            },
        ) {
            Ok(v) => {
                if v != 0 {
                    failure::bail!("query cache at {:?} is from a different version of the software and must be removed manually", &p);
                }
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                tx.execute(
                    "insert into QueryCacheMeta(Key, Value) values('schema-version', 0);",
                    rusqlite::NO_PARAMS,
                )?;
            }
            Err(err) => return Err(err.into()),
        }

        itemset::init_tables(&mut tx)?;

        tx.commit()?;

        Ok(QueryCache { conn: conn })
    }

    pub fn transaction<'a>(self: &'a mut Self) -> Result<QueryCacheTx<'a>, failure::Error> {
        let tx = self.conn.transaction()?;
        Ok(QueryCacheTx { tx })
    }
}

impl<'a> QueryCacheTx<'a> {
    fn clear(&mut self) -> Result<(), failure::Error> {
        self.tx.execute("delete from Items;", rusqlite::NO_PARAMS)?;
        self.tx
            .execute("delete from ItemOpLog;", rusqlite::NO_PARAMS)?;
        Ok(())
    }

    pub fn last_log_op(self: &mut Self) -> Result<i64, failure::Error> {
        let last_id = match self.tx.query_row(
            "select Id from ItemOpLog order by Id desc limit 1;",
            rusqlite::NO_PARAMS,
            |r| {
                let last: i64 = r.get(0)?;
                Ok(last)
            },
        ) {
            Ok(last) => last,
            Err(rusqlite::Error::QueryReturnedNoRows) => -1,
            Err(err) => return Err(err.into()),
        };

        Ok(last_id)
    }

    pub fn current_gc_generation(&mut self) -> Result<Option<String>, failure::Error> {
        match self.tx.query_row(
            "select value from QueryCacheMeta where key = 'gc_generation';",
            rusqlite::NO_PARAMS,
            |r| {
                let generation: String = r.get(0)?;
                Ok(generation)
            },
        ) {
            Ok(generation) => Ok(Some(generation)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(err) => return Err(err.into()),
        }
    }

    pub fn start_sync(self: &mut Self, gc_generation: String) -> Result<(), failure::Error> {
        match self.tx.query_row(
            "select value from QueryCacheMeta where key = 'gc_generation';",
            rusqlite::NO_PARAMS,
            |r| {
                let generation: String = r.get(0)?;
                Ok(generation)
            },
        ) {
            Ok(old_generation) => {
                if gc_generation != old_generation {
                    self.clear()?;
                    self.tx.execute(
                        "update QueryCacheMeta set Value = ? where Key = 'gc_generation';",
                        &[&gc_generation],
                    )?;
                }
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                self.clear()?;
                self.tx.execute(
                    "insert into QueryCacheMeta(Key, Value) values('gc_generation', ?);",
                    &[&gc_generation],
                )?;
            }
            Err(err) => return Err(err.into()),
        }

        Ok(())
    }

    pub fn sync_op(self: &mut Self, id: i64, op: itemset::LogOp) -> Result<i64, failure::Error> {
        itemset::do_op_with_id(&mut self.tx, id, &op)
    }

    pub fn commit(self: Self) -> Result<(), failure::Error> {
        self.tx.commit()?;
        Ok(())
    }

    pub fn walk_items(
        self: &mut Self,
        f: &mut dyn FnMut(i64, itemset::ItemMetadata) -> Result<(), failure::Error>,
    ) -> Result<(), failure::Error> {
        itemset::walk_items(&mut self.tx, f)
    }
}
