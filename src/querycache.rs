use super::crypto;
use super::itemset;
use super::query;
use super::xid::*;
use std::path::PathBuf;

pub struct QueryCache {
    conn: rusqlite::Connection,
}

pub struct QueryCacheTx<'a> {
    tx: rusqlite::Transaction<'a>,
}

pub struct ListOptions {
    pub now: chrono::DateTime<chrono::Utc>,
    pub list_encrypted: bool,
    pub utc_timestamps: bool,
    pub primary_key_id: Option<Xid>,
    pub metadata_dctx: Option<crypto::DecryptionContext>,
    pub query: Option<query::Query>,
}

impl QueryCache {
    pub fn open(p: &PathBuf) -> Result<QueryCache, failure::Error> {
        let mut conn = rusqlite::Connection::open(p)?;
        conn.query_row("pragma journal_mode=WAL;", rusqlite::NO_PARAMS, |_r| Ok(()))?;

        let tx = conn.transaction()?;

        tx.execute(
            "create table if not exists QueryCacheMeta(Key primary key, Value) without rowid;",
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

        itemset::init_tables(&tx)?;

        let recently_cleared = match tx.query_row(
            "select Value from QueryCacheMeta where Key = 'recently-cleared';",
            rusqlite::NO_PARAMS,
            |r| {
                let v: bool = r.get(0)?;
                Ok(v)
            },
        ) {
            Ok(v) => v,
            Err(rusqlite::Error::QueryReturnedNoRows) => false,
            Err(err) => return Err(err.into()),
        };

        if recently_cleared {
            tx.execute(
                "insert or replace into QueryCacheMeta(Key, Value) values('recently-cleared', 0);",
                rusqlite::NO_PARAMS,
            )?;
        }

        tx.commit()?;

        if recently_cleared {
            conn.execute("vacuum;", rusqlite::NO_PARAMS)?;
        }

        Ok(QueryCache { conn })
    }

    pub fn transaction(self: &mut Self) -> Result<QueryCacheTx, failure::Error> {
        let tx = self.conn.transaction()?;
        Ok(QueryCacheTx { tx })
    }
}

impl<'a> QueryCacheTx<'a> {
    fn clear(&mut self) -> Result<(), failure::Error> {
        self.tx.execute("delete from Items;", rusqlite::NO_PARAMS)?;
        self.tx
            .execute("delete from ItemOpLog;", rusqlite::NO_PARAMS)?;
        self.tx.execute(
            "insert or replace into QueryCacheMeta(Key, Value) values('recently-cleared', 1);",
            rusqlite::NO_PARAMS,
        )?;
        Ok(())
    }

    pub fn last_log_op(self: &mut Self) -> Result<i64, failure::Error> {
        let last_id = match self.tx.query_row(
            "select OpId from ItemOpLog order by OpId desc limit 1;",
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

    pub fn current_gc_generation(&mut self) -> Result<Option<Xid>, failure::Error> {
        match self.tx.query_row(
            "select value from QueryCacheMeta where key = 'gc-generation';",
            rusqlite::NO_PARAMS,
            |r| {
                let generation: Xid = r.get(0)?;
                Ok(generation)
            },
        ) {
            Ok(generation) => Ok(Some(generation)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(err) => Err(err.into()),
        }
    }

    pub fn start_sync(self: &mut Self, gc_generation: Xid) -> Result<(), failure::Error> {
        match self.tx.query_row(
            "select value from QueryCacheMeta where key = 'gc-generation';",
            rusqlite::NO_PARAMS,
            |r| {
                let generation: Xid = r.get(0)?;
                Ok(generation)
            },
        ) {
            Ok(old_generation) => {
                if gc_generation != old_generation {
                    self.clear()?;
                    self.tx.execute(
                        "update QueryCacheMeta set Value = ? where Key = 'gc-generation';",
                        &[&gc_generation],
                    )?;
                }
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                self.clear()?;
                self.tx.execute(
                    "insert into QueryCacheMeta(Key, Value) values('gc-generation', ?);",
                    &[&gc_generation],
                )?;
            }
            Err(err) => return Err(err.into()),
        }

        Ok(())
    }

    pub fn sync_op(
        self: &mut Self,
        op_id: i64,
        item_id: Option<Xid>,
        op: itemset::LogOp,
    ) -> Result<(), failure::Error> {
        itemset::sync_ops(&self.tx, op_id, item_id, &op)
    }

    pub fn commit(self: Self) -> Result<(), failure::Error> {
        self.tx.commit()?;
        Ok(())
    }

    pub fn list(
        self: &mut Self,
        mut opts: ListOptions,
        on_match: &mut dyn FnMut(
            Xid,
            std::collections::BTreeMap<String, String>,
        ) -> Result<(), failure::Error>,
    ) -> Result<(), failure::Error> {
        let mut f = |_op_id: i64, item_id: Xid, metadata: itemset::VersionedItemMetadata| {
            match metadata {
                itemset::VersionedItemMetadata::V1(metadata) => {
                    if opts.primary_key_id.is_some()
                        && opts.primary_key_id.unwrap()
                            == metadata.plain_text_metadata.primary_key_id
                    {
                        let mut dmetadata =
                            metadata.decrypt_metadata(opts.metadata_dctx.as_mut().unwrap())?;

                        let ts = if opts.utc_timestamps {
                            dmetadata.timestamp.format("%Y/%m/%d %T").to_string()
                        } else {
                            let local_ts: chrono::DateTime<chrono::Local> =
                                chrono::DateTime::from(dmetadata.timestamp);
                            local_ts.format("%Y/%m/%d %T").to_string()
                        };

                        // Add special builtin tags.
                        dmetadata.tags.insert("id".to_string(), item_id.to_string());
                        dmetadata.tags.insert("timestamp".to_string(), ts);
                        if opts.list_encrypted {
                            dmetadata.tags.insert(
                                "key-id".to_string(),
                                metadata.plain_text_metadata.primary_key_id.to_string(),
                            );
                            dmetadata
                                .tags
                                .insert("metadata-encrypted".to_string(), "no".to_string());
                        }

                        let query_matches = match opts.query {
                            Some(ref query) => query::query_matches(
                                query,
                                &query::QueryContext {
                                    age: opts
                                        .now
                                        .signed_duration_since(dmetadata.timestamp)
                                        .to_std()?,
                                    tagset: &dmetadata.tags,
                                },
                            ),
                            None => true,
                        };

                        if query_matches {
                            on_match(item_id, dmetadata.tags)?;
                        }

                        Ok(())
                    } else {
                        if !opts.list_encrypted {
                            return Ok(());
                        }

                        let mut tags = std::collections::BTreeMap::new();

                        tags.insert("id".to_string(), item_id.to_string());
                        if opts.list_encrypted {
                            tags.insert(
                                "key-id".to_string(),
                                metadata.plain_text_metadata.primary_key_id.to_string(),
                            );
                            tags.insert("metadata-encrypted".to_string(), "yes".to_string());
                        }

                        let query_matches = match opts.query {
                            Some(ref query) => query::query_matches_encrypted(
                                query,
                                &query::QueryEncryptedContext { tagset: &tags },
                            ),
                            None => true,
                        };

                        if query_matches {
                            on_match(item_id, tags)?;
                        }

                        Ok(())
                    }
                }
            }
        };
        itemset::walk_items(&self.tx, &mut f)
    }
}
