use super::cksumvfs;
use super::crypto;
use super::fmtutil;
use super::oplog;
use super::query;
use super::xid::*;
use std::path::Path;

pub struct QueryCache {
    conn: rusqlite::Connection,
}

pub struct QueryCacheTx<'a> {
    sync_offset: u64,
    tx: rusqlite::Transaction<'a>,
}

// This type exists as a lowest common denominator for our different
// metadata versions and what we have access to.
pub struct MetadataListing {
    pub primary_key_id: Xid,
    pub timestamp: Option<chrono::DateTime<chrono::Utc>>,
    pub data_htree: oplog::HTreeMetadata,
    pub index_htree: Option<oplog::HTreeMetadata>,
    pub query_tags: std::collections::BTreeMap<String, String>,
}

pub struct ListOptions {
    pub now: chrono::DateTime<chrono::Utc>,
    pub list_encrypted: bool,
    pub utc_timestamps: bool,
    pub primary_key_id: Option<Xid>,
    pub metadata_dctx: Option<crypto::DecryptionContext>,
    pub query: Option<query::Query>,
}

const SCHEMA_VERSION: i64 = 3;

impl QueryCache {
    pub fn open(p: &Path) -> Result<QueryCache, anyhow::Error> {
        let mut conn = rusqlite::Connection::open(p)?;
        cksumvfs::enable_sqlite_checksums(&conn)?;
        conn.busy_timeout(std::time::Duration::new(6 * 60 * 60, 0))?;

        let needs_init = match conn.query_row(
            "select Value from QueryCacheMeta where Key = 'schema-version';",
            [],
            |r| {
                let v: i64 = r.get(0)?;
                Ok(v)
            },
        ) {
            Ok(v) => v != SCHEMA_VERSION,
            Err(rusqlite::Error::SqliteFailure(err, _))
                if err.code == rusqlite::ErrorCode::SystemIoFailure =>
            {
                // The failure may be due to checksumvfs being enabled
                // for the first time, so attempt a vacuum and try again
                // to rebuild checksums.
                conn.query_row("pragma checksum_verification=OFF;", [], |_r| Ok(()))?;
                conn.execute("vacuum;", [])?;
                conn.query_row("pragma checksum_verification=ON;", [], |_r| Ok(()))?;
                // Force a reinit since we don't know if our checksums were really bad.
                true
            }
            Err(err) => anyhow::bail!("unable to open query cache: {}", err),
        };

        if needs_init {
            conn.query_row("pragma journal_mode=WAL;", [], |_r| Ok(()))?;
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            tx.execute("drop table if exists QueryCacheMeta;", [])?;
            tx.execute("drop table if exists ItemOpLog;", [])?;
            tx.execute("drop table if exists Items;", [])?;
            tx.execute(
                "create table if not exists QueryCacheMeta(Key primary key, Value) without rowid;",
                [],
            )?;
            tx.execute(
                "insert into QueryCacheMeta(Key, Value) values('schema-version', ?);",
                [SCHEMA_VERSION],
            )?;
            tx.execute(
                "insert into QueryCacheMeta(Key, Value) values('want-vacuum', 0);",
                [],
            )?;
            tx.execute(
                "create table if not exists ItemOpLog(LogOffset INTEGER PRIMARY KEY AUTOINCREMENT, ItemId, OpData);",
                [],
            )?;
            tx.execute(
                // No rowid so means we don't need a secondary index for itemid lookups.
                "create table if not exists Items(ItemId PRIMARY KEY, LogOffset INTEGER NOT NULL, Metadata NOT NULL, UNIQUE(LogOffset)) WITHOUT ROWID;",
                [],
            )?;
            tx.commit()?;

            conn.execute("vacuum;", [])?;

            // Final sanity check after (re)initialization.
            let integrity_check = conn.query_row("pragma integrity_check;", [], |r| {
                let v: String = r.get(0)?;
                Ok(v)
            })?;
            if integrity_check != "ok" {
                anyhow::bail!("query cache integrity check failed")
            };
        }

        // Trigger a vacuum for a cache that was recently invalidated.
        let want_vacuum = conn.query_row(
            "select Value from QueryCacheMeta where Key = 'want-vacuum';",
            [],
            |r| r.get(0),
        )?;

        if want_vacuum {
            conn.execute("vacuum;", [])?;
            conn.execute(
                "insert or replace into QueryCacheMeta(Key, Value) values('want-vacuum', 0);",
                [],
            )?;
        }

        Ok(QueryCache { conn })
    }

    pub fn transaction(&mut self) -> Result<QueryCacheTx, anyhow::Error> {
        let tx = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let schema_version = tx.query_row(
            "select Value from QueryCacheMeta where Key = 'schema-version';",
            [],
            |r| {
                let v: i64 = r.get(0)?;
                Ok(v)
            },
        )?;
        if schema_version != SCHEMA_VERSION {
            anyhow::bail!("query cache schema modified by concurrent invocation");
        }
        Ok(QueryCacheTx { tx, sync_offset: 0 })
    }
}

impl<'a> QueryCacheTx<'a> {
    fn clear(&mut self) -> Result<(), anyhow::Error> {
        self.tx.execute("delete from Items;", [])?;
        self.tx.execute("delete from ItemOpLog;", [])?;
        self.tx.execute(
            "insert or replace into QueryCacheMeta(Key, Value) values('want-vacuum', 1);",
            [],
        )?;
        Ok(())
    }

    pub fn last_log_op_offset(&mut self) -> Result<Option<u64>, anyhow::Error> {
        let last_id = match self.tx.query_row(
            "select LogOffset from ItemOpLog order by LogOffset desc limit 1;",
            [],
            |r| {
                let last: i64 = r.get(0)?;
                Ok(last as u64)
            },
        ) {
            Ok(last) => Some(last),
            Err(rusqlite::Error::QueryReturnedNoRows) => None,
            Err(err) => return Err(err.into()),
        };

        Ok(last_id)
    }

    pub fn current_gc_generation(&mut self) -> Result<Option<Xid>, anyhow::Error> {
        match self.tx.query_row(
            "select value from QueryCacheMeta where key = 'gc-generation';",
            [],
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

    pub fn start_sync(&mut self, gc_generation: Xid) -> Result<(), anyhow::Error> {
        match self.tx.query_row(
            "select value from QueryCacheMeta where key = 'gc-generation';",
            [],
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

        match self.tx.query_row(
            "select LogOffset, OpData from ItemOpLog order by LogOffset desc limit 1;",
            [],
            |r| {
                let last: i64 = r.get(0)?;
                let data: Vec<u8> = r.get(1)?;
                Ok(last as u64 + data.len() as u64)
            },
        ) {
            Ok(sync_offset) => self.sync_offset = sync_offset,
            Err(rusqlite::Error::QueryReturnedNoRows) => self.sync_offset = 0,
            Err(err) => return Err(err.into()),
        };

        Ok(())
    }

    pub fn sync_op(&mut self, op: oplog::LogOp) -> Result<(), anyhow::Error> {
        let serialized_op = serde_bare::to_vec(&op)?;
        let op_offset = self.sync_offset;
        self.sync_offset = op_offset + serialized_op.len() as u64;
        match op {
            oplog::LogOp::AddItem((item_id, md)) => {
                self.tx.execute(
                    "insert into ItemOpLog(LogOffset, ItemId, OpData) values(?, ?, ?);",
                    rusqlite::params![op_offset as i64, &item_id, serialized_op],
                )?;
                self.tx.execute(
                    "insert into Items(ItemId, LogOffset, Metadata) values(?, ?, ?);",
                    rusqlite::params![&item_id, op_offset as i64, serde_bare::to_vec(&md)?],
                )?;
            }
            oplog::LogOp::RemoveItems(items) => {
                self.tx.execute(
                    "insert into ItemOpLog(LogOffset, OpData) values(?, ?);",
                    rusqlite::params![op_offset as i64, serialized_op],
                )?;
                for item_id in items {
                    self.tx
                        .execute("delete from Items where ItemId = ?;", [item_id])?;
                }
            }
            oplog::LogOp::RecoverRemoved => {
                self.tx.execute(
                    "insert into ItemOpLog(LogOffset, OpData) values(?, ?);",
                    rusqlite::params![op_offset as i64, serialized_op],
                )?;
                let mut stmt = self.tx.prepare(
                    "select LogOffset, OpData from ItemOpLog where (ItemId is not null) and (ItemId not in (select ItemId from Items));",
                )?;
                let mut rows = stmt.query([])?;
                while let Some(row) = rows.next()? {
                    let offset: i64 = row.get(0)?;
                    let op: Vec<u8> = row.get(1)?;
                    let op: oplog::LogOp = serde_bare::from_slice(&op)?;
                    if let oplog::LogOp::AddItem((item_id, md)) = op {
                        self.tx.execute(
                            "insert into Items(ItemId, LogOffset, Metadata) values(?, ?, ?);",
                            rusqlite::params![&item_id, offset, serde_bare::to_vec(&md)?],
                        )?;
                    }
                }
            }
        }
        Ok(())
    }

    pub fn commit(self) -> Result<(), anyhow::Error> {
        self.tx.commit()?;
        Ok(())
    }

    // XXX How to create a type definition of a closure type?
    #[allow(clippy::type_complexity)]
    pub fn list(
        &mut self,
        mut opts: ListOptions,
        on_match: &mut dyn FnMut(
            Xid,
            &std::collections::BTreeMap<String, String>,
            &oplog::VersionedItemMetadata,
            Option<&oplog::DecryptedItemMetadata>,
        ) -> Result<(), anyhow::Error>,
    ) -> Result<(), anyhow::Error> {
        let mut stmt = self
            .tx
            .prepare("select ItemId, Metadata from Items order by LogOffset asc;")?;
        let mut rows = stmt.query([])?;

        while let Some(row) = rows.next()? {
            let item_id: Xid = row.get(0)?;
            let metadata: Vec<u8> = row.get(1)?;
            let metadata: oplog::VersionedItemMetadata = serde_bare::from_slice(&metadata)?;

            if !opts.list_encrypted
                && opts.primary_key_id.is_some()
                && opts.primary_key_id.unwrap() == *metadata.primary_key_id()
            {
                let mut dmetadata =
                    metadata.decrypt_metadata(opts.metadata_dctx.as_mut().unwrap())?;

                // Add special builtin tags.
                dmetadata.tags.insert("id".to_string(), item_id.to_string());
                dmetadata.tags.insert(
                    "timestamp".to_string(),
                    fmtutil::format_timestamp(&dmetadata.timestamp, opts.utc_timestamps),
                );
                dmetadata.tags.insert(
                    "size".to_string(),
                    fmtutil::format_size(dmetadata.data_size.0 + dmetadata.index_size.0),
                );

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
                    on_match(item_id, &dmetadata.tags, &metadata, Some(&dmetadata))?;
                }
            } else {
                if !opts.list_encrypted {
                    continue;
                }

                let mut tags = std::collections::BTreeMap::new();

                tags.insert("id".to_string(), item_id.to_string());
                tags.insert(
                    "decryption-key-id".to_string(),
                    metadata.primary_key_id().to_string(),
                );

                let query_matches = match opts.query {
                    Some(ref query) => query::query_matches_encrypted(
                        query,
                        &query::QueryEncryptedContext { tagset: &tags },
                    ),
                    None => true,
                };

                if query_matches {
                    on_match(item_id, &tags, &metadata, None)?;
                }
            }
        }

        Ok(())
    }
}
