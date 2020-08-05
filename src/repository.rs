use super::chunk_storage;
use super::crypto;
use super::external_chunk_storage;
use super::hex;
use super::htree;
use super::itemset;
use super::xid::*;
use failure::Fail;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Fail)]
pub enum RepoError {
    #[fail(display = "path {} already exists, refusing to overwrite it", path)]
    AlreadyExists { path: String },
    #[fail(display = "repository was not initialized properly")]
    NotInitializedProperly,
    #[fail(display = "repository does not exist")]
    RepoDoesNotExist,
    #[fail(display = "repository database at unsupported version")]
    UnsupportedSchemaVersion,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum StorageEngineSpec {
    ExternalStore {
        socket_path: String,
        path: String,
        quiescent_period_ms: Option<u64>,
    },
}

#[derive(Clone, Copy)]
pub enum LockMode {
    Shared,
    Exclusive,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct GCStats {
    pub chunks_freed: Option<usize>,
    pub bytes_freed: Option<usize>,
    pub chunks_remaining: Option<usize>,
    pub bytes_remaining: Option<usize>,
}

pub struct Repo {
    repo_id: String,
    lock_id: i64,
    conn: postgres::Client,
    _repo_lock_mode: LockMode,
}

impl Repo {
    pub fn init(
        _repo_connect: &str,
        _storage_engine: Option<StorageEngineSpec>,
    ) -> Result<(), failure::Error> {
        failure::bail!("init is not supported");
    }

    pub fn open(repo: &str) -> Result<Repo, failure::Error> {
        let mut conn =
            postgres::Client::connect(&std::env::var("BUPSTASH_PG_CONNECT")?, postgres::NoTls)?;

        let schema_version: String = conn
            .query_one(
                "select Value from RepositoryMeta where RepoId=$1 and Key='schema-version';",
                &[&repo],
            )?
            .get("Value");
        if schema_version.parse::<u64>().unwrap() != 0 {
            return Err(RepoError::UnsupportedSchemaVersion.into());
        }

        let lock_id: i64 = conn
            .query_one(
                "select Value from RepositoryMeta where RepoId=$1 and Key='lock-id';",
                &[&repo],
            )?
            .get::<&str, String>("Value")
            .parse::<i64>()
            .unwrap();

        conn.execute("select pg_advisory_lock_shared($1);", &[&lock_id])?;

        let mut r = Repo {
            conn,
            lock_id,
            repo_id: repo.to_string(),
            _repo_lock_mode: LockMode::Shared,
        };

        r.handle_gc_dirty()?;

        Ok(r)
    }

    fn handle_gc_dirty(&mut self) -> Result<(), failure::Error> {
        // The gc_dirty flag gets set when a garbage collection exits without
        // proper cleanup. For external storage engines we handle this by applying a delay to any repository
        // actions to ensure the external engine has had time to finish any operations (especially object deletions)
        // that might have been in flight at the time of a crash.
        //
        // Consider the following case:
        //
        // 1. We are deleting a set of objects in an external storage engine.
        // 2. A delete object message is set to the backing store (s3/gcs/w.e.)
        // 3. The repository process crashes.
        // 4. A new put starts.
        // 5. The new process resends the same object that is in the process of deletion.
        // 6. The delete object message gets processed by the backend.
        //
        // I cannot see a precise way to avoid this problem assuming the presence of arbitrary network
        // delays without the storage backend being made aware of gc generations somehow.
        //
        // I think in an ideal world, the external storage engine must be made aware of the gc generation
        // then be able to use it as as a 'fence' (condition that stops the upload or delete from succeeding).
        //
        // The current mitigation introduces the idea of a quiescent_period to an external storage implementation.
        // The idea is that between steps 4 and 5 we introduce a mandatory delay if the gc process crashed. This
        // means in practice we can make what is already an unlikely event, extremely unlikely by increasing this period.

        let gc_dirty: String = self
            .conn
            .query_one(
                "select Value from RepositoryMeta where RepoId=$1 and Key ='gc-dirty';",
                &[&self.repo_id],
            )?
            .get("Value");

        if gc_dirty == "1" {
            match self.storage_engine_spec()? {
                StorageEngineSpec::ExternalStore {
                    quiescent_period_ms,
                    ..
                } => {
                    if let Some(quiescent_period_ms) = quiescent_period_ms {
                        eprintln!("repository garbage collection was cancelled, recovering...");
                        std::thread::sleep(std::time::Duration::from_millis(quiescent_period_ms));
                    }
                }
            }
            self.conn.execute(
                "update RepositoryMeta set Value=$1 where RepoId=$2 and Key='gc-dirty';",
                &[&"0".to_string(), &self.repo_id],
            )?;
        }

        Ok(())
    }

    pub fn alter_lock_mode(&mut self, repo_lock_mode: LockMode) -> Result<(), failure::Error> {
        match (self._repo_lock_mode, repo_lock_mode) {
            (LockMode::Shared, LockMode::Shared) => (),
            (LockMode::Exclusive, LockMode::Exclusive) => (),
            (LockMode::Exclusive, LockMode::Shared) => {
                self.conn
                    .execute("select pg_advisory_unlock($1);", &[&self.lock_id])?;
                self.conn
                    .execute("select pg_advisory_lock_shared($1);", &[&self.lock_id])?;
            }
            (LockMode::Shared, LockMode::Exclusive) => {
                self.conn
                    .execute("select pg_advisory_unlock_shared($1);", &[&self.lock_id])?;
                self.conn
                    .execute("select pg_advisory_lock($1);", &[&self.lock_id])?;
            }
        };

        // There is a brief period where we unlocked the database,
        // ensure our repository still exists by querying it.
        self.conn.query_one(
            "select Value from RepositoryMeta where RepoId=$1 and Key='schema-version';",
            &[&self.repo_id],
        )?;

        self._repo_lock_mode = repo_lock_mode;
        Ok(())
    }

    pub fn storage_engine_spec(&mut self) -> Result<StorageEngineSpec, failure::Error> {
        let storage_path: String = self
            .conn
            .query_one(
                "select Value from RepositoryMeta where RepoId=$1 and Key='storage-path'",
                &[&self.repo_id],
            )?
            .get("Value");
        let socket_path = std::env::var("BUPSTASH_STORAGE_SOCKET")?;
        Ok(StorageEngineSpec::ExternalStore {
            socket_path,
            path: storage_path,
            quiescent_period_ms: Some(20000),
        })
    }

    pub fn storage_engine_from_spec(
        &mut self,
        spec: &StorageEngineSpec,
    ) -> Result<Box<dyn chunk_storage::Engine>, failure::Error> {
        let storage_engine: Box<dyn chunk_storage::Engine> = match spec {
            StorageEngineSpec::ExternalStore {
                socket_path, path, ..
            } => {
                let socket_path = PathBuf::from(socket_path);
                Box::new(external_chunk_storage::ExternalStorage::new(
                    &socket_path,
                    &path,
                )?)
            }
        };
        Ok(storage_engine)
    }

    pub fn storage_engine(&mut self) -> Result<Box<dyn chunk_storage::Engine>, failure::Error> {
        let spec = self.storage_engine_spec()?;
        self.storage_engine_from_spec(&spec)
    }

    pub fn gc_generation(&mut self) -> Result<Xid, failure::Error> {
        Ok(self
            .conn
            .query_one(
                "select Value from RepositoryMeta where RepoId=$1 and Key='gc-generation';",
                &[&self.repo_id],
            )?
            .get("Value"))
    }

    fn checked_serialize_metadata(
        md: &itemset::VersionedItemMetadata,
    ) -> Result<Vec<u8>, failure::Error> {
        let serialized_op = serde_bare::to_vec(&md)?;
        if serialized_op.len() > itemset::MAX_METADATA_SIZE {
            failure::bail!("itemset log item too big!");
        }
        Ok(serialized_op)
    }

    pub fn add_item(&mut self, md: itemset::VersionedItemMetadata) -> Result<Xid, failure::Error> {
        let mut tx = self.conn.transaction()?;
        let item_id = Xid::new();

        let serialized_md = Repo::checked_serialize_metadata(&md)?;
        tx.execute(
            "insert into Items(RepoId, ItemId, Metadata) values($1, $2, $3);",
            &[&self.repo_id, &item_id, &serialized_md],
        )?;
        let op = itemset::LogOp::AddItem(md);
        let serialized_op = serde_bare::to_vec(&op)?;
        tx.execute(
            "insert into ItemOpLog(RepoId, OpData, ItemId) values($1, $2, $3);",
            &[&self.repo_id, &serialized_op, &item_id],
        )?;
        tx.commit()?;
        Ok(item_id)
    }

    pub fn remove_items(&mut self, items: Vec<Xid>) -> Result<(), failure::Error> {
        let mut tx = self.conn.transaction()?;
        let mut existed = Vec::new();
        for item_id in items.iter() {
            let n_deleted = tx.execute(
                "delete from Items where RepoId=$1 and ItemId = $2;",
                &[&self.repo_id, &item_id],
            )?;
            if n_deleted != 0 {
                existed.push(*item_id);
            }
        }
        let op = itemset::LogOp::RemoveItems(existed);
        let serialized_op = serde_bare::to_vec(&op)?;
        tx.execute(
            "insert into ItemOpLog(RepoId, OpData) values($1, $2);",
            &[&self.repo_id, &serialized_op],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn lookup_item_by_id(
        &mut self,
        id: &Xid,
    ) -> Result<Option<itemset::VersionedItemMetadata>, failure::Error> {
        match self
            .conn
            .query(
                "select Metadata from Items where RepoId=$1 and ItemId = $2;",
                &[&self.repo_id, id],
            )?
            .get(0)
        {
            Some(row) => {
                let serialized_md: Vec<u8> = row.get("Metadata");
                Ok(Some(serde_bare::from_slice(&serialized_md)?))
            }
            None => Ok(None),
        }
    }

    pub fn has_item_with_id(&mut self, id: &Xid) -> Result<bool, failure::Error> {
        let has_item = !self
            .conn
            .query(
                "select 1 from ItemOpLog where RepoId=$1 and ItemId = $2;",
                &[&self.repo_id, id],
            )?
            .is_empty();
        Ok(has_item)
    }

    pub fn walk_log(
        &mut self,
        after: i64,
        f: &mut dyn FnMut(i64, Option<Xid>, itemset::LogOp) -> Result<(), failure::Error>,
    ) -> Result<(), failure::Error> {
        let rows = self.conn.query(
            "select OpId, ItemId, OpData from ItemOpLog where RepoId=$1 and OpId > $2 order by OpId asc;",
            &[&self.repo_id, &after],
        )?;

        for row in rows {
            let op_id: i64 = row.get("OpId");
            let item_id: Option<Xid> = row.get("ItemId");
            let op: Vec<u8> = row.get("OpData");
            let op: itemset::LogOp = serde_bare::from_slice(&op)?;
            f(op_id, item_id, op)?;
        }

        Ok(())
    }

    fn walk_items(
        repo_id: &str,
        tx: &mut postgres::Transaction,
        f: &mut dyn FnMut(i64, Xid, itemset::VersionedItemMetadata) -> Result<(), failure::Error>,
    ) -> Result<(), failure::Error> {
        let rows = tx.query(
            "select OpId, ItemId, OpData from ItemOpLog where RepoId=$1 and ItemId in (select ItemId from Items where RepoId=$1);",
            &[&repo_id]
        )?;

        for row in rows {
            let op_id: i64 = row.get("OpId");
            let item_id: Xid = row.get("ItemId");
            let op: Vec<u8> = row.get("OpData");
            let op: itemset::LogOp = serde_bare::from_slice(&op)?;
            let metadata: itemset::VersionedItemMetadata = match op {
                itemset::LogOp::AddItem(metadata) => metadata,
                _ => failure::bail!("itemset/item log is corrupt"),
            };
            f(op_id, item_id, metadata)?;
        }

        Ok(())
    }

    fn random_tmp_reachability_db_path() -> PathBuf {
        let random_suffix = {
            let mut buf = [0; 16];
            crypto::randombytes(&mut buf[..]);
            hex::easy_encode_to_string(&buf[..])
        };
        let file_name = "reachability."
            .chars()
            .chain(random_suffix.chars())
            .chain(".sqlite3".chars())
            .collect::<String>();

        let mut db_path: PathBuf = "/tmp/".into();
        db_path.push(file_name);
        db_path
    }

    pub fn gc(
        &mut self,
        update_progress_msg: &mut dyn FnMut(String) -> Result<(), failure::Error>,
    ) -> Result<GCStats, failure::Error> {
        let reachability_db_path = Repo::random_tmp_reachability_db_path();
        let mut reachability_db = rusqlite::Connection::open(&reachability_db_path)?;

        // Because this is a fresh database (we already removed all tmp files), we
        // are ok to disable synchronous operation. If we get power off event, the next
        // gc will remove the corrupt database first so theres no chance we open a corrupt db.
        reachability_db.execute("pragma synchronous = OFF;", rusqlite::NO_PARAMS)?;

        let reachability_tx =
            reachability_db.transaction_with_behavior(rusqlite::TransactionBehavior::Exclusive)?;

        reachability_tx.execute(
            "create table if not exists ReachabilityMeta(Key primary key, Value) without rowid;",
            rusqlite::NO_PARAMS,
        )?;

        match reachability_tx.query_row(
            "select Value from ReachabilityMeta where Key = 'schema-version';",
            rusqlite::NO_PARAMS,
            |r| {
                let v: i64 = r.get(0)?;
                Ok(v)
            },
        ) {
            Ok(v) => {
                if v != 0 {
                    failure::bail!("reachability database is from a different version of the software and must be upgraded");
                }
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                reachability_tx.execute(
                    "insert into ReachabilityMeta(Key, Value) values('schema-version', 0);",
                    rusqlite::NO_PARAMS,
                )?;
            }
            Err(err) => return Err(err.into()),
        }

        // We want to maintain the invariant that the reachability table contains ALL reachable
        // chunks, or it does not exist at all. This means we can't accidentally query an empty
        // reachability table from a chunk storage plugin and delete everything.
        reachability_tx.execute(
            "create table Reachability(Address primary key) without rowid;",
            rusqlite::NO_PARAMS,
        )?;

        let mut storage_engine = self.storage_engine()?;

        let mut walk_item = |_op_id, _item_id, metadata| match metadata {
            itemset::VersionedItemMetadata::V1(metadata) => {
                let mut add_reachability_stmt = reachability_tx.prepare_cached(
                    "insert into Reachability(Address) values(?) on conflict do nothing;",
                )?;

                let addr = &metadata.plain_text_metadata.address;
                // It seems likely we could do some sort of pipelining or parallel fetch when we walk the tree.
                // For garbage collection walking in order is not a concern, we just need to ensure we touch each reachable node.
                let mut tr = htree::TreeReader::new(metadata.plain_text_metadata.tree_height, addr);
                while let Some((height, addr)) = tr.next_addr()? {
                    let rows_changed =
                        add_reachability_stmt.execute(rusqlite::params![&addr.bytes[..]])?;
                    if rows_changed != 0 && height != 0 {
                        let data = storage_engine.get_chunk(&addr)?;
                        tr.push_level(height - 1, data)?;
                    }
                }
                Ok(())
            }
        };

        update_progress_msg("walking reachable data...".to_string())?;
        {
            // Walk all reachable data WITHOUT an exclusive repo lock, this means
            // we should be able to walk most of the data except data
            // that arrives between the end of this walk and us getting the
            // exclusive lock on the repository.
            let mut tx = self.conn.transaction()?;
            update_progress_msg("walking reachable data...".to_string())?;
            Repo::walk_items(&self.repo_id, &mut tx, &mut walk_item)?;
            tx.commit()?;
        }

        update_progress_msg("acquiring exclusive repository lock...".to_string())?;
        self.alter_lock_mode(LockMode::Exclusive)?;

        // We must commit the new gc generation before we start
        // deleting any chunks, the gc generation is how we invalidate
        // client side put caches.
        self.conn.execute(
            "update RepositoryMeta set Value = $1 where RepoId=$2 and Key = 'gc-generation';",
            &[&Xid::new(), &self.repo_id],
        )?;

        {
            let mut tx = self.conn.transaction()?;

            update_progress_msg("finalizing reachable data...".to_string())?;
            // Will skip items that we already processed when we did not hold
            // an exclusive repository lock.
            Repo::walk_items(&self.repo_id, &mut tx, &mut walk_item)?;

            update_progress_msg("compacting item log...".to_string())?;
            // Remove everything not in the aggregated set.
            tx.execute(
                "delete from ItemOpLog where RepoId=$1 and ((ItemId is null) or (ItemId not in (select ItemId from Items where RepoId=$1)));",
                &[&self.repo_id],
            )?;

            tx.commit()?;
        }

        self.conn.execute(
            "update RepositoryMeta set Value=$1 where RepoId=$2 and Key='gc-dirty';",
            &[&"1", &self.repo_id],
        )?;

        // The after this commit, the reachability database now contains all reachable chunks
        // ready for use by the storage engine.
        reachability_tx.commit()?;

        let mut last_ping = std::time::Instant::now();
        let mut on_heartbeat = || -> Result<(), failure::Error> {
            // We ping the connection to verify our lock still holds.
            // We may not ping every second, it depends on how often the external
            // gc calls progress.
            let now = std::time::Instant::now();
            if now.duration_since(last_ping) > std::time::Duration::from_secs(1) {
                self.conn.query("select 1;", &[])?;
                last_ping = now;
            }

            Ok(())
        };

        update_progress_msg("deleting unused chunks...".to_string())?;
        let stats = storage_engine.gc(
            &reachability_db_path,
            &mut reachability_db,
            &mut on_heartbeat,
        )?;

        // We no longer need this reachability database.
        std::fs::remove_file(&reachability_db_path)?;

        self.conn.execute(
            "update RepositoryMeta set Value=$1 where RepoId=$2 and Key='gc-dirty';",
            &[&"0", &self.repo_id],
        )?;

        Ok(stats)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dir_store_sanity_test() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let mut path_buf = PathBuf::from(tmp_dir.path());
        path_buf.push("repo");
        Repo::init(path_buf.as_path(), Some(StorageEngineSpec::DirStore)).unwrap();
        let repo = Repo::open(path_buf.as_path()).unwrap();
        let mut storage_engine = repo.storage_engine().unwrap();
        let addr = Address::default();
        storage_engine.add_chunk(&addr, vec![1]).unwrap();
        storage_engine.sync().unwrap();
        storage_engine.add_chunk(&addr, vec![2]).unwrap();
        storage_engine.sync().unwrap();
        let v = storage_engine.get_chunk(&addr).unwrap();
        assert_eq!(v, vec![1]);
    }
}
