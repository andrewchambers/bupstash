use super::chunk_storage;
use super::compression;
use super::crypto;
use super::external_chunk_storage;
use super::hex;
use super::htree;
use super::itemset;
use super::xid::*;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::path::PathBuf;

#[non_exhaustive]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum StorageEngineSpec {
    ExternalStore { socket_path: String, path: String },
}

#[derive(Clone, Copy, PartialEq)]
pub enum LockMode {
    None,
    Write,
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

pub enum ItemSyncEvent {
    Start(Xid),
    LogOps(Vec<(i64, Option<Xid>, itemset::LogOp)>),
    End,
}

impl Repo {
    pub fn init(
        _repo_connect: &str,
        _storage_engine: Option<StorageEngineSpec>,
    ) -> Result<(), anyhow::Error> {
        anyhow::bail!("init is not supported");
    }

    fn retryable_txn<T, F>(self: &mut Repo, mut op: F) -> Result<T, anyhow::Error>
    where
        F: FnMut(&str, &mut postgres::Transaction) -> Result<T, anyhow::Error>,
    {
        'retry: loop {
            let mut txn = self
                .conn
                .build_transaction()
                .isolation_level(postgres::IsolationLevel::Serializable)
                .start()?;

            match op(&self.repo_id, &mut txn) {
                Err(err) => {
                    for cause in err.chain() {
                        if let Some(err) = cause.downcast_ref::<postgres::Error>() {
                            if let Some(code) = err.code() {
                                if *code == postgres::error::SqlState::T_R_SERIALIZATION_FAILURE {
                                    continue 'retry;
                                }
                            }
                        }
                    }

                    txn.rollback()?;
                    return Err(err);
                }
                Ok(r) => {
                    txn.commit()?;
                    return Ok(r);
                }
            }
        }
    }

    pub fn open(repo: &str) -> Result<Repo, anyhow::Error> {
        let mut conn =
            postgres::Client::connect(&std::env::var("BUPSTASH_PG_CONNECT")?, postgres::NoTls)?;

        let lock_id: i64 = conn
            .query_one(
                "select Value from RepositoryMeta where RepoId=$1 and Key='lock-id';",
                &[&repo],
            )?
            .get::<_, String>("Value")
            .parse::<i64>()
            .unwrap();

        Ok(Repo {
            conn,
            lock_id,
            repo_id: repo.to_string(),
            _repo_lock_mode: LockMode::None,
        })
    }

    pub fn alter_lock_mode(&mut self, repo_lock_mode: LockMode) -> Result<(), anyhow::Error> {
        if repo_lock_mode != self._repo_lock_mode {
            match self._repo_lock_mode {
                LockMode::None => (),
                LockMode::Write => {
                    self.conn
                        .execute("select pg_advisory_unlock_shared($1);", &[&self.lock_id])?;
                }
                LockMode::Exclusive => {
                    self.conn
                        .execute("select pg_advisory_unlock($1);", &[&self.lock_id])?;
                }
            };

            self._repo_lock_mode = LockMode::None;
            match repo_lock_mode {
                LockMode::None => (),
                LockMode::Write => {
                    self.conn
                        .execute("select pg_advisory_lock_shared($1);", &[&self.lock_id])?;
                }
                LockMode::Exclusive => {
                    self.conn
                        .execute("select pg_advisory_lock($1);", &[&self.lock_id])?;
                }
            };

            self._repo_lock_mode = repo_lock_mode;

            // There is a brief period where we unlocked the database,
            // ensure our repository still exists by querying it.
            self.conn.query_one(
                "select Value from RepositoryMeta where RepoId=$1 and Key='schema-version';",
                &[&self.repo_id],
            )?;

            if matches!(self._repo_lock_mode, LockMode::Write | LockMode::Exclusive) {
                // The gc_dirty id is set when a garbage collection exits without
                // proper cleanup. For external storage engines this poses a problem:
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
                // To solve this we:
                // - explicitly start a gc hold with an id in the storage engine (This hold clears once storage engine gc aborts or finishes).
                // - We then mark the repository as gc-dirty=id.
                // - we then save the gc hold id as gc-hold in the metadata table.
                // - We finally signal to the storage engine it is safe to begin gc deletions.
                // - when deletions finish successfully, we set gc-dirty=false.
                //
                // If during this process, bupstash crashes or is terminated gc-dirty will be set,
                // We cannot safely perform and write or gc operations until we are sure that the interrupted
                // gc has safely terminated in the storage engine.
                //
                // To continue safely gc or writes we must check the gc has finished, we must:
                //
                //  - ensure we have a write or exclusive repository lock.
                //  - check gc-dirty is null, if it is, we can continue with no problems if set we must recover.
                //  - we must explicitly wait for the storage engine backend to tell us our gc operation is complete.
                //  - We can finally remove the gc-dirty marker.

                if let Some(gc_dirty) = self
                    .conn
                    .query_one(
                        "select Value from RepositoryMeta where RepoId=$1 and Key='gc-dirty';",
                        &[&self.repo_id],
                    )?
                    .get(0)
                {
                    let mut storage_engine = self.storage_engine()?;

                    storage_engine.await_gc_completion(gc_dirty)?;

                    self.conn.execute(
                        "update RepositoryMeta set Value = null where RepoId=$1 and Key = 'gc-dirty';",
                        &[&self.repo_id],
                    )?;
                }
            }
        }
        Ok(())
    }

    pub fn storage_engine_spec(&mut self) -> Result<StorageEngineSpec, anyhow::Error> {
        let storage_path: String = self
            .conn
            .query_one(
                "select Value from RepositoryMeta where RepoId=$1 and Key='storage-path'",
                &[&self.repo_id],
            )?
            .get(0);
        let socket_path = std::env::var("BUPSTASH_STORAGE_SOCKET")?;
        Ok(StorageEngineSpec::ExternalStore {
            socket_path,
            path: storage_path,
        })
    }

    pub fn storage_engine_from_spec(
        &mut self,
        spec: &StorageEngineSpec,
    ) -> Result<Box<dyn chunk_storage::Engine>, anyhow::Error> {
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

    pub fn storage_engine(&mut self) -> Result<Box<dyn chunk_storage::Engine>, anyhow::Error> {
        let spec = self.storage_engine_spec()?;
        self.storage_engine_from_spec(&spec)
    }

    pub fn gc_generation(&mut self) -> Result<Xid, anyhow::Error> {
        Ok(self
            .conn
            .query_one(
                "select Value from RepositoryMeta where RepoId=$1 and Key='gc-generation';",
                &[&self.repo_id],
            )?
            .get(0))
    }

    fn checked_serialize_metadata(
        md: &itemset::VersionedItemMetadata,
    ) -> Result<Vec<u8>, anyhow::Error> {
        let serialized_op = serde_bare::to_vec(&md)?;
        if serialized_op.len() > itemset::MAX_METADATA_SIZE {
            anyhow::bail!("itemset log item too big!");
        }
        Ok(serialized_op)
    }

    pub fn add_item(
        &mut self,
        gc_generation: Xid,
        item_metadata: itemset::VersionedItemMetadata,
    ) -> Result<Xid, anyhow::Error> {
        match self._repo_lock_mode {
            LockMode::None => panic!("BUG: write lock not held when adding item"),
            LockMode::Write | LockMode::Exclusive => (),
        }

        const MAX_HTREE_HEIGHT: u64 = 10;

        match item_metadata {
            itemset::VersionedItemMetadata::V1(ref item_metadata) => {
                if item_metadata.plain_text_metadata.data_tree.height.0 > MAX_HTREE_HEIGHT {
                    anyhow::bail!("refusing to add data hash tree taller than application limit");
                }
                if let Some(index_tree) = &item_metadata.plain_text_metadata.index_tree {
                    if index_tree.height.0 > MAX_HTREE_HEIGHT {
                        anyhow::bail!(
                            "refusing to add index hash tree taller than application limit"
                        );
                    }
                }
            }
        }

        self.retryable_txn(|repo_id, tx| {
            let current_gc_generation: Xid = tx
                .query_one(
                    "select Value from RepositoryMeta where RepoId=$1 and Key='gc-generation';",
                    &[&repo_id],
                )?
                .get(0);

            if current_gc_generation != gc_generation {
                anyhow::bail!("gc generation changed during send, aborting");
            }

            let item_id = Xid::new();
            let serialized_md = Repo::checked_serialize_metadata(&item_metadata)?;
            let op = itemset::LogOp::AddItem(item_metadata.clone());
            let serialized_op = serde_bare::to_vec(&op)?;
            let op_id: i64 = tx
                .query_one(
                    "insert into ItemOpLog(RepoId, OpData, ItemId) values($1, $2, $3) returning OpId;",
                    &[&repo_id, &serialized_op, &item_id],
                )?
                .get(0);

            tx.execute(
                "insert into Items(RepoId, OpId, ItemId, Metadata) values($1, $2, $3, $4);",
                &[&repo_id, &op_id, &item_id, &serialized_md],
            )?;
            Ok(item_id)
        })
    }

    pub fn remove_items(&mut self, items: Vec<Xid>) -> Result<(), anyhow::Error> {
        self.alter_lock_mode(LockMode::Write)?;

        self.retryable_txn(|repo_id, tx| {
            let mut existed = Vec::new();
            for item_id in items.iter() {
                let n_deleted = tx.execute(
                    "delete from Items where RepoId=$1 and ItemId = $2;",
                    &[&repo_id, &item_id],
                )?;
                if n_deleted != 0 {
                    existed.push(*item_id);
                }
            }
            let op = itemset::LogOp::RemoveItems(existed);
            let serialized_op = serde_bare::to_vec(&op)?;
            tx.execute(
                "insert into ItemOpLog(RepoId, OpData) values($1, $2);",
                &[&repo_id, &serialized_op],
            )?;

            Ok(())
        })
    }

    pub fn lookup_item_by_id(
        &mut self,
        id: &Xid,
    ) -> Result<Option<itemset::VersionedItemMetadata>, anyhow::Error> {
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

    pub fn has_item_with_id(&mut self, id: &Xid) -> Result<bool, anyhow::Error> {
        let has_item = !self
            .conn
            .query(
                "select 1 from Items where RepoId=$1 and ItemId = $2;",
                &[&self.repo_id, id],
            )?
            .is_empty();
        Ok(has_item)
    }

    pub fn item_sync(
        &mut self,
        after: i64,
        start_gc_generation: Option<Xid>,
        on_sync_event: &mut dyn FnMut(ItemSyncEvent) -> Result<(), anyhow::Error>,
    ) -> Result<(), anyhow::Error> {
        let mut tx = self.conn.transaction()?;

        let current_gc_generation = tx
            .query_one(
                "select Value from RepositoryMeta where RepoId=$1 and Key='gc-generation';",
                &[&self.repo_id],
            )?
            .get("Value");

        let after = match start_gc_generation {
            Some(start_gc_generation) if start_gc_generation == current_gc_generation => after,
            _ => -1,
        };

        on_sync_event(ItemSyncEvent::Start(current_gc_generation))?;

        let mut logops = Vec::new();

        Repo::walk_log(&self.repo_id, &mut tx, after, &mut |op_id, item_id, op| {
            logops.push((op_id, item_id, op));
            if logops.len() >= 64 {
                let mut v = Vec::new();
                std::mem::swap(&mut v, &mut logops);
                on_sync_event(ItemSyncEvent::LogOps(v))?;
            }
            Ok(())
        })?;

        if !logops.is_empty() {
            on_sync_event(ItemSyncEvent::LogOps(logops))?;
        }

        on_sync_event(ItemSyncEvent::End)?;

        tx.commit()?;

        Ok(())
    }

    pub fn walk_log(
        repo_id: &str,
        tx: &mut postgres::Transaction,
        after_op: i64,
        f: &mut dyn FnMut(i64, Option<Xid>, itemset::LogOp) -> Result<(), anyhow::Error>,
    ) -> Result<(), anyhow::Error> {
        tx.execute(
            "declare OpCursor cursor for select OpId, ItemId, OpData from ItemOpLog where RepoId=$1 and OpId > $2 order by OpId asc;",
            &[&repo_id, &after_op],
        )?;

        loop {
            let rows = tx.query("fetch 512 from OpCursor;", &[])?;

            if rows.is_empty() {
                break;
            }

            for row in rows {
                let op_id: i64 = row.get(0);
                let item_id: Option<Xid> = row.get(1);
                let op: Vec<u8> = row.get(2);
                let op: itemset::LogOp = serde_bare::from_slice(&op)?;
                f(op_id, item_id, op)?;
            }
        }

        tx.execute("close OpCursor;", &[])?;
        Ok(())
    }

    fn walk_items(
        repo_id: &str,
        tx: &mut postgres::Transaction,
        f: &mut dyn FnMut(i64, Xid, itemset::VersionedItemMetadata) -> Result<(), anyhow::Error>,
    ) -> Result<(), anyhow::Error> {
        tx.execute(
            "declare ItemCursor cursor for select OpId, ItemId, Metadata from Items where RepoId=$1;",
            &[&repo_id],
        )?;

        loop {
            let rows = tx.query("fetch 512 from ItemCursor;", &[])?;

            if rows.is_empty() {
                break;
            }

            for row in rows {
                let op_id: i64 = row.get(0);
                let item_id: Xid = row.get(1);
                let metadata: Vec<u8> = row.get(2);
                let metadata: itemset::VersionedItemMetadata = serde_bare::from_slice(&metadata)?;
                f(op_id, item_id, metadata)?;
            }
        }

        tx.execute("close ItemCursor;", &[])?;
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

    pub fn restore_removed(&mut self) -> Result<u64, anyhow::Error> {
        self.alter_lock_mode(LockMode::Write)?;

        self.retryable_txn(|repo_id, tx| {

            let mut n_restored = 0;

            let rows = tx.query(
                "select OpId, ItemId, OpData from ItemOpLog where RepoId=$1 and (ItemId is not null) and (ItemId not in (select ItemId from Items where RepoId=$1));", 
                &[&repo_id]
            )?;
            for row in rows {
                let op_id: i64 = row.get(0);
                let item_id: Xid = row.get(1);
                let op: Vec<u8> = row.get(2);
                let op: itemset::LogOp = serde_bare::from_slice(&op)?;
                match &op {
                    itemset::LogOp::AddItem(md) => {
                        n_restored += 1;
                        tx.execute(
                            "insert into Items(ItemId, OpId, Metadata, RepoId) values($1, $2, $3, $4);",
                            &[&item_id, &op_id, &serde_bare::to_vec(&md)?, &repo_id],
                        )?;
                    }
                    _ => (),
                }
            }
            if n_restored > 0 {
                let op = itemset::LogOp::RestoreRemoved;
                let serialized_op = serde_bare::to_vec(&op)?;
                tx.execute(
                    "insert into ItemOpLog(OpData, RepoId) values($1, $2);",
                    &[&serialized_op, &repo_id],
                )?;
            }
            Ok(n_restored)
        })
    }

    pub fn gc(
        &mut self,
        update_progress_msg: &mut dyn FnMut(String) -> Result<(), anyhow::Error>,
    ) -> Result<GCStats, anyhow::Error> {
        self.alter_lock_mode(LockMode::Write)?;

        let reachability_db_path = Repo::random_tmp_reachability_db_path();
        let mut reachability_db = rusqlite::Connection::open(&reachability_db_path)?;

        // Because this is a fresh database (we already removed all tmp files), we
        // are ok to disable synchronous operation. If we get power off event, the next
        // gc will remove the corrupt database first so theres no chance we open a corrupt db.
        reachability_db.execute("pragma synchronous = OFF;", rusqlite::NO_PARAMS)?;
        reachability_db.query_row(
            "pragma journal_mode = OFF;",
            rusqlite::NO_PARAMS,
            |_| Ok(()),
        )?;

        let reachability_tx =
            reachability_db.transaction_with_behavior(rusqlite::TransactionBehavior::Exclusive)?;

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

                // It seems likely we could do some sort of pipelining or parallel fetch when we walk the tree.
                // For garbage collection walking in order is not a concern, we just need to ensure we touch each reachable node.

                let data_tree = metadata.plain_text_metadata.data_tree;

                let trees = if let Some(index_tree) = metadata.plain_text_metadata.index_tree {
                    vec![data_tree, index_tree]
                } else {
                    vec![data_tree]
                };

                for tree in trees {
                    let mut tr = htree::TreeReader::new(
                        tree.height.0.try_into()?,
                        tree.data_chunk_count.0,
                        &tree.address,
                    );
                    while let Some((height, addr)) = tr.next_addr() {
                        let rows_changed =
                            add_reachability_stmt.execute(rusqlite::params![&addr.bytes[..]])?;
                        if rows_changed != 0 && height != 0 {
                            let data = storage_engine.get_chunk(&addr)?;
                            let data = compression::unauthenticated_decompress(data)?;
                            tr.push_level(height - 1, data)?;
                        }
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
            Repo::walk_items(&self.repo_id, &mut tx, &mut walk_item)?;
            tx.commit()?;
        }

        update_progress_msg("acquiring exclusive repository lock...".to_string())?;
        self.alter_lock_mode(LockMode::Exclusive)?;

        update_progress_msg("finalizing reachable data...".to_string())?;
        {
            let mut tx = self.conn.transaction()?;
            Repo::walk_items(&self.repo_id, &mut tx, &mut walk_item)?;
            tx.commit()?;
        }

        // The after this commit, the reachability database now contains all reachable chunks
        // ready for use by the storage engine.
        reachability_tx.commit()?;

        let gc_id = Xid::new();
        storage_engine.prepare_for_gc(gc_id)?;

        update_progress_msg("compacting item log...".to_string())?;
        {
            self.retryable_txn(|repo_id, tx| {
                // We must commit the new gc generation before we start
                // deleting any chunks, the gc generation is how we invalidate
                // client side put caches.
                tx.execute(
                    "update RepositoryMeta set Value = $1 where RepoId=$2 and Key = 'gc-generation';",
                    &[&Xid::new(), &repo_id],
                )?;

                // Remove everything not in the aggregated set.
                tx.execute(
                    "delete from ItemOpLog where RepoId=$1 and OpId not in (select OpId from Items where RepoId=$1);",
                    &[&repo_id],
                )?;

                tx.execute(
                    "update RepositoryMeta set Value = $1 where RepoId=$2 and Key = 'gc-dirty';",
                    &[&gc_id, &repo_id],
                )?;

                Ok(())

             })?;
        }

        update_progress_msg("deleting unused chunks...".to_string())?;
        let stats = storage_engine.gc(&reachability_db_path, &mut reachability_db)?;

        // We no longer need this reachability database.
        std::fs::remove_file(&reachability_db_path)?;

        self.conn.execute(
            "update RepositoryMeta set Value = null where RepoId=$1 and Key = 'gc-dirty';",
            &[&self.repo_id],
        )?;

        Ok(stats)
    }
}
