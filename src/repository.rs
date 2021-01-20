use super::chunk_storage;
use super::compression;
use super::crypto;
use super::dir_chunk_storage;
use super::external_chunk_storage;
use super::fsutil;
use super::hex;
use super::htree;
use super::itemset;
use super::xid::*;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

#[non_exhaustive]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum StorageEngineSpec {
    DirStore,
    ExternalStore { socket_path: String, path: String },
}

#[derive(Clone, PartialEq)]
pub enum LockMode {
    None,
    Write,
    Exclusive,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct GCStats {
    pub chunks_deleted: Option<usize>,
    pub bytes_deleted: Option<usize>,
    pub chunks_remaining: Option<usize>,
    pub bytes_remaining: Option<usize>,
}

pub struct Repo {
    repo_path: PathBuf,
    conn: rusqlite::Connection,
    repo_lock_mode: LockMode,
    repo_lock: Option<fsutil::FileLock>,
}

pub enum ItemSyncEvent {
    Start(Xid),
    LogOps(Vec<(i64, Option<Xid>, itemset::LogOp)>),
    End,
}

impl Repo {
    fn repo_lock_path(repo_path: &Path) -> PathBuf {
        let mut lock_path = repo_path.to_path_buf();
        lock_path.push("repo.lock");
        lock_path
    }

    fn tmp_dir_path(repo_path: &Path) -> PathBuf {
        let mut lock_path = repo_path.to_path_buf();
        lock_path.push("tmp");
        lock_path
    }

    fn repo_db_path(repo_path: &Path) -> PathBuf {
        let mut db_path = repo_path.to_path_buf();
        db_path.push("bupstash.sqlite3");
        db_path
    }

    fn open_db_with_flags(
        db_path: &Path,
        flags: rusqlite::OpenFlags,
    ) -> Result<rusqlite::Connection, anyhow::Error> {
        let conn = rusqlite::Connection::open_with_flags(db_path, flags)?;

        conn.query_row("pragma busy_timeout=3600000;", rusqlite::NO_PARAMS, |_r| {
            Ok(())
        })?;

        Ok(conn)
    }

    fn open_db(db_path: &Path) -> Result<rusqlite::Connection, anyhow::Error> {
        let default_flags = rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE;
        Repo::open_db_with_flags(db_path, default_flags)
    }

    pub fn init(
        repo_path: &Path,
        storage_engine: Option<StorageEngineSpec>,
    ) -> Result<(), anyhow::Error> {
        let storage_engine = match storage_engine {
            Some(storage_engine) => storage_engine,
            None => StorageEngineSpec::DirStore,
        };

        let parent = if repo_path.is_absolute() {
            repo_path.parent().unwrap().to_owned()
        } else {
            let abs = std::env::current_dir()?.join(repo_path);
            let parent = abs.parent().unwrap();
            parent.to_owned()
        };

        let mut path_buf = PathBuf::from(&parent);
        if repo_path.exists() {
            anyhow::bail!(
                "repository already exists at {}",
                repo_path.to_string_lossy().to_string()
            );
        }

        let mut tmpname = repo_path
            .file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new(""))
            .to_os_string();
        tmpname.push(".bupstash-repo-init-tmp");
        path_buf.push(&tmpname);
        if path_buf.exists() {
            anyhow::bail!(
                "temp dir already exists at {}",
                path_buf.to_string_lossy().to_string()
            );
        }

        fs::DirBuilder::new().create(path_buf.as_path())?;

        path_buf.push("repo.lock");
        fsutil::create_empty_file(path_buf.as_path())?;
        path_buf.pop();

        path_buf.push("tmp");
        fs::DirBuilder::new().create(path_buf.as_path())?;
        path_buf.pop();

        path_buf.push("storage-engine.json");
        let storage_engine_buf = serde_json::to_vec_pretty(&storage_engine)?;
        fsutil::atomic_add_file(path_buf.as_path(), &storage_engine_buf)?;
        path_buf.pop();

        let mut conn = Repo::open_db_with_flags(
            &Repo::repo_db_path(&path_buf),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_CREATE,
        )?;

        conn.query_row(
            "PRAGMA journal_mode = WAL;",
            rusqlite::NO_PARAMS,
            |_| Ok(()),
        )?;

        let tx = conn.transaction()?;

        tx.execute(
            "create table RepositoryMeta(Key primary key, Value) without rowid;",
            rusqlite::NO_PARAMS,
        )?;
        tx.execute(
            /* Schema version is a string to keep all meta rows the same type. */
            "insert into RepositoryMeta(Key, Value) values('schema-version', '2');",
            rusqlite::NO_PARAMS,
        )?;
        tx.execute(
            "insert into RepositoryMeta(Key, Value) values('id', ?);",
            rusqlite::params![Xid::new()],
        )?;
        tx.execute(
            "insert into RepositoryMeta(Key, Value) values('gc-generation', ?);",
            rusqlite::params![Xid::new()],
        )?;
        tx.execute(
            "insert into RepositoryMeta(Key, Value) values('gc-dirty', Null);",
            rusqlite::NO_PARAMS,
        )?;

        itemset::init_tables(&tx)?;

        tx.commit()?;
        drop(conn);

        fsutil::sync_dir(&path_buf)?;
        std::fs::rename(&path_buf, repo_path)?;
        Ok(())
    }

    pub fn open(repo_path: &Path) -> Result<Repo, anyhow::Error> {
        if !repo_path.exists() {
            anyhow::bail!("no repository at {}", repo_path.to_string_lossy());
        }

        let conn = Repo::open_db(&Repo::repo_db_path(&repo_path))?;

        let v: String = conn.query_row(
            "select Value from RepositoryMeta where Key='schema-version';",
            rusqlite::NO_PARAMS,
            |row| row.get(0),
        )?;
        if v.parse::<u64>().unwrap() != 2 {
            anyhow::bail!("repository has an unsupported schema version");
        }

        Ok(Repo {
            conn,
            repo_path: fs::canonicalize(&repo_path)?,
            repo_lock_mode: LockMode::None,
            repo_lock: None,
        })
    }

    pub fn alter_lock_mode(&mut self, lock_mode: LockMode) -> Result<(), anyhow::Error> {
        // On error we should perhaps put a poison value.
        if self.repo_lock_mode != lock_mode {
            self.repo_lock_mode = lock_mode.clone();
            self.repo_lock = None;
            self.repo_lock = match lock_mode {
                LockMode::None => None,
                LockMode::Write => Some(fsutil::FileLock::get_shared(&Repo::repo_lock_path(
                    &self.repo_path,
                ))?),
                LockMode::Exclusive => Some(fsutil::FileLock::get_exclusive(
                    &Repo::repo_lock_path(&self.repo_path),
                )?),
            };

            if matches!(self.repo_lock_mode, LockMode::Write | LockMode::Exclusive) {
                // The gc_dirty id is set when a garbage collection exits without
                // proper cleanup. For external storage engines this poses a problem:
                //
                // Consider the following case:
                //
                // 1. We are deleting a set of objects in an external storage engine.
                // 2. A delete object message is sent to the backing store (s3/gcs/w.e.)
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

                if let Some(gc_dirty) = self.gc_check_dirty()? {
                    let mut storage_engine = self.storage_engine()?;
                    storage_engine.await_gc_completion(gc_dirty)?;
                    // Because we hold either a write lock, or the exclusive lock, we know gc-dirty
                    // cannot change from anything but dirty to clean at this point. If multiple
                    // concurrent instances of bupstash reach this point at the same time, it won't
                    // prematurely clear the dirty marker for a different GC.
                    self.gc_clear_dirty()?;
                }
            }
        }

        Ok(())
    }

    pub fn storage_engine_spec(&self) -> Result<StorageEngineSpec, anyhow::Error> {
        let mut p = self.repo_path.clone();
        p.push("storage-engine.json");
        let mut f = std::fs::OpenOptions::new().read(true).open(p)?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf)?;
        let spec = serde_json::from_slice(&buf)?;
        Ok(spec)
    }

    pub fn storage_engine_from_spec(
        &self,
        spec: &StorageEngineSpec,
    ) -> Result<Box<dyn chunk_storage::Engine>, anyhow::Error> {
        let storage_engine: Box<dyn chunk_storage::Engine> = match spec {
            StorageEngineSpec::DirStore => {
                let mut data_dir = self.repo_path.to_path_buf();
                data_dir.push("data");
                Box::new(dir_chunk_storage::DirStorage::new(&data_dir)?)
            }
            StorageEngineSpec::ExternalStore {
                socket_path, path, ..
            } => {
                let socket_path = PathBuf::from(socket_path);
                Box::new(external_chunk_storage::ExternalStorage::new(
                    &socket_path,
                    &path.to_string(),
                )?)
            }
        };
        Ok(storage_engine)
    }

    pub fn storage_engine(&self) -> Result<Box<dyn chunk_storage::Engine>, anyhow::Error> {
        let spec = self.storage_engine_spec()?;
        self.storage_engine_from_spec(&spec)
    }

    pub fn gc_generation(&self) -> Result<Xid, anyhow::Error> {
        Ok(self.conn.query_row(
            "select Value from RepositoryMeta where Key='gc-generation';",
            rusqlite::NO_PARAMS,
            |row| row.get(0),
        )?)
    }

    pub fn add_item(
        &mut self,
        gc_generation: Xid,
        item: itemset::VersionedItemMetadata,
    ) -> Result<Xid, anyhow::Error> {
        match self.repo_lock_mode {
            LockMode::None => panic!("BUG: write lock not held when adding item"),
            LockMode::Write | LockMode::Exclusive => (),
        }

        const MAX_HTREE_HEIGHT: u64 = 10;

        match item {
            itemset::VersionedItemMetadata::V1(ref item) => {
                if item.plain_text_metadata.data_tree.height.0 > MAX_HTREE_HEIGHT {
                    anyhow::bail!("refusing to add data hash tree taller than application limit");
                }
                if let Some(index_tree) = &item.plain_text_metadata.index_tree {
                    if index_tree.height.0 > MAX_HTREE_HEIGHT {
                        anyhow::bail!(
                            "refusing to add index hash tree taller than application limit"
                        );
                    }
                }
            }
        }

        let tx = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

        let current_gc_generation = tx.query_row(
            "select Value from RepositoryMeta where Key='gc-generation';",
            rusqlite::NO_PARAMS,
            |row| row.get(0),
        )?;

        if gc_generation != current_gc_generation {
            anyhow::bail!("gc generation changed during send, aborting");
        }

        let id = itemset::add_item(&tx, item)?;
        tx.commit()?;
        Ok(id)
    }

    pub fn remove_items(&mut self, items: Vec<Xid>) -> Result<(), anyhow::Error> {
        self.alter_lock_mode(LockMode::Write)?;

        let tx = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        itemset::remove_items(&tx, items)?;
        tx.commit()?;
        Ok(())
    }

    pub fn lookup_item_by_id(
        &mut self,
        id: &Xid,
    ) -> Result<Option<itemset::VersionedItemMetadata>, anyhow::Error> {
        let tx = self.conn.transaction()?;
        itemset::lookup_item_by_id(&tx, id)
    }

    pub fn has_item_with_id(&mut self, id: &Xid) -> Result<bool, anyhow::Error> {
        let tx = self.conn.transaction()?;
        itemset::has_item_with_id(&tx, id)
    }

    pub fn item_sync(
        &mut self,
        after: i64,
        start_gc_generation: Option<Xid>,
        on_sync_event: &mut dyn FnMut(ItemSyncEvent) -> Result<(), anyhow::Error>,
    ) -> Result<(), anyhow::Error> {
        let tx = self.conn.transaction()?;

        let current_gc_generation = tx.query_row(
            "select Value from RepositoryMeta where Key='gc-generation';",
            rusqlite::NO_PARAMS,
            |row| row.get(0),
        )?;

        let after = match start_gc_generation {
            Some(start_gc_generation) if start_gc_generation == current_gc_generation => after,
            _ => -1,
        };

        on_sync_event(ItemSyncEvent::Start(current_gc_generation))?;

        let mut logops = Vec::new();

        itemset::walk_log(&tx, after, &mut |op_id, item_id, op| {
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

    pub fn restore_removed(&mut self) -> Result<u64, anyhow::Error> {
        self.alter_lock_mode(LockMode::Write)?;

        let tx = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let n_restored = itemset::restore_removed(&tx)?;
        if n_restored > 0 {
            tx.commit()?;
        }
        Ok(n_restored)
    }

    fn walk_items(
        &mut self,
        f: &mut dyn FnMut(i64, Xid, itemset::VersionedItemMetadata) -> Result<(), anyhow::Error>,
    ) -> Result<(), anyhow::Error> {
        let tx = self.conn.transaction()?;
        itemset::walk_items(&tx, f)?;
        tx.commit()?;
        Ok(())
    }

    fn random_tmp_reachability_db_path(repo_path: &Path) -> PathBuf {
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

        let mut db_path = Repo::tmp_dir_path(repo_path);
        db_path.push(file_name);
        db_path
    }

    fn gc_remove_temp_files(&mut self) -> Result<(), anyhow::Error> {
        debug_assert!(matches!(self.repo_lock_mode, LockMode::Exclusive));

        let mut to_remove = Vec::new();
        for e in std::fs::read_dir(Repo::tmp_dir_path(&self.repo_path))? {
            let e = e?;
            to_remove.push(e.path());
        }
        for p in to_remove.iter() {
            std::fs::remove_file(p)?;
        }

        Ok(())
    }

    fn gc_compact(&mut self) -> Result<(), anyhow::Error> {
        debug_assert!(matches!(self.repo_lock_mode, LockMode::Exclusive));
        let tx = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        itemset::compact(&tx)?;
        tx.commit()?;
        self.conn.execute("vacuum;", rusqlite::NO_PARAMS)?;
        Ok(())
    }

    fn gc_mark_dirty(&mut self, gc_generation: Xid) -> Result<(), anyhow::Error> {
        debug_assert!(matches!(self.repo_lock_mode, LockMode::Exclusive));

        let tx = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

        // We cycle the gc generation here to invalidate client caches.
        tx.execute(
            "update RepositoryMeta set Value = ? where Key = 'gc-generation';",
            rusqlite::params![&gc_generation],
        )?;

        // If a repository is dirty when we lock it, then we must ensure
        // the storage backend has terminated before continuing.
        tx.execute(
            "update RepositoryMeta set Value = ? where Key = 'gc-dirty';",
            rusqlite::params![&gc_generation],
        )?;

        tx.commit()?;
        Ok(())
    }

    fn gc_check_dirty(&mut self) -> Result<Option<Xid>, anyhow::Error> {
        Ok(self.conn.query_row(
            "select Value from RepositoryMeta where Key='gc-dirty';",
            rusqlite::NO_PARAMS,
            |row| row.get(0),
        )?)
    }

    fn gc_clear_dirty(&mut self) -> Result<(), anyhow::Error> {
        debug_assert!(matches!(self.repo_lock_mode, LockMode::Exclusive));

        let tx = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

        tx.execute(
            "update RepositoryMeta set Value = null where Key = 'gc-dirty';",
            rusqlite::NO_PARAMS,
        )?;

        tx.commit()?;
        Ok(())
    }

    pub fn gc(
        &mut self,
        update_progress_msg: &mut dyn FnMut(String) -> Result<(), anyhow::Error>,
    ) -> Result<GCStats, anyhow::Error> {
        self.alter_lock_mode(LockMode::Exclusive)?;

        update_progress_msg("removing temporary files...".to_string())?;

        // We remove stale temporary files first so we don't accumulate them during failed gc attempts.
        self.gc_remove_temp_files()?;

        // Once we have removed temporary files, we can temporarily go back to a shared lock
        // so backups can keep happening.
        self.alter_lock_mode(LockMode::Write)?;

        let reachability_db_path = Repo::random_tmp_reachability_db_path(&self.repo_path);
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

                // For garbage collection walking in order is not a concern,
                // we just need to ensure we touch each reachable node.
                //
                // Note that we could also do some sort of pipelining or parallel fetch,
                // when we walk the tree, for now keep it simple.

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
        // Walk all reachable data WITHOUT an exclusive repo lock, this means
        // we should be able to walk most of the data except data
        // that arrives between the end of this walk and us getting the
        // exclusive lock on the repository.
        self.walk_items(&mut walk_item)?;

        update_progress_msg("acquiring exclusive repository lock...".to_string())?;
        self.alter_lock_mode(LockMode::Exclusive)?;

        update_progress_msg("finalizing reachable data...".to_string())?;
        // Now that we have an exlusive lock, we walk the items again, this will
        // be fast for items we already walked, and lets us pick up any new items.
        self.walk_items(&mut walk_item)?;

        // After this commit the reachability database contains all reachable chunks
        // ready for use by the storage engine.
        reachability_tx.commit()?;

        update_progress_msg("compacting item log...".to_string())?;
        // After compaction, removed items are deleted from the metadata database.
        self.gc_compact()?;

        let gc_generation = Xid::new();
        // We ensure the storage engine has saved this gc_generation before we commit
        // this generation to the repository. The idea here is once we start deleting
        // items asynchronously via a plugin, we must ensure the storage engine signals
        // that the deletions have terminated. This let's us avoid a nasty case
        // of deletions occuring in the background while we think they have finished.
        // One cause of this would be a crash of 'serve' process
        // while it is still holding the repository locks.
        storage_engine.prepare_for_gc(gc_generation)?;
        self.gc_mark_dirty(gc_generation)?;

        update_progress_msg("deleting unused chunks...".to_string())?;
        let stats = storage_engine.gc(&reachability_db_path, &mut reachability_db)?;

        std::fs::remove_file(&reachability_db_path)?;
        self.gc_clear_dirty()?;
        Ok(stats)
    }
}

#[cfg(test)]
mod tests {
    use super::super::address::*;
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
