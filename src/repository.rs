use super::chunk_storage;
use super::crypto;
use super::dir_chunk_storage;
use super::external_chunk_storage;
use super::fsutil;
use super::hex;
use super::htree;
use super::itemset;
use super::xid::*;
use failure::Fail;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

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

#[non_exhaustive]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum StorageEngineSpec {
    DirStore,
    ExternalStore {
        socket_path: String,
        path: String,
        quiescent_period_ms: Option<u64>,
    },
}

#[derive(Clone)]
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
    repo_path: PathBuf,
    conn: rusqlite::Connection,
    _repo_lock_mode: LockMode,
    _repo_lock: Option<fsutil::FileLock>,
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

    fn repo_db_path(repo_path: &Path) -> PathBuf {
        let mut db_path = repo_path.to_path_buf();
        db_path.push("bupstash.sqlite3");
        db_path
    }

    fn open_db_with_flags(
        db_path: &Path,
        flags: rusqlite::OpenFlags,
    ) -> Result<rusqlite::Connection, failure::Error> {
        let conn = rusqlite::Connection::open_with_flags(db_path, flags)?;

        conn.query_row("pragma busy_timeout=3600000;", rusqlite::NO_PARAMS, |_r| {
            Ok(())
        })?;

        Ok(conn)
    }

    fn open_db(db_path: &Path) -> Result<rusqlite::Connection, failure::Error> {
        let default_flags = rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE;
        Repo::open_db_with_flags(db_path, default_flags)
    }

    pub fn init(
        repo_path: &Path,
        storage_engine: Option<StorageEngineSpec>,
    ) -> Result<(), failure::Error> {
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
            return Err(RepoError::AlreadyExists {
                path: repo_path.to_string_lossy().to_string(),
            }
            .into());
        }

        let mut tmpname = repo_path
            .file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new(""))
            .to_os_string();
        tmpname.push(".bupstash-repo-init-tmp");
        path_buf.push(&tmpname);
        if path_buf.exists() {
            return Err(RepoError::AlreadyExists {
                path: path_buf.to_string_lossy().to_string(),
            }
            .into());
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
            "insert into RepositoryMeta(Key, Value) values('schema-version', '1');",
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
            "insert into RepositoryMeta(Key, Value) values('gc-dirty', ?);",
            rusqlite::params![false],
        )?;

        itemset::init_tables(&tx)?;

        tx.commit()?;
        drop(conn);

        fsutil::sync_dir(&path_buf)?;
        std::fs::rename(&path_buf, repo_path)?;
        Ok(())
    }

    pub fn open(repo_path: &Path) -> Result<Repo, failure::Error> {
        if !repo_path.exists() {
            failure::bail!("no repository at {}", repo_path.to_string_lossy());
        }

        let repo_lock = fsutil::FileLock::get_shared(&Repo::repo_lock_path(&repo_path))?;

        let conn = Repo::open_db(&Repo::repo_db_path(&repo_path))?;

        let v: String = conn.query_row(
            "select Value from RepositoryMeta where Key='schema-version';",
            rusqlite::NO_PARAMS,
            |row| row.get(0),
        )?;
        if v.parse::<u64>().unwrap() != 1 {
            return Err(RepoError::UnsupportedSchemaVersion.into());
        }

        let r = Repo {
            conn,
            repo_path: fs::canonicalize(&repo_path)?,
            _repo_lock_mode: LockMode::Shared,
            _repo_lock: Some(repo_lock),
        };

        r.handle_gc_dirty()?;

        Ok(r)
    }

    fn handle_gc_dirty(&self) -> Result<(), failure::Error> {
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

        let gc_dirty: bool = self.conn.query_row(
            "select Value from RepositoryMeta where Key='gc-dirty';",
            rusqlite::NO_PARAMS,
            |row| row.get(0),
        )?;

        if gc_dirty {
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
                StorageEngineSpec::DirStore { .. } => (),
            }
            self.conn.execute(
                "update RepositoryMeta set Value = ? where key = 'gc-dirty';",
                rusqlite::params![false],
            )?;
        }

        Ok(())
    }

    pub fn alter_lock_mode(&mut self, repo_lock_mode: LockMode) -> Result<(), failure::Error> {
        self._repo_lock = None;
        self._repo_lock_mode = repo_lock_mode.clone();
        // On error we should perhaps put a poison value.
        self._repo_lock = match repo_lock_mode {
            LockMode::Shared => Some(fsutil::FileLock::get_shared(&Repo::repo_lock_path(
                &self.repo_path,
            ))?),
            LockMode::Exclusive => Some(fsutil::FileLock::get_exclusive(&Repo::repo_lock_path(
                &self.repo_path,
            ))?),
        };
        Ok(())
    }

    pub fn storage_engine_spec(&self) -> Result<StorageEngineSpec, failure::Error> {
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
    ) -> Result<Box<dyn chunk_storage::Engine>, failure::Error> {
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

    pub fn storage_engine(&self) -> Result<Box<dyn chunk_storage::Engine>, failure::Error> {
        let spec = self.storage_engine_spec()?;
        self.storage_engine_from_spec(&spec)
    }

    pub fn gc_generation(&self) -> Result<Xid, failure::Error> {
        Ok(self.conn.query_row(
            "select Value from RepositoryMeta where Key='gc-generation';",
            rusqlite::NO_PARAMS,
            |row| row.get(0),
        )?)
    }

    pub fn add_item(
        &mut self,
        item: itemset::VersionedItemMetadata,
    ) -> Result<Xid, failure::Error> {
        let tx = self.conn.transaction()?;
        let id = itemset::add_item(&tx, item)?;
        tx.commit()?;
        Ok(id)
    }

    pub fn remove_items(&mut self, items: Vec<Xid>) -> Result<(), failure::Error> {
        let tx = self.conn.transaction()?;
        itemset::remove_items(&tx, items)?;
        tx.commit()?;
        Ok(())
    }

    pub fn lookup_item_by_id(
        &mut self,
        id: &Xid,
    ) -> Result<Option<itemset::VersionedItemMetadata>, failure::Error> {
        let tx = self.conn.transaction()?;
        itemset::lookup_item_by_id(&tx, id)
    }

    pub fn has_item_with_id(&mut self, id: &Xid) -> Result<bool, failure::Error> {
        let tx = self.conn.transaction()?;
        itemset::has_item_with_id(&tx, id)
    }

    pub fn walk_log(
        &mut self,
        after: i64,
        f: &mut dyn FnMut(i64, Option<Xid>, itemset::LogOp) -> Result<(), failure::Error>,
    ) -> Result<(), failure::Error> {
        let tx = self.conn.transaction()?;
        itemset::walk_log(&tx, after, f)
    }

    pub fn restore_removed(&mut self) -> Result<u64, failure::Error> {
        let tx = self.conn.transaction()?;
        let n_restored = itemset::restore_removed(&tx)?;
        if n_restored > 0 {
            tx.commit()?;
        }
        Ok(n_restored)
    }

    pub fn gc(
        &mut self,
        update_progress_msg: &mut dyn FnMut(String) -> Result<(), failure::Error>,
    ) -> Result<GCStats, failure::Error> {
        self.alter_lock_mode(LockMode::Exclusive)?;
        // We remove stale temporary files first so we don't accumulate them during failed gc attempts.
        // For example, this could make out of space problems even worse.
        update_progress_msg("removing temporary files...".to_string())?;
        {
            let mut to_remove = Vec::new();
            for e in std::fs::read_dir(Repo::tmp_dir_path(&self.repo_path))? {
                let e = e?;
                to_remove.push(e.path());
            }
            for p in to_remove.iter() {
                std::fs::remove_file(p)?;
            }
        }
        // Once we have removed temporary files, we can go back to a shared lock.
        self.alter_lock_mode(LockMode::Shared)?;

        let reachability_db_path = Repo::random_tmp_reachability_db_path(&self.repo_path);
        let mut reachability_db = rusqlite::Connection::open(&reachability_db_path)?;

        // Because this is a fresh database (we already removed all tmp files), we
        // are ok to disable synchronous operation. If we get power off event, the next
        // gc will remove the corrupt database first so theres no chance we open a corrupt db.
        reachability_db.execute("pragma synchronous = OFF;", rusqlite::NO_PARAMS)?;

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
                    let mut tr = htree::TreeReader::new(tree.height, &tree.address);
                    while let Some((height, addr)) = tr.next_addr()? {
                        let rows_changed =
                            add_reachability_stmt.execute(rusqlite::params![&addr.bytes[..]])?;
                        if rows_changed != 0 && height != 0 {
                            let data = storage_engine.get_chunk(&addr)?;
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
            let tx = self.conn.transaction()?;
            update_progress_msg("walking reachable data...".to_string())?;
            itemset::walk_items(&tx, &mut walk_item)?;
            tx.commit()?;
        }

        update_progress_msg("acquiring exclusive repository lock...".to_string())?;
        self.alter_lock_mode(LockMode::Exclusive)?;

        // We must commit the new gc generation before we start
        // deleting any chunks, the gc generation is how we invalidate
        // client side put caches.
        self.conn.execute(
            "update RepositoryMeta set Value = ? where Key = 'gc-generation';",
            rusqlite::params![Xid::new()],
        )?;

        {
            let tx = self.conn.transaction()?;

            update_progress_msg("finalizing reachable data...".to_string())?;
            // Will skip items that we already processed when we did not hold
            // an exclusive repository lock.
            itemset::walk_items(&tx, &mut walk_item)?;

            update_progress_msg("compacting item log...".to_string())?;
            itemset::compact(&tx)?;

            tx.commit()?;
        }

        self.conn.execute("vacuum;", rusqlite::NO_PARAMS)?;

        self.conn.execute(
            "update RepositoryMeta set Value = ? where Key = 'gc-dirty';",
            rusqlite::params![true],
        )?;

        // The after this commit, the reachability database now contains all reachable chunks
        // ready for use by the storage engine.
        reachability_tx.commit()?;

        update_progress_msg("deleting unused chunks...".to_string())?;
        let stats = storage_engine.gc(&reachability_db_path, &mut reachability_db)?;

        // We no longer need this reachability database.
        std::fs::remove_file(&reachability_db_path)?;

        self.conn.execute(
            "update RepositoryMeta set Value = ? where Key = 'gc-dirty';",
            rusqlite::params![false],
        )?;

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
