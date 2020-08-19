use super::address::*;
use super::chunk_storage;
use super::dir_chunk_storage;
use super::external_chunk_storage;
use super::fsutil;
use super::htree;
use super::itemset;
use super::sqlite3_chunk_storage;
use super::xid::*;
use failure::Fail;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
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

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum StorageEngineSpec {
    DirStore {
        dir_path: String,
    },
    Sqlite3Store {
        db_path: String,
    },
    ExternalStore {
        socket_path: String,
        path: String,
        quiescent_period_ms: Option<u64>,
    },
}

#[derive(Clone)]
pub enum GCLockMode {
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
    _gc_lock_mode: GCLockMode,
    _gc_lock: Option<fsutil::FileLock>,
}

impl Repo {
    fn gc_lock_path(repo_path: &Path) -> PathBuf {
        let mut lock_path = repo_path.to_path_buf();
        lock_path.push("gc.lock");
        lock_path
    }

    fn open_db_with_flags(
        repo_path: &Path,
        flags: rusqlite::OpenFlags,
    ) -> rusqlite::Result<rusqlite::Connection> {
        let mut db_path = repo_path.to_path_buf();
        db_path.push("bupstash.sqlite3");

        let conn = rusqlite::Connection::open_with_flags(db_path, flags)?;

        conn.query_row("pragma busy_timeout=3600000;", rusqlite::NO_PARAMS, |_r| {
            Ok(())
        })?;

        Ok(conn)
    }

    fn open_db(repo_path: &Path) -> rusqlite::Result<rusqlite::Connection> {
        let default_flags = rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE;
        Repo::open_db_with_flags(repo_path, default_flags)
    }

    pub fn init(
        repo_path: &Path,
        storage_engine: Option<StorageEngineSpec>,
    ) -> Result<(), failure::Error> {
        let storage_engine = match storage_engine {
            Some(storage_engine) => storage_engine,
            None => StorageEngineSpec::DirStore {
                dir_path: "./data".to_string(),
            },
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

        path_buf.push("gc.lock");
        fsutil::create_empty_file(path_buf.as_path())?;
        path_buf.pop();

        path_buf.push("storage-engine.json");
        let storage_engine_buf = serde_json::to_vec_pretty(&storage_engine)?;
        fsutil::atomic_add_file(path_buf.as_path(), &storage_engine_buf)?;
        path_buf.pop();

        let mut conn = Repo::open_db_with_flags(
            &path_buf,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_CREATE,
        )?;

        conn.query_row("PRAGMA journal_mode = WAL;", rusqlite::NO_PARAMS, |_r| {
            Ok(())
        })?;

        let tx = conn.transaction()?;

        tx.execute(
            "create table RepositoryMeta(Key primary key, Value) without rowid;",
            rusqlite::NO_PARAMS,
        )?;
        tx.execute(
            /* Schema version is a string to keep all meta rows the same type. */
            "insert into RepositoryMeta(Key, Value) values('schema-version', '0');",
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
        let gc_lock = fsutil::FileLock::get_shared(&Repo::gc_lock_path(&repo_path))?;

        let conn = Repo::open_db(repo_path)?;

        let v: String = conn.query_row(
            "select Value from RepositoryMeta where Key='schema-version';",
            rusqlite::NO_PARAMS,
            |row| row.get(0),
        )?;
        if v.parse::<u64>().unwrap() != 0 {
            return Err(RepoError::UnsupportedSchemaVersion.into());
        }

        let r = Repo {
            conn,
            repo_path: repo_path.to_path_buf(),
            _gc_lock_mode: GCLockMode::Shared,
            _gc_lock: Some(gc_lock),
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
                StorageEngineSpec::Sqlite3Store { .. } => (),
            }
            self.conn.execute(
                "update RepositoryMeta set Value = ? where key = 'gc-dirty';",
                rusqlite::params![false],
            )?;
        }

        Ok(())
    }

    pub fn alter_gc_lock_mode(&mut self, gc_lock_mode: GCLockMode) -> Result<(), failure::Error> {
        self._gc_lock = None;
        self._gc_lock_mode = gc_lock_mode.clone();
        self._gc_lock = match gc_lock_mode {
            GCLockMode::Shared => Some(fsutil::FileLock::get_shared(&Repo::gc_lock_path(
                &self.repo_path,
            ))?),
            GCLockMode::Exclusive => Some(fsutil::FileLock::get_exclusive(&Repo::gc_lock_path(
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
            StorageEngineSpec::DirStore { dir_path } => {
                let dir_path: std::path::PathBuf = dir_path.into();
                let dir_path = if dir_path.is_relative() {
                    let mut path_buf = self.repo_path.to_path_buf();
                    path_buf.push(dir_path);
                    path_buf
                } else {
                    dir_path
                };
                Box::new(dir_chunk_storage::DirStorage::new(&dir_path)?)
            }
            StorageEngineSpec::Sqlite3Store { db_path } => {
                let db_path: std::path::PathBuf = db_path.into();
                let db_path = if db_path.is_relative() {
                    let mut path_buf = self.repo_path.to_path_buf();
                    path_buf.push(db_path);
                    path_buf
                } else {
                    db_path
                };
                Box::new(sqlite3_chunk_storage::Sqlite3Storage::new(&db_path)?)
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

    pub fn gc(&mut self) -> Result<GCStats, failure::Error> {
        match self._gc_lock_mode {
            GCLockMode::Exclusive => (),
            _ => failure::bail!("unable to collect garbage without an exclusive lock"),
        }

        // We must COMMIT the new gc generation before we start
        // deleting any chunks, the gc generation is how we invalidate
        // client side put caches.
        self.conn.execute(
            "update RepositoryMeta set Value = ? where Key = 'gc-generation';",
            rusqlite::params![Xid::new()],
        )?;

        let mut reachable: HashSet<Address> = std::collections::HashSet::new();
        let mut storage_engine = self.storage_engine()?;

        let on_progress = || -> Result<(), failure::Error> { Ok(()) };

        {
            let tx = self.conn.transaction()?;

            itemset::compact(&tx)?;

            itemset::walk_items(&tx, &mut |_op_id, _item_id, metadata| match metadata {
                itemset::VersionedItemMetadata::V1(metadata) => {
                    let addr = &metadata.plain_text_metadata.address;
                    // IDEA:
                    // It seems likely we could do some sort of pipelining or parallel fetch when we walk the tree.
                    // For garbage collection walking in order is not a concern, we just need to ensure we touch each reachable node.
                    let mut tr =
                        htree::TreeReader::new(metadata.plain_text_metadata.tree_height, addr);
                    while let Some((height, addr)) = tr.next_addr()? {
                        if !reachable.contains(&addr) {
                            reachable.insert(addr);
                            if height != 0 {
                                let data = storage_engine.get_chunk(&addr)?;
                                tr.push_level(height - 1, data)?;
                            }
                        }
                    }
                    Ok(())
                }
            })?;
            tx.commit()?;
        }

        self.conn.execute("vacuum;", rusqlite::NO_PARAMS)?;

        self.conn.execute(
            "update RepositoryMeta set Value = ? where Key = 'gc-dirty';",
            rusqlite::params![true],
        )?;

        let stats = storage_engine.gc(&on_progress, reachable)?;

        self.conn.execute(
            "update RepositoryMeta set Value = ? where Key = 'gc-dirty';",
            rusqlite::params![false],
        )?;

        Ok(stats)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanity_test() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let mut path_buf = PathBuf::from(tmp_dir.path());
        path_buf.push("repo");
        Repo::init(
            path_buf.as_path(),
            Some(StorageEngineSpec::Sqlite3Store {
                db_path: "./data.sqlite3".to_string(),
            }),
        )
        .unwrap();
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
