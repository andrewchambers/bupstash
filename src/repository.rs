use super::address::*;
use super::chunk_storage;
use super::crypto;
use super::external_chunk_storage;
use super::fsutil;
use super::hex;
use super::htree;
use super::itemset;
use super::local_chunk_storage;
use failure::Fail;
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Fail)]
pub enum RepoError {
    #[fail(display = "path {} already exists, refusing to overwrite it", path)]
    AlreadyExists { path: String },
    #[fail(display = "repository was not initialized properly")]
    NotInitializedProperly,
    #[fail(display = "repository does not exist")]
    RepoDoesNotExist,
    #[fail(display = "sqlite error while manipulating the database: {}", err)]
    SqliteError { err: rusqlite::Error },
    #[fail(display = "repository database at unsupported version")]
    UnsupportedSchemaVersion,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum StorageEngineSpec {
    Local,
    External { socket_path: String, path: String },
}

#[derive(Clone)]
pub enum GCLockMode {
    Shared,
    Exclusive,
}

pub struct Repo {
    repo_path: PathBuf,
    conn: rusqlite::Connection,
    _gc_lock_mode: GCLockMode,
    _gc_lock: Option<FileLock>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct GCStats {
    pub chunks_freed: usize,
    pub bytes_freed: usize,
    pub chunks_remaining: usize,
    pub bytes_remaining: usize,
}

struct FileLock {
    f: fs::File,
}

impl FileLock {
    fn get_exclusive(p: &Path) -> Result<FileLock, std::io::Error> {
        let f = fs::File::open(p)?;
        f.lock_exclusive()?;
        Ok(FileLock { f })
    }

    fn get_shared(p: &Path) -> Result<FileLock, std::io::Error> {
        let f = fs::File::open(p)?;
        f.lock_shared()?;
        Ok(FileLock { f })
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        self.f.unlock().unwrap();
    }
}

fn new_random_token() -> String {
    let mut gen: [u8; 32] = [0; 32];
    crypto::randombytes(&mut gen);
    hex::easy_encode_to_string(&gen)
}

impl Repo {
    fn ensure_file_exists(p: &Path) -> Result<(), failure::Error> {
        if p.exists() {
            Ok(())
        } else {
            Err(RepoError::NotInitializedProperly.into())
        }
    }

    fn check_sane(repo_path: &Path) -> Result<(), failure::Error> {
        if !repo_path.exists() {
            return Err(RepoError::RepoDoesNotExist.into());
        }
        let mut path_buf = PathBuf::from(repo_path);
        path_buf.push("data");
        Repo::ensure_file_exists(&path_buf.as_path())?;
        path_buf.pop();
        path_buf.push("archivist.sqlite3");
        Repo::ensure_file_exists(&path_buf.as_path())?;
        path_buf.pop();
        Ok(())
    }

    pub fn init(repo_path: &Path, engine: StorageEngineSpec) -> Result<(), failure::Error> {
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
        tmpname.push(".archivist-repo-init-tmp");
        path_buf.push(&tmpname);
        if path_buf.exists() {
            return Err(RepoError::AlreadyExists {
                path: path_buf.to_string_lossy().to_string(),
            }
            .into());
        }
        fs::DirBuilder::new().create(path_buf.as_path())?;
        path_buf.push("data");
        fs::DirBuilder::new().create(path_buf.as_path())?;
        path_buf.pop();

        path_buf.push("gc.lock");
        fsutil::create_empty_file(path_buf.as_path())?;
        path_buf.pop();

        let mut conn = Repo::open_db(&path_buf)?;

        conn.query_row("pragma journal_mode=WAL;", rusqlite::NO_PARAMS, |_r| Ok(()))?;
        let tx = conn.transaction()?;

        tx.execute(
            "create table RepositoryMeta(Key, Value, UNIQUE(key, value));",
            rusqlite::NO_PARAMS,
        )?;
        tx.execute(
            "insert into RepositoryMeta(Key, Value) values('schema-version', 0);",
            rusqlite::NO_PARAMS,
        )?;
        tx.execute(
            "insert into RepositoryMeta(Key, Value) values('id', ?);",
            rusqlite::params![new_random_token()],
        )?;
        tx.execute(
            "insert into RepositoryMeta(Key, Value) values('gc-generation', ?);",
            rusqlite::params![new_random_token()],
        )?;
        tx.execute(
            "insert into RepositoryMeta(Key, Value) values('storage-engine', ?);",
            rusqlite::params![serde_json::to_string(&engine)?],
        )?;

        itemset::init_tables(&tx)?;

        tx.commit()?;
        drop(conn);

        fsutil::sync_dir(&path_buf)?;
        std::fs::rename(&path_buf, repo_path)?;
        Ok(())
    }

    fn gc_lock_path(repo_path: &Path) -> PathBuf {
        let mut lock_path = repo_path.to_path_buf();
        lock_path.push("gc.lock");
        lock_path
    }

    fn open_db(repo_path: &Path) -> rusqlite::Result<rusqlite::Connection> {
        let mut db_path = repo_path.to_path_buf();
        db_path.push("archivist.sqlite3");
        let conn = rusqlite::Connection::open(db_path)?;
        conn.query_row("pragma busy_timeout=3600000;", rusqlite::NO_PARAMS, |_r| {
            Ok(())
        })?;
        Ok(conn)
    }

    pub fn open(repo_path: &Path) -> Result<Repo, failure::Error> {
        Repo::check_sane(&repo_path)?;

        let conn = Repo::open_db(repo_path)?;
        let v: i32 = conn.query_row(
            "select value from RepositoryMeta where Key='schema-version';",
            rusqlite::NO_PARAMS,
            |row| row.get(0),
        )?;
        if v != 0 {
            return Err(RepoError::UnsupportedSchemaVersion.into());
        }

        Ok(Repo {
            conn,
            repo_path: repo_path.to_path_buf(),
            _gc_lock_mode: GCLockMode::Shared,
            _gc_lock: Some(FileLock::get_shared(&Repo::gc_lock_path(&repo_path))?),
        })
    }

    pub fn alter_gc_lock_mode(&mut self, gc_lock_mode: GCLockMode) {
        self._gc_lock = None;
        self._gc_lock_mode = gc_lock_mode.clone();
        self._gc_lock = match gc_lock_mode {
            GCLockMode::Shared => {
                Some(FileLock::get_shared(&Repo::gc_lock_path(&self.repo_path)).unwrap())
            }
            GCLockMode::Exclusive => {
                Some(FileLock::get_exclusive(&Repo::gc_lock_path(&self.repo_path)).unwrap())
            }
        }
    }

    pub fn storage_engine(&self) -> Result<Box<dyn chunk_storage::Engine>, failure::Error> {
        let engine_meta: String = self.conn.query_row(
            "select value from RepositoryMeta where Key='storage-engine';",
            rusqlite::NO_PARAMS,
            |row| row.get(0),
        )?;

        let spec: StorageEngineSpec = serde_json::from_str(&engine_meta)?;

        let storage_engine: Box<dyn chunk_storage::Engine> = match spec {
            StorageEngineSpec::Local => {
                let mut data_dir = self.repo_path.to_path_buf();
                data_dir.push("data");
                Box::new(local_chunk_storage::LocalStorage::new(&data_dir))
            }
            StorageEngineSpec::External { socket_path, path } => {
                let socket_path = PathBuf::from(socket_path);
                Box::new(external_chunk_storage::ExternalStorage::new(
                    &socket_path,
                    path,
                )?)
            }
        };

        Ok(storage_engine)
    }

    pub fn gc_generation(&self) -> Result<String, failure::Error> {
        Ok(self.conn.query_row(
            "select value from RepositoryMeta where Key='gc-generation';",
            rusqlite::NO_PARAMS,
            |row| row.get(0),
        )?)
    }

    pub fn id(&self) -> Result<String, failure::Error> {
        Ok(self.conn.query_row(
            "select value from RepositoryMeta where Key='id';",
            rusqlite::NO_PARAMS,
            |row| row.get(0),
        )?)
    }

    pub fn do_op(&mut self, op: itemset::LogOp) -> Result<i64, failure::Error> {
        let tx = self.conn.transaction()?;
        let id = itemset::do_op(&tx, &op)?;
        tx.commit()?;
        Ok(id)
    }

    pub fn lookup_item_by_id(
        &mut self,
        id: i64,
    ) -> Result<Option<itemset::VersionedItemMetadata>, failure::Error> {
        let tx = self.conn.transaction()?;
        itemset::lookup_item_by_id(&tx, id)
    }

    pub fn walk_log(
        &mut self,
        after: i64,
        f: &mut dyn FnMut(i64, itemset::LogOp) -> Result<(), failure::Error>,
    ) -> Result<(), failure::Error> {
        let tx = self.conn.transaction()?;
        itemset::walk_log(&tx, after, f)
    }

    pub fn gc(&mut self) -> Result<GCStats, failure::Error> {
        match self._gc_lock_mode {
            GCLockMode::Exclusive => (),
            _ => failure::bail!("unable to collect garbage without an exclusive lock"),
        }

        self.conn.execute("vacuum;", rusqlite::NO_PARAMS)?;

        let mut reachable: HashSet<Address> = std::collections::HashSet::new();
        let mut storage_engine = self.storage_engine()?;

        {
            let tx = self.conn.transaction()?;
            tx.execute(
                "update RepositoryMeta set value = ? where key = 'gc-generation';",
                rusqlite::params![new_random_token()],
            )?;

            itemset::compact(&tx)?;

            itemset::walk_items(&tx, &mut |_id, metadata| match metadata {
                itemset::VersionedItemMetadata::V1(metadata) => {
                    let addr = &metadata.plain_text_metadata.address;
                    if !reachable.contains(&addr) {
                        // IDEA:
                        // It seems likely we could do some sort of pipelining or parallel fetch when we walk the tree.
                        // For garbage collection walking in order is not a concern, we just need to ensure we touch each reachable node.
                        let mut tr =
                            htree::TreeReader::new(metadata.plain_text_metadata.tree_height, addr);
                        while let Some((height, addr)) = tr.next_addr()? {
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

            // We MUST commit the new gc generation before we start
            // deleting any chunks.
            tx.commit()?;
        }

        let stats = storage_engine.gc(reachable)?;
        Ok(stats)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_get_chunk() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let mut path_buf = PathBuf::from(tmp_dir.path());
        path_buf.push("repo");
        Repo::init(path_buf.as_path(), StorageEngineSpec::Local).unwrap();
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
