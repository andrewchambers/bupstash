use super::address::*;
use super::chunk_storage;
use super::fsutil;
use super::hex;
use super::htree;
use super::hydrogen;
use failure::Fail;
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Fail)]
pub enum StoreError {
    #[fail(display = "path {} already exists, refusing to overwrite it", path)]
    AlreadyExists { path: String },
    #[fail(display = "the store was not initialized properly")]
    NotInitializedProperly,
    #[fail(display = "the store was does not exist")]
    StoreDoesNotExist,
    #[fail(display = "io error while accessing store: {}", err)]
    IOError { err: std::io::Error },
    #[fail(display = "sqlite error while manipulating the database: {}", err)]
    SqliteError { err: rusqlite::Error },
    #[fail(display = "archivist database at unsupported version")]
    UnsupportedSchemaVersion,
}

impl From<std::io::Error> for StoreError {
    fn from(err: std::io::Error) -> StoreError {
        StoreError::IOError { err }
    }
}

impl From<rusqlite::Error> for StoreError {
    fn from(err: rusqlite::Error) -> StoreError {
        StoreError::SqliteError { err }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub enum StorageEngineSpec {
    Local,
}

pub struct Store {
    store_path: PathBuf,
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
        let _ = self.f.unlock();
    }
}

// This handle gets a shared gc.lock
// It allows data append and read access.
pub struct StorageHandle {
    _gc_lock: FileLock,
    engine: Box<dyn chunk_storage::Engine>,
}

// This handle gets a shared gc.lock
// It allows updating the metadata db.
pub struct ChangeStoreHandle {
    _gc_lock: FileLock,
    conn: rusqlite::Connection,
}

fn new_gc_generation() -> String {
    let mut gen: [u8; 32] = [0; 32];
    hydrogen::random_buf(&mut gen);
    hex::easy_encode_to_string(&gen)
}

fn open_archivist_db(path: &Path) -> rusqlite::Result<rusqlite::Connection> {
    let conn = rusqlite::Connection::open(path)?;
    conn.query_row("pragma busy_timeout=3600000;", rusqlite::NO_PARAMS, |_r| {
        Ok(())
    })?;
    Ok(conn)
}

impl Store {
    fn ensure_store_check_file_exists(p: &Path) -> Result<(), StoreError> {
        if p.exists() {
            Ok(())
        } else {
            Err(StoreError::NotInitializedProperly)
        }
    }

    pub fn open_db(&self) -> rusqlite::Result<rusqlite::Connection> {
        let mut db_path = self.store_path.clone();
        db_path.push("archivist.db");
        open_archivist_db(&db_path)
    }

    pub fn open(store_path: &Path) -> Result<Store, StoreError> {
        Store::check_store_sane(&store_path)?;
        let mut data_dir_path = store_path.to_path_buf();
        data_dir_path.push("data");

        let mut db_path = store_path.to_path_buf();
        db_path.push("archivist.db");
        let conn = open_archivist_db(&db_path)?;
        let v: i32 = conn.query_row(
            "select value from ArchivistMeta where Key='schema-version';",
            rusqlite::NO_PARAMS,
            |row| row.get(0),
        )?;
        if v != 0 {
            return Err(StoreError::UnsupportedSchemaVersion);
        }

        Ok(Store {
            store_path: store_path.to_path_buf(),
        })
    }

    fn check_store_sane(store_path: &Path) -> Result<(), StoreError> {
        if !store_path.exists() {
            return Err(StoreError::StoreDoesNotExist);
        }
        let mut path_buf = PathBuf::from(store_path);
        path_buf.push("data");
        Store::ensure_store_check_file_exists(&path_buf.as_path())?;
        path_buf.pop();
        path_buf.push("archivist.db");
        Store::ensure_store_check_file_exists(&path_buf.as_path())?;
        path_buf.pop();
        Ok(())
    }

    pub fn init(store_path: &Path, engine: StorageEngineSpec) -> Result<(), failure::Error> {
        let parent = if store_path.is_absolute() {
            store_path.parent().unwrap().to_owned()
        } else {
            let abs = std::env::current_dir()?.join(store_path);
            let parent = abs.parent().unwrap();
            parent.to_owned()
        };
        let mut path_buf = PathBuf::from(&parent);
        if store_path.exists() {
            return Err(StoreError::AlreadyExists {
                path: store_path.to_string_lossy().to_string(),
            }
            .into());
        }
        let mut tmpname = store_path
            .file_name()
            .unwrap_or(std::ffi::OsStr::new(""))
            .to_os_string();
        tmpname.push(".archivist-store-init-tmp");
        path_buf.push(&tmpname);
        if path_buf.exists() {
            return Err(StoreError::AlreadyExists {
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

        path_buf.push("archivist.db");
        let mut conn = open_archivist_db(&path_buf)?;
        conn.query_row("pragma journal_mode=WAL;", rusqlite::NO_PARAMS, |_r| Ok(()))?;
        let tx = conn.transaction()?;
        tx.execute(
            "create table ArchivistMeta(Key, Value, UNIQUE(key, value));",
            rusqlite::NO_PARAMS,
        )?;
        tx.execute(
            "insert into ArchivistMeta(Key, Value) values(?, ?);",
            rusqlite::params!["schema-version", 0],
        )?;
        tx.execute(
            "insert into ArchivistMeta(Key, Value) values(?, ?);",
            rusqlite::params!["gc-generation", new_gc_generation()],
        )?;

        tx.execute(
            "insert into ArchivistMeta(Key, Value) values(?, ?);",
            rusqlite::params!["storage-engine", serde_json::to_string(&engine)?],
        )?;

        tx.commit()?;
        path_buf.pop();

        fsutil::sync_dir(&path_buf)?;

        std::fs::rename(&path_buf, store_path)?;
        Ok(())
    }

    fn get_lock_path(&self, name: &str) -> PathBuf {
        let mut lock_path = self.store_path.clone();
        lock_path.push(name);
        lock_path
    }

    pub fn storage_handle(&self) -> Result<StorageHandle, failure::Error> {
        let mut data_dir = self.store_path.clone();
        data_dir.push("data");

        let conn = self.open_db()?;
        let engine_meta: String = conn.query_row(
            "select value from ArchivistMeta where Key='storage-engine';",
            rusqlite::NO_PARAMS,
            |row| row.get(0),
        )?;

        let spec: StorageEngineSpec = serde_json::from_str(&engine_meta)?;

        let engine: Box<dyn chunk_storage::Engine> = match spec {
            StorageEngineSpec::Local => {
                // XXX fixme, how many workers do we want?
                Box::new(chunk_storage::LocalStorage::new(&data_dir, 4))
            }
        };

        Ok(StorageHandle {
            _gc_lock: FileLock::get_shared(&self.get_lock_path("gc.lock"))?,
            engine,
        })
    }

    pub fn change_store_handle<'a>(&'a self) -> Result<ChangeStoreHandle, StoreError> {
        let conn = self.open_db()?;
        Ok(ChangeStoreHandle {
            _gc_lock: FileLock::get_shared(&self.get_lock_path("gc.lock"))?,
            conn,
        })
    }
}

impl StorageHandle {
    pub fn add_chunk(&mut self, addr: Address, buf: Vec<u8>) -> Result<(), failure::Error> {
        self.engine.add_chunk(addr, buf)
    }

    pub fn get_chunk(&mut self, addr: Address) -> Result<Vec<u8>, failure::Error> {
        self.engine.get_chunk(addr)
    }

    pub fn sync(&mut self) -> Result<(), failure::Error> {
        self.engine.sync()
    }
}

impl htree::Sink for StorageHandle {
    fn send_chunk(&mut self, addr: Address, data: Vec<u8>) -> Result<(), failure::Error> {
        self.add_chunk(addr, data)
    }
}

impl htree::Source for StorageHandle {
    fn get_chunk(&mut self, addr: Address) -> Result<Vec<u8>, failure::Error> {
        self.get_chunk(addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_get_chunk() {
        let tmp_dir = tempdir::TempDir::new("store_test_repo").unwrap();
        let mut path_buf = PathBuf::from(tmp_dir.path());
        path_buf.push("store");
        Store::init(path_buf.as_path(), BackendSpec::Local).unwrap();
        let store = Store::open(path_buf.as_path()).unwrap();
        let mut h = store.storage_handle().unwrap();
        let addr = Address::default();
        h.add_chunk(addr, vec![1]).unwrap();
        h.sync().unwrap();
        h.add_chunk(addr, vec![2]).unwrap();
        h.sync().unwrap();
        let v = h.get_chunk(addr).unwrap();
        assert_eq!(v, vec![1]);
    }
}
