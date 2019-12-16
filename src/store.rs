use super::address::*;
use super::hex;
use super::htree;
use super::hydrogen;
use failure::Fail;
use fs2::FileExt;
use rand::Rng;
use std::fs;
use std::io::prelude::*;
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

pub struct DataStore {
    store_path: PathBuf,
    data_dir_path: PathBuf,
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
// It allows data append and read.
pub struct ChunkHandle<'a> {
    _gc_lock: FileLock,
    scratch_chunk_path: PathBuf,
    store: &'a DataStore,
}

// This handle gets a shared gc.lock
// It allows updating the metadata db.
pub struct ChangeStoreHandle<'a> {
    _gc_lock: FileLock,
    store: &'a DataStore,
    conn: rusqlite::Connection,
}

fn new_gc_generation() -> String {
    let mut gen: [u8; 32] = [0; 32];
    hydrogen::random_buf(&mut gen);
    hex::easy_encode_to_string(&gen)
}

// Does NOT sync the directory. A sync of the directory still needs to be
// done to ensure the atomic rename is persisted.
// That sync can be done once at the end of an 'upload session'.
fn atomic_add_file_no_parent_sync(p: &Path, contents: &[u8]) -> Result<(), std::io::Error> {
    let temp_path = p
        .to_string_lossy()
        .chars()
        .chain(
            std::iter::repeat(())
                .map(|()| rand::thread_rng().sample(rand::distributions::Alphanumeric))
                .take(8),
        )
        .chain(".tmp".chars())
        .collect::<String>();

    let mut tmp_file = fs::File::create(&temp_path)?;
    tmp_file.write_all(contents)?;
    tmp_file.sync_all()?;
    std::fs::rename(temp_path, p)?;
    Ok(())
}

fn sync_dir(p: &Path) -> Result<(), std::io::Error> {
    let dir = fs::File::open(p)?;
    dir.sync_all()?;
    Ok(())
}

fn atomic_add_file_with_parent_sync(p: &Path, contents: &[u8]) -> Result<(), std::io::Error> {
    atomic_add_file_no_parent_sync(p, contents)?;
    sync_dir(p.parent().unwrap())?;
    Ok(())
}

fn atomic_add_dir_with_parent_sync(p: &Path) -> Result<(), std::io::Error> {
    fs::DirBuilder::new().create(p)?;
    sync_dir(p.parent().unwrap())?;
    Ok(())
}

fn open_archivist_db(path: &Path) -> rusqlite::Result<rusqlite::Connection> {
    let conn = rusqlite::Connection::open(path)?;
    conn.query_row("pragma busy_timeout=3600000;", rusqlite::NO_PARAMS, |_r| {
        Ok(())
    })?;
    Ok(conn)
}

impl DataStore {
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

    pub fn count_chunks(&self) -> Result<usize, StoreError> {
        let paths = fs::read_dir(self.data_dir_path.as_path())?;
        Ok(paths
            .filter(|e| {
                if let Ok(d) = e {
                    if let Some(oss) = d.path().extension() {
                        oss != "tmp"
                    } else {
                        true
                    }
                } else {
                    false
                }
            })
            .count())
    }

    pub fn open(store_path: &Path) -> Result<DataStore, StoreError> {
        DataStore::check_store_sane(&store_path)?;
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

        Ok(DataStore {
            store_path: store_path.to_path_buf(),
            data_dir_path,
        })
    }

    fn check_store_sane(store_path: &Path) -> Result<(), StoreError> {
        if !store_path.exists() {
            return Err(StoreError::StoreDoesNotExist);
        }
        let mut path_buf = PathBuf::from(store_path);
        path_buf.push("data");
        DataStore::ensure_store_check_file_exists(&path_buf.as_path())?;
        path_buf.pop();
        path_buf.push("archivist.db");
        DataStore::ensure_store_check_file_exists(&path_buf.as_path())?;
        path_buf.pop();
        Ok(())
    }

    pub fn init(store_path: &Path) -> Result<DataStore, StoreError> {
        let parent = if store_path.is_absolute() {
            store_path.parent().unwrap().to_owned()
        } else {
            let abs = std::env::current_dir()?.join(store_path).clone();
            let parent = abs.parent().unwrap().clone();
            parent.to_owned()
        };
        let mut path_buf = PathBuf::from(&parent);
        if store_path.exists() {
            return Err(StoreError::AlreadyExists {
                path: store_path.to_string_lossy().to_string(),
            });
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
            });
        }
        atomic_add_dir_with_parent_sync(path_buf.as_path())?;
        path_buf.push("data");
        atomic_add_dir_with_parent_sync(path_buf.as_path())?;
        path_buf.pop();
        path_buf.push("gc.lock");
        atomic_add_file_with_parent_sync(path_buf.as_path(), &mut [])?;
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
        tx.commit()?;
        path_buf.pop();

        std::fs::rename(&path_buf, store_path)?;
        DataStore::open(store_path)
    }

    fn get_lock_path(&self, name: &str) -> PathBuf {
        let mut lock_path = self.store_path.clone();
        lock_path.push(name);
        lock_path
    }

    pub fn chunk_handle<'a>(&'a self) -> Result<ChunkHandle<'a>, StoreError> {
        Ok(ChunkHandle {
            _gc_lock: FileLock::get_shared(&self.get_lock_path("gc.lock"))?,
            scratch_chunk_path: self.data_dir_path.clone(),
            store: &self,
        })
    }

    pub fn change_store_handle<'a>(&'a self) -> Result<ChangeStoreHandle<'a>, StoreError> {
        let conn = self.open_db()?;
        Ok(ChangeStoreHandle {
            _gc_lock: FileLock::get_shared(&self.get_lock_path("gc.lock"))?,
            store: &self,
            conn,
        })
    }
}

impl<'a> ChunkHandle<'a> {
    pub fn add_chunk(&mut self, addr: Address, buf: Vec<u8>) -> Result<(), failure::Error> {
        self.scratch_chunk_path.push(addr.as_hex_addr().as_str());
        if !self.scratch_chunk_path.exists() {
            let result = atomic_add_file_no_parent_sync(self.scratch_chunk_path.as_path(), &buf);
            self.scratch_chunk_path.pop();
            Ok(result?)
        } else {
            self.scratch_chunk_path.pop();
            Ok(())
        }
    }

    pub fn get_chunk(&mut self, addr: Address) -> Result<Vec<u8>, std::io::Error> {
        let mut chunk_path = self.store.data_dir_path.clone();
        chunk_path.push(addr.as_hex_addr().as_str());
        Ok(fs::read(chunk_path.as_path())?)
    }

    pub fn sync(&mut self) -> Result<(), StoreError> {
        sync_dir(self.store.data_dir_path.as_path())?;
        Ok(())
    }
}

impl<'a> htree::Sink for ChunkHandle<'a> {
    fn send_chunk(&mut self, addr: Address, data: Vec<u8>) -> Result<(), failure::Error> {
        self.add_chunk(addr, data)
    }
}

impl<'a> htree::Source for ChunkHandle<'a> {
    fn get_chunk(&mut self, addr: Address) -> Result<Vec<u8>, htree::HTreeError> {
        match self.get_chunk(addr) {
            Ok(v) => Ok(v),
            Err(e) => Err(htree::HTreeError::from(e)),
        }
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
        let store = DataStore::init(path_buf.as_path()).unwrap();
        let mut h = store.chunk_handle().unwrap();
        let addr = Address::default();
        h.add_chunk(addr, vec![1]).unwrap();
        h.add_chunk(addr, vec![2]).unwrap();
        h.sync().unwrap();

        let v = h.get_chunk(addr).unwrap();

        assert_eq!(v, vec![1]);
        assert_eq!(store.count_chunks().unwrap(), 1);
    }
}
