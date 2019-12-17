use super::address::*;
use super::fsutil;
use std::path::PathBuf;

pub trait Engine {
    fn get_chunk(&mut self, addr: Address) -> Result<Vec<u8>, failure::Error>;
    fn add_chunk(&mut self, addr: Address, buf: Vec<u8>) -> Result<(), failure::Error>;
    // A write barrier, any previously added chunks are only guaranteed to be
    // in stable storage after a call to sync has returned. A backend
    // can use this to implement concurrent background writes.
    fn sync(&mut self) -> Result<(), failure::Error>;
}

pub struct LocalStorage {
    data_dir: PathBuf,
}

impl LocalStorage {
    pub fn new(path: &std::path::Path) -> Self {
        LocalStorage {
            data_dir: path.to_path_buf(),
        }
    }

    pub fn count_chunks(&self) -> Result<usize, failure::Error> {
        let paths = std::fs::read_dir(self.data_dir.as_path())?;
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
}

impl Engine for LocalStorage {
    // XXX
    // we should only be forced to wait for the file syncs and renames
    // when the storage engine itself gets synced.
    fn add_chunk(&mut self, addr: Address, buf: Vec<u8>) -> Result<(), failure::Error> {
        self.data_dir.push(addr.as_hex_addr().as_str());
        if !self.data_dir.exists() {
            let result = fsutil::atomic_add_file_no_parent_sync(self.data_dir.as_path(), &buf);
            self.data_dir.pop();
            Ok(result?)
        } else {
            self.data_dir.pop();
            Ok(())
        }
    }

    fn get_chunk(&mut self, addr: Address) -> Result<Vec<u8>, failure::Error> {
        self.data_dir.push(addr.as_hex_addr().as_str());
        let p = std::fs::read(self.data_dir.as_path());
        self.data_dir.pop();
        Ok(p?)
    }

    fn sync(&mut self) -> Result<(), failure::Error> {
        fsutil::sync_dir(self.data_dir.as_path())?;
        Ok(())
    }
}
