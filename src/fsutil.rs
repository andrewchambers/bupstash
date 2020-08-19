use super::crypto;
use super::hex;
use fs2::FileExt;
use path_clean::PathClean;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

pub struct FileLock {
    f: fs::File,
}

impl FileLock {
    pub fn get_exclusive(p: &Path) -> Result<FileLock, std::io::Error> {
        let f = fs::File::open(p)?;
        f.lock_exclusive()?;
        Ok(FileLock { f })
    }

    pub fn get_shared(p: &Path) -> Result<FileLock, std::io::Error> {
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

pub fn create_empty_file(p: &Path) -> Result<(), std::io::Error> {
    let f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(p)?;
    f.sync_all()?;
    Ok(())
}

pub fn sync_dir(p: &Path) -> Result<(), std::io::Error> {
    let dir = fs::File::open(p)?;
    dir.sync_all()?;
    Ok(())
}

// Does NOT sync the directory. A sync of the directory still needs to be
// done to ensure the atomic rename is persisted.
pub fn atomic_add_file(p: &Path, contents: &[u8]) -> Result<(), std::io::Error> {
    let random_suffix = {
        let mut buf = [0; 8];
        crypto::randombytes(&mut buf[..]);
        hex::easy_encode_to_string(&buf[..])
    };

    let temp_path = p
        .to_string_lossy()
        .chars()
        .chain(random_suffix.chars())
        .chain(".tmp".chars())
        .collect::<String>();

    let mut tmp_file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_path)?;
    tmp_file.write_all(contents)?;
    tmp_file.sync_all()?;
    std::fs::rename(temp_path, p)?;
    Ok(())
}

// Get an absolute path without resolving symlinks or touching the fs.
pub fn absolute_path<P>(path: P) -> std::io::Result<PathBuf>
where
    P: AsRef<Path>,
{
    let path = path.as_ref();
    let absolute_path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    }
    .clean();

    Ok(absolute_path)
}
