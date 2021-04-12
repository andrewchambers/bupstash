use super::crypto;
use super::hex;
use path_clean::PathClean;
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

pub struct FileLock {
    _f: fs::File,
}

impl FileLock {
    pub fn get_exclusive(p: &Path) -> Result<FileLock, std::io::Error> {
        let f = fs::OpenOptions::new().read(true).write(true).open(p)?;
        let lock_opts = libc::flock {
            l_type: libc::F_WRLCK as libc::c_short,
            l_whence: libc::SEEK_SET as libc::c_short,
            l_start: 0,
            l_len: 0,
            l_pid: 0,
        };
        match nix::fcntl::fcntl(f.as_raw_fd(), nix::fcntl::FcntlArg::F_SETLKW(&lock_opts)) {
            Ok(_) => (),
            Err(err) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("unable to get exclusive lock {:?}: {}", p, err),
                ))
            }
        };
        Ok(FileLock { _f: f })
    }

    pub fn try_get_exclusive(p: &Path) -> Result<Option<FileLock>, std::io::Error> {
        let f = fs::OpenOptions::new().read(true).write(true).open(p)?;
        let lock_opts = libc::flock {
            l_type: libc::F_WRLCK as libc::c_short,
            l_whence: libc::SEEK_SET as libc::c_short,
            l_start: 0,
            l_len: 0,
            l_pid: 0,
        };

        match nix::fcntl::fcntl(f.as_raw_fd(), nix::fcntl::FcntlArg::F_SETLK(&lock_opts)) {
            Ok(_) => (),
            Err(nix::Error::Sys(nix::errno::Errno::EAGAIN))
            | Err(nix::Error::Sys(nix::errno::Errno::EACCES)) => return Ok(None),
            Err(err) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("unable to get exclusive lock {:?}: {}", p, err),
                ))
            }
        };
        Ok(Some(FileLock { _f: f }))
    }

    pub fn get_shared(p: &Path) -> Result<FileLock, std::io::Error> {
        let f = fs::OpenOptions::new().read(true).write(true).open(p)?;
        let lock_opts = libc::flock {
            l_type: libc::F_RDLCK as libc::c_short,
            l_whence: libc::SEEK_SET as libc::c_short,
            l_start: 0,
            l_len: 0,
            l_pid: 0,
        };
        match nix::fcntl::fcntl(f.as_raw_fd(), nix::fcntl::FcntlArg::F_SETLKW(&lock_opts)) {
            Ok(_) => (),
            Err(err) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("unable to get shared lock {:?}: {}", p, err),
                ))
            }
        };
        Ok(FileLock { _f: f })
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

pub fn anon_temp_file() -> Result<std::fs::File, std::io::Error> {
    let name = {
        let mut buf = [0; 16];
        let mut hexbuf = [0; 32];
        crypto::randombytes(&mut buf[..]);
        hex::encode(&buf[..], &mut hexbuf[..]);
        PathBuf::from(std::str::from_utf8(&hexbuf[..]).unwrap())
    };

    let mut p = std::env::temp_dir();
    p.push(name);

    let f = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&p)?;

    std::fs::remove_file(p)?;

    Ok(f)
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

pub fn read_dirents(path: &Path) -> std::io::Result<Vec<std::fs::DirEntry>> {
    let mut dir_ents = Vec::new();
    for entry in std::fs::read_dir(&path)? {
        dir_ents.push(entry?);
    }
    Ok(dir_ents)
}

/* Common path:

Copyright 2018 Paul Woolcock <paul@woolcock.us>

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

pub fn common_path_all(paths: &[PathBuf]) -> Option<PathBuf> {
    let mut path_iter = paths.iter();
    let mut result = path_iter.next()?.to_path_buf();
    for path in path_iter {
        if let Some(r) = common_path(&result, &path) {
            result = r;
        } else {
            return None;
        }
    }
    Some(result)
}

pub fn common_path<P, Q>(one: P, two: Q) -> Option<PathBuf>
where
    P: AsRef<Path>,
    Q: AsRef<Path>,
{
    let one = one.as_ref();
    let two = two.as_ref();
    let one = one.components();
    let two = two.components();
    let mut final_path = PathBuf::new();
    let mut found = false;
    let paths = one.zip(two);
    for (l, r) in paths {
        if l == r {
            final_path.push(l.as_os_str());
            found = true;
        } else {
            break;
        }
    }
    if found {
        Some(final_path)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compare_paths() {
        let one = Path::new("/foo/bar/baz/one.txt");
        let two = Path::new("/foo/bar/quux/quuux/two.txt");
        let result = Path::new("/foo/bar");
        assert_eq!(common_path(&one, &two).unwrap(), result.to_path_buf())
    }

    #[test]
    fn no_common_path() {
        let one = Path::new("/foo/bar");
        let two = Path::new("./baz/quux");
        assert!(common_path(&one, &two).is_none());
    }
}
