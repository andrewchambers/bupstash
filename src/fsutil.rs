use super::crypto;
use super::hex;
use super::ioutil;
use path_clean::PathClean;
use std::convert::TryInto;
use std::fs;
use std::io::{Read, Seek, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

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

// Join two paths exactly as they are without any normalization.
pub fn path_raw_join(l: &Path, r: &Path) -> PathBuf {
    let mut p = l.to_owned().into_os_string();
    p.push(r.as_os_str());
    PathBuf::from(p)
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
    for entry in std::fs::read_dir(path)? {
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
        if let Some(r) = common_path(&result, path) {
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

// A smear error is an error likely caused by the filesystem being altered
// by a concurrent process as we are making a snapshot. An example of this
// happening is we found a file, then tried to open it and it did not exist.
pub fn likely_smear_error(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::NotFound | std::io::ErrorKind::InvalidInput
    )
}

cfg_if::cfg_if! {
    if #[cfg(target_os = "macos")] {

        pub fn makedev(major: u64, minor: u64) -> libc::dev_t
        {
            ((major << 24) | minor) as libc::dev_t
        }

        pub fn dev_major(dev: u64) -> u64 {
            (dev >> 24) & 0xff
        }

        pub fn dev_minor(dev :u64) -> u64 {
            dev & 0xffffff
        }

    } else if #[cfg(target_os = "openbsd")] {

        pub fn makedev(major: u64, minor: u64) -> libc::dev_t {
            (((major & 0xff) << 8) | (minor & 0xff) | ((minor & 0xffff00) << 8)) as libc::dev_t
        }

        pub fn dev_major(dev: u64) -> u64 {
            (dev >> 8) & 0xff
        }

        pub fn dev_minor(dev :u64) -> u64 {
            (dev & 0xff) | ((dev & 0xffff0000) >> 8)
        }

     } else if #[cfg(target_os = "freebsd")] {

        // See https://github.com/freebsd/freebsd-src/sys/sys/types.h
        pub fn makedev(major: u64, minor: u64) -> libc::dev_t {
            (((major & 0xffffff00) << 32) | ((major & 0xff) << 8) |
             ((minor & 0xff00) << 24) | (minor & 0xffff00ff)) as libc::dev_t
        }

        pub fn dev_major(dev: u64) -> u64 {
            ((dev >> 32) & 0xffffff00) | ((dev >> 8) & 0xff)
        }

        pub fn dev_minor(dev :u64) -> u64 {
            ((dev >> 24) & 0xff00) | (dev & 0xffff00ff)
        }

    } else {

        pub fn makedev(major: u64, minor: u64) -> libc::dev_t {
            libc::makedev(major as libc::c_uint, minor as libc::c_uint)
        }

        pub fn dev_major(dev: u64) -> u64 {
            unsafe { libc::major(dev as libc::dev_t) as u64 }
        }

        pub fn dev_minor(dev: u64) -> u64 {
            unsafe { libc::minor(dev as libc::dev_t) as u64 }
        }

    }
}

// Aligns with most filesystem sparse boundaries.
const SPARSE_COPY_BUF_SZ: usize = 4096;

// Copy data from a reader into a file while using seek on runs of zeros
// to encourage the OS to create a sparse file.
pub fn copy_as_sparse_file<R>(src: &mut R, dst: &mut fs::File) -> std::io::Result<u64>
where
    R: Read,
{
    let mut buf = [0; SPARSE_COPY_BUF_SZ];
    let mut ncopied: u64 = 0;
    let mut buffered_zeros: u64 = 0;

    loop {
        let n = src.read(&mut buf[..])?;
        ncopied += n as u64;
        if n == 0 {
            break;
        }

        if ioutil::all_zeros(&buf[..n]) {
            buffered_zeros += n as u64;
            continue;
        }

        if buffered_zeros != 0 {
            dst.seek(std::io::SeekFrom::Current(
                buffered_zeros.try_into().unwrap(),
            ))?;
            buffered_zeros = 0;
        }

        dst.write_all(&buf[..n])?;
    }

    if buffered_zeros != 0 {
        nix::unistd::ftruncate(dst.as_raw_fd(), ncopied.try_into().unwrap())?;
    }

    Ok(ncopied)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    #[test]
    fn fuzz_copy_to_sparse_file() {
        let mut rng = rand::thread_rng();

        for _ in 0..1000 {
            let buffer_sz = rng.gen_range(0..SPARSE_COPY_BUF_SZ * 3);
            let random_bytes: Vec<u8> = (0..buffer_sz)
                .map(|_| rng.gen_bool(0.999))
                .map(|z| if z { 0 } else { 1 })
                .collect();
            let mut cursor = std::io::Cursor::new(random_bytes);
            let mut dst = tempfile::tempfile().unwrap();

            copy_as_sparse_file(&mut cursor, &mut dst).unwrap();

            let random_bytes = cursor.into_inner();

            dst.seek(std::io::SeekFrom::Start(0)).unwrap();

            let mut result = Vec::new();
            dst.read_to_end(&mut result).unwrap();

            if result != random_bytes {
                panic!("copy failed");
            }
        }
    }

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
