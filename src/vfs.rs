// This file contains an abstraction over the local filesystem that
// is used by bupstash to interact with repositories.
//
// The virtual filesystem is deliberately as minimal as needed.
// Making simplifications where possible (utf8 paths, fewer functions, ...).
//
// Currently supported vfs implementations:
//
// Local filesystem:
//
// bupstash list -r ./some-repository
// bupstash -r file://some-repository.
//
// Possible future vfs branches:
//
// 9p2000.L:
//
// vfs+9p2000.l://$user@$server:$port/$path?aname=$aname&msize=$msize
//
// SFTP:
//
// vfs+sftp:////$user@$server:$port/$path
//
// Note that the implementation currently doesn't use traits because
// a self referential trait object can't be used dynamically without boxing.

use bitflags::bitflags;
use std::convert::TryFrom;
use std::io::{Read, Seek, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::AsRawFd;
use std::os::unix::io::FromRawFd;
use std::path::Path;
use uriparse::uri;

bitflags! {
    // Define our own portable OpenFlags (mirroring linux generic arch flags).
    pub struct OpenFlags: u32 {
        const RDONLY = 0;
        const WRONLY = 1;
        const RDWR = 2;
        const CREAT = 0o100;
        const TRUNC = 0o1000;
        const APPEND = 0o2000;
    }
}

pub struct DirEntry {
    pub file_name: String,
}

impl From<nix::dir::Entry> for DirEntry {
    fn from(ent: nix::dir::Entry) -> DirEntry {
        DirEntry {
            // Unwrap is ok here, bupstash repositories
            // always have ascii file names.
            file_name: ent.file_name().to_str().unwrap().to_string(),
        }
    }
}

pub enum LockType {
    Exclusive,
    Shared,
}

pub enum FileType {
    Dir,
    Regular,
    Other,
}

pub struct Metadata {
    pub ftype: FileType,
    pub size: u64,
}

impl From<std::fs::Metadata> for Metadata {
    fn from(m: std::fs::Metadata) -> Metadata {
        let ftype = if m.is_dir() {
            FileType::Dir
        } else if m.is_file() {
            FileType::Regular
        } else {
            FileType::Other
        };
        Metadata {
            ftype,
            size: m.size(),
        }
    }
}

impl From<nix::sys::stat::FileStat> for Metadata {
    fn from(s: nix::sys::stat::FileStat) -> Metadata {
        let type_bits =
            nix::sys::stat::SFlag::from_bits_truncate(s.st_mode) & nix::sys::stat::SFlag::S_IFMT;
        let ftype = if type_bits == nix::sys::stat::SFlag::S_IFDIR {
            FileType::Dir
        } else if type_bits == nix::sys::stat::SFlag::S_IFREG {
            FileType::Regular
        } else {
            FileType::Other
        };
        Metadata {
            ftype,
            size: s.st_size.max(0) as u64,
        }
    }
}

pub enum VFs {
    OsDir(OsDir),
}

impl VFs {
    pub fn create(p: &str) -> Result<VFs, std::io::Error> {
        if p.starts_with("file:") {
            match uri::URI::try_from(p) {
                Ok(u) => VFs::create_from_uri(&u),
                Err(err) => Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("unable to parse file uri: {}", err),
                )),
            }
        } else {
            VFs::create_from_local_path(Path::new(p))
        }
    }

    pub fn create_from_local_path(p: &Path) -> Result<VFs, std::io::Error> {
        Ok(VFs::OsDir(OsDir::new(p)?))
    }

    pub fn create_from_uri(u: &uri::URI<'_>) -> Result<VFs, std::io::Error> {
        let path = u.path().to_string();

        match u.scheme().as_str() {
            "file" => VFs::create_from_local_path(Path::new(&path)),
            scheme => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("unknown uri repository scheme: '{}'", scheme),
            )),
        }
    }

    pub fn try_clone(&self) -> Result<VFs, std::io::Error> {
        self.sub_fs(".")
    }

    pub fn sub_fs(&self, p: &str) -> Result<VFs, std::io::Error> {
        match self {
            VFs::OsDir(fs) => Ok(VFs::OsDir(fs.sub_fs(p)?)),
        }
    }

    pub fn read_dir(&self, p: &str) -> Result<Vec<DirEntry>, std::io::Error> {
        match self {
            VFs::OsDir(fs) => fs.read_dir(p),
        }
    }

    pub fn metadata(&self, p: &str) -> Result<Metadata, std::io::Error> {
        match self {
            VFs::OsDir(fs) => fs.metadata(p),
        }
    }

    pub fn rename(&self, from: &str, to: &str) -> Result<(), std::io::Error> {
        match self {
            VFs::OsDir(fs) => fs.rename(from, to),
        }
    }

    pub fn remove_file(&self, p: &str) -> Result<(), std::io::Error> {
        match self {
            VFs::OsDir(fs) => fs.remove_file(p),
        }
    }

    pub fn open(&self, p: &str, flags: OpenFlags) -> Result<VFile, std::io::Error> {
        match self {
            VFs::OsDir(fs) => Ok(VFile::OsFile(fs.open(p, flags)?)),
        }
    }

    pub fn mkdir(&self, p: &str) -> Result<(), std::io::Error> {
        match self {
            VFs::OsDir(fs) => fs.mkdir(p),
        }
    }
}

pub enum VFile {
    OsFile(OsFile),
}

impl VFile {
    pub fn set_len(&mut self, len: u64) -> Result<(), std::io::Error> {
        match self {
            VFile::OsFile(f) => f.set_len(len),
        }
    }

    pub fn metadata(&mut self) -> Result<Metadata, std::io::Error> {
        match self {
            VFile::OsFile(f) => f.metadata(),
        }
    }

    pub fn lock(&mut self, lock_type: LockType) -> Result<(), std::io::Error> {
        match self {
            VFile::OsFile(f) => f.lock(lock_type),
        }
    }
}

impl Seek for VFile {
    fn seek(&mut self, pos: std::io::SeekFrom) -> Result<u64, std::io::Error> {
        match self {
            VFile::OsFile(f) => f.seek(pos),
        }
    }
}

impl Read for VFile {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        match self {
            VFile::OsFile(f) => f.read(buf),
        }
    }
}

impl Write for VFile {
    fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
        match self {
            VFile::OsFile(f) => f.write(buf),
        }
    }

    fn flush(&mut self) -> Result<(), std::io::Error> {
        match self {
            VFile::OsFile(f) => f.flush(),
        }
    }
}

pub struct OsDir {
    f: std::fs::File,
}

impl OsDir {
    pub fn new(p: &Path) -> Result<OsDir, std::io::Error> {
        let raw_fd = nix::fcntl::open(
            p,
            nix::fcntl::OFlag::O_DIRECTORY | nix::fcntl::OFlag::O_CLOEXEC,
            nix::sys::stat::Mode::from_bits_truncate(0o755),
        )?;
        let f = unsafe { std::fs::File::from_raw_fd(raw_fd) };
        Ok(OsDir { f })
    }

    pub fn sub_fs(&self, p: &str) -> Result<OsDir, std::io::Error> {
        let raw_f = nix::fcntl::openat(
            self.f.as_raw_fd(),
            Path::new(p),
            nix::fcntl::OFlag::O_DIRECTORY | nix::fcntl::OFlag::O_CLOEXEC,
            nix::sys::stat::Mode::from_bits_truncate(0o755),
        )?;
        let f = unsafe { std::fs::File::from_raw_fd(raw_f) };
        Ok(OsDir { f })
    }

    pub fn read_dir(&self, p: &str) -> Result<Vec<DirEntry>, std::io::Error> {
        let mut entries = Vec::with_capacity(16);
        let mut d = nix::dir::Dir::openat(
            self.f.as_raw_fd(),
            Path::new(p),
            nix::fcntl::OFlag::O_DIRECTORY | nix::fcntl::OFlag::O_CLOEXEC,
            nix::sys::stat::Mode::from_bits_truncate(0o644),
        )?;
        let dot = [b'.'];
        let dotdot = [b'.', b'.'];
        for ent in d.iter() {
            let ent = ent?;
            let fname_bytes = ent.file_name().to_bytes();
            if fname_bytes == dot || fname_bytes == dotdot {
                continue;
            }
            entries.push(ent.into())
        }
        Ok(entries)
    }

    pub fn metadata(&self, p: &str) -> Result<Metadata, std::io::Error> {
        let stat = nix::sys::stat::fstatat(
            self.f.as_raw_fd(),
            Path::new(p),
            nix::fcntl::AtFlags::empty(),
        )?;
        Ok(stat.into())
    }

    pub fn rename(&self, from: &str, to: &str) -> Result<(), std::io::Error> {
        nix::fcntl::renameat(
            Some(self.f.as_raw_fd()),
            Path::new(from),
            Some(self.f.as_raw_fd()),
            Path::new(to),
        )?;
        Ok(())
    }

    pub fn remove_file(&self, p: &str) -> Result<(), std::io::Error> {
        nix::unistd::unlinkat(
            Some(self.f.as_raw_fd()),
            Path::new(p),
            nix::unistd::UnlinkatFlags::NoRemoveDir,
        )?;
        Ok(())
    }

    pub fn open(&self, p: &str, flags: OpenFlags) -> Result<OsFile, std::io::Error> {
        let mut osflags = match flags.bits() & 3 {
            0 => nix::fcntl::OFlag::O_RDONLY,
            1 => nix::fcntl::OFlag::O_WRONLY,
            2 => nix::fcntl::OFlag::O_RDWR,
            _ => panic!(),
        };
        if flags.contains(OpenFlags::TRUNC) {
            osflags.set(nix::fcntl::OFlag::O_TRUNC, true)
        }
        if flags.contains(OpenFlags::APPEND) {
            osflags.set(nix::fcntl::OFlag::O_APPEND, true)
        }
        if flags.contains(OpenFlags::CREAT) {
            osflags.set(nix::fcntl::OFlag::O_CREAT, true)
        }
        // Just unconditionally use O_CLOEXEC for VFs files.
        osflags.set(nix::fcntl::OFlag::O_CLOEXEC, true);
        let raw_f = nix::fcntl::openat(
            self.f.as_raw_fd(),
            Path::new(p),
            osflags,
            nix::sys::stat::Mode::from_bits_truncate(0o644),
        )?;
        let f = unsafe { std::fs::File::from_raw_fd(raw_f) };
        Ok(OsFile { f })
    }

    pub fn mkdir(&self, p: &str) -> Result<(), std::io::Error> {
        nix::sys::stat::mkdirat(
            self.f.as_raw_fd(),
            Path::new(p),
            nix::sys::stat::Mode::from_bits_truncate(0o755),
        )?;
        Ok(())
    }
}

pub struct OsFile {
    f: std::fs::File,
}

impl OsFile {
    pub fn metadata(&mut self) -> Result<Metadata, std::io::Error> {
        Ok(self.f.metadata()?.into())
    }

    pub fn seek(&mut self, pos: std::io::SeekFrom) -> Result<u64, std::io::Error> {
        self.f.seek(pos)
    }

    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        self.f.read(buf)
    }

    pub fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
        self.f.write(buf)
    }

    pub fn flush(&mut self) -> Result<(), std::io::Error> {
        self.f.flush()
    }

    pub fn set_len(&mut self, len: u64) -> Result<(), std::io::Error> {
        self.f.set_len(len)
    }

    fn lock(&mut self, lock_type: LockType) -> Result<(), std::io::Error> {
        let lock_type = match lock_type {
            LockType::Exclusive => libc::F_WRLCK,
            LockType::Shared => libc::F_RDLCK,
        };
        let lock_opts = libc::flock {
            l_type: lock_type as libc::c_short,
            l_whence: libc::SEEK_SET as libc::c_short,
            l_start: 0,
            l_len: 0,
            l_pid: 0,
            #[cfg(target_os = "freebsd")]
            l_sysid: 0,
        };
        match nix::fcntl::fcntl(
            self.f.as_raw_fd(),
            nix::fcntl::FcntlArg::F_SETLKW(&lock_opts),
        ) {
            Ok(_) => Ok(()),
            Err(err) => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("unable to get exclusive lock: {}", err),
            )),
        }
    }
}
