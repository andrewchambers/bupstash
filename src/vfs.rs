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
// 9p2000.L over tcp:
//
// vfs+9p2000.l://$user@$server:$port/$path?vfs=9p2000.l&aname=$aname&msize=$msize
//
// Note that the implementation currently doesn't use traits because
// a self referential trait object can't be used dynamically without boxing.

use bitflags::bitflags;
use std::borrow::Cow;
use std::collections::HashMap;
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

impl<'a> From<p92000l::DirEntry<'a>> for DirEntry {
    fn from(ent: p92000l::DirEntry<'a>) -> DirEntry {
        DirEntry {
            // Unwrap is ok here, bupstash repositories
            // always have ascii file names.
            file_name: ent.name.to_string(),
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

impl From<p92000l::Rgetattr> for Metadata {
    fn from(attr: p92000l::Rgetattr) -> Metadata {
        let ftype = if attr.qid.typ.contains(p92000l::QidType::DIR) {
            FileType::Dir
        } else if attr.qid.typ.contains(p92000l::QidType::FILE) {
            FileType::Regular
        } else {
            FileType::Other
        };
        Metadata {
            ftype,
            size: attr.stat.size,
        }
    }
}

pub enum VFs {
    OsDir(OsDir),
    P92000LDir(P92000LDir),
}

impl VFs {
    pub fn create(p: &str) -> Result<VFs, std::io::Error> {
        if p.starts_with("file:") || p.starts_with("vfs+9p2000.l:") {
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

        let query: HashMap<Cow<_>, Cow<_>> = if let Some(query) = u.query() {
            query
                .as_str()
                .split('&')
                .map(|s| s.split_once('=').unwrap_or((s, "")))
                .map(|(k, v)| (urlencoding::decode(k), urlencoding::decode(v)))
                .map(|(k, v)| (k.unwrap_or(Cow::from("")), (v.unwrap_or(Cow::from("")))))
                .collect()
        } else {
            HashMap::new()
        };

        match u.scheme().as_str() {
            "file" => VFs::create_from_local_path(&Path::new(&path)),
            "vfs+9p2000.l" => {
                let empty_cow = Cow::from("");

                let msize = query.get("msize").unwrap_or(&empty_cow).clone();
                let msize = str::parse::<usize>(&msize).unwrap_or(256 * 1024);

                let aname = Cow::from("/");
                let aname = query.get("aname").unwrap_or(&aname).clone();

                let mut uname = "root";
                let mut port = 564;
                if let Some(authority) = u.authority() {
                    if let Some(username) = authority.username() {
                        uname = username.as_str();
                    }
                    if let Some(p) = authority.port() {
                        port = p;
                    }
                }

                let host = Cow::from("127.0.0.1");
                let host = query.get("host").unwrap_or(&host).clone();
                let host = match host {
                    Cow::Borrowed(ref host) => host,
                    Cow::Owned(ref host) => host.as_str(),
                };
                let conn = std::net::TcpStream::connect((host, port))?;
                let client = p92000l::Client::over_tcp_stream(conn, msize)?;

                let (_, root_fid) = client.attach(0, uname, aname.as_ref())?;
                let fs = VFs::P92000LDir(P92000LDir { f: root_fid });

                Ok(fs.sub_fs(&path)?)
            }
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
            VFs::P92000LDir(fs) => Ok(VFs::P92000LDir(fs.sub_fs(p)?)),
        }
    }

    pub fn read_dir(&self, p: &str) -> Result<Vec<DirEntry>, std::io::Error> {
        match self {
            VFs::OsDir(fs) => fs.read_dir(p),
            VFs::P92000LDir(fs) => fs.read_dir(p),
        }
    }

    pub fn metadata(&self, p: &str) -> Result<Metadata, std::io::Error> {
        match self {
            VFs::OsDir(fs) => fs.metadata(p),
            VFs::P92000LDir(fs) => fs.metadata(p),
        }
    }

    pub fn rename(&self, from: &str, to: &str) -> Result<(), std::io::Error> {
        match self {
            VFs::OsDir(fs) => fs.rename(from, to),
            VFs::P92000LDir(fs) => fs.rename(from, to),
        }
    }

    pub fn remove_file(&self, p: &str) -> Result<(), std::io::Error> {
        match self {
            VFs::OsDir(fs) => fs.remove_file(p),
            VFs::P92000LDir(fs) => fs.remove_file(p),
        }
    }

    pub fn open(&self, p: &str, flags: OpenFlags) -> Result<VFile, std::io::Error> {
        match self {
            VFs::OsDir(fs) => Ok(VFile::OsFile(fs.open(p, flags)?)),
            VFs::P92000LDir(fs) => Ok(VFile::P92000LFile(fs.open(p, flags)?)),
        }
    }

    pub fn mkdir(&self, p: &str) -> Result<(), std::io::Error> {
        match self {
            VFs::OsDir(fs) => fs.mkdir(p),
            VFs::P92000LDir(fs) => fs.mkdir(p),
        }
    }
}

pub enum VFile {
    OsFile(OsFile),
    P92000LFile(P92000LFile),
}

impl VFile {
    pub fn set_len(&mut self, len: u64) -> Result<(), std::io::Error> {
        match self {
            VFile::OsFile(f) => f.set_len(len),
            VFile::P92000LFile(f) => f.set_len(len),
        }
    }

    pub fn metadata(&mut self) -> Result<Metadata, std::io::Error> {
        match self {
            VFile::OsFile(f) => f.metadata(),
            VFile::P92000LFile(f) => f.metadata(),
        }
    }

    pub fn lock(&mut self, lock_type: LockType) -> Result<(), std::io::Error> {
        match self {
            VFile::OsFile(f) => f.lock(lock_type),
            VFile::P92000LFile(f) => f.lock(lock_type),
        }
    }
}

impl Seek for VFile {
    fn seek(&mut self, pos: std::io::SeekFrom) -> Result<u64, std::io::Error> {
        match self {
            VFile::OsFile(f) => f.seek(pos),
            VFile::P92000LFile(f) => f.seek(pos),
        }
    }
}

impl Read for VFile {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        match self {
            VFile::OsFile(f) => f.read(buf),
            VFile::P92000LFile(f) => f.read(buf),
        }
    }
}

impl Write for VFile {
    fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
        match self {
            VFile::OsFile(f) => f.write(buf),
            VFile::P92000LFile(f) => f.write(buf),
        }
    }

    fn flush(&mut self) -> Result<(), std::io::Error> {
        match self {
            VFile::OsFile(f) => f.flush(),
            VFile::P92000LFile(f) => f.flush(),
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
        let dot = ['.' as u8];
        let dotdot = ['.' as u8, '.' as u8];
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

pub struct P92000LDir {
    f: p92000l::ClientFid,
}

impl P92000LDir {
    fn path_walk(
        &self,
        p: &str,
    ) -> Result<(Vec<p92000l::Qid>, p92000l::ClientFid), std::io::Error> {
        let wnames: Vec<&str> = p
            .split('/')
            .filter(|name| !(name.is_empty() || *name == "."))
            .collect();
        let (wqids, f) = self.f.walk(&wnames)?;
        if wqids.len() != wnames.len() {
            return Err(std::io::Error::from(std::io::ErrorKind::NotFound));
        }
        Ok((wqids, f))
    }

    pub fn sub_fs(&self, p: &str) -> Result<P92000LDir, std::io::Error> {
        let (_wqids, f) = self.path_walk(p)?;
        // XXX Check if is dir?
        Ok(P92000LDir { f })
    }

    pub fn read_dir(&self, p: &str) -> Result<Vec<DirEntry>, std::io::Error> {
        let (_wqids, f) = self.path_walk(p)?;
        f.open(p92000l::LOpenFlags::O_RDONLY)?;
        Ok(f.read_dir()?
            .drain(..)
            .filter(|e| e.name.as_bytes() != ".".as_bytes() && e.name.as_bytes() != "..".as_bytes())
            .map(|e| e.into())
            .collect())
    }

    pub fn metadata(&self, p: &str) -> Result<Metadata, std::io::Error> {
        let (_wqids, f) = self.path_walk(p)?;
        Ok(f.getattr(p92000l::GetattrMask::all())?.into())
    }

    pub fn rename(&self, from: &str, to: &str) -> Result<(), std::io::Error> {
        if let Some((dir, name)) = to.rsplit_once('/') {
            let (_, f) = self.path_walk(from)?;
            let (_, dfid) = self.path_walk(dir)?;
            Ok(f.rename(&dfid, name)?)
        } else {
            let (_, f) = self.path_walk(from)?;
            Ok(f.rename(&self.f, to)?)
        }
    }

    pub fn remove_file(&self, p: &str) -> Result<(), std::io::Error> {
        let (_, fid) = self.path_walk(p)?;
        Ok(fid.remove()?)
    }

    pub fn open(&self, p: &str, flags: OpenFlags) -> Result<P92000LFile, std::io::Error> {
        let mut p9flags = match flags.bits() & 3 {
            0 => p92000l::LOpenFlags::O_RDONLY,
            1 => p92000l::LOpenFlags::O_WRONLY,
            2 => p92000l::LOpenFlags::O_RDWR,
            _ => panic!(),
        };

        if flags.contains(OpenFlags::TRUNC) {
            p9flags.set(p92000l::LOpenFlags::O_TRUNC, true)
        }

        let f = if flags.contains(OpenFlags::CREAT) {
            let (dir, name) = if let Some(parts) = p.rsplit_once('/') {
                parts
            } else {
                ("", p)
            };
            let (_, f) = self.path_walk(dir)?;
            f.create(name, p9flags, 0o644, 0)?;
            f
        } else {
            let (_, f) = self.path_walk(p)?;
            f.open(p9flags)?;
            f
        };

        let mut offset: u64 = 0;

        if flags.contains(OpenFlags::APPEND) {
            let attr = f.getattr(p92000l::GetattrMask::SIZE)?;
            offset = attr.stat.size;
        }

        Ok(P92000LFile { f, offset })
    }

    pub fn mkdir(&self, p: &str) -> Result<(), std::io::Error> {
        if let Some((dir, name)) = p.rsplit_once('/') {
            let (_, d) = self.path_walk(dir)?;
            d.mkdir(name, 0o755, 0)?;
        } else {
            self.f.mkdir(p, 0o755, 0)?;
        }
        Ok(())
    }
}

pub struct P92000LFile {
    f: p92000l::ClientFid,
    offset: u64,
}

impl P92000LFile {
    pub fn metadata(&mut self) -> Result<Metadata, std::io::Error> {
        Ok(self.f.getattr(p92000l::GetattrMask::all())?.into())
    }

    pub fn seek(&mut self, pos: std::io::SeekFrom) -> Result<u64, std::io::Error> {
        match pos {
            std::io::SeekFrom::Start(offset) => {
                self.offset = offset;
            }
            std::io::SeekFrom::End(offset) => {
                let end = self.f.getattr(p92000l::GetattrMask::SIZE)?.stat.size;
                self.offset = ((end as i64) + offset).max(0) as u64;
            }
            std::io::SeekFrom::Current(offset) => {
                self.offset = ((self.offset as i64) + offset).max(0) as u64;
            }
        }
        Ok(self.offset)
    }

    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        let n = self.f.read(self.offset, buf)?;
        self.offset += n as u64;
        Ok(n)
    }

    pub fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
        let n = self.f.write(self.offset, buf)?;
        self.offset += n as u64;
        Ok(n)
    }

    pub fn flush(&mut self) -> Result<(), std::io::Error> {
        Ok(self.f.fsync()?)
    }

    pub fn set_len(&mut self, len: u64) -> Result<(), std::io::Error> {
        Ok(self.f.setattr(
            p92000l::SetattrMask::SIZE,
            p92000l::SetAttr {
                size: len,
                mtime: p92000l::Time { sec: 0, nsec: 0 },
                atime: p92000l::Time { sec: 0, nsec: 0 },
                gid: 0,
                uid: 0,
                mode: 0,
            },
        )?)
    }

    fn lock(&mut self, lock_type: LockType) -> Result<(), std::io::Error> {
        let lock_type = match lock_type {
            LockType::Exclusive => p92000l::LockType::WRLOCK,
            LockType::Shared => p92000l::LockType::RDLOCK,
        };

        // Specify block, but do exponential backoff too in case
        // the server doesn't support blocking.
        const MAX_DELAY_MILLIS: u64 = 5000;
        let mut delay_millis = 100;

        loop {
            let status = self.f.lock(p92000l::Flock {
                typ: lock_type,
                flags: p92000l::LockFlag::BLOCK,
                start: 0,
                length: 0,
                proc_id: 0,
                client_id: "".into(),
            })?;
            match status {
                p92000l::LockStatus::SUCCESS => break,
                p92000l::LockStatus::BLOCKED => {
                    std::thread::sleep(std::time::Duration::from_millis(delay_millis));
                    delay_millis = (delay_millis * 2).min(MAX_DELAY_MILLIS)
                }
                _ => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "unable to acquire lock",
                    ))
                }
            }
        }
        Ok(())
    }
}
