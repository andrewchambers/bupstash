// This file implements the bupstash transaction layer for updating
// repository metadata. The general idea is we write a 'write ahead log'
// for batches of changes to the repository, fsync them with a checksum,
// then proceed to make the changes. On any crash, the changes are applied
// by the next bupstash process.
//
// Recommended reading:
//
// https://www.sqlite.org/atomiccommit.html
// https://www.sqlite.org/psow.html

use super::vfs;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::io::Read;
use std::io::Seek;
use std::io::Write;

pub const WAL_NAME: &str = "tx.wal";
pub const SEQ_NUM_NAME: &str = "tx.seq";
pub const LOCK_NAME: &str = "tx.lock";

#[derive(Deserialize, Serialize)]
enum WalOp {
    Begin {
        sequence_number: u64,
    },
    End,
    CreateFile {
        path: String,
        data_size: serde_bare::Uint,
    },
    WriteFileAt {
        path: String,
        offset: serde_bare::Uint,
        data_size: serde_bare::Uint,
    },
    Remove {
        path: String,
    },
    Rename {
        path: String,
        to: String,
    },
    Mkdir {
        path: String,
    },
}

struct FileTeeHasher {
    f: vfs::VFile,
    h: blake3::Hasher,
}

impl std::io::Write for FileTeeHasher {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.h.write_all(buf)?;
        self.f.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct WalWriter {
    bw: std::io::BufWriter<FileTeeHasher>,
}

impl WalWriter {
    fn new(
        rollback_journal: vfs::VFile,
        sequence_number: u64,
    ) -> Result<WalWriter, std::io::Error> {
        let mut w = WalWriter {
            bw: std::io::BufWriter::with_capacity(
                256 * 1024,
                FileTeeHasher {
                    f: rollback_journal,
                    h: blake3::Hasher::new(),
                },
            ),
        };

        w.write_op(WalOp::Begin { sequence_number })?;

        Ok(w)
    }

    fn write_op(&mut self, op: WalOp) -> Result<(), std::io::Error> {
        // XXX encode directly to writer?
        self.write_all(&serde_bare::to_vec(&op).unwrap())?;
        Ok(())
    }

    fn finish(mut self) -> Result<(), std::io::Error> {
        // Write RollbackComplete entry.
        self.write_op(WalOp::End)?;
        self.bw.flush()?;

        let tw = match self.bw.into_inner() {
            Ok(tw) => tw,
            Err(_) => {
                // Should never happen, we already flushed.
                // unstable api's would let us remove the extra
                // write syscall, for most people this doesn't matter,
                // for network filesystems it might let us skip a roundtrip.
                panic!();
            }
        };
        let h = tw.h;
        let mut f = tw.f;
        let h = h.finalize();
        let h = h.as_bytes();
        f.write_all(&h[..])?;
        f.fsync()?;
        Ok(())
    }
}

impl std::io::Write for WalWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.bw.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.bw.flush()
    }
}

fn hot_wal(fs: &vfs::VFs) -> Result<bool, std::io::Error> {
    let mut hasher = blake3::Hasher::new();
    let mut f = match fs.open(WAL_NAME, vfs::OpenFlags::RDONLY) {
        Ok(f) => f,
        Err(err) => return Err(err),
    };
    let md = f.metadata()?;
    let sz = md.size;
    if sz < 32 {
        // Incomplete wal, too small.
        return Ok(false);
    }
    let mut t = (&mut f).take(sz - 32);
    std::io::copy(&mut t, &mut hasher)?;
    let mut expected = [0; 32];
    f.read_exact(&mut expected[..])?;
    Ok(expected == *hasher.finalize().as_bytes())
}

fn sync_dir(fs: &vfs::VFs, p: &str) -> Result<(), std::io::Error> {
    let mut f = fs.open(p, vfs::OpenFlags::RDONLY)?;
    f.fsync()?;
    Ok(())
}

fn dir_to_sync(p: &str) -> String {
    let mut parent = std::path::PathBuf::from(p);
    parent.pop();
    let rel = parent.to_str().unwrap();
    let rel = if rel.is_empty() { "." } else { rel };
    rel.to_string()
}

fn keep_wal() -> bool {
    match std::env::var("BUPSTASH_KEEP_WAL") {
        Ok(v) => v == "1",
        _ => false,
    }
}

fn apply_wal(fs: &vfs::VFs, _lock: &vfs::VFile) -> Result<(), std::io::Error> {
    if !hot_wal(fs)? {
        // Truncate the unfinished wal file, no work to do.
        let mut f = fs.open(
            WAL_NAME,
            vfs::OpenFlags::WRONLY | vfs::OpenFlags::CREAT | vfs::OpenFlags::TRUNC,
        )?;
        f.fsync()?;
        return Ok(());
    }

    let wal = fs.open(WAL_NAME, vfs::OpenFlags::RDONLY)?;
    let mut wal = std::io::BufReader::new(wal);

    let sequence_number = match serde_bare::from_reader(&mut wal) {
        Ok(WalOp::Begin {
            sequence_number, ..
        }) => sequence_number,
        Ok(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "wal is malformed, it must start with a 'Begin' wal op",
            ))
        }
        Err(serde_bare::error::Error::Io(err)) => return Err(err),
        Err(err) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("wal is malformed, {}", err),
            ))
        }
    };

    let mut pending_dir_syncs: HashSet<String> = HashSet::new();

    loop {
        match serde_bare::from_reader(&mut wal) {
            Ok(WalOp::Begin { .. }) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "wal is malformed, unexpected 'Begin' wal op",
                ));
            }
            Ok(WalOp::End) => {
                break;
            }
            Ok(WalOp::CreateFile { path, data_size }) => {
                let mut f = fs.open(
                    &path,
                    vfs::OpenFlags::WRONLY | vfs::OpenFlags::CREAT | vfs::OpenFlags::TRUNC,
                )?;
                let wal = &mut wal;
                std::io::copy(&mut wal.take(data_size.0), &mut f)?;
                f.fsync()?;
                std::mem::drop(f);
                pending_dir_syncs.insert(dir_to_sync(&path));
            }
            Ok(WalOp::WriteFileAt {
                path,
                offset,
                data_size,
            }) => {
                let mut f = fs.open(&path, vfs::OpenFlags::WRONLY)?;
                f.seek(std::io::SeekFrom::Start(offset.0))?;
                let wal = &mut wal;
                std::io::copy(&mut wal.take(data_size.0), &mut f)?;
                f.fsync()?;
                std::mem::drop(f);
            }
            Ok(WalOp::Remove { path }) => {
                match fs.remove_file(&path) {
                    Ok(()) => (),
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => (),
                    Err(err) => return Err(err),
                }
                pending_dir_syncs.insert(dir_to_sync(&path));
            }
            Ok(WalOp::Rename { path, to }) => {
                match fs.rename(&path, &to) {
                    Ok(()) => (),
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                        if fs.metadata(&to).is_err() {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                "unable to apply wal 'Rename' op, neither source nor destination file exist",
                            ));
                        }
                    }
                    Err(err) => return Err(err),
                }
                pending_dir_syncs.insert(dir_to_sync(&path));
                pending_dir_syncs.insert(dir_to_sync(&to));
            }
            Ok(WalOp::Mkdir { path }) => {
                match fs.mkdir(&path) {
                    Ok(_) => (),
                    Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => (),
                    Err(err) => return Err(err),
                }
                pending_dir_syncs.insert(dir_to_sync(&path));
            }
            Err(serde_bare::error::Error::Io(err)) => return Err(err),
            Err(err) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("wal is malformed, {}", err),
                ))
            }
        }
    }

    for d in pending_dir_syncs.into_iter() {
        sync_dir(fs, &d)?;
    }

    if keep_wal() {
        // update the sequence number.
        let mut seqf = fs.open(SEQ_NUM_NAME, vfs::OpenFlags::WRONLY | vfs::OpenFlags::CREAT)?;
        seqf.write_all(&(sequence_number + 1).to_le_bytes()[..])?;
        seqf.fsync()?;
        drop(seqf);
        fs.rename(WAL_NAME, &format!("wal/{:0>8}.wal", sequence_number))?;
    } else {
        // Truncate the wal, instead of removing it.
        let mut f = fs.open(
            WAL_NAME,
            vfs::OpenFlags::WRONLY | vfs::OpenFlags::CREAT | vfs::OpenFlags::TRUNC,
        )?;
        f.fsync()?;
    }

    sync_dir(fs, ".")?;
    Ok(())
}

pub struct ReadTxn<'a> {
    fs: &'a vfs::VFs,
    _lock: vfs::VFile,
}

impl<'a> ReadTxn<'a> {
    pub fn begin_at(fs: &'a vfs::VFs) -> Result<Self, std::io::Error> {
        'try_again: loop {
            let mut lock = fs.open(LOCK_NAME, vfs::OpenFlags::RDONLY)?;
            lock.lock(vfs::LockType::Shared)?;

            // Check if there is a non empty WAL with a read lock applied.
            // We use 'open' to force a stat refresh on fuse filesystems,
            // it cannot be cached.
            match fs.open(WAL_NAME, vfs::OpenFlags::RDONLY) {
                Ok(mut wal) => {
                    if wal.metadata()?.size > 0 {
                        drop(lock);
                        lock = fs.open(LOCK_NAME, vfs::OpenFlags::RDWR)?;
                        lock.lock(vfs::LockType::Exclusive)?;

                        // Now we have the exclusive lock, apply the wal and try again.
                        apply_wal(fs, &lock)?;
                        continue 'try_again;
                    }
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => (),
                Err(err) => return Err(err),
            }
            return Ok(ReadTxn { _lock: lock, fs });
        }
    }

    pub fn end(self) {}

    pub fn read(&self, p: &str) -> Result<Vec<u8>, std::io::Error> {
        let mut f = self.fs.open(p, vfs::OpenFlags::RDONLY)?;
        let mut data = Vec::with_capacity(f.metadata()?.size.try_into().unwrap());
        f.read_to_end(&mut data)?;
        Ok(data)
    }

    pub fn read_string(&self, p: &str) -> Result<String, std::io::Error> {
        let buf = self.read(p)?;
        match String::from_utf8(buf) {
            Ok(s) => Ok(s),
            Err(_) => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "invalid string data",
            )),
        }
    }

    pub fn open(&self, p: &str) -> Result<vfs::VFile, std::io::Error> {
        self.fs.open(p, vfs::OpenFlags::RDONLY)
    }

    pub fn read_dir(&self, p: &str) -> Result<Vec<vfs::DirEntry>, std::io::Error> {
        self.fs.read_dir(p)
    }

    pub fn file_exists(&self, p: &str) -> Result<bool, std::io::Error> {
        // Using open plays better with fuse caching.
        match self.fs.open(p, vfs::OpenFlags::RDONLY) {
            Ok(_) => Ok(true),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(err) => Err(err),
        }
    }
}

enum WriteTxnOp {
    Remove,
    Write(Vec<u8>),
    WriteFile(std::fs::File),
    Append(Vec<u8>),
    Rename(String),
    RenameTarget,
    Mkdir,
}

pub struct WriteTxn<'a> {
    fs: &'a vfs::VFs,
    change_set: HashMap<String, WriteTxnOp>,
    change_order: Vec<String>,
    lock: vfs::VFile,
}

impl<'a> WriteTxn<'a> {
    pub fn begin_at(fs: &'a vfs::VFs) -> Result<WriteTxn, std::io::Error> {
        let mut lock_file = fs.open(LOCK_NAME, vfs::OpenFlags::RDWR)?;
        lock_file.lock(vfs::LockType::Exclusive)?;

        // Use open as this forces a stat refresh on fuse filesystems.
        match fs.open(WAL_NAME, vfs::OpenFlags::RDONLY) {
            Ok(mut wal) => {
                if wal.metadata()?.size > 0 {
                    apply_wal(fs, &lock_file)?;
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => (),
            Err(err) => return Err(err),
        }

        Ok(WriteTxn {
            fs,
            change_set: HashMap::new(),
            change_order: Vec::new(),
            lock: lock_file,
        })
    }

    fn add_change(&mut self, p: &str, op: WriteTxnOp) {
        if self.change_set.insert(p.into(), op).is_none() {
            self.change_order.push(p.into());
        }
    }

    pub fn commit(mut self) -> Result<(), std::io::Error> {
        if self.change_order.is_empty() {
            return Ok(());
        }

        let sequence_number = if keep_wal() {
            match self.fs.open(SEQ_NUM_NAME, vfs::OpenFlags::RDONLY) {
                Ok(mut f) => {
                    let mut buf: [u8; 8] = [0; 8];
                    f.read_exact(&mut buf[..])?;
                    u64::from_le_bytes(buf)
                }
                Err(err) => return Err(err),
            }
        } else {
            0
        };

        let mut wal = WalWriter::new(
            self.fs.open(
                WAL_NAME,
                vfs::OpenFlags::WRONLY | vfs::OpenFlags::CREAT | vfs::OpenFlags::TRUNC,
            )?,
            sequence_number,
        )?;

        for p in self.change_order.drain(..) {
            match self.change_set.remove(&p).unwrap() {
                WriteTxnOp::Remove => {
                    wal.write_op(WalOp::Remove { path: p.clone() })?;
                }
                WriteTxnOp::Write(data) => {
                    wal.write_op(WalOp::CreateFile {
                        path: p.clone(),
                        data_size: serde_bare::Uint(data.len() as u64),
                    })?;
                    wal.write_all(&data)?;
                }
                WriteTxnOp::Mkdir => {
                    wal.write_op(WalOp::Mkdir { path: p.clone() })?;
                }
                WriteTxnOp::WriteFile(mut f) => {
                    let data_size = f.seek(std::io::SeekFrom::End(0))?;
                    f.seek(std::io::SeekFrom::Start(0))?;
                    wal.write_op(WalOp::CreateFile {
                        path: p.clone(),
                        data_size: serde_bare::Uint(data_size),
                    })?;
                    std::io::copy(&mut f, &mut wal)?;
                }
                WriteTxnOp::Append(data) => match self.fs.metadata(&p) {
                    Ok(md) => {
                        let op = WalOp::WriteFileAt {
                            path: p.clone(),
                            offset: serde_bare::Uint(md.size),
                            data_size: serde_bare::Uint(data.len() as u64),
                        };
                        wal.write_op(op)?;
                        wal.write_all(&data)?;
                    }
                    Err(err) => return Err(err),
                },
                WriteTxnOp::Rename(to) => {
                    self.fs.metadata(&p)?;
                    match self.fs.metadata(&to) {
                        Ok(_) => {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                "refusing to rename over existing file in write transaction",
                            ));
                        }
                        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                            let op = WalOp::Rename {
                                path: p.clone(),
                                to: to.clone(),
                            };
                            wal.write_op(op)?;
                        }
                        Err(err) => return Err(err),
                    }
                }
                WriteTxnOp::RenameTarget => (),
            };
        }
        wal.finish()?;
        // Ensure the wal is in on disk, flushing the dir ensures
        // the file appears in the directory.
        sync_dir(self.fs, ".")?;
        apply_wal(self.fs, &self.lock)?;
        Ok(())
    }

    pub fn read(&self, p: &str) -> Result<Vec<u8>, std::io::Error> {
        let mut f = self.fs.open(p, vfs::OpenFlags::RDONLY)?;
        let mut data = Vec::with_capacity(f.metadata()?.size.try_into().unwrap());
        f.read_to_end(&mut data)?;
        Ok(data)
    }

    pub fn read_opt(&mut self, p: &str) -> Result<Option<Vec<u8>>, std::io::Error> {
        match self.fs.open(p, vfs::OpenFlags::RDONLY) {
            Ok(mut f) => {
                let mut data = Vec::with_capacity(f.metadata()?.size.try_into().unwrap());
                f.read_to_end(&mut data)?;
                Ok(Some(data))
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err),
        }
    }

    pub fn read_string(&mut self, p: &str) -> Result<String, std::io::Error> {
        let buf = self.read(p)?;
        match String::from_utf8(buf) {
            Ok(s) => Ok(s),
            Err(_) => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "invalid string data",
            )),
        }
    }

    pub fn read_opt_string(&mut self, p: &str) -> Result<Option<String>, std::io::Error> {
        match self.read_opt(p)? {
            Some(v) => match String::from_utf8(v) {
                Ok(s) => Ok(Some(s)),
                Err(_) => Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "invalid string data",
                )),
            },
            None => Ok(None),
        }
    }

    pub fn open(&self, p: &str) -> Result<vfs::VFile, std::io::Error> {
        self.fs.open(p, vfs::OpenFlags::RDONLY)
    }

    pub fn file_exists(&self, p: &str) -> Result<bool, std::io::Error> {
        // Using open plays better with fuse caching.
        match self.fs.open(p, vfs::OpenFlags::RDONLY) {
            Ok(_) => Ok(true),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(err) => Err(err),
        }
    }

    pub fn read_dir(&self, p: &str) -> Result<Vec<vfs::DirEntry>, std::io::Error> {
        self.fs.read_dir(p)
    }

    pub fn add_mkdir(&mut self, p: &str) -> Result<(), std::io::Error> {
        if self.change_set.contains_key(p) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "unable to mkdir over path modified in transaction",
            ));
        }
        self.add_change(p, WriteTxnOp::Mkdir);
        Ok(())
    }

    pub fn add_rm(&mut self, p: &str) -> Result<(), std::io::Error> {
        if self.change_set.contains_key(p) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "unable to remove file modified in transaction",
            ));
        }
        self.add_change(p, WriteTxnOp::Remove);
        Ok(())
    }

    pub fn add_write(&mut self, p: &str, data: Vec<u8>) -> Result<(), std::io::Error> {
        if self.change_set.contains_key(p) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "unable to write to file modified in transaction",
            ));
        }
        self.add_change(p, WriteTxnOp::Write(data));
        Ok(())
    }

    pub fn add_write_from_file(&mut self, p: &str, f: std::fs::File) -> Result<(), std::io::Error> {
        if self.change_set.contains_key(p) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "unable to write to file modified in transaction",
            ));
        }
        self.add_change(p, WriteTxnOp::WriteFile(f));
        Ok(())
    }

    pub fn add_string_write(&mut self, p: &str, data: String) -> Result<(), std::io::Error> {
        if self.change_set.contains_key(p) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "unable to write to file modified in transaction",
            ));
        }
        self.add_change(p, WriteTxnOp::Write(data.into_bytes()));
        Ok(())
    }

    pub fn add_append(&mut self, p: &str, mut data: Vec<u8>) -> Result<(), std::io::Error> {
        match self.change_set.get_mut(p) {
            Some(op) => match op {
                WriteTxnOp::Write(ref mut old_data) => old_data.append(&mut data),
                WriteTxnOp::WriteFile(ref mut dataf) => {
                    dataf.write_all(&data)?;
                }
                WriteTxnOp::Append(ref mut old_data) => old_data.append(&mut data),
                _ => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "unable to append data to file modified in transaction",
                    ))
                }
            },
            None => {
                self.add_change(p, WriteTxnOp::Append(data));
            }
        }
        Ok(())
    }

    pub fn add_rename(&mut self, from: &str, to: &str) -> Result<(), std::io::Error> {
        if self.change_set.contains_key(from) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "unable to rename file modified in transaction",
            ));
        }
        if self.change_set.contains_key(to) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "unable to rename over file modified in transaction",
            ));
        }
        self.add_change(from, WriteTxnOp::Rename(to.to_string()));
        self.add_change(to, WriteTxnOp::RenameTarget);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_wal_ops() {
        let d = tempfile::tempdir().unwrap();
        let fs = vfs::VFs::create(d.path().to_str().unwrap()).unwrap();

        drop(
            fs.open(LOCK_NAME, vfs::OpenFlags::WRONLY | vfs::OpenFlags::CREAT)
                .unwrap(),
        );
        drop(
            fs.open("remove", vfs::OpenFlags::CREAT | vfs::OpenFlags::WRONLY)
                .unwrap(),
        );
        drop(
            fs.open(
                "write_file_at",
                vfs::OpenFlags::CREAT | vfs::OpenFlags::WRONLY,
            )
            .unwrap(),
        );
        drop(
            fs.open("rename1", vfs::OpenFlags::CREAT | vfs::OpenFlags::WRONLY)
                .unwrap(),
        );

        // Loop checks idempotency.
        for i in 0..4 {
            let mut wal = WalWriter::new(
                fs.open(WAL_NAME, vfs::OpenFlags::WRONLY | vfs::OpenFlags::CREAT)
                    .unwrap(),
                0,
            )
            .unwrap();

            wal.write_op(WalOp::CreateFile {
                path: "create_file".into(),
                data_size: serde_bare::Uint(1),
            })
            .unwrap();
            wal.write(&[255]).unwrap();

            wal.write_op(WalOp::Remove {
                path: "remove".into(),
            })
            .unwrap();

            wal.write_op(WalOp::WriteFileAt {
                path: "write_file_at".into(),
                offset: serde_bare::Uint(0),
                data_size: serde_bare::Uint(1),
            })
            .unwrap();
            wal.write(&[255]).unwrap();

            wal.write_op(WalOp::Mkdir {
                path: "mkdir".into(),
            })
            .unwrap();

            wal.write_op(WalOp::Rename {
                path: "rename1".into(),
                to: "rename2".into(),
            })
            .unwrap();

            wal.finish().unwrap();

            if (i % 2) == 0 {
                ReadTxn::begin_at(&fs).unwrap().end();
            } else {
                WriteTxn::begin_at(&fs).unwrap().commit().unwrap();
            }

            assert!(fs.metadata("create_file").unwrap().size == 1);
            assert!(fs.metadata("remove").is_err());
            assert!(fs.metadata("write_file_at").unwrap().size == 1);
            assert!(matches!(
                fs.metadata("mkdir").unwrap().ftype,
                vfs::FileType::Dir
            ));
            assert!(fs.metadata("rename1").is_err());
            assert!(fs.metadata("rename2").is_ok());
        }
    }

    #[test]
    fn test_write_txn() {
        let d = tempfile::tempdir().unwrap();
        let fs = vfs::VFs::create(d.path().to_str().unwrap()).unwrap();

        drop(
            fs.open(LOCK_NAME, vfs::OpenFlags::CREAT | vfs::OpenFlags::WRONLY)
                .unwrap(),
        );
        drop({
            let mut f = fs
                .open(SEQ_NUM_NAME, vfs::OpenFlags::CREAT | vfs::OpenFlags::WRONLY)
                .unwrap();
            f.write(&[0, 0, 0, 0, 0, 0, 0, 0][..]).unwrap();
            f
        });
        drop(
            fs.open("append", vfs::OpenFlags::CREAT | vfs::OpenFlags::WRONLY)
                .unwrap(),
        );
        drop(
            fs.open("rename", vfs::OpenFlags::CREAT | vfs::OpenFlags::WRONLY)
                .unwrap(),
        );

        let mut txn = WriteTxn::begin_at(&fs).unwrap();
        txn.add_append("append", vec![1, 2, 3]).unwrap();
        txn.add_write("write", vec![4, 5, 6]).unwrap();
        txn.add_rename("rename", "renamed").unwrap();
        txn.add_mkdir("some_dir").unwrap();

        let mut f = tempfile::tempfile().unwrap();
        f.write(&[7, 8, 9]).unwrap();
        txn.add_write_from_file("write_file", f).unwrap();
        txn.commit().unwrap();

        let txn = ReadTxn::begin_at(&fs).unwrap();
        assert_eq!(txn.read("append").unwrap(), vec![1, 2, 3]);
        assert_eq!(txn.read("write").unwrap(), vec![4, 5, 6]);
        assert!(txn.metadata("renamed").is_ok());
        assert!(txn.metadata("some_dir").is_ok());
        txn.end();
    }
}
