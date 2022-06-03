// This file implements the bupstash transaction layer for updating
// repository metadata. The general idea is we write a rollback journal
// for batches of changes to the repository, fsync them, then proceed
// to make the changes. On any crash, the changes are rolled back by
// the next bupstash process.
//
// Recommended reading:
//
// https://www.sqlite.org/atomiccommit.html
// https://www.sqlite.org/psow.html

use super::vfs;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::TryInto;
use std::io::Read;
use std::io::Seek;
use std::io::Write;

const RJ_NAME: &str = "rollback.journal";
const LOCK_NAME: &str = "tx.lock";

#[derive(Deserialize, Serialize)]
enum RollbackOp {
    RollbackComplete,
    RemoveFile(String),
    WriteFile((String, serde_bare::Uint)),
    TruncateFile((String, serde_bare::Uint)),
    RenameFile { from: String, to: String },
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

struct RollbackJournalWriter {
    bw: std::io::BufWriter<FileTeeHasher>,
}

impl RollbackJournalWriter {
    fn new(rollback_journal: vfs::VFile) -> RollbackJournalWriter {
        RollbackJournalWriter {
            bw: std::io::BufWriter::with_capacity(
                256 * 1024,
                FileTeeHasher {
                    f: rollback_journal,
                    h: blake3::Hasher::new(),
                },
            ),
        }
    }

    fn write_op(&mut self, op: RollbackOp) -> Result<(), std::io::Error> {
        self.write_all(&serde_bare::to_vec(&op).unwrap())?;
        Ok(())
    }

    fn borrow_buf_writer(&mut self) -> &mut std::io::BufWriter<FileTeeHasher> {
        &mut self.bw
    }

    fn finish(mut self) -> Result<(), std::io::Error> {
        // Write RollbackComplete entry.
        self.bw.write_all(&[0])?;
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
        f.flush()?;
        Ok(())
    }
}

impl std::io::Write for RollbackJournalWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.bw.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.bw.flush()
    }
}

fn hot_rollback_journal(fs: &vfs::VFs) -> Result<bool, std::io::Error> {
    let mut hasher = blake3::Hasher::new();
    let mut f = fs.open(RJ_NAME, vfs::OpenFlags::RDONLY)?;
    let md = f.metadata()?;
    let sz = md.size;
    if sz < 32 {
        // Incomplete journal, too small.
        return Ok(false);
    }
    let mut t = (&mut f).take(sz - 32);
    std::io::copy(&mut t, &mut hasher)?;
    let mut expected = [0; 32];
    f.read_exact(&mut expected[..])?;
    Ok(expected == *hasher.finalize().as_bytes())
}

fn sync_dir(fs: &vfs::VFs) -> Result<(), std::io::Error> {
    let mut f = fs.open(".", vfs::OpenFlags::RDONLY)?;
    f.flush()?;
    Ok(())
}

fn sync_parent_dir(fs: &vfs::VFs, p: &str) -> Result<(), std::io::Error> {
    // XXX allocation seems unneccessary
    let mut parent = std::path::PathBuf::from(p);
    parent.pop();
    let rel = parent.to_str().unwrap();
    let rel = if rel.is_empty() { "." } else { rel };
    let mut f = fs.open(rel, vfs::OpenFlags::RDONLY)?;
    f.flush()?;
    Ok(())
}

fn rollback(fs: &vfs::VFs, _lock: &vfs::VFile) -> Result<(), std::io::Error> {
    if !hot_rollback_journal(fs)? {
        fs.remove_file(RJ_NAME)?;
        return Ok(());
    }

    let rj = fs.open(RJ_NAME, vfs::OpenFlags::RDONLY)?;
    let mut rj = std::io::BufReader::new(rj);
    loop {
        match serde_bare::from_reader(&mut rj) {
            Ok(RollbackOp::RollbackComplete) => {
                break;
            }
            Ok(RollbackOp::WriteFile((path, sz))) => {
                let mut f = fs.open(
                    &path,
                    vfs::OpenFlags::WRONLY | vfs::OpenFlags::CREAT | vfs::OpenFlags::TRUNC,
                )?;
                let rj = &mut rj;
                std::io::copy(&mut rj.take(sz.0), &mut f)?;
                f.flush()?;
                std::mem::drop(f);
                sync_parent_dir(fs, &path)?;
            }
            Ok(RollbackOp::TruncateFile((path, sz))) => {
                let mut f = fs.open(&path, vfs::OpenFlags::WRONLY | vfs::OpenFlags::APPEND)?;
                f.set_len(sz.0)?;
                f.flush()?;
                std::mem::drop(f);
                sync_parent_dir(fs, &path)?;
            }
            Ok(RollbackOp::RemoveFile(path)) => {
                match fs.remove_file(&path) {
                    Ok(()) => (),
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => (),
                    Err(err) => return Err(err),
                }
                sync_parent_dir(fs, &path)?;
            }
            Ok(RollbackOp::RenameFile { from, to }) => {
                match fs.rename(&from, &to) {
                    Ok(()) => (),
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                        if fs.metadata(&to).is_err() {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                "unable to rollback rename in transaction, neither source nor destination file exist",
                            ));
                        }
                    }
                    Err(err) => return Err(err),
                }
                sync_parent_dir(fs, &from)?;
                sync_parent_dir(fs, &to)?;
            }
            Err(_) => {
                panic!("malformed rollback journal")
            }
        }
    }
    fs.remove_file(RJ_NAME)?;

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

            match fs.metadata(RJ_NAME) {
                Ok(_) => {
                    std::mem::drop(lock);
                    {
                        lock = fs.open(LOCK_NAME, vfs::OpenFlags::RDWR)?;
                        lock.lock(vfs::LockType::Exclusive)?;

                        // Now we have the exclusive lock, check if we still need to rollback.
                        if fs.metadata(RJ_NAME).is_ok() {
                            rollback(&fs, &lock)?;
                        }
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

    pub fn metadata(&self, p: &str) -> Result<vfs::Metadata, std::io::Error> {
        self.fs.metadata(p)
    }

    pub fn read_dir(&self, p: &str) -> Result<Vec<vfs::DirEntry>, std::io::Error> {
        self.fs.read_dir(p)
    }

    pub fn file_exists(&self, p: &str) -> Result<bool, std::io::Error> {
        match self.fs.metadata(p) {
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
}

pub struct WriteTxn<'a> {
    fs: &'a vfs::VFs,
    changes: HashMap<String, WriteTxnOp>,
    _lock: vfs::VFile,
}

impl<'a> WriteTxn<'a> {
    pub fn begin_at(fs: &'a vfs::VFs) -> Result<WriteTxn, std::io::Error> {
        let mut lock_file = fs.open(LOCK_NAME, vfs::OpenFlags::RDWR)?;
        lock_file.lock(vfs::LockType::Exclusive)?;

        match fs.metadata(RJ_NAME) {
            Ok(_) => {
                rollback(&fs, &lock_file)?;
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => (),
            Err(err) => return Err(err),
        }
        Ok(WriteTxn {
            fs,
            changes: HashMap::new(),
            _lock: lock_file,
        })
    }

    pub fn commit(mut self) -> Result<(), std::io::Error> {
        if self.changes.is_empty() {
            return Ok(());
        }

        let mut rj = RollbackJournalWriter::new(self.fs.open(
            RJ_NAME,
            vfs::OpenFlags::WRONLY | vfs::OpenFlags::CREAT | vfs::OpenFlags::TRUNC,
        )?);
        for (p, op) in self.changes.iter() {
            match op {
                WriteTxnOp::Remove => {
                    match self.fs.open(p, vfs::OpenFlags::RDONLY) {
                        Ok(mut f) => {
                            let md = f.metadata()?;
                            let rollback_op =
                                RollbackOp::WriteFile((p.clone(), serde_bare::Uint(md.size)));
                            rj.write_op(rollback_op)?;
                            // copy is specialized for BufWriter, so use that.
                            let n = std::io::copy(&mut f, rj.borrow_buf_writer())?;
                            if n != md.size {
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::Other,
                                    "file modified outside of write transaction",
                                ));
                            }
                        }
                        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                            // Nothing to do.
                        }
                        Err(err) => return Err(err),
                    }
                }
                WriteTxnOp::Write(_) | WriteTxnOp::WriteFile(_) => {
                    match self.fs.open(p, vfs::OpenFlags::RDONLY) {
                        Ok(mut f) => {
                            let md = f.metadata()?;
                            let rollback_op =
                                RollbackOp::WriteFile((p.clone(), serde_bare::Uint(md.size)));
                            rj.write_op(rollback_op)?;
                            // copy is specialized for BufWriter, so use that.
                            let n = std::io::copy(&mut f, rj.borrow_buf_writer())?;
                            if n != md.size {
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::Other,
                                    "file modified outside of write transaction",
                                ));
                            }
                        }
                        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                            let rollback_op = RollbackOp::RemoveFile(p.clone());
                            rj.write_op(rollback_op)?;
                        }
                        Err(err) => return Err(err),
                    }
                }
                WriteTxnOp::Append(_) => match self.fs.metadata(p) {
                    Ok(md) => {
                        let rollback_op =
                            RollbackOp::TruncateFile((p.clone(), serde_bare::Uint(md.size)));
                        rj.write_op(rollback_op)?;
                    }
                    Err(err) => return Err(err),
                },
                WriteTxnOp::Rename(to) => {
                    self.fs.metadata(p)?;
                    match self.fs.metadata(to) {
                        Ok(_) => {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                "refusing to rename over existing file in write transaction",
                            ));
                        }
                        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                            let rollback_op = RollbackOp::RenameFile {
                                from: to.clone(),
                                to: p.clone(),
                            };
                            rj.write_op(rollback_op)?;
                        }
                        Err(err) => return Err(err),
                    }
                }
                WriteTxnOp::RenameTarget => (),
            };
        }
        rj.finish()?;
        sync_dir(&self.fs)?;

        for (p, op) in self.changes.iter_mut() {
            // Apply the write transaction. We always unlink files
            // before we overwrite them so that its safe to open
            // a file during a read transaction but then keep it open.
            match op {
                WriteTxnOp::Remove => match self.fs.remove_file(p) {
                    Ok(_) => {
                        sync_parent_dir(&self.fs, p)?;
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => (),
                    Err(err) => return Err(err),
                },
                WriteTxnOp::Write(data) => {
                    match self.fs.remove_file(p) {
                        Ok(_) => (),
                        Err(err) if err.kind() == std::io::ErrorKind::NotFound => (),
                        Err(err) => return Err(err),
                    };
                    let mut f = self.fs.open(
                        p,
                        vfs::OpenFlags::WRONLY | vfs::OpenFlags::CREAT | vfs::OpenFlags::TRUNC,
                    )?;
                    f.write_all(data)?;
                    f.flush()?;
                    sync_parent_dir(&self.fs, p)?;
                }
                WriteTxnOp::WriteFile(ref mut dataf) => {
                    match self.fs.remove_file(p) {
                        Ok(_) => (),
                        Err(err) if err.kind() == std::io::ErrorKind::NotFound => (),
                        Err(err) => return Err(err),
                    };
                    dataf.seek(std::io::SeekFrom::Start(0))?;
                    let mut outf = self.fs.open(
                        p,
                        vfs::OpenFlags::WRONLY | vfs::OpenFlags::CREAT | vfs::OpenFlags::TRUNC,
                    )?;
                    std::io::copy(dataf, &mut outf)?;
                    outf.flush()?;
                    sync_parent_dir(&self.fs, p)?;
                }
                WriteTxnOp::Append(data) => {
                    let mut f = self
                        .fs
                        .open(p, vfs::OpenFlags::WRONLY | vfs::OpenFlags::APPEND)?;
                    f.write_all(data)?;
                    f.flush()?;
                    sync_parent_dir(&self.fs, p)?;
                }
                WriteTxnOp::Rename(to) => {
                    self.fs.rename(p, to)?;
                    sync_parent_dir(&self.fs, p)?;
                    sync_parent_dir(&self.fs, to)?;
                }
                WriteTxnOp::RenameTarget => (),
            };
        }

        self.fs.remove_file(RJ_NAME)?;

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

    pub fn metadata(&self, p: &str) -> Result<vfs::Metadata, std::io::Error> {
        self.fs.metadata(p)
    }

    pub fn file_exists(&self, p: &str) -> Result<bool, std::io::Error> {
        match self.fs.metadata(p) {
            Ok(_) => Ok(true),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(err) => Err(err),
        }
    }

    pub fn read_dir(&self, p: &str) -> Result<Vec<vfs::DirEntry>, std::io::Error> {
        self.fs.read_dir(p)
    }

    pub fn add_rm(&mut self, p: &str) -> Result<(), std::io::Error> {
        if self.changes.contains_key(p) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "unable to remove file modified in transaction",
            ));
        }
        self.changes.insert(p.into(), WriteTxnOp::Remove);
        Ok(())
    }

    pub fn add_write(&mut self, p: &str, data: Vec<u8>) -> Result<(), std::io::Error> {
        if self.changes.contains_key(p) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "unable to write to file modified in transaction",
            ));
        }
        self.changes.insert(p.into(), WriteTxnOp::Write(data));
        Ok(())
    }

    pub fn add_write_from_file(&mut self, p: &str, f: std::fs::File) -> Result<(), std::io::Error> {
        if self.changes.contains_key(p) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "unable to write to file modified in transaction",
            ));
        }
        self.changes.insert(p.into(), WriteTxnOp::WriteFile(f));
        Ok(())
    }

    pub fn add_string_write(&mut self, p: &str, data: String) -> Result<(), std::io::Error> {
        if self.changes.contains_key(p) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "unable to write to file modified in transaction",
            ));
        }
        self.changes
            .insert(p.into(), WriteTxnOp::Write(data.into_bytes()));
        Ok(())
    }

    pub fn add_append(&mut self, p: &str, mut data: Vec<u8>) -> Result<(), std::io::Error> {
        match self.changes.get_mut(p) {
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
                self.changes.insert(p.to_string(), WriteTxnOp::Append(data));
            }
        }
        Ok(())
    }

    pub fn add_rename(&mut self, from: &str, to: &str) -> Result<(), std::io::Error> {
        if self.changes.contains_key(from) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "unable to rename file modified in transaction",
            ));
        }
        if self.changes.contains_key(to) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "unable to rename over file modified in transaction",
            ));
        }
        self.changes
            .insert(from.to_string(), WriteTxnOp::Rename(to.to_string()));
        self.changes
            .insert(to.to_string(), WriteTxnOp::RenameTarget);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_write_file_rollback() {
        let d = tempfile::tempdir().unwrap();
        let fs = vfs::VFs::create(d.path().to_str().unwrap()).unwrap();

        drop(
            fs.open(LOCK_NAME, vfs::OpenFlags::WRONLY | vfs::OpenFlags::CREAT)
                .unwrap(),
        );

        let mut rj = RollbackJournalWriter::new(
            fs.open(RJ_NAME, vfs::OpenFlags::WRONLY | vfs::OpenFlags::CREAT)
                .unwrap(),
        );

        rj.write_op(RollbackOp::WriteFile((
            "foobar.txt".into(),
            serde_bare::Uint(1),
        )))
        .unwrap();
        rj.write(&[255]).unwrap();
        rj.finish().unwrap();

        ReadTxn::begin_at(&fs).unwrap().end();
        assert!(fs.metadata("foobar.txt").is_ok());
    }

    #[test]
    fn test_remove_file_rollback() {
        let d = tempfile::tempdir().unwrap();
        let fs = vfs::VFs::create(d.path().to_str().unwrap()).unwrap();

        drop(
            fs.open(LOCK_NAME, vfs::OpenFlags::CREAT | vfs::OpenFlags::WRONLY)
                .unwrap(),
        );
        drop(
            fs.open("foobar.txt", vfs::OpenFlags::CREAT | vfs::OpenFlags::WRONLY)
                .unwrap(),
        );

        let mut rj = RollbackJournalWriter::new(
            fs.open(RJ_NAME, vfs::OpenFlags::CREAT | vfs::OpenFlags::WRONLY)
                .unwrap(),
        );
        rj.write_op(RollbackOp::RemoveFile("foobar.txt".into()))
            .unwrap();
        rj.finish().unwrap();

        ReadTxn::begin_at(&fs).unwrap().end();

        assert!(fs.metadata("foobar.txt").is_err());
    }

    #[test]
    fn test_rename_file_rollback() {
        let d = tempfile::tempdir().unwrap();
        let fs = vfs::VFs::create(d.path().to_str().unwrap()).unwrap();

        drop(
            fs.open(LOCK_NAME, vfs::OpenFlags::CREAT | vfs::OpenFlags::WRONLY)
                .unwrap(),
        );
        drop(
            fs.open("foo.x", vfs::OpenFlags::CREAT | vfs::OpenFlags::WRONLY)
                .unwrap(),
        );
        drop(
            fs.open("bar", vfs::OpenFlags::CREAT | vfs::OpenFlags::WRONLY)
                .unwrap(),
        );

        let mut rj = RollbackJournalWriter::new(
            fs.open(RJ_NAME, vfs::OpenFlags::CREAT | vfs::OpenFlags::WRONLY)
                .unwrap(),
        );
        rj.write_op(RollbackOp::RenameFile {
            from: "foo.x".into(),
            to: "foo".into(),
        })
        .unwrap();
        rj.write_op(RollbackOp::RenameFile {
            from: "bar.x".into(),
            to: "bar".into(),
        })
        .unwrap();
        rj.finish().unwrap();

        ReadTxn::begin_at(&fs).unwrap().end();

        assert!(fs.metadata("foo.x").is_err());
        assert!(fs.metadata("foo").is_ok());
        assert!(fs.metadata("bar").is_ok());
    }

    #[test]
    fn test_truncate_file_rollback() {
        let d = tempfile::tempdir().unwrap();
        let fs = vfs::VFs::create(d.path().to_str().unwrap()).unwrap();

        drop(
            fs.open(LOCK_NAME, vfs::OpenFlags::CREAT | vfs::OpenFlags::WRONLY)
                .unwrap(),
        );
        let mut f = fs
            .open("foobar.txt", vfs::OpenFlags::CREAT | vfs::OpenFlags::WRONLY)
            .unwrap();
        f.write(&[1, 2, 3]).unwrap();
        f.flush().unwrap();
        drop(f);

        let mut rj = RollbackJournalWriter::new(
            fs.open(RJ_NAME, vfs::OpenFlags::CREAT | vfs::OpenFlags::WRONLY)
                .unwrap(),
        );
        rj.write_op(RollbackOp::TruncateFile((
            "foobar.txt".to_string(),
            serde_bare::Uint(0),
        )))
        .unwrap();
        rj.finish().unwrap();

        ReadTxn::begin_at(&fs).unwrap().end();

        assert!(fs.metadata("foobar.txt").unwrap().size == 0);
    }

    #[test]
    fn test_write_txn() {
        let d = tempfile::tempdir().unwrap();
        let fs = vfs::VFs::create(d.path().to_str().unwrap()).unwrap();

        drop(
            fs.open(LOCK_NAME, vfs::OpenFlags::CREAT | vfs::OpenFlags::WRONLY)
                .unwrap(),
        );
        drop(
            fs.open("append.txt", vfs::OpenFlags::CREAT | vfs::OpenFlags::WRONLY)
                .unwrap(),
        );
        drop(
            fs.open("rename.txt", vfs::OpenFlags::CREAT | vfs::OpenFlags::WRONLY)
                .unwrap(),
        );

        let mut txn = WriteTxn::begin_at(&fs).unwrap();
        txn.add_append("append.txt", vec![1, 2, 3]).unwrap();
        txn.add_write("write.txt", vec![4, 5, 6]).unwrap();
        txn.add_rename("rename.txt", "renamed.txt").unwrap();

        let mut f = tempfile::tempfile().unwrap();
        f.write(&[7, 8, 9]).unwrap();
        txn.add_write_from_file("write_file.txt", f).unwrap();
        txn.commit().unwrap();

        let txn = ReadTxn::begin_at(&fs).unwrap();
        assert_eq!(txn.read("append.txt").unwrap(), vec![1, 2, 3]);
        assert_eq!(txn.read("write.txt").unwrap(), vec![4, 5, 6]);
        assert!(txn.metadata("renamed.txt").is_ok());
        txn.end();
    }
}
