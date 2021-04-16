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

use super::fsutil;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::TryInto;
use std::io::Read;
use std::io::Seek;
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

const RJ_NAME: &str = "rollback.journal";
const LOCK_NAME: &str = "tx.lock";

#[derive(Deserialize, Serialize)]
enum RollbackOp {
    RollbackComplete,
    RemoveFile(String),
    WriteFile((String, serde_bare::Uint)),
    TruncateFile((String, serde_bare::Uint)),
}

#[derive(Debug)]
struct FileTeeHasher {
    f: std::fs::File,
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
    fn create(dirf: &openat::Dir) -> Result<Self, std::io::Error> {
        Ok(Self {
            bw: std::io::BufWriter::with_capacity(
                256 * 1024,
                FileTeeHasher {
                    f: dirf.write_file(RJ_NAME, 0o666)?,
                    h: blake3::Hasher::new(),
                },
            ),
        })
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
        // unwrap ok, we already flushed.
        // unstable api's would let us remove the extra
        // write syscall, for most people this doesn't matter,
        // for network filesystems it might let us skip a roundtrip.
        let tw = self.bw.into_inner().unwrap();
        let h = tw.h;
        let mut f = tw.f;
        let h = h.finalize();
        let h = h.as_bytes();
        f.write_all(&h[..])?;
        f.sync_all()?;
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

fn hot_rollback_journal(dirf: &openat::Dir) -> Result<bool, std::io::Error> {
    let mut hasher = blake3::Hasher::new();
    let mut f = dirf.open_file(RJ_NAME)?;
    let md = f.metadata()?;
    let sz = md.size();
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

fn sync_dir(dirf: &openat::Dir) -> Result<(), std::io::Error> {
    let f = dirf.open_file(".")?;
    f.sync_all()?;
    Ok(())
}

fn sync_parent_dir(dirf: &openat::Dir, p: &str) -> Result<(), std::io::Error> {
    let mut parent = PathBuf::from(p);
    parent.pop();
    let rel = parent.to_str().unwrap();
    let rel = if rel.is_empty() { "." } else { rel };
    let f = dirf.open_file(rel)?;
    f.sync_all()?;
    Ok(())
}

fn rollback(dirf: &openat::Dir, _lock: &fsutil::FileLock) -> Result<(), std::io::Error> {
    if !hot_rollback_journal(dirf)? {
        dirf.remove_file(RJ_NAME)?;
        return Ok(());
    }

    let rj = dirf.open_file(RJ_NAME)?;
    let mut rj = std::io::BufReader::new(rj);
    loop {
        match serde_bare::from_reader(&mut rj) {
            Ok(RollbackOp::RollbackComplete) => {
                break;
            }
            Ok(RollbackOp::WriteFile((path, sz))) => {
                let mut f = dirf.write_file(&path, 0o666)?;
                let rj = &mut rj;
                std::io::copy(&mut rj.take(sz.0), &mut f)?;
                f.sync_all()?;
                std::mem::drop(f);
                sync_parent_dir(dirf, &path)?;
            }
            Ok(RollbackOp::TruncateFile((path, sz))) => {
                let f = dirf.append_file(&path, 0o666)?;
                f.set_len(sz.0)?;
                f.sync_all()?;
                std::mem::drop(f);
                sync_parent_dir(dirf, &path)?;
            }
            Ok(RollbackOp::RemoveFile(path)) => {
                match dirf.remove_file(&path) {
                    Ok(()) => (),
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => (),
                    Err(err) => return Err(err),
                }
                sync_parent_dir(&dirf, &path)?;
            }
            Err(_) => {
                panic!("malformed rollback journal")
            }
        }
    }
    dirf.remove_file(RJ_NAME)?;

    Ok(())
}

pub struct ReadTxn {
    dirf: openat::Dir,
    _lock: fsutil::FileLock,
}

impl ReadTxn {
    pub fn begin(dir: &Path) -> Result<Self, std::io::Error> {
        let dirf = openat::Dir::open(dir)?;
        'try_again: loop {
            let lock = fsutil::FileLock::shared_on_file(dirf.open_file(LOCK_NAME)?)?;
            match dirf.metadata(RJ_NAME) {
                Ok(_) => {
                    std::mem::drop(lock);
                    {
                        let lock = fsutil::FileLock::exclusive_on_file(
                            dirf.update_file(LOCK_NAME, 0o666)?,
                        )?;
                        // Now we have the exclusive lock, check if we still need to rollback.
                        if dirf.metadata(RJ_NAME).is_ok() {
                            rollback(&dirf, &lock)?;
                        }
                        continue 'try_again;
                    }
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => (),
                Err(err) => return Err(err),
            }
            return Ok(ReadTxn { _lock: lock, dirf });
        }
    }

    pub fn end(self) {}

    pub fn read(&self, p: &str) -> Result<Vec<u8>, std::io::Error> {
        let mut f = self.dirf.open_file(p)?;
        let mut data = Vec::with_capacity(f.metadata()?.size().try_into().unwrap());
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

    pub fn open(&self, p: &str) -> Result<std::fs::File, std::io::Error> {
        self.dirf.open_file(p)
    }

    pub fn metadata(&self, p: &str) -> Result<openat::Metadata, std::io::Error> {
        self.dirf.metadata(p)
    }

    pub fn read_dir(&self, p: &str) -> Result<openat::DirIter, std::io::Error> {
        self.dirf.list_dir(p)
    }
}

enum WriteTxnOp {
    Remove,
    Write(Vec<u8>),
    WriteFile(std::fs::File),
    Append(Vec<u8>),
}

pub struct WriteTxn {
    dirf: openat::Dir,
    changes: HashMap<String, WriteTxnOp>,
    _lock: fsutil::FileLock,
}

impl WriteTxn {
    pub fn begin(dir: &Path) -> Result<WriteTxn, std::io::Error> {
        let dirf = openat::Dir::open(dir)?;
        let lock = fsutil::FileLock::exclusive_on_file(dirf.update_file(LOCK_NAME, 0o666)?)?;
        match dirf.metadata(RJ_NAME) {
            Ok(_) => {
                rollback(&dirf, &lock)?;
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => (),
            Err(err) => return Err(err),
        }
        Ok(WriteTxn {
            dirf,
            changes: HashMap::new(),
            _lock: lock,
        })
    }

    pub fn commit(mut self) -> Result<(), std::io::Error> {
        if !self.changes.is_empty() {
            let mut rj = RollbackJournalWriter::create(&self.dirf)?;
            for (p, op) in self.changes.iter() {
                match op {
                    WriteTxnOp::Remove => {
                        match self.dirf.open_file(p) {
                            Ok(mut f) => {
                                let md = f.metadata()?;
                                let rollback_op =
                                    RollbackOp::WriteFile((p.clone(), serde_bare::Uint(md.size())));
                                rj.write_op(rollback_op)?;
                                // copy is specialized for BufWriter, so use that.
                                let n = std::io::copy(&mut f, rj.borrow_buf_writer())?;
                                if n != md.size() {
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
                        match self.dirf.open_file(p) {
                            Ok(mut f) => {
                                let md = f.metadata()?;
                                let rollback_op =
                                    RollbackOp::WriteFile((p.clone(), serde_bare::Uint(md.size())));
                                rj.write_op(rollback_op)?;
                                // copy is specialized for BufWriter, so use that.
                                let n = std::io::copy(&mut f, rj.borrow_buf_writer())?;
                                if n != md.size() {
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
                    WriteTxnOp::Append(_) => match self.dirf.metadata(p) {
                        Ok(md) => {
                            let rollback_op =
                                RollbackOp::TruncateFile((p.clone(), serde_bare::Uint(md.len())));
                            rj.write_op(rollback_op)?;
                        }
                        Err(err) => return Err(err),
                    },
                };
            }
            rj.finish()?;
            sync_dir(&self.dirf)?;

            for (p, op) in self.changes.iter_mut() {
                // Apply the write transaction. We always unlink files
                // before we overwrite them so that its safe to open
                // a file during a read transaction but then keep it open.
                match op {
                    WriteTxnOp::Remove => match self.dirf.remove_file(p) {
                        Ok(_) => {
                            sync_parent_dir(&self.dirf, p)?;
                        }
                        Err(err) if err.kind() == std::io::ErrorKind::NotFound => (),
                        Err(err) => return Err(err),
                    },
                    WriteTxnOp::Write(data) => {
                        match self.dirf.remove_file(p) {
                            Ok(_) => (),
                            Err(err) if err.kind() == std::io::ErrorKind::NotFound => (),
                            Err(err) => return Err(err),
                        };
                        let mut f = self.dirf.write_file(p, 0o666)?;
                        f.write_all(data)?;
                        f.sync_all()?;
                        sync_parent_dir(&self.dirf, p)?;
                    }
                    WriteTxnOp::WriteFile(ref mut dataf) => {
                        match self.dirf.remove_file(p) {
                            Ok(_) => (),
                            Err(err) if err.kind() == std::io::ErrorKind::NotFound => (),
                            Err(err) => return Err(err),
                        };
                        dataf.seek(std::io::SeekFrom::Start(0))?;
                        let mut outf = self.dirf.write_file(p, 0o666)?;
                        std::io::copy(dataf, &mut outf)?;
                        outf.sync_all()?;
                        sync_parent_dir(&self.dirf, p)?;
                    }
                    WriteTxnOp::Append(data) => {
                        let mut f = self.dirf.append_file(p, 0o666)?;
                        f.write_all(&data)?;
                        f.sync_all()?;
                        sync_parent_dir(&self.dirf, p)?;
                    }
                };
            }

            self.dirf.remove_file(RJ_NAME)?;
        }
        Ok(())
    }

    pub fn read(&self, p: &str) -> Result<Vec<u8>, std::io::Error> {
        let mut f = self.dirf.open_file(p)?;
        let mut data = Vec::with_capacity(f.metadata()?.size().try_into().unwrap());
        f.read_to_end(&mut data)?;
        Ok(data)
    }

    pub fn read_opt(&mut self, p: &str) -> Result<Option<Vec<u8>>, std::io::Error> {
        match self.dirf.open_file(p) {
            Ok(mut f) => {
                let mut data = Vec::with_capacity(f.metadata()?.size().try_into().unwrap());
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

    pub fn open(&self, p: &str) -> Result<std::fs::File, std::io::Error> {
        self.dirf.open_file(p)
    }

    pub fn metadata(&self, p: &str) -> Result<openat::Metadata, std::io::Error> {
        self.dirf.metadata(p)
    }

    pub fn read_dir(&self, p: &str) -> Result<openat::DirIter, std::io::Error> {
        self.dirf.list_dir(p)
    }

    pub fn add_rm(&mut self, p: &str) {
        self.changes.insert(p.into(), WriteTxnOp::Remove);
    }

    pub fn add_write(&mut self, p: &str, data: Vec<u8>) {
        self.changes.insert(p.into(), WriteTxnOp::Write(data));
    }

    pub fn add_write_from_file(&mut self, p: &str, f: std::fs::File) {
        self.changes.insert(p.into(), WriteTxnOp::WriteFile(f));
    }

    pub fn add_string_write(&mut self, p: &str, data: String) {
        self.changes
            .insert(p.into(), WriteTxnOp::Write(data.into_bytes()));
    }

    pub fn add_append(&mut self, p: &str, mut data: Vec<u8>) -> Result<(), std::io::Error> {
        match self.changes.get_mut(p) {
            Some(op) => match op {
                WriteTxnOp::Remove => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "unable to append data to file removed in transaction",
                    ))
                }
                WriteTxnOp::Write(ref mut old_data) => old_data.append(&mut data),
                WriteTxnOp::WriteFile(ref mut dataf) => {
                    dataf.write_all(&data)?;
                }
                WriteTxnOp::Append(ref mut old_data) => old_data.append(&mut data),
            },
            None => {
                self.changes.insert(p.to_string(), WriteTxnOp::Append(data));
            }
        }

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
        let mut p = d.path().to_owned();
        let d = openat::Dir::open(&p).unwrap();

        p.push(LOCK_NAME);
        std::fs::File::create(&p).unwrap();
        p.pop();

        let mut rj = RollbackJournalWriter::create(&d).unwrap();

        rj.write_op(RollbackOp::WriteFile((
            "foobar.txt".into(),
            serde_bare::Uint(1),
        )))
        .unwrap();
        rj.write(&[255]).unwrap();
        rj.finish().unwrap();

        ReadTxn::begin(&p).unwrap().end();
        p.push("foobar.txt");
        assert!(p.exists());
    }

    #[test]
    fn test_remove_file_rollback() {
        let d = tempfile::tempdir().unwrap();
        let mut p = d.path().to_owned();
        let d = openat::Dir::open(&p).unwrap();

        p.push(LOCK_NAME);
        std::fs::File::create(&p).unwrap();
        p.pop();

        p.push("foobar.txt");
        std::fs::write(&p, &vec![]).unwrap();
        p.pop();

        let mut rj = RollbackJournalWriter::create(&d).unwrap();
        rj.write_op(RollbackOp::RemoveFile("foobar.txt".into()))
            .unwrap();
        rj.finish().unwrap();

        ReadTxn::begin(&p).unwrap().end();

        p.push("foobar.txt");
        assert!(!p.exists());
        p.pop();
    }

    #[test]
    fn test_truncate_file_rollback() {
        let d = tempfile::tempdir().unwrap();
        let mut p = d.path().to_owned();
        let d = openat::Dir::open(&p).unwrap();

        p.push(LOCK_NAME);
        std::fs::File::create(&p).unwrap();
        p.pop();

        p.push("foobar.txt");
        std::fs::write(&p, &vec![]).unwrap();
        p.pop();

        let mut rj = RollbackJournalWriter::create(&d).unwrap();
        rj.write_op(RollbackOp::TruncateFile((
            "foobar.txt".to_string(),
            serde_bare::Uint(0),
        )))
        .unwrap();
        rj.finish().unwrap();

        ReadTxn::begin(&p).unwrap().end();

        p.push("foobar.txt");
        assert!(p.metadata().unwrap().size() == 0);
        p.pop();
    }

    #[test]
    fn test_write_txn() {
        let d = tempfile::tempdir().unwrap();
        let mut p = d.path().to_owned();

        p.push(LOCK_NAME);
        std::fs::File::create(&p).unwrap();
        p.pop();
        p.push("append.txt");
        std::fs::File::create(&p).unwrap();
        p.pop();

        let mut txn = WriteTxn::begin(d.path()).unwrap();
        txn.add_append("append.txt", vec![1, 2, 3]).unwrap();
        txn.add_write("write.txt", vec![4, 5, 6]);

        let mut f = tempfile::tempfile().unwrap();
        f.write(&[7, 8, 9]).unwrap();
        txn.add_write_from_file("write_file.txt", f);
        txn.commit().unwrap();

        let txn = ReadTxn::begin(d.path()).unwrap();
        assert_eq!(txn.read("append.txt").unwrap(), vec![1, 2, 3]);
        assert_eq!(txn.read("write.txt").unwrap(), vec![4, 5, 6]);
        assert_eq!(txn.read("write_file.txt").unwrap(), vec![7, 8, 9]);
        txn.end();
    }
}
