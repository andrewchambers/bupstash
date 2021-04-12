use super::fsutil;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Read;
use std::io::Seek;
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

fn lock_path(dir: &Path) -> PathBuf {
    let mut p = dir.to_owned();
    p.push("tx.lock");
    p
}

fn rollback_journal_path(dir: &Path) -> PathBuf {
    let mut p = dir.to_owned();
    p.push("rollback.journal");
    p
}

#[derive(Deserialize, Serialize)]
enum RollbackOp {
    RollbackComplete,
    RemoveFile(PathBuf),
    WriteFile((PathBuf, serde_bare::Uint)),
    TruncateFile((PathBuf, serde_bare::Uint)),
}

struct RollbackJournalWriter {
    f: std::fs::File,
    h: blake3::Hasher,
}

impl RollbackJournalWriter {
    fn create(p: &Path) -> Result<Self, std::io::Error> {
        Ok(Self {
            f: std::fs::File::create(p)?,
            h: blake3::Hasher::new(),
        })
    }

    fn write_op(&mut self, op: RollbackOp) -> Result<(), std::io::Error> {
        self.write_all(&serde_bare::to_vec(&op).unwrap())?;
        Ok(())
    }

    fn finish(mut self) -> Result<(), std::io::Error> {
        // RollbackComplete
        self.write_all(&[0])?;
        let h = self.h.finalize();
        let h = h.as_bytes();
        self.f.write_all(&h[..])?;
        self.f.sync_all()?;
        Ok(())
    }
}

impl std::io::Write for RollbackJournalWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.h.write_all(buf)?;
        self.f.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.f.sync_data()
    }
}

fn hot_rollback_journal(rollback_journal: &Path) -> Result<bool, std::io::Error> {
    let mut hasher = blake3::Hasher::new();
    let mut f = std::fs::File::open(rollback_journal)?;
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

fn rollback(
    dir: &Path,
    _lock: &fsutil::FileLock,
    rollback_journal: &Path,
) -> Result<(), std::io::Error> {
    if !hot_rollback_journal(rollback_journal)? {
        std::fs::remove_file(rollback_journal)?;
        return Ok(());
    }

    let rj = std::fs::File::open(rollback_journal)?;
    let mut rj = std::io::BufReader::new(rj);
    loop {
        match serde_bare::from_reader(&mut rj) {
            Ok(RollbackOp::RollbackComplete) => {
                break;
            }
            Ok(RollbackOp::WriteFile((path, sz))) => {
                let mut full_path = dir.to_owned();
                full_path.push(path);
                let mut f = std::fs::File::create(&full_path)?;
                let rj = &mut rj;
                std::io::copy(&mut rj.take(sz.0), &mut f)?;
                f.sync_all()?;
                full_path.pop();
                fsutil::sync_dir(&full_path)?;
            }
            Ok(RollbackOp::TruncateFile((path, sz))) => {
                let mut full_path = dir.to_owned();
                full_path.push(path);
                let f = std::fs::OpenOptions::new().append(true).open(&full_path)?;
                f.set_len(sz.0)?;
                f.sync_all()?;
                full_path.pop();
                fsutil::sync_dir(&full_path)?;
            }
            Ok(RollbackOp::RemoveFile(path)) => {
                let mut full_path = dir.to_owned();
                full_path.push(path);
                match std::fs::remove_file(&full_path) {
                    Ok(()) => (),
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => (),
                    Err(err) => return Err(err),
                }
                full_path.pop();
                fsutil::sync_dir(&full_path)?;
            }
            Err(_) => {
                panic!("malformed rollback journal")
            }
        }
    }

    std::fs::remove_file(rollback_journal)?;

    Ok(())
}

pub struct ReadTxn {
    dir: PathBuf,
    _lock: fsutil::FileLock,
}

impl ReadTxn {
    pub fn begin(dir: &Path) -> Result<Self, std::io::Error> {
        let lock_path = lock_path(dir);
        let rollback_journal_path = rollback_journal_path(dir);

        'try_again: loop {
            let lock = fsutil::FileLock::get_shared(&lock_path)?;
            match rollback_journal_path.metadata() {
                Ok(_) => {
                    std::mem::drop(lock);
                    {
                        let lock = fsutil::FileLock::get_exclusive(&lock_path)?;
                        // Now we have the exclusive lock, check if we still need to rollback.
                        if rollback_journal_path.metadata().is_ok() {
                            rollback(dir, &lock, &rollback_journal_path)?;
                        }
                        continue 'try_again;
                    }
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => (),
                Err(err) => return Err(err),
            }
            return Ok(ReadTxn {
                dir: dir.to_owned(),
                _lock: lock,
            });
        }
    }

    pub fn end(self) {}

    pub fn full_path(&self, p: &str) -> std::path::PathBuf {
        let mut full_path = self.dir.clone();
        full_path.push(p);
        full_path
    }

    pub fn read(&self, p: &str) -> Result<Vec<u8>, std::io::Error> {
        let mut full_path = self.dir.clone();
        full_path.push(p);
        std::fs::read(&full_path)
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
        let mut full_path = self.dir.clone();
        full_path.push(p);
        std::fs::File::open(&full_path)
    }

    pub fn metadata(&self, p: &str) -> Result<std::fs::Metadata, std::io::Error> {
        let mut full_path = self.dir.clone();
        full_path.push(p);
        std::fs::metadata(&full_path)
    }

    pub fn read_dir(&self, p: &str) -> Result<std::fs::ReadDir, std::io::Error> {
        let mut full_path = self.dir.clone();
        full_path.push(p);
        std::fs::read_dir(&full_path)
    }
}

enum WriteTxnOp {
    Remove,
    Write(Vec<u8>),
    WriteFile(std::fs::File),
    Append(Vec<u8>),
}

pub struct WriteTxn {
    dir: PathBuf,
    changes: HashMap<PathBuf, WriteTxnOp>,
    _lock: fsutil::FileLock,
}

impl WriteTxn {
    pub fn begin(dir: &Path) -> Result<WriteTxn, std::io::Error> {
        let lock_path = lock_path(dir);
        let rollback_journal_path = rollback_journal_path(dir);
        let lock = fsutil::FileLock::get_exclusive(&lock_path)?;
        match rollback_journal_path.metadata() {
            Ok(_) => {
                rollback(dir, &lock, &rollback_journal_path)?;
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => (),
            Err(err) => return Err(err),
        }
        Ok(WriteTxn {
            dir: dir.to_owned(),
            changes: HashMap::new(),
            _lock: lock,
        })
    }

    pub fn commit(mut self) -> Result<(), std::io::Error> {
        if !self.changes.is_empty() {
            let rollback_journal_path = rollback_journal_path(&self.dir);
            let mut rj = RollbackJournalWriter::create(&rollback_journal_path)?;
            for (p, op) in self.changes.iter() {
                let mut full_path = self.dir.clone();
                full_path.push(p);
                match op {
                    WriteTxnOp::Remove => {
                        match full_path.metadata() {
                            Ok(md) => {
                                let rollback_op =
                                    RollbackOp::WriteFile((p.clone(), serde_bare::Uint(md.size())));
                                rj.write_op(rollback_op)?;
                                let mut f = std::fs::File::open(&full_path)?;
                                std::io::copy(&mut f, &mut rj)?;
                            }
                            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                                // Nothing to do.
                            }
                            Err(err) => return Err(err),
                        }
                    }
                    WriteTxnOp::Write(_) | WriteTxnOp::WriteFile(_) => match full_path.metadata() {
                        Ok(md) => {
                            let rollback_op =
                                RollbackOp::WriteFile((p.clone(), serde_bare::Uint(md.size())));
                            rj.write_op(rollback_op)?;
                            let mut f = std::fs::File::open(&full_path)?;
                            let n = std::io::copy(&mut f, &mut rj)?;
                            if n != md.size() {
                                panic!("file modified outside of write transaction");
                            }
                        }
                        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                            let rollback_op = RollbackOp::RemoveFile(p.clone());
                            rj.write_op(rollback_op)?;
                        }
                        Err(err) => return Err(err),
                    },
                    WriteTxnOp::Append(_) => match full_path.metadata() {
                        Ok(md) => {
                            let rollback_op =
                                RollbackOp::TruncateFile((p.clone(), serde_bare::Uint(md.size())));
                            rj.write_op(rollback_op)?;
                        }
                        Err(err) => return Err(err),
                    },
                };
            }
            rj.finish()?;
            fsutil::sync_dir(&self.dir)?;

            for (p, op) in self.changes.iter_mut() {
                let mut full_path = self.dir.clone();
                full_path.push(p);
                // Apply the write transaction. We always unlink files
                // before we overwrite them so that its safe to open
                // a file during a read transaction but then keep it open.
                match op {
                    WriteTxnOp::Remove => match std::fs::remove_file(&full_path) {
                        Ok(_) => {
                            full_path.pop();
                            fsutil::sync_dir(&full_path)?;
                        }
                        Err(err) if err.kind() == std::io::ErrorKind::NotFound => (),
                        Err(err) => return Err(err),
                    },
                    WriteTxnOp::Write(data) => {
                        match std::fs::remove_file(&full_path) {
                            Ok(_) => (),
                            Err(err) if err.kind() == std::io::ErrorKind::NotFound => (),
                            Err(err) => return Err(err),
                        };
                        std::fs::write(&full_path, data)?;
                        full_path.pop();
                        fsutil::sync_dir(&full_path)?;
                    }
                    WriteTxnOp::WriteFile(ref mut dataf) => {
                        match std::fs::remove_file(&full_path) {
                            Ok(_) => (),
                            Err(err) if err.kind() == std::io::ErrorKind::NotFound => (),
                            Err(err) => return Err(err),
                        };
                        dataf.seek(std::io::SeekFrom::Start(0))?;
                        let mut outf = std::fs::File::create(&full_path)?;
                        std::io::copy(dataf, &mut outf)?;
                        outf.sync_all()?;
                        full_path.pop();
                        fsutil::sync_dir(&full_path)?;
                    }
                    WriteTxnOp::Append(data) => {
                        let mut f = std::fs::OpenOptions::new().append(true).open(&full_path)?;
                        f.write_all(&data)?;
                        f.sync_all()?;
                        full_path.pop();
                        fsutil::sync_dir(&full_path)?;
                    }
                };
            }

            std::fs::remove_file(rollback_journal_path)?;
        }
        Ok(())
    }

    pub fn read(&mut self, p: &str) -> Result<Vec<u8>, std::io::Error> {
        let mut full_path = self.dir.clone();
        full_path.push(p);
        std::fs::read(&full_path)
    }

    pub fn read_opt(&mut self, p: &str) -> Result<Option<Vec<u8>>, std::io::Error> {
        let mut full_path = self.dir.clone();
        full_path.push(p);
        match std::fs::read(&full_path) {
            Ok(v) => Ok(Some(v)),
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
        let mut full_path = self.dir.clone();
        full_path.push(p);
        std::fs::File::open(&full_path)
    }

    pub fn metadata(&self, p: &str) -> Result<std::fs::Metadata, std::io::Error> {
        let mut full_path = self.dir.clone();
        full_path.push(p);
        std::fs::metadata(&full_path)
    }

    pub fn read_dir(&self, p: &str) -> Result<std::fs::ReadDir, std::io::Error> {
        let mut full_path = self.dir.clone();
        full_path.push(p);
        std::fs::read_dir(&full_path)
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
        let p: PathBuf = p.into();
        match self.changes.get_mut(&p) {
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
                self.changes.insert(p, WriteTxnOp::Append(data));
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

        p.push("tx.lock");
        std::fs::File::create(&p).unwrap();
        p.pop();

        p.push("rollback.journal");
        let mut rj = RollbackJournalWriter::create(&p).unwrap();
        p.pop();

        let rb_ent = RollbackOp::WriteFile((PathBuf::from("foobar.txt"), serde_bare::Uint(1)));
        rj.write(&serde_bare::to_vec(&rb_ent).unwrap()).unwrap();
        rj.write(&[255]).unwrap();
        rj.finish().unwrap();

        ReadTxn::begin(d.path()).unwrap().end();
        p.push("foobar.txt");
        assert!(p.exists());
    }

    #[test]
    fn test_remove_file_rollback() {
        let d = tempfile::tempdir().unwrap();
        let mut p = d.path().to_owned();

        p.push("tx.lock");
        std::fs::File::create(&p).unwrap();
        p.pop();

        p.push("rollback.journal");
        let mut rj = RollbackJournalWriter::create(&p).unwrap();
        p.pop();

        p.push("foobar.txt");
        std::fs::write(&p, &vec![]).unwrap();

        let rb_ent = RollbackOp::RemoveFile(PathBuf::from("foobar.txt"));
        rj.write(&serde_bare::to_vec(&rb_ent).unwrap()).unwrap();
        rj.finish().unwrap();
        ReadTxn::begin(d.path()).unwrap().end();
        assert!(!p.exists());
    }

    #[test]
    fn test_truncate_file_rollback() {
        let d = tempfile::tempdir().unwrap();
        let mut p = d.path().to_owned();

        p.push("tx.lock");
        std::fs::File::create(&p).unwrap();
        p.pop();

        p.push("rollback.journal");
        let mut rj = RollbackJournalWriter::create(&p).unwrap();
        p.pop();

        p.push("foobar.txt");
        std::fs::write(&p, &vec![0]).unwrap();

        let rb_ent = RollbackOp::TruncateFile((PathBuf::from("foobar.txt"), serde_bare::Uint(0)));
        rj.write(&serde_bare::to_vec(&rb_ent).unwrap()).unwrap();
        rj.finish().unwrap();
        ReadTxn::begin(d.path()).unwrap().end();
        assert!(p.metadata().unwrap().size() == 0);
    }

    #[test]
    fn test_write_txn() {
        let d = tempfile::tempdir().unwrap();
        let mut p = d.path().to_owned();

        p.push("tx.lock");
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
