use super::address::Address;
use super::chunk_storage::Engine;
use super::crypto;
use super::hex;
use super::repository;

use std::convert::TryInto;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

const RENAME_BATCH_SIZE: u64 = 256;

enum ReadWorkerMsg {
    GetChunk(
        (
            Address,
            crossbeam_channel::Sender<Result<Vec<u8>, failure::Error>>,
        ),
    ),
    Exit,
}

enum WriteWorkerMsg {
    AddChunk((Address, Vec<u8>)),
    Barrier(crossbeam_channel::Sender<Option<failure::Error>>),
    Exit,
}

// A backend that stores all data in a directory,
// it operates by swapping between two batches of pending
// fsyncs, and round robin writing to each. It supports
// concurrent reading and writing from multiple instances
// of bupstash.
pub struct DirStorage {
    dir_path: PathBuf,

    // Reading
    read_worker_handles: Vec<std::thread::JoinHandle<()>>,
    read_worker_tx: crossbeam_channel::Sender<ReadWorkerMsg>,
    read_worker_rx: crossbeam_channel::Receiver<ReadWorkerMsg>,

    // Writing
    had_io_error: Arc<AtomicBool>,
    write_worker_handles: Vec<std::thread::JoinHandle<()>>,
    write_worker_tx: Vec<crossbeam_channel::Sender<WriteWorkerMsg>>,
    write_chunk_count: u64,
    write_round_robin_index: usize,
}

impl DirStorage {
    fn add_write_worker_thread(&mut self) -> Result<(), failure::Error> {
        let mut data_path = self.dir_path.clone();
        let had_io_error = self.had_io_error.clone();
        let (write_worker_tx, write_worker_rx) = crossbeam_channel::bounded(0);

        let mut pending_batch_rename = Vec::new();

        fn do_batch_rename(
            batch: &mut Vec<(PathBuf, PathBuf, std::fs::File)>,
        ) -> Result<(), std::io::Error> {
            for (_, _, f) in batch.iter() {
                f.sync_data()?;
            }

            for (dest, tmp, _) in batch.drain(..) {
                std::fs::rename(tmp, dest)?;
            }

            Ok(())
        }

        macro_rules! worker_bail {
            ($err:expr) => {{
                had_io_error.store(true, Ordering::SeqCst);
                let mut write_err: failure::Error = $err.into();
                loop {
                    match write_worker_rx.recv() {
                        Ok(WriteWorkerMsg::AddChunk(_)) => (),
                        Ok(WriteWorkerMsg::Barrier(rendezvous_tx)) => {
                            let _ = rendezvous_tx.send(Some(write_err));
                        }
                        Ok(WriteWorkerMsg::Exit) | Err(_) => {
                            return;
                        }
                    }
                    write_err = failure::format_err!("io error");
                }
            }};
        }

        macro_rules! worker_try {
            ($e:expr) => {
                match ($e) {
                    Ok(v) => v,
                    Err(err) => worker_bail!(err),
                }
            };
        }

        let worker = std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(move || {
                // Open dir handle over duration of renames, we want
                // to guarantee when we sync the directory, we get notified
                // of any io errors that happen on that directory.
                let dir_handle = worker_try!(std::fs::File::open(&data_path));

                loop {
                    match write_worker_rx.recv() {
                        Ok(WriteWorkerMsg::AddChunk((addr, data))) => {
                            data_path.push(addr.as_hex_addr().as_str());
                            let dest = data_path.clone();
                            data_path.pop();

                            if dest.exists() {
                                continue;
                            }

                            let random_suffix = {
                                let mut buf = [0; 12];
                                crypto::randombytes(&mut buf[..]);
                                hex::easy_encode_to_string(&buf[..])
                            };

                            let tmp = dest
                                .to_string_lossy()
                                .chars()
                                .chain(".".chars())
                                .chain(random_suffix.chars())
                                .chain(".tmp".chars())
                                .collect::<String>();

                            let mut tmp_file = worker_try!(std::fs::OpenOptions::new()
                                .write(true)
                                .create_new(true)
                                .open(&tmp));

                            worker_try!(tmp_file.write_all(&data));

                            pending_batch_rename.push((dest, tmp.into(), tmp_file));
                            if pending_batch_rename.len() >= RENAME_BATCH_SIZE.try_into().unwrap() {
                                worker_try!(do_batch_rename(&mut pending_batch_rename))
                            }
                        }
                        Ok(WriteWorkerMsg::Barrier(rendezvous_tx)) => {
                            match do_batch_rename(&mut pending_batch_rename) {
                                Ok(()) => match dir_handle.sync_all() {
                                    Ok(()) => {
                                        let _ = rendezvous_tx.send(None);
                                    }
                                    Err(err) => {
                                        let _ = rendezvous_tx.send(Some(err.into()));
                                        worker_bail!(failure::format_err!("io error"));
                                    }
                                },
                                Err(err) => {
                                    let _ = rendezvous_tx.send(Some(err.into()));
                                    worker_bail!(failure::format_err!("io error"));
                                }
                            };
                        }
                        Ok(WriteWorkerMsg::Exit) | Err(_) => {
                            return;
                        }
                    }
                }
            })
            .unwrap();

        self.write_worker_handles.push(worker);
        self.write_worker_tx.push(write_worker_tx);
        Ok(())
    }

    fn add_read_worker_thread(&mut self) -> Result<(), failure::Error> {
        let mut data_path = self.dir_path.clone();
        let read_worker_rx = self.read_worker_rx.clone();

        let worker = std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(move || loop {
                match read_worker_rx.recv() {
                    Ok(ReadWorkerMsg::GetChunk((addr, result_tx))) => {
                        data_path.push(addr.as_hex_addr().as_str());
                        let result = std::fs::read(data_path.as_path());
                        data_path.pop();
                        let result = match result {
                            Ok(data) => Ok(data),
                            Err(err) => Err(err.into()),
                        };
                        let _ = result_tx.send(result);
                    }
                    Ok(ReadWorkerMsg::Exit) | Err(_) => {
                        return;
                    }
                }
            })
            .unwrap();
        self.read_worker_handles.push(worker);
        Ok(())
    }

    fn stop_workers(&mut self) {
        for _i in 0..self.read_worker_handles.len() {
            self.read_worker_tx.send(ReadWorkerMsg::Exit).unwrap();
        }
        debug_assert!(self.write_worker_handles.len() == self.write_worker_tx.len());
        for i in 0..self.write_worker_handles.len() {
            self.write_worker_tx[i].send(WriteWorkerMsg::Exit).unwrap();
        }
        for h in self.read_worker_handles.drain(..) {
            h.join().unwrap();
        }
        for h in self.write_worker_handles.drain(..) {
            h.join().unwrap();
        }
        self.write_worker_tx.clear();
    }

    fn scaling_read_worker_dispatch(&mut self, msg: ReadWorkerMsg) -> Result<(), failure::Error> {
        // Should this be configurable?
        const MAX_READ_WORKERS: usize = 10;

        if self.read_worker_handles.len() < MAX_READ_WORKERS {
            match self.read_worker_tx.try_send(msg) {
                Ok(_) => Ok(()),
                Err(crossbeam_channel::TrySendError::Full(msg)) => {
                    self.add_read_worker_thread()?;
                    Ok(self.read_worker_tx.send(msg)?)
                }
                Err(err) => Err(err.into()),
            }
        } else {
            Ok(self.read_worker_tx.send(msg)?)
        }
    }

    fn sync_write_workers(&mut self) -> Result<(), failure::Error> {
        let mut rendezvous = Vec::with_capacity(self.write_worker_handles.len());

        debug_assert!(self.write_worker_handles.len() == self.write_worker_tx.len());
        for i in 0..self.write_worker_handles.len() {
            let (rendezvous_tx, rendezvous_rx) = crossbeam_channel::bounded(0);
            rendezvous.push(rendezvous_rx);
            self.write_worker_tx[i]
                .send(WriteWorkerMsg::Barrier(rendezvous_tx))
                .unwrap();
        }

        let mut result: Result<(), failure::Error> = Ok(());
        for c in rendezvous.iter() {
            if let Some(err) = c.recv().unwrap() {
                if result.is_ok() {
                    result = Err(err)
                }
            }
        }
        result
    }

    fn check_write_worker_io_errors(&mut self) -> Result<(), failure::Error> {
        if self.had_io_error.load(Ordering::SeqCst) {
            match self.sync_write_workers() {
                Ok(()) => Err(failure::format_err!("io error")),
                Err(err) => Err(err),
            }
        } else {
            Ok(())
        }
    }

    pub fn new(dir_path: &std::path::Path) -> Result<Self, failure::Error> {
        if !dir_path.exists() {
            std::fs::DirBuilder::new().create(dir_path)?;
        }

        let read_worker_handles = Vec::new();
        let write_worker_handles = Vec::new();
        let write_worker_tx = Vec::new();
        let had_io_error = Arc::new(AtomicBool::new(false));
        let (read_worker_tx, read_worker_rx) = crossbeam_channel::bounded(0);

        Ok(DirStorage {
            dir_path: dir_path.to_owned(),
            read_worker_handles,
            read_worker_tx,
            read_worker_rx,
            had_io_error,
            write_worker_handles,
            write_worker_tx,
            write_chunk_count: 0,
            write_round_robin_index: 0,
        })
    }
}

impl Drop for DirStorage {
    fn drop(&mut self) {
        self.stop_workers();
    }
}

impl Engine for DirStorage {
    fn add_chunk(&mut self, addr: &Address, buf: Vec<u8>) -> Result<(), failure::Error> {
        // Lazily start our write threads.
        while self.write_worker_handles.len() < 2 {
            self.add_write_worker_thread()?;
        }

        self.check_write_worker_io_errors()?;

        self.write_worker_tx[self.write_round_robin_index]
            .send(WriteWorkerMsg::AddChunk((*addr, buf)))?;

        self.write_chunk_count += 1;

        if self.write_chunk_count >= RENAME_BATCH_SIZE {
            self.write_chunk_count = 0;
            self.write_round_robin_index += 1;
            if self.write_round_robin_index >= 2 {
                self.write_round_robin_index = 0;
            }
        }

        Ok(())
    }

    fn get_chunk_async(
        &mut self,
        addr: &Address,
    ) -> crossbeam_channel::Receiver<Result<Vec<u8>, failure::Error>> {
        let (tx, rx) = crossbeam_channel::bounded(1);
        match self.scaling_read_worker_dispatch(ReadWorkerMsg::GetChunk((*addr, tx))) {
            Ok(()) => rx,
            Err(err) => {
                let (tx, rx) = crossbeam_channel::bounded(1);
                tx.send(Err(err)).unwrap();
                rx
            }
        }
    }

    fn sync(&mut self) -> Result<(), failure::Error> {
        self.sync_write_workers()
    }

    fn gc(
        &mut self,
        _reachability_db_path: &std::path::Path,
        reachability_db: &mut rusqlite::Connection,
    ) -> Result<repository::GCStats, failure::Error> {
        self.stop_workers();

        let reachability_tx = reachability_db.transaction()?;
        let mut check_reachability_stmt =
            reachability_tx.prepare_cached("select 1 from reachability where Address = ?;")?;

        let mut entries = Vec::new();
        // Collect entries into memory first so we don't have to
        // worry about fs semantics of removing while iterating.
        for e in std::fs::read_dir(&self.dir_path)? {
            entries.push(e?);
        }

        let mut bytes_freed = 0;
        let mut chunks_remaining = 0;
        let mut chunks_freed = 0;
        let mut bytes_remaining = 0;

        for e in entries {
            match Address::from_hex_str(&e.file_name().to_string_lossy()) {
                Ok(addr) => {
                    let reachable = match check_reachability_stmt
                        .query_row(rusqlite::params![&addr.bytes[..]], |_| Ok(()))
                    {
                        Ok(_) => true,
                        Err(rusqlite::Error::QueryReturnedNoRows) => false,
                        Err(err) => return Err(err.into()),
                    };

                    if !reachable {
                        if let Ok(md) = e.metadata() {
                            bytes_freed += md.len() as usize
                        }
                        std::fs::remove_file(e.path())?;
                        chunks_freed += 1;
                    } else {
                        if let Ok(md) = e.metadata() {
                            bytes_remaining += md.len() as usize
                        }
                        chunks_remaining += 1;
                    }
                }
                Err(_) => {
                    // This is not a chunk, so don't count it.
                    std::fs::remove_file(e.path())?;
                }
            }
        }
        Ok(repository::GCStats {
            chunks_remaining: Some(chunks_remaining),
            chunks_freed: Some(chunks_freed),
            bytes_freed: Some(bytes_freed),
            bytes_remaining: Some(bytes_remaining),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_get_chunk() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let mut path_buf = PathBuf::from(tmp_dir.path());
        path_buf.push("data");
        let mut storage = DirStorage::new(&path_buf).unwrap();
        let addr = Address::default();
        storage.add_chunk(&addr, vec![1]).unwrap();
        storage.sync().unwrap();
        storage.add_chunk(&addr, vec![2]).unwrap();
        storage.sync().unwrap();
        let v = storage.get_chunk(&addr).unwrap();
        assert_eq!(v, vec![1]);
        let v = storage.get_chunk_async(&addr).recv().unwrap().unwrap();
        assert_eq!(v, vec![1]);
    }
}
