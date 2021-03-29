use super::abloom;
use super::address::Address;
use super::chunk_storage::Engine;
use super::crypto;
use super::fsutil;
use super::hex;
use super::protocol;
use super::repository;
use super::xid;

use std::collections::VecDeque;
use std::convert::TryInto;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

const MAX_READ_WORKERS: usize = 16;
const MAX_WRITE_WORKERS: usize = 16;

enum ReadWorkerMsg {
    GetChunk(
        (
            Address,
            crossbeam_channel::Sender<Result<Vec<u8>, anyhow::Error>>,
        ),
    ),
    Exit,
}

enum WriteWorkerMsg {
    AddChunk((Address, Vec<u8>)),
    Barrier(crossbeam_channel::Sender<Result<protocol::SyncStats, anyhow::Error>>),
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
    write_round_robin_index: usize,

    // Garbage collection
    gc_exclusive_lock: Option<fsutil::FileLock>,
}

impl DirStorage {
    fn add_write_worker_thread(&mut self) {
        let mut data_path = self.dir_path.clone();
        let had_io_error = self.had_io_error.clone();
        let (write_worker_tx, write_worker_rx) = crossbeam_channel::bounded(0);

        macro_rules! worker_bail {
            ($err:expr) => {{
                had_io_error.store(true, Ordering::SeqCst);
                let mut write_err: anyhow::Error = $err.into();
                loop {
                    match write_worker_rx.recv() {
                        Ok(WriteWorkerMsg::AddChunk(_)) => (),
                        Ok(WriteWorkerMsg::Barrier(rendezvous_tx)) => {
                            let _ = rendezvous_tx.send(Err(write_err));
                        }
                        Ok(WriteWorkerMsg::Exit) | Err(_) => {
                            return;
                        }
                    }
                    write_err = anyhow::format_err!("io error");
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

                let mut added_chunks: u64 = 0;
                let mut added_bytes: u64 = 0;

                loop {
                    match write_worker_rx.recv() {
                        Ok(WriteWorkerMsg::AddChunk((addr, data))) => {
                            data_path.push(addr.as_hex_addr().as_str());
                            let dest = data_path.clone();
                            data_path.pop();

                            if dest.exists() {
                                continue;
                            }

                            added_chunks += 1;
                            added_bytes += data.len() as u64;

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
                            worker_try!(tmp_file.sync_data());
                            worker_try!(std::fs::rename(tmp, dest));
                        }
                        Ok(WriteWorkerMsg::Barrier(rendezvous_tx)) => match dir_handle.sync_all() {
                            Ok(()) => {
                                let _ = rendezvous_tx.send(Ok(protocol::SyncStats {
                                    added_chunks,
                                    added_bytes,
                                }));
                                added_chunks = 0;
                                added_bytes = 0;
                            }
                            Err(err) => {
                                let _ = rendezvous_tx.send(Err(err.into()));
                                worker_bail!(anyhow::format_err!("io error"));
                            }
                        },
                        Ok(WriteWorkerMsg::Exit) | Err(_) => {
                            return;
                        }
                    }
                }
            })
            .unwrap();

        self.write_worker_handles.push(worker);
        self.write_worker_tx.push(write_worker_tx);
    }

    fn add_read_worker_thread(&mut self) {
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

    fn scaling_read_worker_dispatch(&mut self, msg: ReadWorkerMsg) -> Result<(), anyhow::Error> {
        if self.read_worker_handles.len() < MAX_READ_WORKERS {
            match self.read_worker_tx.try_send(msg) {
                Ok(_) => Ok(()),
                Err(crossbeam_channel::TrySendError::Full(msg)) => {
                    self.add_read_worker_thread();
                    Ok(self.read_worker_tx.send(msg)?)
                }
                Err(err) => Err(err.into()),
            }
        } else {
            Ok(self.read_worker_tx.send(msg)?)
        }
    }

    fn sync_write_workers(&mut self) -> Result<protocol::SyncStats, anyhow::Error> {
        let mut aggregate_stats = protocol::SyncStats {
            added_bytes: 0,
            added_chunks: 0,
        };

        let mut rendezvous = Vec::with_capacity(self.write_worker_handles.len());

        debug_assert!(self.write_worker_handles.len() == self.write_worker_tx.len());
        for i in 0..self.write_worker_handles.len() {
            let (rendezvous_tx, rendezvous_rx) = crossbeam_channel::bounded(0);
            rendezvous.push(rendezvous_rx);
            self.write_worker_tx[i]
                .send(WriteWorkerMsg::Barrier(rendezvous_tx))
                .unwrap();
        }

        let mut aggregate_err: Option<anyhow::Error> = None;
        for c in rendezvous.iter() {
            match c.recv().unwrap() {
                Ok(stats) => {
                    aggregate_stats.added_bytes += stats.added_bytes;
                    aggregate_stats.added_chunks += stats.added_chunks;
                }
                Err(err) => {
                    if aggregate_err.is_none() {
                        aggregate_err = Some(err)
                    }
                }
            }
        }

        match aggregate_err {
            None => Ok(aggregate_stats),
            Some(err) => Err(err),
        }
    }

    fn check_write_worker_io_errors(&mut self) -> Result<(), anyhow::Error> {
        if self.had_io_error.load(Ordering::SeqCst) {
            match self.sync_write_workers() {
                Ok(_) => Err(anyhow::format_err!("io error")),
                Err(err) => Err(err),
            }
        } else {
            Ok(())
        }
    }

    fn lock_file_path(&self) -> PathBuf {
        let mut p = self.dir_path.clone();
        p.pop();
        p.push("repo.lock");
        p
    }

    pub fn new(dir_path: &std::path::Path) -> Result<Self, anyhow::Error> {
        match std::fs::DirBuilder::new().create(dir_path) {
            Ok(_) => (),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => (),
            Err(err) => return Err(err.into()),
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
            write_round_robin_index: 0,
            gc_exclusive_lock: None,
        })
    }
}

impl Drop for DirStorage {
    fn drop(&mut self) {
        self.stop_workers();
    }
}

impl Engine for DirStorage {
    fn pipelined_get_chunks(
        &mut self,
        addresses: &[Address],
        on_chunk: &mut dyn FnMut(&Address, &[u8]) -> Result<(), anyhow::Error>,
    ) -> Result<(), anyhow::Error> {
        let mut pipeline_get_queue = VecDeque::new();

        for addr in addresses.iter() {
            let (tx, rx) = crossbeam_channel::bounded(1);
            self.scaling_read_worker_dispatch(ReadWorkerMsg::GetChunk((*addr, tx)))?;
            pipeline_get_queue.push_back((addr, rx));

            if pipeline_get_queue.len() >= MAX_READ_WORKERS {
                let (addr, rx) = pipeline_get_queue.pop_front().unwrap();
                let data = rx.recv()??;
                on_chunk(&addr, &data)?;
            }
        }

        while !pipeline_get_queue.is_empty() {
            let (addr, rx) = pipeline_get_queue.pop_front().unwrap();
            let data = rx.recv()??;
            on_chunk(&addr, &data)?;
        }

        Ok(())
    }

    fn get_chunk(&mut self, addr: &Address) -> Result<Vec<u8>, anyhow::Error> {
        self.dir_path.push(addr.as_hex_addr().as_str());
        let result = std::fs::read(self.dir_path.as_path());
        self.dir_path.pop();
        Ok(result?)
    }

    fn add_chunk(&mut self, addr: &Address, buf: Vec<u8>) -> Result<(), anyhow::Error> {
        // Lazily start our write threads.
        while self.write_worker_handles.len() < self.write_round_robin_index + 1 {
            self.add_write_worker_thread();
        }

        self.check_write_worker_io_errors()?;

        self.write_worker_tx[self.write_round_robin_index]
            .send(WriteWorkerMsg::AddChunk((*addr, buf)))?;

        self.write_round_robin_index += 1;
        if self.write_round_robin_index >= MAX_WRITE_WORKERS {
            self.write_round_robin_index = 0;
        }

        Ok(())
    }

    fn sync(&mut self) -> Result<protocol::SyncStats, anyhow::Error> {
        self.sync_write_workers()
    }

    fn prepare_for_gc(&mut self, _gc_id: xid::Xid) -> Result<(), anyhow::Error> {
        self.gc_exclusive_lock = None; // Explicitly free and drop lock.

        match fsutil::FileLock::try_get_exclusive(&self.lock_file_path()) {
            Ok(l) => {
                self.gc_exclusive_lock = Some(l);
                Ok(())
            }
            Err(err) if err.raw_os_error() == Some(libc::EWOULDBLOCK) => Err(anyhow::format_err!(
                "garbage collection already in progress"
            )),
            Err(err) => Err(err.into()),
        }
    }

    fn estimate_chunk_count(&mut self) -> Result<u64, anyhow::Error> {
        Ok(std::fs::read_dir(&self.dir_path)?.count().try_into()?)
    }

    fn gc(&mut self, reachable: abloom::ABloom) -> Result<repository::GcStats, anyhow::Error> {
        self.stop_workers();

        assert!(self.gc_exclusive_lock.is_some());

        // Collect removals into memory first so we don't have to
        // worry about fs semantics when removing while iterating.
        let mut to_remove = Vec::new();

        let mut chunks_remaining: u64 = 0;
        let mut chunks_deleted: u64 = 0;
        let mut bytes_deleted: u64 = 0;
        let mut bytes_remaining: u64 = 0;

        for e in std::fs::read_dir(&self.dir_path)? {
            let e = e?;
            match Address::from_hex_str(&e.file_name().to_string_lossy()) {
                Ok(addr) => {
                    if reachable.probably_has(&addr) {
                        if let Ok(md) = e.metadata() {
                            bytes_remaining += md.len() as u64
                        }
                        chunks_remaining += 1
                    } else {
                        if let Ok(md) = e.metadata() {
                            bytes_deleted += md.len() as u64
                        }
                        to_remove.push(e.path());
                        chunks_deleted += 1;
                    }
                }
                Err(_) => {
                    // This is not a chunk, so don't count it.
                    to_remove.push(e.path());
                }
            }
        }

        for p in to_remove.iter() {
            std::fs::remove_file(p)?;
        }

        self.gc_exclusive_lock = None;

        Ok(repository::GcStats {
            chunks_remaining: Some(chunks_remaining),
            chunks_deleted: Some(chunks_deleted),
            bytes_deleted: Some(bytes_deleted),
            bytes_remaining: Some(bytes_remaining),
        })
    }

    fn gc_completed(&mut self, _gc_id: xid::Xid) -> Result<bool, anyhow::Error> {
        match fsutil::FileLock::try_get_exclusive(&self.lock_file_path()) {
            Ok(_) => Ok(true),
            Err(err) if err.raw_os_error() == Some(libc::EWOULDBLOCK) => Ok(false),
            Err(err) => Err(err.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_and_get_chunk() {
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
    }

    #[test]
    fn pipelined_get_chunks() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let mut path_buf = PathBuf::from(tmp_dir.path());
        path_buf.push("data");
        let mut storage = DirStorage::new(&path_buf).unwrap();

        let addr = Address::default();
        storage.add_chunk(&addr, vec![1]).unwrap();
        storage.sync().unwrap();

        let mut result = Vec::new();

        let mut on_chunk = |fetched_addr: &Address, data: &[u8]| {
            assert_eq!(addr, *fetched_addr);
            result.extend_from_slice(data);
            Ok(())
        };

        storage
            .pipelined_get_chunks(&vec![addr, addr, addr, addr], &mut on_chunk)
            .unwrap();

        assert_eq!(result, vec![1, 1, 1, 1]);
    }
}
