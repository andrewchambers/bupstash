use super::address::Address;
use super::chunk_storage::Engine;
use super::fsutil;
use super::repository;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

enum WorkerMsg {
    AddChunk((Address, Vec<u8>)),
    GetChunk(
        (
            Address,
            crossbeam::channel::Sender<Result<Vec<u8>, failure::Error>>,
        ),
    ),
    Barrier,
    Exit,
}

pub struct LocalStorage {
    had_io_error: Arc<AtomicBool>,
    data_dir: PathBuf,
    worker_handles: Vec<std::thread::JoinHandle<()>>,
    dispatch: crossbeam::channel::Sender<WorkerMsg>,
    rendezvous: crossbeam::channel::Receiver<Option<failure::Error>>,
}

impl Drop for LocalStorage {
    fn drop(&mut self) {
        for _i in 0..self.worker_handles.len() {
            let _ = self.dispatch.send(WorkerMsg::Exit);
        }
        for h in self.worker_handles.drain(..) {
            let _ = h.join();
        }
    }
}

impl LocalStorage {
    pub fn new(path: &std::path::Path, mut nworkers: usize) -> Self {
        if nworkers == 0 {
            nworkers = 1
        }

        let mut worker_handles = Vec::new();
        let had_io_error = Arc::new(AtomicBool::new(false));
        let (dispatch, rx) = crossbeam::channel::bounded(0);
        let (ack_barrier, rendezvous) = crossbeam::channel::bounded(0);

        for _i in 0..nworkers {
            // Quite a small stack for these workers.
            let builder = std::thread::Builder::new().stack_size(256 * 1024);
            let mut data_dir = path.to_path_buf();
            let had_io_error = had_io_error.clone();
            let rx = rx.clone();
            let ack_barrier = ack_barrier.clone();

            let worker = builder
                .spawn(move || {
                    let mut write_err: Option<failure::Error> = None;
                    loop {
                        match rx.recv() {
                            Ok(WorkerMsg::GetChunk((addr, tx))) => {
                                data_dir.push(addr.as_hex_addr().as_str());
                                let result = std::fs::read(data_dir.as_path());
                                data_dir.pop();
                                let result = match result {
                                    Ok(data) => Ok(data),
                                    Err(err) => Err(err.into()),
                                };
                                let _ = tx.send(result);
                            }
                            Ok(WorkerMsg::AddChunk((addr, buf))) => {
                                data_dir.push(addr.as_hex_addr().as_str());
                                let result = if !data_dir.exists() {
                                    fsutil::atomic_add_file(data_dir.as_path(), &buf)
                                } else {
                                    Ok(())
                                };
                                data_dir.pop();
                                if let Err(err) = result {
                                    had_io_error.store(true, Ordering::SeqCst);
                                    if write_err.is_none() {
                                        write_err = Some(err.into());
                                    }
                                }
                            }
                            Ok(WorkerMsg::Barrier) => {
                                let mut err = None;
                                std::mem::swap(&mut write_err, &mut err);
                                ack_barrier.send(err).unwrap();
                            }
                            Ok(WorkerMsg::Exit) | Err(_) => {
                                return;
                            }
                        }
                    }
                })
                .unwrap();
            worker_handles.push(worker);
        }

        LocalStorage {
            data_dir: path.to_path_buf(),
            worker_handles,
            dispatch,
            rendezvous,
            had_io_error,
        }
    }

    fn sync_workers(&mut self) -> Result<(), failure::Error> {
        for _i in 0..self.worker_handles.len() {
            self.dispatch.send(WorkerMsg::Barrier).unwrap();
        }
        let mut write_error: Option<failure::Error> = None;
        for _i in 0..self.worker_handles.len() {
            if let Some(err) = self.rendezvous.recv().unwrap() {
                if write_error.is_none() {
                    write_error = Some(err)
                }
            }
        }
        // fsync regardless
        fsutil::sync_dir(&self.data_dir)?;
        if let Some(err) = write_error {
            return Err(err);
        }
        Ok(())
    }

    fn check_worker_io_errors(&mut self) -> Result<(), failure::Error> {
        if self.had_io_error.load(Ordering::SeqCst) {
            match self.sync_workers() {
                Ok(()) => Err(failure::format_err!("io error")),
                Err(err) => Err(err),
            }
        } else {
            Ok(())
        }
    }

    pub fn count_chunks(&self) -> Result<usize, failure::Error> {
        let paths = std::fs::read_dir(self.data_dir.as_path())?;
        Ok(paths
            .filter(|e| {
                if let Ok(d) = e {
                    if let Some(oss) = d.path().extension() {
                        oss != "tmp"
                    } else {
                        true
                    }
                } else {
                    false
                }
            })
            .count())
    }
}

impl Engine for LocalStorage {
    fn add_chunk(&mut self, addr: &Address, buf: Vec<u8>) -> Result<(), failure::Error> {
        // Abort upload early on any io errors.
        self.check_worker_io_errors()?;
        self.dispatch
            .send(WorkerMsg::AddChunk((*addr, buf)))
            .unwrap();
        Ok(())
    }

    fn gc(
        &mut self,
        reachable: std::collections::HashSet<Address>,
    ) -> Result<repository::GCStats, failure::Error> {
        let mut stats = repository::GCStats {
            chunks_remaining: 0,
            chunks_freed: 0,
            bytes_freed: 0,
            bytes_remaining: 0,
        };

        let mut entries = Vec::new();
        // Collect entries into memory first so we don't have to
        // worry about fs semantics of removing while iterating.
        for e in std::fs::read_dir(&self.data_dir)? {
            entries.push(e?);
        }

        for e in entries.drain(..) {
            match Address::from_hex_str(&e.file_name().to_string_lossy()) {
                Ok(addr) => {
                    if !reachable.contains(&addr) {
                        if let Ok(md) = e.metadata() {
                            stats.bytes_freed += md.len() as usize
                        }
                        std::fs::remove_file(e.path())?;
                        stats.chunks_freed += 1;
                    } else {
                        if let Ok(md) = e.metadata() {
                            stats.bytes_remaining += md.len() as usize
                        }
                        stats.chunks_remaining += 1;
                    }
                }
                Err(_) => {
                    // This is not a chunk, so don't count it.
                    std::fs::remove_file(e.path())?;
                }
            }
        }
        Ok(stats)
    }

    fn get_chunk_async(
        &mut self,
        addr: &Address,
    ) -> crossbeam::channel::Receiver<Result<Vec<u8>, failure::Error>> {
        let (tx, rx) = crossbeam::channel::bounded(1);
        self.dispatch
            .send(WorkerMsg::GetChunk((*addr, tx)))
            .unwrap();
        rx
    }

    fn sync(&mut self) -> Result<(), failure::Error> {
        self.sync_workers()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_storage_add_get_chunk() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let path_buf = PathBuf::from(tmp_dir.path());
        let mut local_storage = LocalStorage::new(&path_buf, 5);
        let addr = Address::default();
        local_storage.add_chunk(&addr, vec![1]).unwrap();
        local_storage.sync().unwrap();
        local_storage.add_chunk(&addr, vec![2]).unwrap();
        local_storage.sync().unwrap();
        let v = local_storage.get_chunk(&addr).unwrap();
        assert_eq!(v, vec![1]);
        let v = local_storage
            .get_chunk_async(&addr)
            .recv()
            .unwrap()
            .unwrap();
        assert_eq!(v, vec![1]);
    }
}
