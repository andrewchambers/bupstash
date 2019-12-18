use super::address::*;
use super::fsutil;
use std::path::PathBuf;

pub trait Engine {
    // Get a chunk from the storage engine.
    fn get_chunk(&mut self, addr: Address) -> Result<Vec<u8>, failure::Error>;

    // Get a chunk from the storage engine using the worker pool.
    fn get_chunk_async(
        &mut self,
        addr: Address,
    ) -> crossbeam::channel::Receiver<Result<Vec<u8>, failure::Error>>;

    // Add a chunk, potentially asynchronously. Does not overwrite existing
    // chunks with the same name. The write is not guaranteed to be completed until
    // after a call to Engine::sync completes without error.
    fn add_chunk(&mut self, addr: Address, buf: Vec<u8>) -> Result<(), failure::Error>;

    // A write barrier, any previously added chunks are only guaranteed to be
    // in stable storage after a call to sync has returned. A backend
    // can use this to implement concurrent background writes.
    fn sync(&mut self) -> Result<(), failure::Error>;
}

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
    data_dir: PathBuf,
    worker_handles: Vec<std::thread::JoinHandle<()>>,
    dispatch: crossbeam::channel::Sender<WorkerMsg>,
    rendezvous: crossbeam::channel::Receiver<bool>,
}

impl Drop for LocalStorage {
    fn drop(&mut self) {
        for _i in 0..self.worker_handles.len() {
            self.dispatch.send(WorkerMsg::Exit).unwrap();
        }
        for h in self.worker_handles.drain(..) {
            h.join().unwrap();
        }
    }
}

impl LocalStorage {
    pub fn new(path: &std::path::Path, mut nworkers: usize) -> Self {
        if nworkers == 0 {
            nworkers = 1
        }
        let mut worker_handles = Vec::new();

        let (dispatch, rx) = crossbeam::channel::bounded(0);
        let (ack_barrier, rendezvous) = crossbeam::channel::bounded(0);

        for _i in 0..nworkers {
            // Quite a small stack for these workers.
            let builder = std::thread::Builder::new().stack_size(256 * 1024);
            let mut worker_data_dir = path.to_path_buf();

            let worker_rx = rx.clone();
            let worker_ack_barrier = ack_barrier.clone();

            let worker = builder
                .spawn(move || {
                    // FIXME: TODO: send actual io error.
                    let mut is_ok = true;
                    loop {
                        match worker_rx.recv() {
                            Ok(WorkerMsg::GetChunk((addr, tx))) => {
                                worker_data_dir.push(addr.as_hex_addr().as_str());
                                let result = std::fs::read(worker_data_dir.as_path());
                                worker_data_dir.pop();
                                let result = match result {
                                    Ok(data) => Ok(data),
                                    Err(err) => Err(err.into()),
                                };
                                let _ = tx.send(result);
                            }
                            Ok(WorkerMsg::AddChunk((addr, buf))) => {
                                worker_data_dir.push(addr.as_hex_addr().as_str());
                                let result = if !worker_data_dir.exists() {
                                    fsutil::atomic_add_file(worker_data_dir.as_path(), &buf)
                                } else {
                                    Ok(())
                                };
                                worker_data_dir.pop();
                                match result {
                                    Ok(_) => (),
                                    Err(_) => is_ok = false,
                                }
                            }
                            Ok(WorkerMsg::Barrier) => {
                                worker_ack_barrier.send(is_ok).unwrap();
                            }
                            Ok(WorkerMsg::Exit) => {
                                return;
                            }
                            Err(_) => return,
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
    fn add_chunk(&mut self, addr: Address, buf: Vec<u8>) -> Result<(), failure::Error> {
        self.dispatch
            .send(WorkerMsg::AddChunk((addr, buf)))
            .unwrap();
        Ok(())
    }

    fn get_chunk(&mut self, addr: Address) -> Result<Vec<u8>, failure::Error> {
        self.data_dir.push(addr.as_hex_addr().as_str());
        let p = std::fs::read(self.data_dir.as_path());
        self.data_dir.pop();
        Ok(p?)
    }

    fn get_chunk_async(
        &mut self,
        addr: Address,
    ) -> crossbeam::channel::Receiver<Result<Vec<u8>, failure::Error>> {
        let (tx, rx) = crossbeam::channel::bounded(1);
        self.dispatch.send(WorkerMsg::GetChunk((addr, tx))).unwrap();
        rx
    }

    fn sync(&mut self) -> Result<(), failure::Error> {
        for _i in 0..self.worker_handles.len() {
            self.dispatch.send(WorkerMsg::Barrier).unwrap();
        }
        let mut all_ok = true;
        for _i in 0..self.worker_handles.len() {
            let ok = self.rendezvous.recv().unwrap();
            if !ok {
                all_ok = false;
            }
        }
        if !all_ok {
            // FIXME: real io error.
            return Err(failure::format_err!("io error syncing data"));
        }
        fsutil::sync_dir(&self.data_dir)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_storage_add_get_chunk() {
        let tmp_dir = tempdir::TempDir::new("store_test_repo").unwrap();
        let path_buf = PathBuf::from(tmp_dir.path());
        let mut local_storage = LocalStorage::new(&path_buf, 5);
        let addr = Address::default();
        local_storage.add_chunk(addr, vec![1]).unwrap();
        local_storage.sync().unwrap();
        local_storage.add_chunk(addr, vec![2]).unwrap();
        local_storage.sync().unwrap();
        let v = local_storage.get_chunk(addr).unwrap();
        assert_eq!(v, vec![1]);
        let v = local_storage.get_chunk_async(addr).recv().unwrap().unwrap();
        assert_eq!(v, vec![1]);
    }
}
