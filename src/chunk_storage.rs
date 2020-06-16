use super::address::*;
use super::fsutil;
use super::htree;
use super::repository;

use futures::future::Future;
use futures::stream::Stream;
use rusoto_s3::{S3Client, S3};
use std::path::PathBuf;

pub trait Engine {
    // Get a chunk from the storage engine using the worker pool.
    fn get_chunk_async(
        &mut self,
        addr: &Address,
    ) -> crossbeam::channel::Receiver<Result<Vec<u8>, failure::Error>>;

    // Get a chunk from the storage engine.
    fn get_chunk(&mut self, addr: &Address) -> Result<Vec<u8>, failure::Error> {
        self.get_chunk_async(addr).recv()?
    }

    // Call should_keep on each item in chunk storage.
    // if it returns false, delete the data associated with the address.
    // Returns the number of chunks removed.
    fn gc(
        &mut self,
        should_keep: &dyn Fn(&Address) -> bool,
    ) -> Result<repository::GCStats, failure::Error>;

    // Add a chunk, potentially asynchronously. Does not overwrite existing
    // chunks with the same name to protect historic items from corruption.
    // The write is not guaranteed to be completed until
    // after a call to Engine::sync completes without error.
    fn add_chunk(&mut self, addr: &Address, buf: Vec<u8>) -> Result<(), failure::Error>;

    // A write barrier, any previously added chunks are only guaranteed to be
    // in stable storage after a call to sync has returned. A backend
    // can use this to implement concurrent background writes.
    fn sync(&mut self) -> Result<(), failure::Error>;
}

impl htree::Sink for Box<dyn Engine> {
    fn add_chunk(&mut self, addr: &Address, buf: Vec<u8>) -> Result<(), failure::Error> {
        self.as_mut().add_chunk(addr, buf)
    }
}

impl htree::Source for Box<dyn Engine> {
    fn get_chunk(&mut self, addr: &Address) -> Result<Vec<u8>, failure::Error> {
        self.as_mut().get_chunk(addr)
    }
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
    rendezvous: crossbeam::channel::Receiver<Option<failure::Error>>,
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
                    let mut write_err: Option<failure::Error> = None;
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
                                if let Err(err) = result {
                                    if write_err.is_none() {
                                        write_err = Some(err.into());
                                    }
                                }
                            }
                            Ok(WorkerMsg::Barrier) => {
                                let mut err = None;
                                std::mem::swap(&mut write_err, &mut err);
                                worker_ack_barrier.send(err).unwrap();
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
    fn add_chunk(&mut self, addr: &Address, buf: Vec<u8>) -> Result<(), failure::Error> {
        self.dispatch
            .send(WorkerMsg::AddChunk((*addr, buf)))
            .unwrap();
        Ok(())
    }

    fn gc(
        &mut self,
        should_keep: &dyn Fn(&Address) -> bool,
    ) -> Result<repository::GCStats, failure::Error> {
        let mut stats = repository::GCStats {
            chunks_remaining: 0,
            chunks_freed: 0,
            bytes_freed: 0,
            bytes_remaining: 0,
        };
        for e in std::fs::read_dir(&self.data_dir)? {
            let e = e?;
            match Address::from_hex_str(&e.file_name().to_string_lossy()) {
                Ok(addr) => {
                    if !should_keep(&addr) {
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

        // Sync regardless
        fsutil::sync_dir(&self.data_dir)?;

        if let Some(err) = write_error {
            return Err(err);
        }
        Ok(())
    }
}

pub struct S3Storage {
    endpoint: String,
    bucket: String,
    prefix: String,
    worker_handles: Vec<std::thread::JoinHandle<()>>,
    dispatch: crossbeam::channel::Sender<WorkerMsg>,
    rendezvous: crossbeam::channel::Receiver<Option<failure::Error>>,
}

impl Drop for S3Storage {
    fn drop(&mut self) {
        for _i in 0..self.worker_handles.len() {
            self.dispatch.send(WorkerMsg::Exit).unwrap();
        }
        for h in self.worker_handles.drain(..) {
            h.join().unwrap();
        }
    }
}

impl S3Storage {
    fn new_client(endpoint: String) -> S3Client {
        S3Client::new(rusoto_core::Region::Custom {
            name: "".to_string(),
            endpoint: endpoint.to_string(),
        })
    }

    fn get_object(
        client: &mut S3Client,
        bucket: String,
        key: String,
    ) -> Result<Vec<u8>, failure::Error> {
        let resp = client
            .get_object(rusoto_s3::GetObjectRequest {
                bucket: bucket.clone(),
                key,
                ..Default::default()
            })
            .sync()?;

        match resp.body {
            Some(body) => Ok(body.concat2().wait()?.to_vec()),
            None => failure::bail!("object body missing in storage reply"),
        }
    }

    pub fn new(endpoint: &str, bucket: &str, prefix: &str, mut nworkers: usize) -> Self {
        if nworkers == 0 {
            nworkers = 1
        }
        let mut worker_handles = Vec::new();

        let (dispatch, rx) = crossbeam::channel::bounded(0);
        let (ack_barrier, rendezvous) = crossbeam::channel::bounded(0);

        for _i in 0..nworkers {
            // Quite a small stack for these workers.
            let builder = std::thread::Builder::new().stack_size(256 * 1024);
            let endpoint = endpoint.to_owned();
            let bucket = bucket.to_owned();
            let prefix = prefix.to_owned();

            let worker_rx = rx.clone();
            let worker_ack_barrier = ack_barrier.clone();

            let worker = builder
                .spawn(move || {
                    let mut client = S3Storage::new_client(endpoint);
                    let mut write_err: Option<failure::Error> = None;
                    loop {
                        match worker_rx.recv() {
                            Ok(WorkerMsg::GetChunk((addr, tx))) => {
                                match S3Storage::get_object(
                                    &mut client,
                                    bucket.clone(),
                                    format!("{}{}", prefix, addr.as_hex_addr().as_str()),
                                ) {
                                    Ok(data) => {
                                        let _ = tx.send(Ok(data));
                                    }
                                    Err(err) => {
                                        let _ = tx.send(Err(err.into()));
                                    }
                                };
                            }
                            Ok(WorkerMsg::AddChunk((addr, buf))) => {
                                let k = format!("{}{}", prefix, addr.as_hex_addr().as_str());
                                match client
                                    .head_object(rusoto_s3::HeadObjectRequest {
                                        key: k.clone(),
                                        bucket: bucket.to_owned(),
                                        ..Default::default()
                                    })
                                    .sync()
                                {
                                    Ok(_) => continue,
                                    Err(rusoto_core::RusotoError::Service(
                                        rusoto_s3::HeadObjectError::NoSuchKey(_),
                                    )) => (),
                                    Err(err) => {
                                        if write_err.is_none() {
                                            write_err = Some(err.into());
                                        }
                                        continue;
                                    }
                                }

                                let result = client
                                    .put_object(rusoto_s3::PutObjectRequest {
                                        key: k,
                                        bucket: bucket.to_owned(),
                                        body: Some(buf.into()),
                                        ..Default::default()
                                    })
                                    .sync();
                                match result {
                                    Ok(_) => (),
                                    Err(err) => {
                                        if write_err.is_none() {
                                            write_err = Some(err.into());
                                        }
                                    }
                                }
                            }
                            Ok(WorkerMsg::Barrier) => {
                                let mut err = None;
                                std::mem::swap(&mut write_err, &mut err);
                                worker_ack_barrier.send(err).unwrap();
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

        S3Storage {
            endpoint: endpoint.to_string(),
            bucket: bucket.to_string(),
            prefix: prefix.to_string(),
            worker_handles,
            dispatch,
            rendezvous,
        }
    }
}

impl Engine for S3Storage {
    fn add_chunk(&mut self, addr: &Address, buf: Vec<u8>) -> Result<(), failure::Error> {
        self.dispatch
            .send(WorkerMsg::AddChunk((*addr, buf)))
            .unwrap();
        Ok(())
    }

    fn gc(
        &mut self,
        should_keep: &dyn Fn(&Address) -> bool,
    ) -> Result<repository::GCStats, failure::Error> {
        let mut stats = repository::GCStats {
            chunks_freed: 0,
            chunks_remaining: 0,
            bytes_freed: 0,
            bytes_remaining: 0,
        };
        let client = S3Storage::new_client(self.endpoint.clone());

        let mut req = rusoto_s3::ListObjectsV2Request {
            bucket: self.bucket.clone(),
            prefix: Some(self.prefix.clone()),
            ..Default::default()
        };

        let mut to_delete = Vec::new();

        // Gather objects to delete first, we do this
        // so we don't have to worry about the underlying
        // s3 implementations delete+iteration guarantees.
        loop {
            let resp = client.list_objects_v2(req.clone()).sync()?;
            if let Some(contents) = resp.contents {
                for o in contents {
                    match o.key {
                        Some(key) => {
                            if let Ok(addr) = Address::from_hex_str(&key[self.prefix.len()..]) {
                                if !should_keep(&addr) {
                                    to_delete.push(addr);
                                    stats.chunks_freed += 1;
                                    stats.bytes_freed += o.size.unwrap_or(0) as usize;
                                } else {
                                    stats.chunks_remaining += 1;
                                    stats.bytes_remaining += o.size.unwrap_or(0) as usize;
                                }
                            }
                        }
                        None => (),
                    }
                }
            }

            match resp.next_continuation_token {
                Some(next_continuation_token) => {
                    req = rusoto_s3::ListObjectsV2Request {
                        continuation_token: Some(next_continuation_token),
                        ..Default::default()
                    }
                }
                None => break,
            }
        }

        for addresses in to_delete.chunks(512) {
            let mut objects: Vec<rusoto_s3::ObjectIdentifier> = Vec::with_capacity(addresses.len());
            for address in addresses {
                let address = address.as_hex_addr();
                let key = format!("{}{}", &self.prefix, address.as_str());
                objects.push(rusoto_s3::ObjectIdentifier {
                    key,
                    ..Default::default()
                });
            }
            let req = client.delete_objects(rusoto_s3::DeleteObjectsRequest {
                bucket: self.bucket.to_string(),
                delete: rusoto_s3::Delete {
                    objects,
                    ..Default::default()
                },
                ..Default::default()
            });

            req.sync()?;
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

        if let Some(err) = write_error {
            return Err(err);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_storage_add_get_chunk() {
        let tmp_dir = tempdir::TempDir::new("test_dir").unwrap();
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
