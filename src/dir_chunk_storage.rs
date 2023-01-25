use super::abloom;
use super::address::Address;
use super::chunk_storage::Engine;
use super::crypto;
use super::hex;
use super::protocol;
use super::repository;
use super::vfs;
use super::xid;

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

const MAX_READ_WORKERS: usize = 32;
const MAX_WRITE_WORKERS: usize = 32;

enum ReadWorkerMsg {
    GetChunk(
        (
            Address,
            crossbeam_channel::Sender<Result<Vec<u8>, anyhow::Error>>,
        ),
    ),
    FilterExisting(
        (
            Vec<Address>,
            crossbeam_channel::Sender<Result<Vec<Address>, anyhow::Error>>,
        ),
    ),
    Exit,
}

enum WriteWorkerMsg {
    AddChunk((Address, Vec<u8>)),
    Barrier(crossbeam_channel::Sender<Result<protocol::FlushStats, anyhow::Error>>),
    Exit,
}

pub struct DirStorage {
    // An array of VFS directories, one for each chunk dir.
    chunk_dirs: Arc<Vec<vfs::VFs>>,

    // Reading
    read_worker_handles: Vec<std::thread::JoinHandle<()>>,
    read_worker_tx: crossbeam_channel::Sender<ReadWorkerMsg>,
    read_worker_rx: crossbeam_channel::Receiver<ReadWorkerMsg>,

    // Writing
    had_io_error: Arc<AtomicBool>,
    write_worker_handles: Vec<std::thread::JoinHandle<()>>,
    write_worker_tx: Vec<crossbeam_channel::Sender<WriteWorkerMsg>>,
    write_round_robin_index: usize,
}

impl DirStorage {
    fn add_write_worker_thread(&mut self) {
        let chunk_dirs = self.chunk_dirs.clone();
        let had_io_error = self.had_io_error.clone();
        let (write_worker_tx, write_worker_rx) = crossbeam_channel::bounded(0);

        let err_forever = move |rx: crossbeam_channel::Receiver<WriteWorkerMsg>, mut err| {
            had_io_error.store(true, Ordering::SeqCst);
            loop {
                match rx.recv() {
                    Ok(WriteWorkerMsg::AddChunk(_)) => (),
                    Ok(WriteWorkerMsg::Barrier(rendezvous_tx)) => {
                        let _ = rendezvous_tx.send(Err(err));
                    }
                    Ok(WriteWorkerMsg::Exit) | Err(_) => {
                        return;
                    }
                }
                err = anyhow::format_err!("io error");
            }
        };

        macro_rules! worker_bail {
            ($err:expr) => {{
                err_forever(write_worker_rx, $err.into());
                return;
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
                let mut added_chunks: u64 = 0;
                let mut added_bytes: u64 = 0;

                loop {
                    match write_worker_rx.recv() {
                        Ok(WriteWorkerMsg::AddChunk((addr, data))) => {
                            let shard = ((addr.bytes[0] & 0xf0) >> 4) as usize;
                            let addr = addr.as_hex_addr();
                            let file_name = &addr.as_str()[1..];

                            // Using open to check if it exists works better with fuse caching.
                            match chunk_dirs[shard].open(file_name, vfs::OpenFlags::RDONLY) {
                                Ok(_) => continue,
                                Err(err) if err.kind() == std::io::ErrorKind::NotFound => (),
                                Err(err) => worker_bail!(err),
                            }

                            added_chunks += 1;
                            added_bytes += data.len() as u64;

                            let random_suffix = {
                                let mut buf = [0; 12];
                                crypto::randombytes(&mut buf[..]);
                                hex::easy_encode_to_string(&buf[..])
                            };

                            let tmp = file_name
                                .chars()
                                .chain(".".chars())
                                .chain(random_suffix.chars())
                                .chain(".tmp".chars())
                                .collect::<String>();

                            let mut tmp_file = worker_try!(chunk_dirs[shard].open(
                                &tmp,
                                vfs::OpenFlags::TRUNC
                                    | vfs::OpenFlags::WRONLY
                                    | vfs::OpenFlags::CREAT
                            ));

                            worker_try!(tmp_file.write_all(&data));
                            worker_try!(tmp_file.fsync());
                            worker_try!(chunk_dirs[shard].rename(&tmp, file_name));
                        }
                        Ok(WriteWorkerMsg::Barrier(rendezvous_tx)) => {
                            let _ = rendezvous_tx.send(Ok(protocol::FlushStats {
                                added_chunks,
                                added_bytes,
                            }));
                            added_chunks = 0;
                            added_bytes = 0;
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
    }

    fn add_read_worker_thread(&mut self) {
        let chunk_dirs = self.chunk_dirs.clone();
        let read_worker_rx = self.read_worker_rx.clone();

        let worker = std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(move || 'worker_loop: loop {
                match read_worker_rx.recv() {
                    Ok(ReadWorkerMsg::GetChunk((addr, result_tx))) => {
                        let shard = ((addr.bytes[0] & 0xf0) >> 4) as usize;
                        let addr = addr.as_hex_addr();
                        let file_name = &addr.as_str()[1..];
                        let result = match chunk_dirs[shard].open(file_name, vfs::OpenFlags::RDONLY)
                        {
                            Ok(mut f) => {
                                let mut data = Vec::with_capacity(2 * 1024 * 1024);
                                match f.read_to_end(&mut data) {
                                    Ok(_) => Ok(data),
                                    Err(err) => Err(err.into()),
                                }
                            }
                            Err(err) => Err(err.into()),
                        };
                        let _ = result_tx.send(result);
                    }
                    Ok(ReadWorkerMsg::FilterExisting((addresses, result_tx))) => {
                        let mut missing = Vec::with_capacity(addresses.len());
                        for addr in addresses.iter() {
                            let shard = ((addr.bytes[0] & 0xf0) >> 4) as usize;
                            let hex_addr = addr.as_hex_addr();
                            let file_name = &hex_addr.as_str()[1..];
                            // Using open to check if it exists works better with fuse caching.
                            match chunk_dirs[shard].open(file_name, vfs::OpenFlags::RDONLY) {
                                Ok(_) => (),
                                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                                    missing.push(*addr)
                                }
                                Err(err) => {
                                    let _ = result_tx.send(Err(err.into()));
                                    continue 'worker_loop;
                                }
                            }
                        }
                        let _ = result_tx.send(Ok(missing));
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
        self.write_round_robin_index = 0;
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

    fn flush_write_workers(&mut self) -> Result<protocol::FlushStats, anyhow::Error> {
        let mut aggregate_stats = protocol::FlushStats {
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

        for d in self.chunk_dirs.iter() {
            d.sync()?;
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
            match self.flush_write_workers() {
                Ok(_) => Err(anyhow::format_err!("io error")),
                Err(err) => Err(err),
            }
        } else {
            Ok(())
        }
    }

    pub fn new(fs: vfs::VFs) -> Result<Self, anyhow::Error> {
        let read_worker_handles = Vec::new();
        let write_worker_handles = Vec::new();
        let write_worker_tx = Vec::new();
        let had_io_error = Arc::new(AtomicBool::new(false));
        let (read_worker_tx, read_worker_rx) = crossbeam_channel::bounded(0);

        let mut chunk_dirs = Vec::new();
        for i in 0..16 {
            chunk_dirs.push(fs.sub_fs(&format!("{:x}", i))?);
        }

        Ok(DirStorage {
            chunk_dirs: Arc::new(chunk_dirs),
            read_worker_handles,
            read_worker_tx,
            read_worker_rx,
            had_io_error,
            write_worker_handles,
            write_worker_tx,
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
    fn pipelined_get_chunks(
        &mut self,
        addresses: &[Address],
        on_chunk: &mut dyn FnMut(&Address, &[u8]) -> Result<(), anyhow::Error>,
    ) -> Result<(), anyhow::Error> {
        let mut pipeline_queue = VecDeque::new();

        for addr in addresses.iter() {
            let (tx, rx) = crossbeam_channel::bounded(1);
            self.scaling_read_worker_dispatch(ReadWorkerMsg::GetChunk((*addr, tx)))?;
            pipeline_queue.push_back((addr, rx));

            if pipeline_queue.len() >= MAX_READ_WORKERS {
                let (addr, rx) = pipeline_queue.pop_front().unwrap();
                let data = rx.recv()??;
                on_chunk(addr, &data)?;
            }
        }

        while !pipeline_queue.is_empty() {
            let (addr, rx) = pipeline_queue.pop_front().unwrap();
            let data = rx.recv()??;
            on_chunk(addr, &data)?;
        }

        Ok(())
    }

    fn filter_existing_chunks(
        &mut self,
        on_progress: &mut dyn FnMut(u64) -> Result<(), anyhow::Error>,
        addresses: Vec<Address>,
    ) -> Result<Vec<Address>, anyhow::Error> {
        let mut filtered = Vec::with_capacity(addresses.len());
        let mut pipeline_queue = VecDeque::new();

        for addrs in addresses.chunks(4096) {
            let (tx, rx) = crossbeam_channel::bounded(1);
            pipeline_queue.push_back((addrs.len() as u64, rx));
            self.scaling_read_worker_dispatch(ReadWorkerMsg::FilterExisting((addrs.to_vec(), tx)))?;
            if pipeline_queue.len() >= MAX_READ_WORKERS {
                let (new_progress, rx) = pipeline_queue.pop_front().unwrap();
                filtered.append(&mut rx.recv()??);
                on_progress(new_progress)?;
            }
        }

        while !pipeline_queue.is_empty() {
            let (new_progress, rx) = pipeline_queue.pop_front().unwrap();
            filtered.append(&mut rx.recv()??);
            on_progress(new_progress)?;
        }

        Ok(filtered)
    }

    fn get_chunk(&mut self, addr: &Address) -> Result<Vec<u8>, anyhow::Error> {
        let shard = ((addr.bytes[0] & 0xf0) >> 4) as usize;
        let addr = addr.as_hex_addr();
        let file_name = &addr.as_str()[1..];
        let mut f = self.chunk_dirs[shard].open(file_name, vfs::OpenFlags::RDONLY)?;
        let mut data = Vec::with_capacity(1024 * 1024);
        f.read_to_end(&mut data)?;
        Ok(data)
    }

    fn add_chunk(&mut self, addr: &Address, buf: Vec<u8>) -> Result<(), anyhow::Error> {
        self.check_write_worker_io_errors()?;

        let msg = WriteWorkerMsg::AddChunk((*addr, buf));

        if self.write_worker_tx.is_empty() {
            self.add_write_worker_thread();
            self.write_worker_tx[self.write_round_robin_index].send(msg)?;
        } else if self.write_round_robin_index == self.write_worker_tx.len()
            && self.write_worker_tx.len() != MAX_WRITE_WORKERS
        {
            match self.write_worker_tx[0].try_send(msg) {
                Ok(_) => {
                    self.write_round_robin_index = 0;
                }
                Err(crossbeam_channel::TrySendError::Full(msg)) => {
                    self.add_write_worker_thread();
                    self.write_worker_tx[self.write_round_robin_index].send(msg)?;
                }
                Err(_) => anyhow::bail!("write worker exited"),
            }
        } else {
            self.write_worker_tx[self.write_round_robin_index].send(msg)?;
        }

        self.write_round_robin_index = (self.write_round_robin_index + 1) % MAX_WRITE_WORKERS;

        Ok(())
    }

    fn flush(&mut self) -> Result<protocol::FlushStats, anyhow::Error> {
        self.flush_write_workers()
    }

    fn prepare_for_sweep(&mut self, _gc_id: xid::Xid) -> Result<(), anyhow::Error> {
        Ok(())
    }

    fn estimate_chunk_count(&mut self) -> Result<u64, anyhow::Error> {
        let n_chunks = self.chunk_dirs[0].read_dir(".")?.len() as u64;
        let n_shards = self.chunk_dirs.len() as u64;
        Ok(n_shards * n_chunks)
    }

    fn sweep(
        &mut self,
        update_progress_msg: &mut dyn FnMut(String) -> Result<(), anyhow::Error>,
        reachable: abloom::ABloom,
    ) -> Result<repository::GcStats, anyhow::Error> {
        // We don't strictly need to stop them, but it saves memory.
        self.stop_workers();

        // Collect removals into memory first so we don't have to
        // worry about fs semantics when removing while iterating.
        let mut to_remove = Vec::with_capacity(512);

        let mut chunks_remaining: u64 = 0;
        let mut chunks_deleted: u64 = 0;
        let mut bytes_deleted: u64 = 0;
        let mut bytes_remaining: u64 = 0;

        // Simple filter to reduce the number of time syscalls, but still look natural.
        let is_update_idx = |i| i % 991 == 0;
        let progress_update_delay = std::time::Duration::from_millis(500);
        let mut last_progress_update = std::time::Instant::now()
            .checked_sub(progress_update_delay)
            .unwrap();

        // XXX: The following steps should be done in parallel.
        // XXX: we are slowing the gc down by doing stat operatons on each chunk for diagnostics.

        for shard in 0..self.chunk_dirs.len() {
            for (i, e) in self.chunk_dirs[shard]
                .read_dir(".")?
                .into_iter()
                .enumerate()
            {
                if is_update_idx(i) && last_progress_update.elapsed() >= progress_update_delay {
                    last_progress_update = std::time::Instant::now();
                    update_progress_msg(format!(
                        "enumerating chunks, {} reachable, {} unreachable...",
                        chunks_remaining, chunks_deleted
                    ))?;
                }
                match Address::from_hex_str(&format!("{:x}{}", shard, e.file_name)) {
                    Ok(addr) if reachable.probably_has(&addr) => {
                        if let Ok(md) = self.chunk_dirs[shard].metadata(&e.file_name) {
                            bytes_remaining += md.size
                        }
                        chunks_remaining += 1
                    }
                    _ => {
                        if let Ok(md) = self.chunk_dirs[shard].metadata(&e.file_name) {
                            bytes_deleted += md.size
                        }
                        to_remove.push((shard, e.file_name));
                        chunks_deleted += 1;
                    }
                }
            }
        }

        for (i, (shard, file_name)) in to_remove.drain(..).enumerate() {
            // Limit the number of updates, but always show the final update.
            if (is_update_idx(i) && last_progress_update.elapsed() >= progress_update_delay)
                || ((i + 1) as u64 == chunks_deleted)
            {
                last_progress_update = std::time::Instant::now();
                update_progress_msg(format!(
                    "deleting unreachable chunk {}/{}...",
                    i + 1,
                    chunks_deleted
                ))?;
            }
            self.chunk_dirs[shard].remove_file(&file_name)?;
        }

        Ok(repository::GcStats {
            chunks_remaining: Some(chunks_remaining),
            chunks_deleted: Some(chunks_deleted),
            bytes_deleted: Some(bytes_deleted),
            bytes_remaining: Some(bytes_remaining),
        })
    }

    fn sweep_completed(&mut self, _gc_id: xid::Xid) -> Result<bool, anyhow::Error> {
        // For the dir storage engine we can only call this if we have an exclusive
        // repository lock, which means the sweep has definitely finished.
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_and_get_chunk() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let fs = vfs::VFs::create(tmp_dir.path().to_str().unwrap()).unwrap();
        for i in 0..16 {
            fs.mkdir(&format!("{:x}", i)).unwrap();
        }
        let mut storage = DirStorage::new(fs).unwrap();
        let addr = Address::default();
        storage.add_chunk(&addr, vec![1]).unwrap();
        storage.flush().unwrap();
        storage.add_chunk(&addr, vec![2]).unwrap();
        storage.flush().unwrap();
        let v = storage.get_chunk(&addr).unwrap();
        assert_eq!(v, vec![1]);
    }

    #[test]
    fn pipelined_get_chunks() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let fs = vfs::VFs::create(tmp_dir.path().to_str().unwrap()).unwrap();
        for i in 0..16 {
            fs.mkdir(&format!("{:x}", i)).unwrap();
        }
        let mut storage = DirStorage::new(fs).unwrap();
        let addr = Address::default();
        storage.add_chunk(&addr, vec![1]).unwrap();
        storage.flush().unwrap();

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
