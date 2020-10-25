use super::address::Address;
use super::chunk_storage::Engine;
use super::protocol;
use super::repository;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

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

pub struct ExternalStorage {
    socket_path: std::path::PathBuf,
    path: String,

    // Reading
    read_worker_handles: Vec<std::thread::JoinHandle<()>>,
    read_worker_tx: crossbeam_channel::Sender<ReadWorkerMsg>,
    read_worker_rx: crossbeam_channel::Receiver<ReadWorkerMsg>,

    // Writing
    had_io_error: Arc<AtomicBool>,
    write_worker_handles: Vec<std::thread::JoinHandle<()>>,
    write_worker_tx: crossbeam_channel::Sender<WriteWorkerMsg>,
    write_worker_rx: crossbeam_channel::Receiver<WriteWorkerMsg>,
}

fn socket_connect(socket_path: &std::path::Path, path: &str) -> Result<UnixStream, failure::Error> {
    let mut sock = UnixStream::connect(socket_path)?;
    protocol::write_packet(
        &mut sock,
        &protocol::Packet::StorageConnect(protocol::StorageConnect {
            protocol: "s-0".to_string(),
            path: path.to_string(),
        }),
    )?;
    Ok(sock)
}

impl ExternalStorage {
    fn add_write_worker_thread(&mut self) -> Result<(), failure::Error> {
        let mut sock = socket_connect(&self.socket_path, &self.path)?;
        let had_io_error = self.had_io_error.clone();
        let write_worker_rx = self.write_worker_rx.clone();

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
            .spawn(move || loop {
                match write_worker_rx.recv() {
                    Ok(WriteWorkerMsg::AddChunk((address, data))) => {
                        let chunk = protocol::Chunk { address, data };
                        worker_try!(protocol::write_packet(
                            &mut sock,
                            &protocol::Packet::Chunk(chunk)
                        ));
                    }
                    Ok(WriteWorkerMsg::Barrier(rendezvous_tx)) => {
                        match protocol::write_packet(
                            &mut sock,
                            &protocol::Packet::TStorageWriteBarrier,
                        ) {
                            Ok(()) => (),
                            Err(err) => {
                                let _ = rendezvous_tx.send(Some(err));
                                worker_bail!(failure::format_err!("io error"));
                            }
                        }
                        match protocol::read_packet(&mut sock, protocol::DEFAULT_MAX_PACKET_SIZE) {
                            Ok(protocol::Packet::RStorageWriteBarrier) => {
                                let _ = rendezvous_tx.send(None);
                            }
                            Ok(_) => {
                                let _ = rendezvous_tx.send(Some(failure::format_err!("bug")));
                                worker_bail!(failure::format_err!("io error"));
                            }
                            Err(err) => {
                                let _ = rendezvous_tx.send(Some(err));
                                worker_bail!(failure::format_err!("io error"));
                            }
                        }
                    }
                    Ok(WriteWorkerMsg::Exit) | Err(_) => {
                        return;
                    }
                }
            })
            .unwrap();

        self.write_worker_handles.push(worker);
        Ok(())
    }

    fn add_read_worker_thread(&mut self) -> Result<(), failure::Error> {
        let mut sock = socket_connect(&self.socket_path, &self.path)?;
        let read_worker_rx = self.read_worker_rx.clone();

        let worker = std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(move || loop {
                match read_worker_rx.recv() {
                    Ok(ReadWorkerMsg::GetChunk((addr, result_tx))) => {
                        match protocol::write_packet(
                            &mut sock,
                            &protocol::Packet::TRequestChunk(addr),
                        ) {
                            Ok(()) => (),
                            Err(err) => result_tx.send(Err(err)).unwrap(),
                        }
                        match protocol::read_packet(&mut sock, protocol::DEFAULT_MAX_PACKET_SIZE) {
                            Ok(protocol::Packet::RRequestChunk(data)) => {
                                let _ = result_tx.send(Ok(data));
                            }
                            Ok(_) => {
                                let _ = result_tx.send(Err(failure::format_err!(
                                    "storage engine protocol error"
                                )));
                            }
                            Err(err) => {
                                let _ = result_tx.send(Err(err));
                            }
                        }
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
        for _i in 0..self.write_worker_handles.len() {
            self.write_worker_tx.send(WriteWorkerMsg::Exit).unwrap();
        }
        for h in self.read_worker_handles.drain(..) {
            h.join().unwrap();
        }
        for h in self.write_worker_handles.drain(..) {
            h.join().unwrap();
        }
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

    fn scaling_write_worker_dispatch(&mut self, msg: WriteWorkerMsg) -> Result<(), failure::Error> {
        const MAX_WRITE_WORKERS: usize = 1;

        if self.write_worker_handles.len() < MAX_WRITE_WORKERS {
            match self.write_worker_tx.try_send(msg) {
                Ok(_) => Ok(()),
                Err(crossbeam_channel::TrySendError::Full(msg)) => {
                    self.add_write_worker_thread()?;
                    Ok(self.write_worker_tx.send(msg)?)
                }
                Err(err) => Err(err.into()),
            }
        } else {
            Ok(self.write_worker_tx.send(msg)?)
        }
    }

    fn sync_write_workers(&mut self) -> Result<(), failure::Error> {
        let mut rendezvous = Vec::with_capacity(self.write_worker_handles.len());

        for _i in 0..self.write_worker_handles.len() {
            let (rendezvous_tx, rendezvous_rx) = crossbeam_channel::bounded(0);
            rendezvous.push(rendezvous_rx);
            self.write_worker_tx
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

    pub fn new(socket_path: &std::path::Path, path: &str) -> Result<Self, failure::Error> {
        let read_worker_handles = Vec::new();
        let write_worker_handles = Vec::new();
        let had_io_error = Arc::new(AtomicBool::new(false));
        // We do not want any buffering.
        let (read_worker_tx, read_worker_rx) = crossbeam_channel::bounded(0);
        let (write_worker_tx, write_worker_rx) = crossbeam_channel::bounded(0);

        Ok(ExternalStorage {
            path: path.to_owned(),
            socket_path: socket_path.to_owned(),
            read_worker_handles,
            read_worker_tx,
            read_worker_rx,
            had_io_error,
            write_worker_handles,
            write_worker_tx,
            write_worker_rx,
        })
    }
}

impl Drop for ExternalStorage {
    fn drop(&mut self) {
        self.stop_workers();
    }
}

impl Engine for ExternalStorage {
    fn add_chunk(&mut self, addr: &Address, buf: Vec<u8>) -> Result<(), failure::Error> {
        self.check_write_worker_io_errors()?;
        self.scaling_write_worker_dispatch(WriteWorkerMsg::AddChunk((*addr, buf)))?;
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
        _reachability_db: &mut rusqlite::Connection,
    ) -> Result<repository::GCStats, failure::Error> {
        self.stop_workers();

        let mut sock = socket_connect(&self.socket_path, &self.path)?;

        protocol::write_packet(&mut sock, &protocol::Packet::StorageBeginGC)?;

        failure::bail!("unimplemented, external chunk storage gc");
        /* XXX Replace
        /* Transfer addresses over in chunks, terminated with an empty block */
        const ADDRESSES_PER_PACKET: usize = 4096;
        let mut reachable_part = Vec::with_capacity(ADDRESSES_PER_PACKET * ADDRESS_SZ);
        for a in reachable.iter() {
            reachable_part.extend_from_slice(&a.bytes[..]);
            if reachable_part.len() == ADDRESSES_PER_PACKET * ADDRESS_SZ {
                protocol::write_packet(
                    &mut sock,
                    &protocol::Packet::StorageGCReachable(reachable_part.clone()),
                )?;
                reachable_part.clear();
            }
        }
        if !reachable_part.is_empty() {
            protocol::write_packet(
                &mut sock,
                &protocol::Packet::StorageGCReachable(reachable_part.clone()),
            )?;
            reachable_part.clear();
        }
        */

        /* Empty block */
        /*
        protocol::write_packet(
            &mut sock,
            &protocol::Packet::StorageGCReachable(reachable_part),
        )?;

        loop {
            match protocol::read_packet(&mut sock, protocol::DEFAULT_MAX_PACKET_SIZE) {
                Ok(protocol::Packet::StorageGCHeartBeat) => (),
                Ok(protocol::Packet::StorageGCComplete(stats)) => {
                    let _ = protocol::write_packet(&mut sock, &protocol::Packet::EndOfTransmission);
                    return Ok(stats);
                }
                Ok(_) => failure::bail!("unexpected packet response"),
                Err(err) => return Err(err),
            }
        }
        */
    }
}
