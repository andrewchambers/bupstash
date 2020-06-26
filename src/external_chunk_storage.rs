use super::address::Address;
use super::chunk_storage::Engine;
use super::protocol;
use super::repository;
use std::os::unix::net::UnixStream;
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

pub struct ExternalStorage {
    socket_path: std::path::PathBuf,
    // Perhaps a misnomer, but 'path' can be anything the backend wants.
    path: String,
    had_io_error: Arc<AtomicBool>,
    worker_handles: Vec<std::thread::JoinHandle<()>>,
    worker_tx: crossbeam::channel::Sender<WorkerMsg>,
    worker_rx: crossbeam::channel::Receiver<WorkerMsg>,
    rendezvous_tx: crossbeam::channel::Sender<Option<failure::Error>>,
    rendezvous_rx: crossbeam::channel::Receiver<Option<failure::Error>>,
}

impl Drop for ExternalStorage {
    fn drop(&mut self) {
        for _i in 0..self.worker_handles.len() {
            let _ = self.worker_tx.send(WorkerMsg::Exit);
        }
        for h in self.worker_handles.drain(..) {
            let _ = h.join();
        }
    }
}

fn socket_connect(
    socket_path: &std::path::Path,
    path: &String,
) -> Result<UnixStream, failure::Error> {
    let mut sock = UnixStream::connect(socket_path)?;
    protocol::write_packet(
        &mut sock,
        &protocol::Packet::StorageConnect(protocol::StorageConnect {
            protocol: "storage-0".to_string(),
            path: path.clone(),
        }),
    )?;
    Ok(sock)
}

impl ExternalStorage {
    fn add_worker_thread(&mut self) {
        // Quite a small stack for these workers.
        let had_io_error = self.had_io_error.clone();
        let worker_rx = self.worker_rx.clone();
        let rendezvous_tx = self.rendezvous_tx.clone();
        let socket_path = self.socket_path.clone();
        let path = self.path.clone();

        let worker = std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(move || {
                let mut write_err: Option<failure::Error> = None;
                let mut sock = match socket_connect(&socket_path, &path) {
                    Ok(s) => s,
                    Err(err) => {
                        had_io_error.store(true, Ordering::SeqCst);
                        write_err = Some(err.into());
                        // This could be refactored...
                        // The problem is that we need a valid socket so we can report
                        // io errors via the normal code path, socket pair is an ok way
                        // to get a valid, but disconnected socket.
                        let (s, _) = UnixStream::pair().unwrap();
                        s
                    }
                };
                loop {
                    match worker_rx.recv() {
                        Ok(WorkerMsg::GetChunk((addr, tx))) => {
                            match protocol::write_packet(
                                &mut sock,
                                &protocol::Packet::TRequestChunk(addr),
                            ) {
                                Ok(()) => (),
                                Err(err) => tx.send(Err(err.into())).unwrap(),
                            }
                            match protocol::read_packet(
                                &mut sock,
                                protocol::DEFAULT_MAX_PACKET_SIZE,
                            ) {
                                Ok(protocol::Packet::RRequestChunk(data)) => {
                                    let _ = tx.send(Ok(data));
                                }
                                Ok(_) => {
                                    let _ = tx.send(Err(failure::format_err!(
                                        "storage engine protocol error"
                                    )));
                                }
                                Err(err) => {
                                    let _ = tx.send(Err(err.into()));
                                }
                            }
                        }
                        Ok(WorkerMsg::AddChunk((addr, buf))) => {
                            let chunk = protocol::Chunk {
                                address: addr,
                                data: buf,
                            };
                            match protocol::write_packet(&mut sock, &protocol::Packet::Chunk(chunk))
                            {
                                Ok(()) => (),
                                Err(err) => {
                                    had_io_error.store(true, Ordering::SeqCst);
                                    write_err = Some(err)
                                }
                            }
                        }
                        Ok(WorkerMsg::Barrier) => {
                            let mut maybe_err = None;
                            std::mem::swap(&mut write_err, &mut maybe_err);

                            match protocol::write_packet(
                                &mut sock,
                                &protocol::Packet::TStorageWriteBarrier,
                            ) {
                                Ok(()) => (),
                                Err(err) => {
                                    if maybe_err.is_none() {
                                        maybe_err = Some(err)
                                    }
                                }
                            }

                            match protocol::read_packet(
                                &mut sock,
                                protocol::DEFAULT_MAX_PACKET_SIZE,
                            ) {
                                Ok(protocol::Packet::TStorageWriteBarrier) => (),
                                Ok(_) => {
                                    if maybe_err.is_none() {
                                        maybe_err = Some(failure::format_err!("protocol error"));
                                    }
                                }
                                Err(err) => {
                                    if maybe_err.is_none() {
                                        maybe_err = Some(err.into());
                                    }
                                }
                            }

                            rendezvous_tx.send(maybe_err).unwrap();
                        }
                        Ok(WorkerMsg::Exit) => {
                            let _ = protocol::write_packet(
                                &mut sock,
                                &protocol::Packet::EndOfTransmission,
                            );
                            return;
                        }
                        Err(_) => return,
                    }
                }
            })
            .unwrap();
        self.worker_handles.push(worker);
    }

    fn scaling_worker_dispatch(&mut self, msg: WorkerMsg) -> Result<(), failure::Error> {
        // Should this be configurable?
        const MAX_WORKERS: usize = 4;

        if self.worker_handles.len() < MAX_WORKERS {
            match self.worker_tx.try_send(msg) {
                Ok(_) => Ok(()),
                Err(crossbeam::channel::TrySendError::Full(msg)) => {
                    self.add_worker_thread();
                    Ok(self.worker_tx.send(msg)?)
                }
                Err(err) => Err(err.into()),
            }
        } else {
            Ok(self.worker_tx.send(msg)?)
        }
    }

    pub fn new(socket_path: &std::path::Path, path: String) -> Result<Self, failure::Error> {
        let had_io_error = Arc::new(AtomicBool::new(false));
        let worker_handles = Vec::new();
        let (worker_tx, worker_rx) = crossbeam::channel::bounded(0);
        let (rendezvous_tx, rendezvous_rx) = crossbeam::channel::bounded(0);

        Ok(ExternalStorage {
            socket_path: socket_path.to_path_buf(),
            path,
            had_io_error,
            worker_handles,
            worker_tx,
            worker_rx,
            rendezvous_tx,
            rendezvous_rx,
        })
    }

    fn sync_workers(&mut self) -> Result<(), failure::Error> {
        for _i in 0..self.worker_handles.len() {
            self.worker_tx.send(WorkerMsg::Barrier).unwrap();
        }
        let mut write_error: Option<failure::Error> = None;
        for _i in 0..self.worker_handles.len() {
            if let Some(err) = self.rendezvous_rx.recv().unwrap() {
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
}

impl Engine for ExternalStorage {
    fn add_chunk(&mut self, addr: &Address, buf: Vec<u8>) -> Result<(), failure::Error> {
        self.check_worker_io_errors()?;
        self.scaling_worker_dispatch(WorkerMsg::AddChunk((*addr, buf)))?;
        Ok(())
    }

    fn get_chunk_async(
        &mut self,
        addr: &Address,
    ) -> crossbeam::channel::Receiver<Result<Vec<u8>, failure::Error>> {
        let (tx, rx) = crossbeam::channel::bounded(1);
        self.scaling_worker_dispatch(WorkerMsg::GetChunk((*addr, tx)))
            .unwrap();
        rx
    }

    fn sync(&mut self) -> Result<(), failure::Error> {
        self.sync_workers()
    }

    fn gc(
        &mut self,
        reachable: std::collections::HashSet<Address>,
    ) -> Result<repository::GCStats, failure::Error> {
        let mut sock = socket_connect(&self.socket_path, &self.path)?;
        protocol::write_packet(
            &mut sock,
            &protocol::Packet::TStorageGC(protocol::TStorageGC { reachable }),
        )?;
        match protocol::read_packet(&mut sock, protocol::DEFAULT_MAX_PACKET_SIZE) {
            Ok(protocol::Packet::RStorageGC(stats)) => {
                let _ = protocol::write_packet(&mut sock, &protocol::Packet::EndOfTransmission);
                Ok(stats)
            }
            Ok(_) => failure::bail!("unexpected packet response"),
            Err(err) => Err(err.into()),
        }
    }
}
