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
    dispatch: crossbeam::channel::Sender<WorkerMsg>,
    rendezvous: crossbeam::channel::Receiver<Option<failure::Error>>,
}

impl Drop for ExternalStorage {
    fn drop(&mut self) {
        for _i in 0..self.worker_handles.len() {
            let _ = self.dispatch.send(WorkerMsg::Exit);
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
    pub fn new(
        socket_path: &std::path::Path,
        path: String,
        mut nworkers: usize,
    ) -> Result<Self, failure::Error> {
        if nworkers == 0 {
            nworkers = 1
        }

        let had_io_error = Arc::new(AtomicBool::new(false));
        let mut worker_handles = Vec::new();

        let (dispatch, rx) = crossbeam::channel::bounded(0);
        let (ack_barrier, rendezvous) = crossbeam::channel::bounded(0);

        for _i in 0..nworkers {
            // Quite a small stack for these workers.
            let builder = std::thread::Builder::new().stack_size(256 * 1024);
            let had_io_error = had_io_error.clone();
            let rx = rx.clone();
            let ack_barrier = ack_barrier.clone();
            let mut sock = socket_connect(socket_path, &path)?;

            let worker = builder
                .spawn(move || {
                    let mut write_err: Option<failure::Error> = None;
                    loop {
                        match rx.recv() {
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
                                match protocol::write_packet(
                                    &mut sock,
                                    &protocol::Packet::Chunk(chunk),
                                ) {
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
                                            maybe_err =
                                                Some(failure::format_err!("protocol error"));
                                        }
                                    }
                                    Err(err) => {
                                        if maybe_err.is_none() {
                                            maybe_err = Some(err.into());
                                        }
                                    }
                                }

                                ack_barrier.send(maybe_err).unwrap();
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
            worker_handles.push(worker);
        }

        Ok(ExternalStorage {
            socket_path: socket_path.to_path_buf(),
            path,
            had_io_error,
            worker_handles,
            dispatch,
            rendezvous,
        })
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
        self.dispatch.send(WorkerMsg::AddChunk((*addr, buf)))?;
        Ok(())
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
