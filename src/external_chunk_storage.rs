use super::address::Address;
use super::chunk_storage::Engine;
use super::protocol;
use super::repository;
use std::os::unix::net::UnixStream;

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
    worker_handles: Vec<std::thread::JoinHandle<()>>,
    dispatch: crossbeam::channel::Sender<WorkerMsg>,
    rendezvous: crossbeam::channel::Receiver<Option<failure::Error>>,
}

impl Drop for ExternalStorage {
    fn drop(&mut self) {
        for _i in 0..self.worker_handles.len() {
            self.dispatch.send(WorkerMsg::Exit).unwrap();
        }
        for h in self.worker_handles.drain(..) {
            h.join().unwrap();
        }
    }
}

impl ExternalStorage {
    pub fn new(socket_path: &std::path::Path, mut nworkers: usize) -> Result<Self, failure::Error> {
        if nworkers == 0 {
            nworkers = 1
        }

        let mut worker_handles = Vec::new();

        let (dispatch, rx) = crossbeam::channel::bounded(0);
        let (ack_barrier, rendezvous) = crossbeam::channel::bounded(0);

        for _i in 0..nworkers {
            // Quite a small stack for these workers.
            let builder = std::thread::Builder::new().stack_size(256 * 1024);
            let worker_socket_path = socket_path.to_owned();
            let worker_rx = rx.clone();
            let worker_ack_barrier = ack_barrier.clone();
            let mut sock = UnixStream::connect(worker_socket_path)?;

            protocol::write_packet(
                &mut sock,
                &protocol::Packet::Identify(protocol::Identify {
                    protocol: "storage-0".to_string(),
                    ident: "".to_string(),
                }),
            )?;

            let worker = builder
                .spawn(move || {
                    let mut write_err: Option<failure::Error> = None;
                    loop {
                        match worker_rx.recv() {
                            Ok(WorkerMsg::GetChunk((addr, tx))) => {
                                match protocol::write_packet(
                                    &mut sock,
                                    &protocol::Packet::RequestChunk(addr),
                                ) {
                                    Ok(()) => (),
                                    Err(err) => tx.send(Err(err.into())).unwrap(),
                                }
                                match protocol::read_packet(&mut sock) {
                                    Ok(protocol::Packet::AckRequestChunk(data)) => {
                                        tx.send(Ok(data)).unwrap()
                                    }
                                    Ok(_) => tx
                                        .send(Err(failure::format_err!(
                                            "storage engine protocol error"
                                        )))
                                        .unwrap(),
                                    Err(err) => tx.send(Err(err.into())).unwrap(),
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
                                    Err(err) => write_err = Some(err),
                                }
                            }
                            Ok(WorkerMsg::Barrier) => {
                                let mut err = None;
                                std::mem::swap(&mut write_err, &mut err);
                                worker_ack_barrier.send(err).unwrap();
                            }
                            Ok(WorkerMsg::Exit) => return,
                            Err(_) => return,
                        }
                    }
                })
                .unwrap();
            worker_handles.push(worker);
        }

        Ok(ExternalStorage {
            worker_handles,
            dispatch,
            rendezvous,
        })
    }
}

impl Engine for ExternalStorage {
    fn add_chunk(&mut self, addr: &Address, buf: Vec<u8>) -> Result<(), failure::Error> {
        self.dispatch
            .send(WorkerMsg::AddChunk((*addr, buf)))
            .unwrap();
        Ok(())
    }

    fn gc(
        &mut self,
        _reachable: std::collections::HashSet<Address>,
    ) -> Result<repository::GCStats, failure::Error> {
        failure::bail!("TODO");
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
