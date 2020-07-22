use super::address::Address;
use super::chunk_storage::Engine;
use super::repository;
use std::convert::TryInto;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

enum ReadWorkerMsg {
    GetChunk(
        (
            Address,
            crossbeam::channel::Sender<Result<Vec<u8>, failure::Error>>,
        ),
    ),
    Exit,
}

enum WriteWorkerMsg {
    AddChunk((Address, Vec<u8>)),
    Barrier(crossbeam::channel::Sender<Option<failure::Error>>),
    Exit,
}

pub struct Sqlite3Storage {
    db_path: PathBuf,

    // Reading
    read_worker_handles: Vec<std::thread::JoinHandle<()>>,
    read_worker_tx: crossbeam::channel::Sender<ReadWorkerMsg>,
    read_worker_rx: crossbeam::channel::Receiver<ReadWorkerMsg>,

    // Writing
    had_io_error: Arc<AtomicBool>,
    write_worker_handles: Vec<std::thread::JoinHandle<()>>,
    write_worker_tx: crossbeam::channel::Sender<WriteWorkerMsg>,
    write_worker_rx: crossbeam::channel::Receiver<WriteWorkerMsg>,
}

impl Sqlite3Storage {
    fn open_db(p: &PathBuf) -> Result<rusqlite::Connection, failure::Error> {
        let mut db = rusqlite::Connection::open(p)?;

        db.query_row("pragma busy_timeout=3600000;", rusqlite::NO_PARAMS, |_r| {
            Ok(())
        })?;

        db.query_row("pragma wal_autocheckpoint=0;", rusqlite::NO_PARAMS, |_r| {
            Ok(())
        })?;

        // larger cache than default for sqlite3
        // Should consider a config option?
        db.execute("pragma cache_size=5000;", rusqlite::NO_PARAMS)?;

        let tx = db.transaction()?;

        tx.execute(
            "create table if not exists DataDBMeta(Key primary key, Value) without rowid;",
            rusqlite::NO_PARAMS,
        )?;

        let mut just_created = false;

        match tx.query_row(
            "select Value from DataDBMeta where Key = 'schema-version';",
            rusqlite::NO_PARAMS,
            |r| {
                let v: i64 = r.get(0)?;
                Ok(v)
            },
        ) {
            Ok(v) => {
                if v != 0 {
                    failure::bail!(
                        "data db at {:?} is from a different version of the software.",
                        &p
                    );
                }
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                just_created = true;
                tx.execute(
                    "insert into DataDBMeta(Key, Value) values('schema-version', 0);",
                    rusqlite::NO_PARAMS,
                )?;
            }
            Err(err) => return Err(err.into()),
        }

        tx.execute(
            "create table if not exists Chunks(Address blob primary key, Data blob) without rowid;",
            rusqlite::NO_PARAMS,
        )?;

        tx.commit()?;

        if just_created {
            // We can only change page size and auto_vacuum by running a full vacuum.
            db.execute("pragma page_size=65536;", rusqlite::NO_PARAMS)?;
            db.execute("pragma auto_vacuum=INCREMENTAL;", rusqlite::NO_PARAMS)?;
            // Vacuum once to change page size and auto vacuum mode...
            db.execute("vacuum;", rusqlite::NO_PARAMS)?;
            // Now that the other setup is done, we can change to wal mode.
            db.query_row("pragma journal_mode=WAL;", rusqlite::NO_PARAMS, |_r| Ok(()))?;
        }

        Ok(db)
    }

    fn add_write_worker_thread(&mut self) -> Result<(), failure::Error> {
        let mut db = Sqlite3Storage::open_db(&self.db_path)?;

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
                let tx = worker_try!(db.transaction());

                loop {
                    match write_worker_rx.recv() {
                        Ok(WriteWorkerMsg::AddChunk((addr, data))) => {
                            worker_try!(tx
                                .prepare_cached(
                                    "insert or ignore into Chunks(Address, Data) Values(?, ?);",
                                )
                                .unwrap()
                                .execute(rusqlite::params![&addr.bytes[..], data]));
                        }
                        Ok(WriteWorkerMsg::Barrier(rendezvous_tx)) => {
                            match tx.commit() {
                                Err(err) => {
                                    let _ = rendezvous_tx.send(Some(err.into()));
                                    worker_bail!(failure::format_err!("io error"));
                                }
                                Ok(()) => {
                                    let _ = rendezvous_tx.send(None);
                                }
                            };

                            worker_try!(db.query_row(
                                "pragma wal_checkpoint(TRUNCATE);",
                                rusqlite::NO_PARAMS,
                                |_r| Ok(()),
                            ));
                            break;
                        }
                        Ok(WriteWorkerMsg::Exit) | Err(_) => {
                            return;
                        }
                    }
                }
            })
            .unwrap();

        self.write_worker_handles.push(worker);
        Ok(())
    }

    fn add_read_worker_thread(&mut self) -> Result<(), failure::Error> {
        let mut db = Sqlite3Storage::open_db(&self.db_path)?;
        let read_worker_rx = self.read_worker_rx.clone();

        let worker = std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(move || loop {
                match db.transaction() {
                    Ok(tx) => {
                        let mut stmt = tx
                            .prepare("select Data from Chunks where Address = ?;")
                            .unwrap();

                        loop {
                            match read_worker_rx.recv() {
                                Ok(ReadWorkerMsg::GetChunk((addr, result_tx))) => {
                                    let result = match stmt.query_row(
                                        rusqlite::params![&addr.bytes[..]],
                                        |r| {
                                            let v: Vec<u8> = r.get(0)?;
                                            Ok(v)
                                        },
                                    ) {
                                        Ok(v) => Ok(v),
                                        Err(rusqlite::Error::QueryReturnedNoRows) => {
                                            Err(failure::format_err!(
                                                "data at chunk address {} is missing",
                                                addr
                                            ))
                                        }
                                        Err(err) => Err(err.into()),
                                    };

                                    let _ = result_tx.send(result);
                                }
                                Ok(ReadWorkerMsg::Exit) | Err(_) => {
                                    return;
                                }
                            }
                        }
                    }
                    Err(err) => match read_worker_rx.recv() {
                        Ok(ReadWorkerMsg::GetChunk((_, result_tx))) => {
                            let _ = result_tx.send(Err(err.into()));
                        }
                        Ok(ReadWorkerMsg::Exit) | Err(_) => {
                            return;
                        }
                    },
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
                Err(crossbeam::channel::TrySendError::Full(msg)) => {
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
        // We only support one due to sqlite3.
        // We could simplify because of this.
        const MAX_WRITE_WORKERS: usize = 1;

        if self.write_worker_handles.len() < MAX_WRITE_WORKERS {
            match self.write_worker_tx.try_send(msg) {
                Ok(_) => Ok(()),
                Err(crossbeam::channel::TrySendError::Full(msg)) => {
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
            let (rendezvous_tx, rendezvous_rx) = crossbeam::channel::bounded(0);
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

    pub fn new(db_path: &std::path::Path) -> Result<Self, failure::Error> {
        let read_worker_handles = Vec::new();
        let write_worker_handles = Vec::new();
        let had_io_error = Arc::new(AtomicBool::new(false));
        // We do not want any buffering.
        let (read_worker_tx, read_worker_rx) = crossbeam::channel::bounded(0);
        let (write_worker_tx, write_worker_rx) = crossbeam::channel::bounded(0);

        Ok(Sqlite3Storage {
            db_path: db_path.to_owned(),
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

impl Drop for Sqlite3Storage {
    fn drop(&mut self) {
        self.stop_workers();
    }
}

impl Engine for Sqlite3Storage {
    fn add_chunk(&mut self, addr: &Address, buf: Vec<u8>) -> Result<(), failure::Error> {
        self.check_write_worker_io_errors()?;
        self.scaling_write_worker_dispatch(WriteWorkerMsg::AddChunk((*addr, buf)))
            .unwrap();
        Ok(())
    }

    fn get_chunk_async(
        &mut self,
        addr: &Address,
    ) -> crossbeam::channel::Receiver<Result<Vec<u8>, failure::Error>> {
        let (tx, rx) = crossbeam::channel::bounded(1);
        self.scaling_read_worker_dispatch(ReadWorkerMsg::GetChunk((*addr, tx)))
            .unwrap();
        rx
    }

    fn sync(&mut self) -> Result<(), failure::Error> {
        self.sync_write_workers()
    }

    fn gc(
        &mut self,
        _on_progress: &dyn Fn() -> Result<(), failure::Error>,
        reachable: std::collections::HashSet<Address>,
    ) -> Result<repository::GCStats, failure::Error> {
        self.stop_workers();

        let mut stats = repository::GCStats {
            chunks_remaining: reachable.len(),
            chunks_freed: 0,
            bytes_freed: 0,
            bytes_remaining: 0,
        };

        let db_start_size = std::fs::metadata(&self.db_path)?.size();

        let mut db = Sqlite3Storage::open_db(&self.db_path)?;

        let tx = db.transaction()?;
        tx.execute(
            "create temporary table TempReachable(Address primary key) without rowid;",
            rusqlite::NO_PARAMS,
        )?;

        {
            let mut insert_reachable =
                tx.prepare("insert into TempReachable(Address) values(?);")?;

            for addr in reachable.iter() {
                insert_reachable.execute(&[&addr.bytes[..]])?;
            }
        }

        stats.chunks_freed = tx.execute("delete from Chunks where not exists (select * from TempReachable where TempReachable.Address = Chunks.Address);", rusqlite::NO_PARAMS)?;
        tx.commit()?;

        db.query_row(
            "pragma wal_checkpoint(TRUNCATE);",
            rusqlite::NO_PARAMS,
            |_r| Ok(()),
        )?;

        {
            let mut incr_vacuum_stmt = db.prepare("pragma incremental_vacuum;")?;
            let mut rows = incr_vacuum_stmt.query(rusqlite::NO_PARAMS)?;
            while let Some(_) = rows.next()? {}
        }

        // Needed for db size change to appear, (at least on btrfs).
        std::mem::drop(db);

        let db_end_size = std::fs::metadata(&self.db_path)?.size();

        stats.bytes_remaining = db_end_size.try_into()?;
        stats.bytes_freed = (db_start_size - db_end_size).try_into().unwrap_or(0);

        Ok(stats)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_get_chunk() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let mut path_buf = PathBuf::from(tmp_dir.path());
        path_buf.push("data.sqlite3");
        let mut storage = Sqlite3Storage::new(&path_buf).unwrap();
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
