use super::address::*;
use super::htree;
use super::repository;
use super::xid;

pub trait Engine {
    // Get a chunk from the storage engine using the worker pool.
    fn get_chunk_async(
        &mut self,
        addr: &Address,
    ) -> crossbeam_channel::Receiver<Result<Vec<u8>, anyhow::Error>>;

    // Get a chunk from the storage engine.
    fn get_chunk(&mut self, addr: &Address) -> Result<Vec<u8>, anyhow::Error> {
        self.get_chunk_async(addr).recv()?
    }

    // Set the gc_id for the following call to gc. This is a form
    // of two phase commit where we ensure the backend saves this
    // id so we can later check if it has completed.
    fn prepare_for_gc(&mut self, gc_id: xid::Xid) -> Result<(), anyhow::Error>;

    // Remove all chunks not in the reachable set.
    fn gc(
        &mut self,
        reachability_db_path: &std::path::Path,
        reachability_db: &mut rusqlite::Connection,
    ) -> Result<repository::GCStats, anyhow::Error>;

    // Check that a previous invocation of gc has finished.
    fn await_gc_completion(&mut self, gc_id: xid::Xid) -> Result<(), anyhow::Error>;

    // Add a chunk, potentially asynchronously. Does not overwrite existing
    // chunks with the same name to protect historic items from corruption.
    // The write is not guaranteed to be completed until
    // after a call to Engine::sync completes without error.
    fn add_chunk(&mut self, addr: &Address, buf: Vec<u8>) -> Result<(), anyhow::Error>;

    // A write barrier, any previously added chunks are only guaranteed to be
    // in stable storage after a call to sync has returned. A backend
    // can use this to implement concurrent background writes.
    fn sync(&mut self) -> Result<(), anyhow::Error>;
}

impl htree::Sink for Box<dyn Engine> {
    fn add_chunk(&mut self, addr: &Address, buf: Vec<u8>) -> Result<(), anyhow::Error> {
        self.as_mut().add_chunk(addr, buf)
    }
}

impl htree::Source for Box<dyn Engine> {
    fn get_chunk(&mut self, addr: &Address) -> Result<Vec<u8>, anyhow::Error> {
        self.as_mut().get_chunk(addr)
    }
}
