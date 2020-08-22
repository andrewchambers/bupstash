use super::address::*;
use super::htree;
use super::repository;

pub trait Engine {
    // Get a chunk from the storage engine using the worker pool.
    fn get_chunk_async(
        &mut self,
        addr: &Address,
    ) -> crossbeam_channel::Receiver<Result<Vec<u8>, failure::Error>>;

    // Get a chunk from the storage engine.
    fn get_chunk(&mut self, addr: &Address) -> Result<Vec<u8>, failure::Error> {
        self.get_chunk_async(addr).recv()?
    }

    // Remove all chunks not in the reachable set.
    fn gc(
        &mut self,
        reachable: std::collections::HashSet<Address>,
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
