use super::abloom;
use super::address::*;
use super::protocol;
use super::repository;
use super::xid;

pub trait Engine {
    // Get many chunks in an efficient pipeline.
    #[allow(clippy::type_complexity)]
    fn pipelined_get_chunks(
        &mut self,
        addresses: &[Address],
        on_chunk: &mut dyn FnMut(&Address, &[u8]) -> Result<(), anyhow::Error>,
    ) -> Result<(), anyhow::Error>;

    // Get a chunk from the storage engine.
    fn get_chunk(&mut self, addr: &Address) -> Result<Vec<u8>, anyhow::Error>;

    // Set the gc_id for the following call to sweep. This is a form
    // of two phase commit where we ensure the backend saves this
    // id so we can later check if it has completed.
    fn prepare_for_sweep(&mut self, gc_id: xid::Xid) -> Result<(), anyhow::Error>;

    // Remove all chunks not in the reachable set.
    fn sweep(
        &mut self,
        update_progress_msg: &mut dyn FnMut(String) -> Result<(), anyhow::Error>,
        reachable: abloom::ABloom,
    ) -> Result<repository::GcStats, anyhow::Error>;

    // Check that a previous invocation of sweep has finished.
    fn sweep_completed(&mut self, gc_id: xid::Xid) -> Result<bool, anyhow::Error>;

    // Add a chunk, potentially asynchronously. Does not overwrite existing
    // chunks with the same name to protect historic items from corruption.
    // The write is not guaranteed to be completed until
    // after a call to Engine::sync completes without error.
    fn add_chunk(&mut self, addr: &Address, buf: Vec<u8>) -> Result<(), anyhow::Error>;

    // Filter a list of chunk addresses removing any that already exist in the repository.
    // This function is often called in very large batches so requires the backend to periodically
    // report progress, the argument to on_progress is how many addresses have been processed since the last
    // progress report.
    fn filter_existing_chunks(
        &mut self,
        on_progress: &mut dyn FnMut(u64) -> Result<(), anyhow::Error>,
        addr: Vec<Address>,
    ) -> Result<Vec<Address>, anyhow::Error>;

    // A write barrier, any previously added chunks are only guaranteed to be
    // in stable storage after a call to flush has returned. A backend
    // can use this to implement concurrent background writes.
    fn flush(&mut self) -> Result<protocol::FlushStats, anyhow::Error>;

    // Estimate how many chunks we have stored, the implementation is free to
    // make a rough guess to increase performance. One trick is sampling
    // a single address prefix.
    fn estimate_chunk_count(&mut self) -> Result<u64, anyhow::Error>;
}
