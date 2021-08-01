use super::abloom;
use super::acache;
use super::address::*;
use super::chunk_storage;
use super::compression;
use super::dir_chunk_storage;
use super::external_chunk_storage;
use super::fstx;
use super::fsutil;
use super::htree;
use super::migrate;
use super::oplog;
use super::protocol;
use super::xid::*;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::convert::TryInto;
use std::fs;
use std::io::BufRead;
use std::io::Read;
use std::io::Seek;
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

#[non_exhaustive]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum StorageEngineSpec {
    DirStore,
    ExternalStore { socket_path: String, path: String },
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct GcStats {
    pub chunks_deleted: Option<u64>,
    pub bytes_deleted: Option<u64>,
    pub chunks_remaining: Option<u64>,
    pub bytes_remaining: Option<u64>,
}

#[derive(Clone, PartialEq)]
pub enum RepoLockMode {
    None,
    Shared,
    Exclusive,
}

enum RepoLock {
    None,
    Shared(fsutil::FileLock),
    Exclusive(fsutil::FileLock),
}

impl RepoLock {
    fn mode(&self) -> RepoLockMode {
        match self {
            RepoLock::None => RepoLockMode::None,
            RepoLock::Shared(_) => RepoLockMode::Shared,
            RepoLock::Exclusive(_) => RepoLockMode::Exclusive,
        }
    }
}

pub struct Repo {
    repo_dirf: openat::Dir,
    storage_engine: Box<dyn chunk_storage::Engine>,
    repo_lock: RepoLock,
}

pub enum ItemSyncEvent {
    Start(Xid),
    LogOps(Vec<oplog::LogOp>),
    End,
}

const REPO_LOCK_CTX_TAG: fsutil::FileLockTag = 0xc969b6cb9ba99dc5;
const CURRENT_SCHEMA_VERSION: &str = "6";
const MIN_GC_BLOOM_SIZE: usize = 128 * 1024;
const MAX_GC_BLOOM_SIZE: usize = 0xffffffff; // Current plugin protocol uses 32 bits.

impl Repo {
    pub fn init(
        repo_path: &Path,
        storage_engine: Option<StorageEngineSpec>,
    ) -> Result<(), anyhow::Error> {
        let storage_engine = match storage_engine {
            Some(storage_engine) => storage_engine,
            None => StorageEngineSpec::DirStore,
        };

        if repo_path.exists() {
            anyhow::bail!(
                "{} already exists, remove it and try again",
                repo_path.to_string_lossy().to_string()
            );
        }

        let mut tmpname = repo_path
            .file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new(""))
            .to_os_string();
        tmpname.push(".bupstash-repo-init-tmp");

        let parent = if repo_path.is_absolute() {
            repo_path.parent().unwrap().to_owned()
        } else {
            let abs = std::env::current_dir()?.join(repo_path);
            let parent = abs.parent().unwrap();
            parent.to_owned()
        };

        let mut path_buf = PathBuf::from(&parent);
        path_buf.push(&tmpname);
        if path_buf.exists() {
            anyhow::bail!(
                "temp dir already exists at {}, remove it and try again",
                path_buf.to_string_lossy().to_string()
            );
        }

        fs::DirBuilder::new().create(path_buf.as_path())?;

        path_buf.push("repo.lock");
        fsutil::create_empty_file(path_buf.as_path())?;
        path_buf.pop();

        path_buf.push("tx.lock");
        fsutil::create_empty_file(path_buf.as_path())?;
        path_buf.pop();

        path_buf.push("repo.oplog");
        fsutil::create_empty_file(path_buf.as_path())?;
        path_buf.pop();

        path_buf.push("items");
        std::fs::create_dir(path_buf.as_path())?;
        path_buf.pop();

        path_buf.push("meta");
        {
            std::fs::create_dir(path_buf.as_path())?;
            path_buf.push("gc_generation");
            fsutil::atomic_add_file(path_buf.as_path(), format!("{:x}", Xid::new()).as_bytes())?;
            path_buf.pop();

            path_buf.push("schema_version");
            fsutil::atomic_add_file(
                path_buf.as_path(),
                CURRENT_SCHEMA_VERSION.to_string().as_bytes(),
            )?;
            path_buf.pop();

            path_buf.push("storage_engine");
            let storage_engine_buf = serde_json::to_vec_pretty(&storage_engine)?;
            fsutil::atomic_add_file(path_buf.as_path(), &storage_engine_buf)?;
            path_buf.pop();
        }
        path_buf.pop();

        fsutil::sync_dir(&path_buf)?;
        std::fs::rename(&path_buf, repo_path)?;
        Ok(())
    }

    pub fn open(repo_path: &Path, initial_lock_mode: RepoLockMode) -> Result<Repo, anyhow::Error> {
        let mut repo_path = fsutil::absolute_path(&repo_path)?;

        let repo_dirf = match openat::Dir::open(&repo_path) {
            Ok(dirf) => dirf,
            Err(err) => anyhow::bail!(
                "unable to open repository at {}: {}",
                repo_path.display(),
                err
            ),
        };

        let tx_file_exists = repo_dirf.metadata("tx.lock").is_ok();

        if !tx_file_exists {
            // Handle upgrade from the old sqlite3 repository format.
            repo_path.push("bupstash.sqlite3");
            let sqlite3_db_path = repo_path.clone();
            repo_path.pop();

            if sqlite3_db_path.exists() {
                let default_flags = rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE;
                let mut db = rusqlite::Connection::open_with_flags(sqlite3_db_path, default_flags)?;
                migrate::repo_upgrade_to_5(&mut db, &repo_path)?;
            } else {
                anyhow::bail!(
                    "{} is not an intialized repository",
                    repo_path.to_string_lossy()
                );
            }
        }

        let mut repo_lock = match initial_lock_mode {
            RepoLockMode::None => RepoLock::None,
            RepoLockMode::Shared => RepoLock::Shared(fsutil::FileLock::shared_on_file(
                REPO_LOCK_CTX_TAG,
                repo_dirf.update_file("repo.lock", 0o600)?,
            )?),
            RepoLockMode::Exclusive => RepoLock::Exclusive(fsutil::FileLock::exclusive_on_file(
                REPO_LOCK_CTX_TAG,
                repo_dirf.update_file("repo.lock", 0o600)?,
            )?),
        };

        let mut txn = fstx::ReadTxn::begin(&repo_path)?;
        let mut schema_version = txn.read_string("meta/schema_version")?;
        if schema_version != CURRENT_SCHEMA_VERSION {
            txn.end();
            // Unlock for upgrades, which can lock again if they need to.
            repo_lock = RepoLock::None;

            if schema_version == "5" {
                migrate::repo_upgrade_to_5_to_6(&repo_path)?;
            }
            // restart read transaction we cancelled...
            txn = fstx::ReadTxn::begin_at(repo_dirf.try_clone()?)?;
            schema_version = txn.read_string("meta/schema_version")?;
            if schema_version != CURRENT_SCHEMA_VERSION {
                anyhow::bail!(
                    "the current version of bupstash expects repository schema version {}, got {}",
                    CURRENT_SCHEMA_VERSION,
                    schema_version
                );
            }
        }

        let storage_engine: Box<dyn chunk_storage::Engine> = {
            let mut f = txn.open("meta/storage_engine")?;
            let mut buf = Vec::with_capacity(128);
            f.read_to_end(&mut buf)?;
            let spec: StorageEngineSpec = serde_json::from_slice(&buf)?;
            match spec {
                StorageEngineSpec::DirStore => {
                    let mut data_dir = repo_path;
                    data_dir.push("data");
                    Box::new(dir_chunk_storage::DirStorage::new(&data_dir)?)
                }
                StorageEngineSpec::ExternalStore {
                    socket_path, path, ..
                } => {
                    let socket_path = PathBuf::from(socket_path);
                    Box::new(external_chunk_storage::ExternalStorage::new(
                        &socket_path,
                        &path,
                    )?)
                }
            }
        };

        txn.end();

        Ok(Repo {
            repo_dirf,
            storage_engine,
            repo_lock,
        })
    }

    pub fn pipelined_get_chunks(
        &mut self,
        addresses: &[Address],
        on_chunk: &mut dyn FnMut(&Address, &[u8]) -> Result<(), anyhow::Error>,
    ) -> Result<(), anyhow::Error> {
        self.storage_engine
            .pipelined_get_chunks(addresses, on_chunk)
    }

    pub fn get_chunk(&mut self, addr: &Address) -> Result<Vec<u8>, anyhow::Error> {
        self.storage_engine.get_chunk(addr)
    }

    pub fn add_chunk(&mut self, addr: &Address, buf: Vec<u8>) -> Result<(), anyhow::Error> {
        self.storage_engine.add_chunk(addr, buf)
    }

    pub fn sync(&mut self) -> Result<protocol::SyncStats, anyhow::Error> {
        self.storage_engine.sync()
    }

    pub fn alter_lock_mode(&mut self, lock_mode: RepoLockMode) -> Result<(), anyhow::Error> {
        if self.repo_lock.mode() != lock_mode {
            // Explicit drop of old lock.
            self.repo_lock = RepoLock::None;
            self.repo_lock = match lock_mode {
                RepoLockMode::None => RepoLock::None,
                RepoLockMode::Shared => RepoLock::Shared(fsutil::FileLock::shared_on_file(
                    REPO_LOCK_CTX_TAG,
                    self.repo_dirf.update_file("repo.lock", 0o600)?,
                )?),
                RepoLockMode::Exclusive => {
                    RepoLock::Exclusive(fsutil::FileLock::exclusive_on_file(
                        REPO_LOCK_CTX_TAG,
                        self.repo_dirf.update_file("repo.lock", 0o600)?,
                    )?)
                }
            };

            if matches!(
                self.repo_lock.mode(),
                RepoLockMode::Shared | RepoLockMode::Exclusive
            ) {
                // The gc_dirty id is set when a garbage collection exits without
                // proper cleanup. For external storage engines this poses a problem:
                //
                // Consider the following case:
                //
                // 1. We are deleting a set of objects in an external storage engine.
                // 2. A delete object message is sent to the backing store (s3/gcs/w.e.)
                // 3. The repository process crashes.
                // 4. A new put starts.
                // 5. The new process resends the same object that is in the process of deletion.
                // 6. The delete object message gets processed by the backend.
                //
                // To solve this we:
                // - explicitly start a sweep hold with an id in the storage engine.
                // - we then mark the repository as gc-dirty=id.
                // - we finally signal to the storage engine it is safe to begin sweeping deletions.
                // - when deletions finish successfully, we set can delete the gc-dirty metadata.
                //
                // If during this process, bupstash terminates, gc-dirty will be set.
                // We cannot safely perform and write or gc operations until we are sure that the interrupted
                // gc has safely terminated in the storage engine.
                //
                // To continue gc or write operations we must check the sweep has finished, we must:
                //
                //  - ensure we have a write or exclusive repository lock.
                //  - check gc-dirty is not set, we can then continue with no problems.
                //  - if gc-dirty is set, we must explicitly wait for the storage engine
                //    backend to tell us our sweep operation is complete.
                //  - We can finally remove the gc-dirty marker.

                let mut txn = fstx::WriteTxn::begin_at(self.repo_dirf.try_clone()?)?;
                {
                    let gc_dirty: Option<Xid> = match txn.read_opt_string("meta/gc_dirty")? {
                        Some(s) => Some(Xid::parse(&s)?),
                        None => None,
                    };
                    if let Some(dirty_generation) = gc_dirty {
                        const MAX_DELAY: u64 = 10_000;
                        let mut delay = 500;
                        loop {
                            if self.storage_engine.sweep_completed(dirty_generation)? {
                                txn.add_rm("meta/gc_dirty");
                                break;
                            }
                            std::thread::sleep(std::time::Duration::from_millis(delay));
                            delay = (delay * 2).min(MAX_DELAY);
                        }
                    }
                }
                txn.commit()?;
            }
        }

        Ok(())
    }

    pub fn add_item(
        &mut self,
        id: Xid,
        item: oplog::VersionedItemMetadata,
    ) -> Result<Xid, anyhow::Error> {
        self.alter_lock_mode(RepoLockMode::Shared)?;

        const MAX_HTREE_HEIGHT: u64 = 10;

        if item.data_tree().height.0 > MAX_HTREE_HEIGHT {
            anyhow::bail!("refusing to add data hash tree taller than application limit");
        }
        if let Some(index_tree) = item.index_tree() {
            if index_tree.height.0 > MAX_HTREE_HEIGHT {
                anyhow::bail!("refusing to add index hash tree taller than application limit");
            }
        }

        let mut txn = fstx::WriteTxn::begin_at(self.repo_dirf.try_clone()?)?;
        {
            let serialized_md = oplog::checked_serialize_metadata(&item)?;
            let item_path = format!("items/{:x}", id);
            if txn.file_exists(&item_path)? {
                anyhow::bail!("item id already exists in repository");
            }
            txn.add_write(&item_path, serialized_md);
            let op = oplog::LogOp::AddItem((id, item));
            let serialized_op = serde_bare::to_vec(&op)?;
            txn.add_append("repo.oplog", serialized_op)?;
        }
        txn.commit()?;
        Ok(id)
    }

    pub fn remove_items(&mut self, mut items: Vec<Xid>) -> Result<u64, anyhow::Error> {
        self.alter_lock_mode(RepoLockMode::Shared)?;

        let mut txn = fstx::WriteTxn::begin_at(self.repo_dirf.try_clone()?)?;

        let mut deleted_items = Vec::with_capacity(items.len());

        for item in items.drain(..) {
            let path = format!("items/{:x}", item);
            match txn.metadata(&path) {
                Ok(_) => {
                    txn.add_rm(&path);
                    deleted_items.push(item)
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => (),
                Err(err) => return Err(err.into()),
            };
        }

        let n_deleted = deleted_items.len() as u64;

        if !deleted_items.is_empty() {
            let op = oplog::LogOp::RemoveItems(deleted_items);
            let serialized_op = serde_bare::to_vec(&op)?;
            txn.add_append("repo.oplog", serialized_op)?;
        }
        txn.commit()?;

        Ok(n_deleted)
    }

    pub fn lookup_item_by_id(
        &mut self,
        id: &Xid,
    ) -> Result<Option<oplog::VersionedItemMetadata>, anyhow::Error> {
        let txn = fstx::ReadTxn::begin_at(self.repo_dirf.try_clone()?)?;
        let r = match txn.open(&format!("items/{:x}", id)) {
            Ok(mut f) => {
                let mut buf = Vec::with_capacity(1024);
                f.read_to_end(&mut buf)?;
                Ok(Some(serde_bare::from_slice(&buf)?))
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err.into()),
        };
        txn.end();
        r
    }

    pub fn has_item_with_id(&mut self, id: &Xid) -> Result<bool, anyhow::Error> {
        let txn = fstx::ReadTxn::begin_at(self.repo_dirf.try_clone()?)?;
        let r = match txn.metadata(&format!("items/{:x}", id)) {
            Ok(_) => Ok(true),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(err) => Err(err.into()),
        };
        txn.end();
        r
    }

    pub fn item_sync(
        &mut self,
        after: Option<u64>,
        start_gc_generation: Option<Xid>,
        on_sync_event: &mut dyn FnMut(ItemSyncEvent) -> Result<(), anyhow::Error>,
    ) -> Result<(), anyhow::Error> {
        let txn = fstx::ReadTxn::begin_at(self.repo_dirf.try_clone()?)?;

        let current_gc_generation: Xid = Xid::parse(&txn.read_string("meta/gc_generation")?)?;
        let after = match start_gc_generation {
            Some(start_gc_generation) if start_gc_generation == current_gc_generation => after,
            _ => None,
        };

        // Open the files and collect metadata during the transaction.
        // We are able to close the transaction once we have these files open
        // as we never modify an open op.log or op.tx except via appending.
        let mut log_file = txn.open("repo.oplog")?;
        let log_meta = log_file.metadata()?;
        txn.end();

        if let Some(after) = after {
            log_file.seek(std::io::SeekFrom::Start(after))?;
        };

        on_sync_event(ItemSyncEvent::Start(current_gc_generation))?;

        const BATCH_SIZE: usize = 64;
        let mut op_batch = Vec::with_capacity(BATCH_SIZE);
        // We limit the size of the log file to what it was when the read txn happend.
        // this lets slow clients keep syncing while other transactions continue.
        let log_file = log_file.take(log_meta.size() - after.unwrap_or(0));
        let mut log_file = std::io::BufReader::new(log_file);
        let mut done = false;

        if after.is_some() {
            // We discard the first item after bsearch, client has seen this before.
            serde_bare::from_reader::<_, oplog::LogOp>(&mut log_file)?;
        }

        while !done {
            while op_batch.len() < BATCH_SIZE {
                if log_file.fill_buf()?.is_empty() {
                    done = true;
                    break;
                }
                let op: oplog::LogOp = serde_bare::from_reader(&mut log_file)?;
                op_batch.push(op);
            }

            if !op_batch.is_empty() {
                let mut send_batch = Vec::with_capacity(if !done { BATCH_SIZE } else { 0 });
                std::mem::swap(&mut send_batch, &mut op_batch);
                on_sync_event(ItemSyncEvent::LogOps(send_batch))?;
            }
        }

        on_sync_event(ItemSyncEvent::End)?;

        Ok(())
    }

    pub fn recover_removed(&mut self) -> Result<u64, anyhow::Error> {
        self.alter_lock_mode(RepoLockMode::Shared)?;

        let mut txn = fstx::WriteTxn::begin_at(self.repo_dirf.try_clone()?)?;

        let mut n_restored = 0;
        let log_file = txn.open("repo.oplog")?;
        let mut log_file = std::io::BufReader::new(log_file);

        while !log_file.fill_buf()?.is_empty() {
            let op = serde_bare::from_reader(&mut log_file)?;
            if let oplog::LogOp::AddItem((id, md)) = op {
                let p = format!("items/{:x}", id);
                match txn.metadata(&p) {
                    Ok(_) => (),
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                        let serialized_md = serde_bare::to_vec(&md)?;
                        txn.add_write(&p, serialized_md);
                        n_restored += 1;
                    }
                    Err(err) => return Err(err.into()),
                }
            }
        }

        if n_restored != 0 {
            let op = oplog::LogOp::RecoverRemoved;
            let serialized_op = serde_bare::to_vec(&op)?;
            txn.add_append("repo.oplog", serialized_op)?;
        }

        txn.commit()?;

        Ok(n_restored)
    }

    pub fn gc_generation(&mut self) -> Result<Xid, anyhow::Error> {
        let txn = fstx::ReadTxn::begin_at(self.repo_dirf.try_clone()?)?;
        let gc_generation = Xid::parse(&txn.read_string("meta/gc_generation")?)?;
        txn.end();
        Ok(gc_generation)
    }

    pub fn gc(
        &mut self,
        update_progress_msg: &mut dyn FnMut(String) -> Result<(), anyhow::Error>,
    ) -> Result<GcStats, anyhow::Error> {
        // Start with a shared lock, by the end we will have an exclusive lock.
        self.alter_lock_mode(RepoLockMode::Shared)?;

        let gc_generation = Xid::new();

        update_progress_msg("walking reachable data...".to_string())?;

        let estimated_chunk_count = self.storage_engine.estimate_chunk_count()?;
        let reachable_bloom_mem_size =
            abloom::approximate_mem_size_upper_bound(0.02, estimated_chunk_count)
                .min(MAX_GC_BLOOM_SIZE)
                .max(MIN_GC_BLOOM_SIZE);

        // Set of item ids we have walked before.
        let mut xid_wset = HashSet::with_capacity(65536);
        // Fixed size cache of addresses we have walked before.
        let mut address_wcache = acache::ACache::new(1048576);
        // Bloom filter used in the sweep phase.
        let mut reachable = abloom::ABloom::new(reachable_bloom_mem_size);

        let mut walk_item = |storage_engine: &mut dyn chunk_storage::Engine,
                             metadata: oplog::VersionedItemMetadata|
         -> Result<(), anyhow::Error> {
            // For garbage collection walking in order is not a concern,
            // we just need to ensure we touch each reachable node.
            //
            // Note that we could also do some sort of pipelining or parallel fetch,
            // when we walk the tree, for now keep it simple.

            let data_tree = metadata.data_tree();

            let trees = if let Some(index_tree) = metadata.index_tree() {
                vec![data_tree, index_tree]
            } else {
                vec![data_tree]
            };

            for tree in trees {
                let mut tr = htree::TreeReader::new(
                    tree.height.0.try_into()?,
                    tree.data_chunk_count.0,
                    &tree.address,
                );

                while let Some((height, addr)) = tr.next_addr() {
                    reachable.add(&addr);

                    if height != 0 && address_wcache.add(&addr) {
                        let data = storage_engine.get_chunk(&addr)?;
                        let data = compression::unauthenticated_decompress(data)?;
                        tr.push_level(height - 1, data)?;
                    }
                }
            }
            Ok(())
        };

        let mut walk_items =
            |repo_dirf: openat::Dir,
             update_progress_msg: &mut dyn FnMut(String) -> Result<(), anyhow::Error>,
             storage_engine: &mut dyn chunk_storage::Engine|
             -> Result<(), anyhow::Error> {
                let txn = fstx::ReadTxn::begin_at(repo_dirf)?;

                let mut items_dir_ents: Vec<_> = txn.read_dir("items")?.collect();
                let mut reachable_items = HashSet::with_capacity(items_dir_ents.len());

                for item in items_dir_ents.drain(..) {
                    let item = item?;
                    let item_id_string = item.file_name().to_string_lossy();
                    let item_id = Xid::parse(&item_id_string)?;
                    reachable_items.insert(item_id);
                }

                let update_delay_millis = std::time::Duration::from_millis(500);
                let mut last_progress_update = std::time::Instant::now()
                    .checked_sub(update_delay_millis)
                    .unwrap();

                let mut i = 1; // Start at 1, the progress update is item 1/N.

                let log_file = txn.open("repo.oplog")?;
                let log_meta = log_file.metadata()?;
                // It's an explicit guarantee we make that op logs are only appended to, so
                // we can get a consistent snapshot of the log by limiting our reads to
                // what was present when we were in our read transaction.
                let log_file = log_file.take(log_meta.size());
                let mut log_file = std::io::BufReader::new(log_file);
                // We close the transaction so other operations can continue concurrently
                // while we are walking the log.
                txn.end();

                while !log_file.fill_buf()?.is_empty() {
                    let op = serde_bare::from_reader(&mut log_file)?;
                    if let oplog::LogOp::AddItem((item_id, metadata)) = op {
                        if !reachable_items.contains(&item_id) {
                            continue;
                        }
                        if !xid_wset.insert(item_id) {
                            continue;
                        }
                        // Put a rate limit on updates but always show
                        // the last item, this just looks better.
                        if last_progress_update.elapsed() >= update_delay_millis
                            || i == reachable_items.len()
                        {
                            last_progress_update = std::time::Instant::now();
                            update_progress_msg(format!(
                                "walking item {}/{}...",
                                i,
                                reachable_items.len()
                            ))?;
                        }
                        walk_item(storage_engine, metadata)?;
                        i += 1;
                    }
                }

                Ok(())
            };

        // Walk all reachable data WITHOUT locking the repository.
        // We should be able to walk most of the data except data
        // that arrives between the end of this walk and us locking
        // the repository.
        walk_items(
            self.repo_dirf.try_clone()?,
            update_progress_msg,
            &mut *self.storage_engine,
        )?;

        // From this point on, nobody else is modifying the repository.
        update_progress_msg("getting exclusive repository lock...".to_string())?;
        self.alter_lock_mode(RepoLockMode::Exclusive)?;

        // Signal to the storage engine a sweep is about to begin,
        // this marks a sweep in progress for this gc_generation such that it
        // can't be removed until the storage engine confirms it has terminated.
        // It *MUST* be done before the gc_dirty flag is set. This then operates
        // as a two phase commit preventing a new put from happening before the
        // external plugin process has finished sweeping.
        self.storage_engine.prepare_for_sweep(gc_generation)?;

        update_progress_msg("compacting repository log...".to_string())?;
        {
            let mut txn = fstx::WriteTxn::begin_at(self.repo_dirf.try_clone()?)?;

            // We cycle the gc generation here to invalidate client caches.
            txn.add_write(
                "meta/gc_generation",
                format!("{:x}", gc_generation).into_bytes(),
            );

            // If a repository is dirty when we lock it, then we must ensure
            // the storage backend has terminated before continuing.
            txn.add_write("meta/gc_dirty", format!("{:x}", gc_generation).into_bytes());

            // We compact the op log in the same transaction the the gc-generation
            // is cycled to keep client query caches consistent. They rely on the
            // gc-generation being in sync with any oplog changes.
            //
            // Another case to consider is if we split the compaction to another
            // transaction and the external storage engine crashes and then marks
            // the gc as complete, we must ensure that gc-dirty is still valid
            // for any compaction operations we perform.

            let log_file = txn.open("repo.oplog")?;
            let mut log_file = std::io::BufReader::new(log_file);
            let mut compacted_log = std::io::BufWriter::new(fsutil::anon_temp_file()?);

            while !log_file.fill_buf()?.is_empty() {
                let op = serde_bare::from_reader(&mut log_file)?;
                if let oplog::LogOp::AddItem((id, md)) = op {
                    let p = format!("items/{:x}", id);
                    match txn.metadata(&p) {
                        Ok(_) => {
                            compacted_log.write_all(&serde_bare::to_vec(
                                &oplog::LogOp::AddItem((id, md)),
                            )?)?;
                        }
                        Err(err) if err.kind() == std::io::ErrorKind::NotFound => (),
                        Err(err) => return Err(err.into()),
                    }
                }
            }

            compacted_log.flush()?;
            txn.add_write_from_file("repo.oplog", compacted_log.into_inner()?);

            txn.commit()?;
        }

        update_progress_msg("finalizing reachable data...".to_string())?;
        // Now that we have gc_dirty marked, and have effectively locked the storage
        // engine, we walk all the items again, this will be fast for items we already walked, and
        // lets us pick up any new items that arrived between the old walk and before we marked gc_dirty.
        walk_items(
            self.repo_dirf.try_clone()?,
            update_progress_msg,
            &mut *self.storage_engine,
        )?;

        if std::env::var("BUPSTASH_DEBUG_GC").is_ok() {
            eprintln!("dbg_gc_estimated_chunk_count={}", estimated_chunk_count);
            eprintln!("dbg_gc_reachable_bloom_mem_size={}", reachable.mem_size());
            eprintln!(
                "dbg_gc_reachable_bloom_utilization={}",
                reachable.estimate_utilization()
            );
            eprintln!(
                "dbg_gc_reachable_bloom_estimated_false_positive_rate={}",
                reachable.estimate_false_positive_rate()
            );
            eprintln!(
                "dbg_gc_reachable_bloom_estimated_add_count={}",
                reachable.estimate_add_count()
            );
            eprintln!("dbg_gc_xid_walk_set_size={}", xid_wset.len(),);
            eprintln!(
                "dbg_gc_address_walk_cache_hit_count={}/{}",
                address_wcache.hit_count, address_wcache.add_count
            );
            eprintln!(
                "dbg_gc_address_walk_cache_utilization={}",
                address_wcache.utilization()
            );
        }

        // Drop the caches, we no longer need to free this memory for the storage engine.
        std::mem::drop(xid_wset);
        std::mem::drop(address_wcache);

        let stats = self.storage_engine.sweep(update_progress_msg, reachable)?;

        // We are now done and can stop, mark the gc as complete.
        {
            let mut txn = fstx::WriteTxn::begin_at(self.repo_dirf.try_clone()?)?;

            let gc_dirty: Option<Xid> = match txn.read_opt_string("meta/gc_dirty")? {
                Some(s) => Some(Xid::parse(&s)?),
                None => None,
            };

            // Only clear this collection dirty flag.
            if gc_dirty == Some(gc_generation) {
                txn.add_rm("meta/gc_dirty");
            }

            txn.commit()?;
        }

        Ok(stats)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Tests are serial due to our file lock context system.
    use serial_test::serial;

    #[test]
    #[serial]
    fn dir_store_sanity_test() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let mut path_buf = PathBuf::from(tmp_dir.path());
        path_buf.push("repo");
        Repo::init(path_buf.as_path(), Some(StorageEngineSpec::DirStore)).unwrap();
        let mut repo = Repo::open(path_buf.as_path(), RepoLockMode::Exclusive).unwrap();
        let addr = Address::default();
        repo.add_chunk(&addr, vec![1]).unwrap();
        repo.sync().unwrap();
        repo.add_chunk(&addr, vec![2]).unwrap();
        repo.sync().unwrap();
        let v = repo.get_chunk(&addr).unwrap();
        assert_eq!(v, vec![1]);
    }
}
