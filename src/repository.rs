use super::abloom;
use super::acache;
use super::address::*;
use super::chunk_storage;
use super::compression;
use super::dir_chunk_storage;
use super::external_chunk_storage;
use super::fsutil;
use super::htree;
use super::itemset;
use super::protocol;
use super::xid::*;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::fs;
use std::io::Read;
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

pub struct Repo {
    conn: rusqlite::Connection,
    storage_engine: Box<dyn chunk_storage::Engine>,
}

pub enum ItemSyncEvent {
    Start(Xid),
    LogOps(Vec<(i64, Option<Xid>, itemset::LogOp)>),
    End,
}

pub enum GcStatus {
    Running(Xid),
    Complete(Xid),
}

const MIN_GC_BLOOM_SIZE: usize = 128 * 1024;
const MAX_GC_BLOOM_SIZE: usize = 1024 * 1024 * 1024;

impl Repo {
    fn repo_db_path(repo_path: &Path) -> PathBuf {
        let mut db_path = repo_path.to_path_buf();
        db_path.push("bupstash.sqlite3");
        db_path
    }

    fn open_db_with_flags(
        db_path: &Path,
        flags: rusqlite::OpenFlags,
    ) -> Result<rusqlite::Connection, anyhow::Error> {
        let conn = rusqlite::Connection::open_with_flags(db_path, flags)?;

        conn.query_row("pragma busy_timeout=3600000;", rusqlite::NO_PARAMS, |_r| {
            Ok(())
        })?;

        Ok(conn)
    }

    fn open_db(db_path: &Path) -> Result<rusqlite::Connection, anyhow::Error> {
        let default_flags = rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE;
        Repo::open_db_with_flags(db_path, default_flags)
    }

    pub fn init(
        repo_path: &Path,
        storage_engine: Option<StorageEngineSpec>,
    ) -> Result<(), anyhow::Error> {
        let storage_engine = match storage_engine {
            Some(storage_engine) => storage_engine,
            None => StorageEngineSpec::DirStore,
        };

        let parent = if repo_path.is_absolute() {
            repo_path.parent().unwrap().to_owned()
        } else {
            let abs = std::env::current_dir()?.join(repo_path);
            let parent = abs.parent().unwrap();
            parent.to_owned()
        };

        let mut path_buf = PathBuf::from(&parent);
        if repo_path.exists() {
            anyhow::bail!(
                "repository already exists at {}",
                repo_path.to_string_lossy().to_string()
            );
        }

        let mut tmpname = repo_path
            .file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new(""))
            .to_os_string();
        tmpname.push(".bupstash-repo-init-tmp");
        path_buf.push(&tmpname);
        if path_buf.exists() {
            anyhow::bail!(
                "temp dir already exists at {}",
                path_buf.to_string_lossy().to_string()
            );
        }

        fs::DirBuilder::new().create(path_buf.as_path())?;

        path_buf.push("repo.lock");
        fsutil::create_empty_file(path_buf.as_path())?;
        path_buf.pop();

        path_buf.push("storage-engine.json");
        let storage_engine_buf = serde_json::to_vec_pretty(&storage_engine)?;
        fsutil::atomic_add_file(path_buf.as_path(), &storage_engine_buf)?;
        path_buf.pop();

        let mut conn = Repo::open_db_with_flags(
            &Repo::repo_db_path(&path_buf),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_CREATE,
        )?;

        conn.query_row(
            "PRAGMA journal_mode = WAL;",
            rusqlite::NO_PARAMS,
            |_| Ok(()),
        )?;

        let tx = conn.transaction()?;

        tx.execute(
            "create table RepositoryMeta(Key primary key, Value) without rowid;",
            rusqlite::NO_PARAMS,
        )?;
        tx.execute(
            /* Schema version is a string to keep all meta rows the same type. */
            "insert into RepositoryMeta(Key, Value) values('schema-version', '4');",
            rusqlite::NO_PARAMS,
        )?;
        tx.execute(
            "insert into RepositoryMeta(Key, Value) values('id', ?);",
            rusqlite::params![Xid::new()],
        )?;
        tx.execute(
            "insert into RepositoryMeta(Key, Value) values('gc-generation', ?);",
            rusqlite::params![Xid::new()],
        )?;
        tx.execute(
            "insert into RepositoryMeta(Key, Value) values('gc-dirty', Null);",
            rusqlite::NO_PARAMS,
        )?;

        itemset::init_tables(&tx)?;

        tx.commit()?;
        drop(conn);

        fsutil::sync_dir(&path_buf)?;
        std::fs::rename(&path_buf, repo_path)?;
        Ok(())
    }

    fn upgrade_2_to_3(
        conn: &mut rusqlite::Connection,
        repo_path: &Path,
    ) -> Result<(), anyhow::Error> {
        eprintln!("upgrading repository schema from version 2 to version 3...");

        let repo_lock = {
            let mut lock_path = repo_path.to_owned();
            lock_path.push("repo.lock");
            fsutil::FileLock::try_get_exclusive(&lock_path)?
        };

        // We no longer need the temporary directory.
        {
            let mut tmp_dir = repo_path.to_owned();
            tmp_dir.push("tmp");
            if tmp_dir.exists() {
                std::fs::remove_dir_all(&tmp_dir)?;
            }
        }

        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

        tx.execute(
            "update RepositoryMeta set value = '3' where key = 'schema-version';",
            rusqlite::NO_PARAMS,
        )?;

        tx.commit()?;
        drop(repo_lock);

        eprintln!("repository upgrade successful...");
        Ok(())
    }

    fn upgrade_3_to_4(
        conn: &mut rusqlite::Connection,
        _repo_path: &Path,
    ) -> Result<(), anyhow::Error> {
        eprintln!("upgrading repository schema from version 3 to version 4...");
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        // Invalidate client side caches that would not understand the new metadata format.
        tx.execute(
            "update RepositoryMeta set Value = ? where Key = 'gc-generation';",
            rusqlite::params![&Xid::new()],
        )?;
        tx.execute(
            "update RepositoryMeta set value = '4' where key = 'schema-version';",
            rusqlite::NO_PARAMS,
        )?;
        tx.commit()?;
        eprintln!("repository upgrade successful...");
        Ok(())
    }

    pub fn open(repo_path: &Path) -> Result<Repo, anyhow::Error> {
        if !repo_path.exists() {
            anyhow::bail!("no repository at {}", repo_path.to_string_lossy());
        }

        let repo_path = fs::canonicalize(&repo_path)?;

        let mut conn = Repo::open_db(&Repo::repo_db_path(&repo_path))?;

        let v: String = conn.query_row(
            "select Value from RepositoryMeta where Key='schema-version';",
            rusqlite::NO_PARAMS,
            |row| row.get(0),
        )?;

        let mut schema_version = v.parse::<u64>().unwrap();

        // We should be able to phase these checks out as versions age.
        if schema_version == 2 {
            Repo::upgrade_2_to_3(&mut conn, &repo_path)?;
            schema_version = 3;
        }

        if schema_version == 3 {
            Repo::upgrade_3_to_4(&mut conn, &repo_path)?;
            schema_version = 4;
        }

        if schema_version != 4 {
            anyhow::bail!(
                "repository has an unsupported schema version, want 4, got {}",
                schema_version
            );
        }

        let storage_engine: Box<dyn chunk_storage::Engine> = {
            let mut p = repo_path.clone();
            p.push("storage-engine.json");
            let mut f = std::fs::OpenOptions::new().read(true).open(p)?;
            let mut buf = Vec::new();
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

        Ok(Repo {
            conn,
            storage_engine,
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

    fn gc_dirty_check(
        tx: &rusqlite::Transaction,
        storage_engine: &mut Box<dyn chunk_storage::Engine>,
        busy_msg: &'static str,
    ) -> Result<(), anyhow::Error> {
        let gc_dirty: Option<Xid> = tx.query_row(
            "select Value from RepositoryMeta where Key='gc-dirty';",
            rusqlite::NO_PARAMS,
            |row| row.get(0),
        )?;

        if let Some(dirty_generation) = gc_dirty {
            if !storage_engine.gc_completed(dirty_generation)? {
                anyhow::bail!(busy_msg);
            }
            tx.execute(
                "update RepositoryMeta set Value = null where Key = 'gc-dirty' and Value = ?;",
                rusqlite::params![&dirty_generation],
            )?;
        }

        Ok(())
    }

    pub fn add_item(
        &mut self,
        gc_generation: Xid,
        item: itemset::VersionedItemMetadata,
    ) -> Result<Xid, anyhow::Error> {
        const MAX_HTREE_HEIGHT: u64 = 10;

        if item.data_tree().height.0 > MAX_HTREE_HEIGHT {
            anyhow::bail!("refusing to add data hash tree taller than application limit");
        }
        if let Some(index_tree) = item.index_tree() {
            if index_tree.height.0 > MAX_HTREE_HEIGHT {
                anyhow::bail!("refusing to add index hash tree taller than application limit");
            }
        }

        let tx = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

        Repo::gc_dirty_check(
            &tx,
            &mut self.storage_engine,
            "cannot add item while garbage collection is in progress",
        )?;

        let current_gc_generation = tx.query_row(
            "select Value from RepositoryMeta where Key='gc-generation';",
            rusqlite::NO_PARAMS,
            |row| row.get(0),
        )?;

        if gc_generation != current_gc_generation {
            anyhow::bail!("garbage collection invalidated upload, try again");
        }

        let id = itemset::add_item(&tx, item)?;
        tx.commit()?;
        Ok(id)
    }

    pub fn remove_items(&mut self, items: Vec<Xid>) -> Result<(), anyhow::Error> {
        let tx = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

        Repo::gc_dirty_check(
            &tx,
            &mut self.storage_engine,
            "cannot remove items while garbage collection is in progress",
        )?;

        itemset::remove_items(&tx, items)?;
        tx.commit()?;
        Ok(())
    }

    pub fn lookup_item_by_id(
        &mut self,
        id: &Xid,
    ) -> Result<Option<itemset::VersionedItemMetadata>, anyhow::Error> {
        let tx = self.conn.transaction()?;
        itemset::lookup_item_by_id(&tx, id)
    }

    pub fn has_item_with_id(&mut self, id: &Xid) -> Result<bool, anyhow::Error> {
        let tx = self.conn.transaction()?;
        itemset::has_item_with_id(&tx, id)
    }

    pub fn item_sync(
        &mut self,
        after: i64,
        start_gc_generation: Option<Xid>,
        on_sync_event: &mut dyn FnMut(ItemSyncEvent) -> Result<(), anyhow::Error>,
    ) -> Result<(), anyhow::Error> {
        let tx = self.conn.transaction()?;

        let current_gc_generation = tx.query_row(
            "select Value from RepositoryMeta where Key='gc-generation';",
            rusqlite::NO_PARAMS,
            |row| row.get(0),
        )?;

        let after = match start_gc_generation {
            Some(start_gc_generation) if start_gc_generation == current_gc_generation => after,
            _ => -1,
        };

        on_sync_event(ItemSyncEvent::Start(current_gc_generation))?;

        let mut logops = Vec::new();

        itemset::walk_log(&tx, after, &mut |op_id, item_id, op| {
            logops.push((op_id, item_id, op));
            if logops.len() >= 64 {
                let mut v = Vec::new();
                std::mem::swap(&mut v, &mut logops);
                on_sync_event(ItemSyncEvent::LogOps(v))?;
            }
            Ok(())
        })?;

        if !logops.is_empty() {
            on_sync_event(ItemSyncEvent::LogOps(logops))?;
        }

        on_sync_event(ItemSyncEvent::End)?;

        tx.commit()?;

        Ok(())
    }

    pub fn restore_removed(&mut self) -> Result<u64, anyhow::Error> {
        let tx = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

        Repo::gc_dirty_check(
            &tx,
            &mut self.storage_engine,
            "cannot restore items while garbage collection is in progress",
        )?;

        let n_restored = itemset::restore_removed(&tx)?;
        if n_restored > 0 {
            tx.commit()?;
        }
        Ok(n_restored)
    }

    pub fn gc_status(&mut self) -> Result<GcStatus, anyhow::Error> {
        let tx = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

        let gc_dirty: Option<Xid> = tx.query_row(
            "select Value from RepositoryMeta where Key='gc-dirty';",
            rusqlite::NO_PARAMS,
            |row| row.get(0),
        )?;

        let status = if let Some(gc_generation) = gc_dirty {
            if self.storage_engine.gc_completed(gc_generation)? {
                tx.execute(
                    "update RepositoryMeta set Value = null where Key = 'gc-dirty' and Value = ?;",
                    rusqlite::params![&gc_generation],
                )?;
                GcStatus::Complete(gc_generation)
            } else {
                GcStatus::Running(gc_generation)
            }
        } else {
            let gc_generation = tx.query_row(
                "select Value from RepositoryMeta where Key='gc-generation';",
                rusqlite::NO_PARAMS,
                |row| row.get(0),
            )?;
            GcStatus::Complete(gc_generation)
        };

        tx.commit()?;
        Ok(status)
    }

    pub fn gc(
        &mut self,
        update_progress_msg: &mut dyn FnMut(String) -> Result<(), anyhow::Error>,
    ) -> Result<GcStats, anyhow::Error> {
        let gc_generation = Xid::new();
        let storage_engine = &mut self.storage_engine;
        let conn = &mut self.conn;

        // Initial check that can clear any stale garbage collections that
        // have already finished. We might be able to do this in the compaction
        // transaction with some refactoring.
        {
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

            Repo::gc_dirty_check(
                &tx,
                storage_engine,
                "garbage collection already in progress",
            )?;

            tx.commit()?;
        }

        // Signal to the storage engine a gc is about to begin, this involves marking a gc
        // in progress for this gc_generation such that it can't be removed until the
        // storage engine confirms it has terminated.
        storage_engine.prepare_for_gc(gc_generation)?;

        update_progress_msg("walking reachable data...".to_string())?;

        let estimated_chunk_count = storage_engine.estimate_chunk_count()?;
        let reachable_bloom_mem_size =
            abloom::approximate_mem_size_upper_bound(0.02, estimated_chunk_count)
                .min(MAX_GC_BLOOM_SIZE)
                .max(MIN_GC_BLOOM_SIZE);

        // Set of item ids we have walked before.
        let mut xid_wset = std::collections::HashSet::with_capacity(65536);
        // Fixed size cache of addresses we have walked before.
        let mut address_wcache = acache::ACache::new(65536);
        // Bloom filter used in the sweep phase.
        let mut reachable = abloom::ABloom::new(reachable_bloom_mem_size);

        let mut walk_item = |_op_id, item_id, metadata: itemset::VersionedItemMetadata| {
            if !xid_wset.insert(item_id) {
                return Ok(());
            }

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

        // Walk all reachable data WITHOUT marking the repository as
        // gc_dirty, we should be able to walk most of the data except data
        // that arrives between the end of this walk and us marking
        // gc_dirty in the repository.
        {
            let tx = conn.transaction()?;
            itemset::walk_items(&tx, &mut walk_item)?;
            tx.commit()?;
        }

        update_progress_msg("compacting item log...".to_string())?;
        {
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

            let gc_dirty: Option<Xid> = tx.query_row(
                "select Value from RepositoryMeta where Key='gc-dirty';",
                rusqlite::NO_PARAMS,
                |row| row.get(0),
            )?;

            // We must check this again in case it changed since the initial check.
            if gc_dirty.is_some() {
                anyhow::bail!("garbage collection already in progress");
            }

            // We cycle the gc generation here to invalidate client caches.
            tx.execute(
                "update RepositoryMeta set Value = ? where Key = 'gc-generation';",
                rusqlite::params![&gc_generation],
            )?;

            // If a repository is dirty when we lock it, then we must ensure
            // the storage backend has terminated before continuing.
            tx.execute(
                "update RepositoryMeta set Value = ? where Key = 'gc-dirty';",
                rusqlite::params![&gc_generation],
            )?;

            // We compact the item set in the same transaction the the gc-generation
            // is cycled to keep client query caches consistent. They rely on the
            // gc-generation being in sync with any oplog changes.
            //
            // Another case to consider is if we split the compaction to another
            // transaction and the external storage engine crashes and then marks
            // the gc as complete, we must ensure that gc-dirty is still valid
            // for any compaction operations we perform.
            itemset::compact(&tx)?;

            tx.commit()?;

            // It doesn't really matter when we run this, sqlite handles locking for us here.
            conn.execute("vacuum;", rusqlite::NO_PARAMS)?;
        }

        update_progress_msg("finalizing reachable data...".to_string())?;
        // Now that we have gc_dirty marked, and have effectively locked the storage
        // engine, we walk all the items again, this will be fast for items we already walked, and
        // lets us pick up any new items that arrived between the old walk and before we marked gc_dirty.
        {
            let tx = conn.transaction()?;
            itemset::walk_items(&tx, &mut walk_item)?;
            tx.commit()?;
        }

        if std::env::var("BUPSTASH_DEBUG_GC").is_ok() {
            eprintln!("dbg_gc_estimated_chunk_count={}", estimated_chunk_count);
            eprintln!("dbg_gc_reachable_bloom_size={}", reachable.mem_size());
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

        update_progress_msg("deleting unused chunks...".to_string())?;
        let stats = self.storage_engine.gc(reachable)?;

        // We are now done and can stop, mark the gc as complete.
        conn.execute(
            "update RepositoryMeta set Value = null where Key = 'gc-dirty' and Value = ?;",
            rusqlite::params![&gc_generation],
        )?;

        Ok(stats)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dir_store_sanity_test() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let mut path_buf = PathBuf::from(tmp_dir.path());
        path_buf.push("repo");
        Repo::init(path_buf.as_path(), Some(StorageEngineSpec::DirStore)).unwrap();
        let mut repo = Repo::open(path_buf.as_path()).unwrap();
        let addr = Address::default();
        repo.add_chunk(&addr, vec![1]).unwrap();
        repo.sync().unwrap();
        repo.add_chunk(&addr, vec![2]).unwrap();
        repo.sync().unwrap();
        let v = repo.get_chunk(&addr).unwrap();
        assert_eq!(v, vec![1]);
    }
}
