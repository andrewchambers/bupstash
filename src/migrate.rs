// This file contains code to perform repository migrations.
// The code here is often deliberately duplicated and avoids dependencies
// on other modules so that the upgrade migration code can avoid churn with
// other changes.
use super::fstx;
use super::fsutil;
use super::oplog;
use super::xid;
use std::collections::HashSet;
use std::io::BufRead;
use std::path::Path;

// This lock context tag is duplicated from repository to make migrate a stand alone module.
const REPO_LOCK_CTX_TAG: fsutil::FileLockTag = 0xc969b6cb9ba99dc5;

fn repo_upgrade_2_to_3(
    conn: &mut rusqlite::Connection,
    repo_path: &Path,
) -> Result<(), anyhow::Error> {
    eprintln!("upgrading repository schema from version 2 to version 3...");

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
        [],
    )?;

    tx.commit()?;

    eprintln!("repository upgrade successful...");
    Ok(())
}

fn repo_upgrade_3_to_4(
    conn: &mut rusqlite::Connection,
    _repo_path: &Path,
) -> Result<(), anyhow::Error> {
    eprintln!("upgrading repository schema from version 3 to version 4...");
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    // Invalidate client side caches that would not understand the new metadata format.
    tx.execute(
        "update RepositoryMeta set Value = ? where Key = 'gc-generation';",
        rusqlite::params![&xid::Xid::new()],
    )?;
    tx.execute(
        "update RepositoryMeta set value = '4' where key = 'schema-version';",
        [],
    )?;
    tx.commit()?;
    eprintln!("repository upgrade successful...");
    Ok(())
}

fn repo_upgrade_4_to_5(
    conn: &mut rusqlite::Connection,
    repo_path: &Path,
) -> Result<(), anyhow::Error> {
    eprintln!("upgrading repository schema from version 4 to version 5...");
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    // Convert all AddItem(md) to AddItem((ItemId, md)).
    tx.execute(
        "update ItemOpLog set OpData =
         cast((substr(OpData, 1, 1) || ItemId || substr(OpData, 2)) as blob) where ItemId is not null;",
         [])?;
    // Create the new directories so that we can use fstx.
    let mut p = repo_path.to_owned();
    p.push("storage-engine.json");
    let storage_engine = std::fs::read(&p)?;
    p.pop();

    {
        p.push("meta");
        if !p.exists() {
            std::fs::create_dir(&p)?;
        }
        p.pop();

        p.push("tx.lock");
        if !p.exists() {
            fsutil::create_empty_file(&p)?;
        }
        p.pop();

        p.push("items");
        if !p.exists() {
            std::fs::create_dir(&p)?;
        }
        p.pop();
        fsutil::sync_dir(&p)?;
    }

    let mut fstx = fstx::WriteTxn::begin(&p)?;
    {
        fstx.add_write(
            "meta/gc_generation",
            format!("{:x}", xid::Xid::new()).into_bytes(),
        )?;
        fstx.add_write("meta/storage_engine", storage_engine)?;
        fstx.add_write("meta/schema_version", "5".to_string().into_bytes())?;
        fstx.add_write_from_file("repo.oplog", fsutil::anon_temp_file()?)?;

        let mut stmt = tx.prepare("select OpData from ItemOpLog order by OpId;")?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let op: Vec<u8> = row.get(0)?;
            fstx.add_append("repo.oplog", op)?;
        }

        let mut stmt = tx.prepare("select ItemId, Metadata from Items;")?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let item_id: xid::Xid = row.get(0)?;
            let metadata: Vec<u8> = row.get(1)?;
            fstx.add_write(&format!("items/{:x}", item_id), metadata)?;
        }
    }
    fstx.commit()?;

    // no need to commit our changes to the database.
    tx.rollback()?;

    p.push("storage-engine.json");
    std::fs::remove_file(&p)?;
    p.pop();
    p.push("bupstash.sqlite3");
    std::fs::remove_file(&p)?;
    p.pop();
    p.push("bupstash.sqlite3-shm");
    if p.exists() {
        std::fs::remove_file(&p)?;
    }
    p.pop();
    p.push("bupstash.sqlite3-wal");
    if p.exists() {
        std::fs::remove_file(&p)?;
    }
    p.pop();

    eprintln!("repository upgrade successful...");
    Ok(())
}

pub fn repo_upgrade_to_5(
    db: &mut rusqlite::Connection,
    repo_path: &Path,
) -> Result<(), anyhow::Error> {
    let v: String = db.query_row(
        "select Value from RepositoryMeta where Key='schema-version';",
        [],
        |row| row.get(0),
    )?;
    let mut schema_version = v.parse::<u64>()?;

    if schema_version == 2 {
        repo_upgrade_2_to_3(db, repo_path)?;
        schema_version = 3;
    }

    if schema_version == 3 {
        repo_upgrade_3_to_4(db, repo_path)?;
        schema_version = 4;
    }

    if schema_version == 4 {
        repo_upgrade_4_to_5(db, repo_path)?;
        schema_version = 5;
    }

    if schema_version != 5 {
        anyhow::bail!(
            "repository has an unsupported schema version - {}",
            schema_version
        );
    }

    Ok(())
}

pub fn repo_upgrade_to_5_to_6(repo_path: &Path) -> Result<(), anyhow::Error> {
    // This upgrade mainly just prevents clients from seeing index entries they
    // cannot decode... repositories of version 5 and 6 are compatible except
    // for an additional index entry type.
    // This upgrade simply increments the schema version.
    eprintln!("upgrading repository schema from version 5 to version 6...");

    eprintln!("getting exclusive repository lock for upgrade...");
    let lock_path = {
        let mut p = repo_path.to_owned();
        p.push("repo.lock");
        p
    };
    let lock = fsutil::FileLock::get_exclusive(REPO_LOCK_CTX_TAG, &lock_path)?;

    let mut fstx = fstx::WriteTxn::begin(repo_path)?;
    let schema_version = fstx.read_string("meta/schema_version")?;
    if schema_version != "5" {
        anyhow::bail!(
            "unable to upgrade, expected schema version 5, got {}",
            schema_version
        )
    }
    fstx.add_write("meta/schema_version", "6".to_string().into_bytes())?;
    fstx.commit()?;
    eprintln!("repository upgrade successful...");
    std::mem::drop(lock);
    Ok(())
}

pub fn repo_upgrade_to_6_to_7(repo_path: &Path) -> Result<(), anyhow::Error> {
    // This upgrade adds sparse files and zstd compression.
    // This upgrade also adds the '.removed' suffix for removed items.
    eprintln!("upgrading repository schema from version 6 to version 7...");

    eprintln!("getting exclusive repository lock for upgrade...");
    let lock_path = {
        let mut p = repo_path.to_owned();
        p.push("repo.lock");
        p
    };
    let lock = fsutil::FileLock::get_exclusive(REPO_LOCK_CTX_TAG, &lock_path)?;

    let mut txn = fstx::WriteTxn::begin(repo_path)?;

    let mut active_items: HashSet<xid::Xid> = HashSet::new();
    for item in txn.read_dir("items")? {
        let item = item?;
        let id = item.file_name().to_string_lossy();
        match xid::Xid::parse(&id) {
            Ok(id) => {
                active_items.insert(id);
            }
            Err(_) => anyhow::bail!("unable to parse item id at path items/{}", id),
        }
    }

    let log_file = txn.open("repo.oplog")?;

    let mut log_file = std::io::BufReader::new(log_file);

    while !log_file.fill_buf()?.is_empty() {
        let op = serde_bare::from_reader(&mut log_file)?;
        if let oplog::LogOp::AddItem((id, md)) = op {
            if !active_items.contains(&id) {
                let serialized_md = serde_bare::to_vec(&md)?;
                txn.add_write(&format!("items/{:x}.removed", id), serialized_md)?;
            }
        }
    }

    let schema_version = txn.read_string("meta/schema_version")?;
    if schema_version != "6" {
        anyhow::bail!(
            "unable to upgrade, expected schema version 6, got {}",
            schema_version
        )
    }

    txn.add_write("meta/schema_version", "7".to_string().into_bytes())?;
    txn.commit()?;

    eprintln!("repository upgrade successful...");
    std::mem::drop(lock);
    Ok(())
}
