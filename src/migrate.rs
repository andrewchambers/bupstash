// This file contains code to perform repository migrations.
// The code here is often deliberately duplicated and avoids dependencies
// on other modules so that the upgrade migration code can avoid churn with
// other changes.

use super::fstx1;
use super::fstx2;
use super::oplog;
use super::vfs;
use super::xid;
use std::collections::HashSet;
use std::io::BufRead;

pub fn repo_upgrade_to_5_to_6(repo_fs: &vfs::VFs) -> Result<(), anyhow::Error> {
    // This upgrade mainly just prevents clients from seeing index entries they
    // cannot decode... repositories of version 5 and 6 are compatible except
    // for an additional index entry type.
    // This upgrade simply increments the schema version.
    eprintln!("upgrading repository schema from version 5 to version 6...");

    let mut lock_file = repo_fs.open("repo.lock", vfs::OpenFlags::RDWR)?;
    eprintln!("getting exclusive repository lock for upgrade...");
    lock_file.lock(vfs::LockType::Exclusive)?;

    let mut fstx1 = fstx1::WriteTxn::begin_at(repo_fs)?;
    let schema_version = fstx1.read_string("meta/schema_version")?;
    if schema_version != "5" {
        anyhow::bail!(
            "unable to upgrade, expected schema version 5, got {}",
            schema_version
        )
    }
    fstx1.add_write("meta/schema_version", "6".to_string().into_bytes())?;
    fstx1.commit()?;
    eprintln!("repository upgrade successful...");
    drop(lock_file);
    Ok(())
}

pub fn repo_upgrade_to_6_to_7(repo_fs: &vfs::VFs) -> Result<(), anyhow::Error> {
    // This upgrade adds sparse files and zstd compression.
    // This upgrade also adds the '.removed' suffix for removed items.
    eprintln!("upgrading repository schema from version 6 to version 7...");

    let mut lock_file = repo_fs.open("repo.lock", vfs::OpenFlags::RDWR)?;
    eprintln!("getting exclusive repository lock for upgrade...");
    lock_file.lock(vfs::LockType::Exclusive)?;

    let mut txn = fstx1::WriteTxn::begin_at(repo_fs)?;

    let mut active_items: HashSet<xid::Xid> = HashSet::new();
    for item in txn.read_dir("items")? {
        let id = item.file_name;
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
    std::mem::drop(lock_file);
    Ok(())
}

pub fn repo_upgrade_to_7_to_8(repo_fs: &vfs::VFs) -> Result<(), anyhow::Error> {
    // This upgrade migrates from fstx1 to fstx2 (WAL mode).
    eprintln!("upgrading repository schema from version 7 to version 8...");

    let mut lock_file = repo_fs.open("repo.lock", vfs::OpenFlags::RDWR)?;
    eprintln!("getting exclusive repository lock for upgrade...");
    lock_file.lock(vfs::LockType::Exclusive)?;

    // Rollback any failed old style transactions, prepare for new style.
    let mut txn = fstx1::WriteTxn::begin_at(repo_fs)?;
    {
        txn.add_write(fstx2::SEQ_NUM_NAME, vec![0, 0, 0, 0, 0, 0, 0, 0])?;
    }
    txn.commit()?;

    // Do upgrade with new style transactions.
    let mut txn = fstx2::WriteTxn::begin_at(repo_fs)?;
    {
        for d in ["data", "wal"] {
            if !txn.file_exists(d)? {
                txn.add_mkdir(d)?;
            }
        }
        txn.add_write("meta/schema_version", "8".to_string().into_bytes())?;
    }
    txn.commit()?;

    eprintln!("repository upgrade successful...");
    std::mem::drop(lock_file);
    Ok(())
}
