use super::address::*;
use super::crypto;
use super::xid::*;
use serde::{Deserialize, Serialize};

pub const MAX_TAG_SET_SIZE: usize = 32 * 1024;
// Tags plus some leeway, we can adjust this if we need to.
pub const MAX_METADATA_SIZE: usize = MAX_TAG_SET_SIZE + 2048;

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct HTreeMetadata {
    pub height: serde_bare::Uint,
    pub data_chunk_count: serde_bare::Uint,
    pub address: Address,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct PlainTextItemMetadata {
    pub primary_key_id: Xid,
    pub data_tree: HTreeMetadata,
    pub index_tree: Option<HTreeMetadata>,
}

impl PlainTextItemMetadata {
    pub fn hash(&self) -> [u8; crypto::HASH_BYTES] {
        let mut hst = crypto::HashState::new(None);
        hst.update(&serde_bare::to_vec(&self).unwrap());
        hst.finish()
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct EncryptedItemMetadata {
    pub plain_text_hash: [u8; crypto::HASH_BYTES],
    pub send_key_id: Xid,
    pub idx_hash_key_part_2: crypto::PartialHashKey,
    pub data_hash_key_part_2: crypto::PartialHashKey,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    // We want ordered serialization.
    pub tags: std::collections::BTreeMap<String, String>,
    pub data_size: serde_bare::Uint,
    // 0 if we have no index.
    pub index_size: serde_bare::Uint,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct ItemMetadata {
    pub plain_text_metadata: PlainTextItemMetadata,
    // An encrypted instance of EncryptedItemMetadata
    pub encrypted_metadata: Vec<u8>,
}

impl ItemMetadata {
    pub fn decrypt_metadata(
        &self,
        dctx: &mut crypto::DecryptionContext,
    ) -> Result<EncryptedItemMetadata, anyhow::Error> {
        let data = dctx.decrypt_data(self.encrypted_metadata.clone())?;
        let emd: EncryptedItemMetadata = serde_bare::from_slice(&data)?;
        if self.plain_text_metadata.hash() != emd.plain_text_hash {
            anyhow::bail!("item metadata is corrupt or tampered with");
        }
        Ok(emd)
    }
}

#[non_exhaustive]
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub enum VersionedItemMetadata {
    V1(ItemMetadata),
}

#[non_exhaustive]
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum LogOp {
    AddItem(VersionedItemMetadata),
    // Note: There is an asymmetry here in that we can delete many items with one log op.
    // This is because batch deleting is possible, but batch makes less sense.
    RemoveItems(Vec<Xid>),

    RestoreRemoved,
}

pub fn init_tables(tx: &rusqlite::Transaction) -> Result<(), anyhow::Error> {
    tx.execute(
        "create table if not exists ItemOpLog(OpId INTEGER PRIMARY KEY AUTOINCREMENT, ItemId, OpData);",
        rusqlite::NO_PARAMS,
    )?;
    tx.execute(
        // No rowid so means we don't need a secondary index for itemid lookups.
        "create table if not exists Items(ItemId PRIMARY KEY, OpId INTEGER NOT NULL, Metadata NOT NULL,  UNIQUE(OpId)) WITHOUT ROWID;",
        rusqlite::NO_PARAMS,
    )?;
    Ok(())
}

fn checked_serialize_metadata(md: &VersionedItemMetadata) -> Result<Vec<u8>, anyhow::Error> {
    let serialized_op = serde_bare::to_vec(&md)?;
    if serialized_op.len() > MAX_METADATA_SIZE {
        anyhow::bail!("itemset log item metadata too big!");
    }
    Ok(serialized_op)
}

pub fn add_item(
    tx: &rusqlite::Transaction,
    md: VersionedItemMetadata,
) -> Result<Xid, anyhow::Error> {
    let item_id = Xid::new();
    let serialized_md = checked_serialize_metadata(&md)?;
    let op = LogOp::AddItem(md);
    let serialized_op = serde_bare::to_vec(&op)?;

    tx.execute(
        "insert into ItemOpLog(OpData, ItemId) values(?, ?);",
        rusqlite::params![serialized_op, item_id],
    )?;

    let op_id = tx.last_insert_rowid();

    tx.execute(
        "insert into Items(ItemId, OpId, Metadata) values(?, ?, ?);",
        rusqlite::params![&item_id, op_id, serialized_md],
    )?;

    Ok(item_id)
}

pub fn remove_items(tx: &rusqlite::Transaction, items: Vec<Xid>) -> Result<(), anyhow::Error> {
    let mut existed = Vec::new();
    for item_id in items.iter() {
        let n_deleted = tx.execute("delete from Items where ItemId = ?;", &[item_id])?;
        if n_deleted != 0 {
            existed.push(*item_id);
        }
    }
    let op = LogOp::RemoveItems(existed);
    let serialized_op = serde_bare::to_vec(&op)?;
    tx.execute("insert into ItemOpLog(OpData) values(?);", &[serialized_op])?;
    Ok(())
}

fn restore_removed_no_log_op(tx: &rusqlite::Transaction) -> Result<u64, anyhow::Error> {
    let mut stmt = tx.prepare(
        "select OpId, ItemId, OpData from ItemOpLog where (ItemId is not null) and (ItemId not in (select ItemId from Items));",
    )?;
    let mut n_restored = 0;
    let mut rows = stmt.query(rusqlite::NO_PARAMS)?;
    loop {
        match rows.next()? {
            Some(row) => {
                let op_id: i64 = row.get(0)?;
                let item_id: Xid = row.get(1)?;
                let op: Vec<u8> = row.get(2)?;
                let op: LogOp = serde_bare::from_slice(&op)?;
                if let LogOp::AddItem(md) = op {
                    n_restored += 1;
                    tx.execute(
                        "insert into Items(ItemId, OpId, Metadata) values(?, ?, ?);",
                        rusqlite::params![&item_id, op_id, checked_serialize_metadata(&md)?],
                    )?;
                }
            }
            None => {
                return Ok(n_restored);
            }
        }
    }
}

pub fn restore_removed(tx: &rusqlite::Transaction) -> Result<u64, anyhow::Error> {
    let op = LogOp::RestoreRemoved;
    let serialized_op = serde_bare::to_vec(&op)?;
    tx.execute(
        "insert into ItemOpLog(OpData) values(?);",
        rusqlite::params![serialized_op],
    )?;
    restore_removed_no_log_op(tx)
}

pub fn sync_ops(
    tx: &rusqlite::Transaction,
    op_id: i64,
    item_id: Option<Xid>,
    op: &LogOp,
) -> Result<(), anyhow::Error> {
    let serialized_op = serde_bare::to_vec(&op)?;
    match op {
        LogOp::AddItem(md) => {
            if item_id.is_none() {
                anyhow::bail!("corrupt op log");
            }
            let item_id = item_id.unwrap();
            tx.execute(
                "insert into ItemOpLog(OpId, ItemId, OpData) values(?, ?, ?);",
                rusqlite::params![op_id, &item_id, serialized_op],
            )?;
            tx.execute(
                "insert into Items(ItemId, OpId, Metadata) values(?, ?, ?);",
                rusqlite::params![&item_id, op_id, checked_serialize_metadata(&md)?],
            )?;
            Ok(())
        }
        LogOp::RemoveItems(items) => {
            if item_id.is_some() {
                anyhow::bail!("corrupt op log");
            }
            tx.execute(
                "insert into ItemOpLog(OpId, OpData) values(?, ?);",
                rusqlite::params![op_id, serialized_op],
            )?;
            for item_id in items {
                tx.execute("delete from Items where ItemId = ?;", &[item_id])?;
            }
            Ok(())
        }
        LogOp::RestoreRemoved => {
            if item_id.is_some() {
                anyhow::bail!("corrupt op log");
            }
            tx.execute(
                "insert into ItemOpLog(OpId, OpData) values(?, ?);",
                rusqlite::params![op_id, serialized_op],
            )?;
            restore_removed_no_log_op(tx)?;
            Ok(())
        }
    }
}

pub fn compact(tx: &rusqlite::Transaction) -> Result<(), anyhow::Error> {
    // Remove everything not in the aggregated set.
    tx.execute(
        "delete from ItemOpLog where OpId not in (select OpId from Items);",
        rusqlite::NO_PARAMS,
    )?;
    Ok(())
}

pub fn has_item_with_id(tx: &rusqlite::Transaction, id: &Xid) -> Result<bool, anyhow::Error> {
    match tx.query_row("select 1 from Items where ItemId = ?;", &[id], |_row| {
        Ok(true)
    }) {
        Ok(_) => Ok(true),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(false),
        Err(e) => Err(e.into()),
    }
}

pub fn lookup_item_by_id(
    tx: &rusqlite::Transaction,
    id: &Xid,
) -> Result<Option<VersionedItemMetadata>, anyhow::Error> {
    match tx.query_row(
        "select Metadata from Items where ItemId = ?;",
        &[id],
        |row| {
            let serialized_md: Vec<u8> = row.get(0)?;
            Ok(serialized_md)
        },
    ) {
        Ok(data) => Ok(Some(serde_bare::from_slice(&data)?)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

pub fn walk_items(
    tx: &rusqlite::Transaction,
    f: &mut dyn FnMut(i64, Xid, VersionedItemMetadata) -> Result<(), anyhow::Error>,
) -> Result<(), anyhow::Error> {
    let mut stmt = tx.prepare("select OpId, ItemId, Metadata from Items order by OpId asc;")?;
    let mut rows = stmt.query(rusqlite::NO_PARAMS)?;
    loop {
        match rows.next()? {
            Some(row) => {
                let op_id: i64 = row.get(0)?;
                let item_id: Xid = row.get(1)?;
                let metadata: Vec<u8> = row.get(2)?;
                let metadata: VersionedItemMetadata = serde_bare::from_slice(&metadata)?;
                f(op_id, item_id, metadata)?;
            }
            None => {
                return Ok(());
            }
        }
    }
}

pub fn walk_log(
    tx: &rusqlite::Transaction,
    after_op: i64,
    f: &mut dyn FnMut(i64, Option<Xid>, LogOp) -> Result<(), anyhow::Error>,
) -> Result<(), anyhow::Error> {
    let mut stmt =
        tx.prepare("select OpId, ItemId, OpData from ItemOpLog where OpId > ? order by OpId asc;")?;
    let mut rows = stmt.query(&[after_op])?;
    loop {
        match rows.next()? {
            Some(row) => {
                let op_id: i64 = row.get(0)?;
                let item_id: Option<Xid> = row.get(1)?;
                let op: Vec<u8> = row.get(2)?;
                let op: LogOp = serde_bare::from_slice(&op)?;
                f(op_id, item_id, op)?;
            }
            None => {
                return Ok(());
            }
        }
    }
}
