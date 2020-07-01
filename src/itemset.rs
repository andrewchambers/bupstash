use super::address::*;
use super::crypto;
use super::keys;
use serde::{Deserialize, Serialize};

pub const MAX_TAG_SET_SIZE: usize = 32 * 1024;
// Tags plus some leeway, we can adjust this if we need to.
pub const MAX_OPLOG_ITEM_SIZE: usize = MAX_TAG_SET_SIZE + 8 * 1024;

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct PlainTextItemMetadata {
    pub master_key_id: [u8; keys::KEYID_SZ],
    pub tree_height: usize,
    pub address: Address,
}

impl PlainTextItemMetadata {
    pub fn hash(&self) -> [u8; crypto::HASH_BYTES] {
        let mut hst = crypto::HashState::new(None);
        hst.update(&bincode::serialize(&self).unwrap());
        hst.finish()
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct EncryptedItemMetadata {
    pub plain_text_hash: [u8; crypto::HASH_BYTES],
    pub hash_key_part_2: crypto::PartialHashKey,
    // We want ordered serialization.
    pub tags: std::collections::BTreeMap<String, Option<String>>,
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
    ) -> Result<EncryptedItemMetadata, failure::Error> {
        let data = dctx.decrypt_data(self.encrypted_metadata.clone())?;
        let emd: EncryptedItemMetadata = bincode::deserialize(&data)?;
        if self.plain_text_metadata.hash() != emd.plain_text_hash {
            failure::bail!("item metadata is corrupt or tampered with");
        }
        Ok(emd)
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub enum VersionedItemMetadata {
    V1(ItemMetadata),
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum LogOp {
    AddItem(VersionedItemMetadata),
    // Note: There is an asymmetry here in that we can delete many items with one log op.
    // This is because batch deleting is possible, but batch makes less sense.
    RemoveItems(Vec<i64>),
}

pub fn init_tables(tx: &rusqlite::Transaction) -> Result<(), failure::Error> {
    tx.execute(
        "create table if not exists ItemOpLog(Id INTEGER PRIMARY KEY AUTOINCREMENT, OpData);",
        rusqlite::NO_PARAMS,
    )?;
    tx.execute(
        "create table if not exists Items(LogOpId, Unique(LogOpId), FOREIGN KEY(LogOpId) REFERENCES ItemOpLog(Id));",
        rusqlite::NO_PARAMS,
    )?;
    Ok(())
}

fn checked_serialize_log_op(op: &LogOp) -> Result<Vec<u8>, failure::Error> {
    let serialized_op = bincode::serialize(&op)?;
    if serialized_op.len() > MAX_OPLOG_ITEM_SIZE {
        failure::bail!("itemset log item too big!");
    }
    Ok(serialized_op)
}

pub fn do_op(tx: &rusqlite::Transaction, op: &LogOp) -> Result<i64, failure::Error> {
    let serialized_op = checked_serialize_log_op(op)?;
    match &op {
        LogOp::AddItem(_) => {
            tx.execute("insert into ItemOpLog(OpData) values(?);", &[serialized_op])?;
            let id = tx.last_insert_rowid();
            tx.execute("insert into Items(LogOpId) values(?);", &[id])?;
            Ok(id)
        }
        LogOp::RemoveItems(items) => {
            for itemid in items {
                tx.execute("delete from Items where LogOpId = ?;", &[*itemid])?;
            }
            tx.execute("insert into ItemOpLog(OpData) values(?);", &[serialized_op])?;
            Ok(tx.last_insert_rowid())
        }
    }
}

pub fn do_op_with_id(
    tx: &rusqlite::Transaction,
    id: i64,
    op: &LogOp,
) -> Result<i64, failure::Error> {
    let serialized_op = checked_serialize_log_op(&op)?;
    match &op {
        LogOp::AddItem(_) => {
            tx.execute(
                "insert into ItemOpLog(Id, OpData) values(?, ?);",
                rusqlite::params![id, serialized_op],
            )?;
            tx.execute("insert into Items(LogOpId) values(?);", &[id])?;
            Ok(id)
        }
        LogOp::RemoveItems(items) => {
            for itemid in items {
                tx.execute("delete from Items where LogOpId = ?;", &[*itemid])?;
            }
            tx.execute(
                "insert into ItemOpLog(Id, OpData) values(?, ?);",
                rusqlite::params![id, serialized_op],
            )?;
            Ok(tx.last_insert_rowid())
        }
    }
}

pub fn compact(tx: &rusqlite::Transaction) -> Result<(), failure::Error> {
    tx.execute("DELETE FROM ItemOpLog WHERE Id IN \
(SELECT ItemOpLog.Id FROM ItemOpLog LEFT JOIN Items ON ItemOpLog.Id=Items.LogOpId WHERE Items.LogOpId IS NULL);", rusqlite::NO_PARAMS)?;
    Ok(())
}

pub fn lookup_item_by_id(
    tx: &rusqlite::Transaction,
    id: i64,
) -> Result<Option<VersionedItemMetadata>, failure::Error> {
    match tx.query_row("select 1 from Items where LogOpId = ?;", &[id], |_row| {
        Ok(true)
    }) {
        Ok(_) => (),
        Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let opdata: Vec<u8> =
        tx.query_row("select OpData from ItemOpLog where Id = ?;", &[id], |row| {
            row.get(0)
        })?;
    let logop: LogOp = bincode::deserialize(&opdata)?;
    match logop {
        LogOp::AddItem(metadata) => Ok(Some(metadata)),
        _ => failure::bail!("itemset/item log is corrupt"),
    }
}

pub fn walk_items(
    tx: &rusqlite::Transaction,
    f: &mut dyn FnMut(i64, VersionedItemMetadata) -> Result<(), failure::Error>,
) -> Result<(), failure::Error> {
    let mut stmt =
        tx.prepare("select Id, OpData from ItemOpLog where id in (select LogOpId from Items);")?;
    let mut rows = stmt.query(rusqlite::NO_PARAMS)?;
    loop {
        match rows.next()? {
            Some(row) => {
                let id: i64 = row.get(0)?;
                let opdata: Vec<u8> = row.get(1)?;
                let logop: LogOp = bincode::deserialize(&opdata)?;
                let metadata: VersionedItemMetadata = match logop {
                    LogOp::AddItem(metadata) => metadata,
                    _ => failure::bail!("itemset/item log is corrupt"),
                };
                f(id, metadata)?;
            }
            None => {
                return Ok(());
            }
        }
    }
}

pub fn walk_log(
    tx: &rusqlite::Transaction,
    after: i64,
    f: &mut dyn FnMut(i64, LogOp) -> Result<(), failure::Error>,
) -> Result<(), failure::Error> {
    let mut stmt = tx.prepare("select Id, OpData from ItemOpLog where Id > ? order by Id asc;")?;
    let mut rows = stmt.query(&[after])?;
    loop {
        match rows.next()? {
            Some(row) => {
                let id: i64 = row.get(0)?;
                let logop: Vec<u8> = row.get(1)?;
                let logop: LogOp = bincode::deserialize(&logop)?;
                f(id, logop)?;
            }
            None => {
                return Ok(());
            }
        }
    }
}
