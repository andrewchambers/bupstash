use super::address::*;
use super::crypto;
use super::hex;
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
    RemoveItems(Vec<String>),
}

pub fn init_tables(tx: &rusqlite::Transaction) -> Result<(), failure::Error> {
    tx.execute(
        "create table if not exists ItemOpLog(OpId INTEGER PRIMARY KEY AUTOINCREMENT, ItemId, OpData, unique(ItemId));",
        rusqlite::NO_PARAMS,
    )?;
    tx.execute(
        "create table if not exists Items(ItemId, unique(ItemId), FOREIGN KEY(ItemId) references ItemOpLog(ItemId));",
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

fn random_op_id() -> String {
    let mut buf = [0; 20];
    crypto::randombytes(&mut buf[..]);
    hex::easy_encode_to_string(&buf[..])
}

pub fn do_op(
    tx: &rusqlite::Transaction,
    op: &LogOp,
) -> Result<(i64, Option<String>), failure::Error> {
    let serialized_op = checked_serialize_log_op(op)?;
    match &op {
        LogOp::AddItem(_) => {
            let item_id = random_op_id();
            tx.execute(
                "insert into ItemOpLog(OpData, ItemId) values(?, ?);",
                rusqlite::params![serialized_op, item_id],
            )?;
            let op_id = tx.last_insert_rowid();
            tx.execute("insert into Items(ItemId) values(?);", &[&item_id])?;
            Ok((op_id, Some(item_id)))
        }
        LogOp::RemoveItems(items) => {
            for itemid in items {
                tx.execute("delete from Items where ItemId = ?;", &[itemid])?;
            }
            tx.execute("insert into ItemOpLog(OpData) values(?);", &[serialized_op])?;
            Ok((tx.last_insert_rowid(), None))
        }
    }
}

pub fn do_op_with_ids(
    tx: &rusqlite::Transaction,
    op_id: i64,
    item_id: Option<String>,
    op: &LogOp,
) -> Result<(), failure::Error> {
    let serialized_op = checked_serialize_log_op(&op)?;
    match &op {
        LogOp::AddItem(_) => {
            if item_id.is_none() {
                failure::bail!("corrupt op log");
            }
            let item_id = item_id.unwrap();
            tx.execute(
                "insert into ItemOpLog(OpId, ItemId, OpData) values(?, ?, ?);",
                rusqlite::params![op_id, &item_id, serialized_op],
            )?;
            tx.execute("insert into Items(ItemId) values(?);", &[&item_id])?;
            Ok(())
        }
        LogOp::RemoveItems(items) => {
            if item_id.is_some() {
                failure::bail!("corrupt op log");
            }
            for item_id in items {
                tx.execute("delete from Items where ItemId = ?;", &[item_id])?;
            }
            tx.execute(
                "insert into ItemOpLog(OpId, OpData) values(?, ?);",
                rusqlite::params![op_id, serialized_op],
            )?;
            Ok(())
        }
    }
}

pub fn compact(tx: &rusqlite::Transaction) -> Result<(), failure::Error> {
    // Only keep add entries.
    tx.execute(
        "delete from ItemOpLog where ItemId is null;",
        rusqlite::NO_PARAMS,
    )?;
    // Remove everything not in the aggregated set.
    tx.execute(
        "delete from ItemOpLog where ItemId not in (select ItemId from Items);",
        rusqlite::NO_PARAMS,
    )?;
    Ok(())
}

pub fn item_with_id_in_oplog(tx: &rusqlite::Transaction, id: &str) -> Result<bool, failure::Error> {
    match tx.query_row("select 1 from ItemOpLog where ItemId = ?;", &[id], |_row| {
        Ok(true)
    }) {
        Ok(_) => Ok(true),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(false),
        Err(e) => Err(e.into()),
    }
}

pub fn lookup_item_by_id(
    tx: &rusqlite::Transaction,
    id: &str,
) -> Result<Option<VersionedItemMetadata>, failure::Error> {
    match tx.query_row("select 1 from Items where ItemId = ?;", &[id], |_row| {
        Ok(true)
    }) {
        Ok(_) => (),
        Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let opdata: Vec<u8> = tx.query_row(
        "select OpData from ItemOpLog where ItemId = ?;",
        &[id],
        |row| row.get(0),
    )?;
    let logop: LogOp = bincode::deserialize(&opdata)?;
    match logop {
        LogOp::AddItem(metadata) => Ok(Some(metadata)),
        _ => failure::bail!("itemset/item log is corrupt"),
    }
}

pub fn walk_items(
    tx: &rusqlite::Transaction,
    f: &mut dyn FnMut(i64, String, VersionedItemMetadata) -> Result<(), failure::Error>,
) -> Result<(), failure::Error> {
    let mut stmt = tx.prepare(
        "select OpId, ItemId, OpData from ItemOpLog where ItemId in (select ItemId from Items);",
    )?;
    let mut rows = stmt.query(rusqlite::NO_PARAMS)?;
    loop {
        match rows.next()? {
            Some(row) => {
                let op_id: i64 = row.get(0)?;
                let item_id: String = row.get(1)?;
                let op: Vec<u8> = row.get(2)?;
                let op: LogOp = bincode::deserialize(&op)?;
                let metadata: VersionedItemMetadata = match op {
                    LogOp::AddItem(metadata) => metadata,
                    _ => failure::bail!("itemset/item log is corrupt"),
                };
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
    f: &mut dyn FnMut(i64, Option<String>, LogOp) -> Result<(), failure::Error>,
) -> Result<(), failure::Error> {
    let mut stmt =
        tx.prepare("select OpId, ItemId, OpData from ItemOpLog where OpId > ? order by OpId asc;")?;
    let mut rows = stmt.query(&[after_op])?;
    loop {
        match rows.next()? {
            Some(row) => {
                let op_id: i64 = row.get(0)?;
                let item_id: Option<String> = row.get(1)?;
                let op: Vec<u8> = row.get(2)?;
                let op: LogOp = bincode::deserialize(&op)?;
                f(op_id, item_id, op)?;
            }
            None => {
                return Ok(());
            }
        }
    }
}
