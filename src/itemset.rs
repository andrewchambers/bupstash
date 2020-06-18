use super::address::*;
use super::keys;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct ItemMetadata {
    // XXX TODO FIXME, all unencrypted metadata
    // could be bound to the address via some sort of authentication code.
    pub tree_height: usize,
    pub master_key_id: [u8; keys::KEYID_SZ],
    pub address: Address,
    // XXX TODO FIXME this hash_key could be encrypted?
    // instead of split? The only person who needs access
    // to the hash key is the master key.
    pub hash_key_part_2a: [u8; keys::PARTIAL_HASH_KEY_SZ],
    pub hash_key_part_2b: [u8; keys::PARTIAL_HASH_KEY_SZ],
    pub encrypted_tags: Vec<u8>,
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

pub fn do_op(tx: &rusqlite::Transaction, op: &LogOp) -> Result<i64, failure::Error> {
    match &op {
        LogOp::AddItem(_) => {
            tx.execute(
                "insert into ItemOpLog(OpData) values(?);",
                &[bincode::serialize(&op)?],
            )?;
            let id = tx.last_insert_rowid();
            tx.execute("insert into Items(LogOpId) values(?);", &[id])?;
            Ok(id)
        }
        LogOp::RemoveItems(items) => {
            for itemid in items {
                tx.execute("delete from Items where LogOpId = ?;", &[*itemid])?;
            }
            tx.execute(
                "insert into ItemOpLog(OpData) values(?);",
                &[bincode::serialize(&op)?],
            )?;
            Ok(tx.last_insert_rowid())
        }
    }
}

pub fn do_op_with_id(
    tx: &rusqlite::Transaction,
    id: i64,
    op: &LogOp,
) -> Result<i64, failure::Error> {
    match &op {
        LogOp::AddItem(_) => {
            tx.execute(
                "insert into ItemOpLog(Id, OpData) values(?, ?);",
                rusqlite::params![id, bincode::serialize(&op)?],
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
                rusqlite::params![id, bincode::serialize(&op)?],
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
