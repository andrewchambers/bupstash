use super::address::*;
use super::crypto;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct ItemMetadata {
    pub tree_height: usize,
    pub encrypt_header: crypto::VersionedEncryptionHeader,
    pub encrypted_tags: Vec<u8>,
    pub address: Address,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum LogOp {
    AddItem(ItemMetadata),
    RemoveItem(i64),
}

pub fn init_tables(tx: &rusqlite::Transaction) -> Result<(), failure::Error> {
    tx.execute(
        "create table if not exists ItemOpLog(Id INTEGER PRIMARY KEY AUTOINCREMENT, OpData);",
        rusqlite::NO_PARAMS,
    )?;
    tx.execute("create table if not exists Items(LogOpId, Unique(LogOpId), FOREIGN KEY(LogOpId) REFERENCES ItemOpLog(Id));", rusqlite::NO_PARAMS)?;
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
        LogOp::RemoveItem(itemid) => {
            match tx.query_row("select 1 from Items where LogOpId = ?;", &[itemid], |_r| {
                Ok(())
            }) {
                Ok(_) => {
                    tx.execute("delete from Items where LogOpId = ?;", &[itemid])?;
                    tx.execute(
                        "insert into ItemOpLog(OpData) values(?);",
                        &[bincode::serialize(&op)?],
                    )?;
                    Ok(tx.last_insert_rowid())
                }
                Err(rusqlite::Error::QueryReturnedNoRows) => {
                    Err(failure::format_err!("no item with id {}", itemid))
                }
                Err(err) => Err(err.into()),
            }
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
        LogOp::RemoveItem(itemid) => {
            match tx.query_row("select 1 from Items where LogOpId = ?;", &[itemid], |_r| {
                Ok(())
            }) {
                Ok(_) => {
                    tx.execute("delete from Items where LogOpId = ?;", &[itemid])?;
                    tx.execute(
                        "insert into ItemOpLog(Id, OpData) values(?, ?);",
                        rusqlite::params![id, bincode::serialize(&op)?],
                    )?;
                    Ok(id)
                }
                Err(rusqlite::Error::QueryReturnedNoRows) => {
                    Err(failure::format_err!("no item with id {}", itemid))
                }
                Err(err) => Err(err.into()),
            }
        }
    }
}

pub fn compact(tx: &rusqlite::Transaction) -> Result<(), failure::Error> {
    tx.execute("DELETE FROM ItemOpLog WHERE Id IN \
(SELECT ItemOpLog.Id FROM ItemOpLog LEFT JOIN Items ON ItemOpLog.Id=Items.LogOpId WHERE Items.LogOpId IS NULL);", rusqlite::NO_PARAMS)?;
    Ok(())
}

pub fn add_item(tx: &rusqlite::Transaction, metadata: ItemMetadata) -> Result<i64, failure::Error> {
    do_op(tx, &LogOp::AddItem(metadata))
}

pub fn remove_item(tx: &rusqlite::Transaction, id: i64) -> Result<(), failure::Error> {
    do_op(tx, &LogOp::RemoveItem(id))?;
    Ok(())
}

pub fn lookup_item_by_id(
    tx: &rusqlite::Transaction,
    id: i64,
) -> Result<Option<ItemMetadata>, failure::Error> {
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
    f: &mut dyn FnMut(i64, ItemMetadata) -> Result<(), failure::Error>,
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
                let metadata: ItemMetadata = match logop {
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
