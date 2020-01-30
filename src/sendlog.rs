use super::address::*;
use std::path::PathBuf;

pub struct SendLog {
    conn: rusqlite::Connection,
}

pub struct SendLogTx<'a> {
    // Each 'sent' entry is either a or b.
    // When a send is complete, we delete the old entries.
    ab: bool,
    tx: rusqlite::Transaction<'a>,
}

impl SendLog {
    pub fn open(p: &PathBuf, gc_generation: &str) -> Result<SendLog, failure::Error> {
        let mut conn = rusqlite::Connection::open(p)?;
        conn.query_row(
            "pragma locking_mode=EXCLUSIVE;",
            rusqlite::NO_PARAMS,
            |_r| Ok(()),
        )?;
        conn.query_row("pragma journal_mode=WAL;", rusqlite::NO_PARAMS, |_r| Ok(()))?;
        let tx = conn.transaction()?;
        // We only really need one process per write log at a time.
        tx.execute(
            "create table if not exists LogMeta(Key, Value, unique(Key)); ",
            rusqlite::NO_PARAMS,
        )?;
        tx.execute(
            "create table if not exists Sent(Addr, AB, unique(Addr)); ",
            rusqlite::NO_PARAMS,
        )?;
        match tx.query_row(
            "select value from LogMeta where key = 'gc_generation';",
            rusqlite::NO_PARAMS,
            |r| {
                let generation: String = r.get(0)?;
                Ok(generation)
            },
        ) {
            Ok(old_generation) => {
                if gc_generation != old_generation {
                    tx.execute("delete from sent;", rusqlite::NO_PARAMS)?;
                    tx.execute(
                        "update LogMeta(Key, Value) set Value = ? where Key = 'gc_generation';",
                        &[&gc_generation],
                    )?;
                }
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                tx.execute("delete from sent;", rusqlite::NO_PARAMS)?;
                tx.execute(
                    "insert into LogMeta(Key, Value) values('gc_generation', ?);",
                    &[&gc_generation],
                )?;
            }
            Err(err) => return Err(err.into()),
        }
        tx.commit()?;

        Ok(SendLog { conn: conn })
    }

    pub fn transaction<'a>(self: &'a mut Self) -> Result<SendLogTx<'a>, failure::Error> {
        let tx = self.conn.transaction()?;

        let old_ab = match tx.query_row(
            "select value from LogMeta where key = 'ab';",
            rusqlite::NO_PARAMS,
            |r| {
                let ab: bool = r.get(0)?;
                Ok(ab)
            },
        ) {
            Ok(ab) => ab,
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                let ab = false;
                tx.execute("insert into LogMeta(Key, Value) values('ab', ?);", &[ab])?;
                ab
            }
            Err(err) => return Err(err.into()),
        };

        Ok(SendLogTx { ab: !old_ab, tx })
    }
}

impl<'a> SendLogTx<'a> {
    pub fn add_address(self: &mut Self, addr: &Address) -> Result<(), failure::Error> {
        // Store raw bytes as this is performance sensitive and it is pointless converting.
        self.tx.execute(
            "insert or replace into Sent(Addr, AB) values(?, ?); ",
            rusqlite::params![&addr.bytes[..], self.ab],
        )?;
        Ok(())
    }

    pub fn has_address(self: &mut Self, addr: &Address) -> Result<bool, failure::Error> {
        // Store raw bytes as this is performance sensitive and it is pointless converting.
        match self.tx.query_row(
            "select 1 from Sent where Addr=?;",
            &[&addr.bytes[..]],
            |_r| Ok(()),
        ) {
            Ok(_) => Ok(true),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(false),
            Err(err) => Err(err.into()),
        }
    }

    pub fn commit(self: Self) -> Result<(), failure::Error> {
        // Delete old values from the send log.
        self.tx
            .execute("delete from sent where ab = ?;", &[!self.ab])?;
        self.tx
            .execute("update LogMeta set Value = ? where Key = 'ab';", &[self.ab])?;
        self.tx.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_cycling() {
        let mut sendlog = SendLog::open(&PathBuf::from(":memory:"), "123").unwrap();
        let addr = Address::default();
        // Commit adding an address
        let mut tx = sendlog.transaction().unwrap();
        assert!(!tx.has_address(&addr).unwrap());
        tx.add_address(&addr).unwrap();
        assert!(tx.has_address(&addr).unwrap());
        tx.commit().unwrap();
        // Start a new tx, ensure we still have that address.
        // then add the address again.
        let mut tx = sendlog.transaction().unwrap();
        assert!(tx.has_address(&addr).unwrap());
        tx.add_address(&addr).unwrap();
        assert!(tx.has_address(&addr).unwrap());
        tx.commit().unwrap();
        // Start a new tx, ensure we still have that address.
        // This time we don't readd the address, it should expire
        // when the transaction cycles.
        let mut tx = sendlog.transaction().unwrap();
        assert!(tx.has_address(&addr).unwrap());
        tx.commit().unwrap();
        // Verify the value was cycled away.
        let mut tx = sendlog.transaction().unwrap();
        assert!(!tx.has_address(&addr).unwrap());
        tx.commit().unwrap();
    }
}
