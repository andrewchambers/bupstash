// Bindings and helpers for csrc/cksumvfs.
// these functions let us add add checksums to our sqlite3 files.
// For more info see: https://www.sqlite.org/cksumvfs.html

extern "C" {
    #[cfg(feature = "bundled-sqlite")]
    fn cksumvfs_sqlite_version_number() -> ::std::os::raw::c_int;

    fn sqlite3_register_cksumvfs(unused: *const u8) -> ::std::os::raw::c_int;
}

pub fn register_cksumvfs() {
    // Because have our own copy of the sqlite3 header file, this
    // test ensures we are using the same header rusqlite used.
    // This is not needed (nor desirable) when building with a
    // system-provided libsqlite.
    #[cfg(feature = "bundled-sqlite")]
    assert_eq!(
        unsafe { cksumvfs_sqlite_version_number() },
        rusqlite::version_number()
    );
    assert_eq!(
        unsafe { sqlite3_register_cksumvfs(std::ptr::null()) },
        rusqlite::ffi::SQLITE_OK
    )
}

pub fn enable_sqlite_checksums(db: &rusqlite::Connection) -> Result<(), anyhow::Error> {
    let mut n = 8;
    if unsafe {
        rusqlite::ffi::sqlite3_file_control(
            db.handle(),
            std::ptr::null(),
            rusqlite::ffi::SQLITE_FCNTL_RESERVE_BYTES,
            (&mut n) as *mut i32 as *mut core::ffi::c_void,
        )
    } != rusqlite::ffi::SQLITE_OK
    {
        anyhow::bail!("unable to reserve bytes for sqlite3 page checksums");
    }
    if n != 0 && n != 8 {
        anyhow::bail!("database has incorrect reserve bytes for checksums");
    }
    if n == 0 {
        db.execute("vacuum;", [])?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_cksumvfs_can_be_enabled() {
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("test.db3");
        {
            register_cksumvfs();
            let db = rusqlite::Connection::open(&path).unwrap();
            enable_sqlite_checksums(&db).unwrap();
            let enabled: String = db
                .query_row("PRAGMA checksum_verification;", [], |r| {
                    Ok(r.get(0).unwrap())
                })
                .unwrap();
            assert_eq!(enabled, "1");
        }
    }
}
