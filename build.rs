fn main() {
    pkg_config::probe_library("libsodium").unwrap();

    println!("cargo:rerun-if-changed=csrc/cksumvfs/sqlite3.h");
    cc::Build::new()
        .warnings(false) // Not our code/warnings to fix.
        .flag("-DSQLITE_CKSUMVFS_STATIC")
        .flag("-Icsrc/cksumvfs")
        .file("csrc/cksumvfs/cksumvfs.c")
        .file("csrc/cksumvfs/cksumvfs_sqlite_version_number.c")
        .compile("cksumvfs");
}
