fn main() {
    pkg_config::probe_library("libsodium").unwrap();

    println!("cargo:rerun-if-changed=csrc/cksumvfs/sqlite3.h");

    let mut build = cc::Build::new();
    build
        .warnings(false) // Not our code/warnings to fix.
        .flag("-DSQLITE_CKSUMVFS_STATIC");
    if cfg!(feature = "bundled-sqlite") {
        build
            .flag("-Icsrc/cksumvfs")
            .file("csrc/cksumvfs/cksumvfs_sqlite_version_number.c");
    }
    build.file("csrc/cksumvfs/cksumvfs.c").compile("cksumvfs");
}
