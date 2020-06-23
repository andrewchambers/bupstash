use std::env;
use std::path::PathBuf;

fn main() {
    let bindings = bindgen::Builder::default()
        .header("csrc/libsodium/bindings.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .whitelist_function("crypto_.*")
        .whitelist_type("crypto_.*")
        .whitelist_var("crypto_.*")
        .whitelist_function("sodium_.*")
        .whitelist_type("sodium_.*")
        .whitelist_var("sodium_.*")
        .whitelist_function("randombytes_.*")
        .rustfmt_bindings(true)
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("sodium_bindings.rs"))
        .expect("Couldn't write bindings!");

    pkg_config::probe_library("libsodium").unwrap();
}
