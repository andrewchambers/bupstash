use std::env;
use std::path::PathBuf;

fn main() {
    cc::Build::new()
        .file("csrc/libhydrogen/hydrogen.c")
        .compile("hydrogen");

    let bindings = bindgen::Builder::default()
        .header("csrc/libhydrogen/hydrogen.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .whitelist_function("hydro_.*")
        .whitelist_type("hydro_.*")
        .whitelist_var("hydro_.*")
        .rustfmt_bindings(true)
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("hydrogen_bindings.rs"))
        .expect("Couldn't write bindings!");
}
