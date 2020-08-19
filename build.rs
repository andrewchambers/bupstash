fn main() {
    pkg_config::probe_library("libsodium").unwrap();
}
