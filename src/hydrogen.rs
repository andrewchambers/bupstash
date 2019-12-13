// The simplest possible bindings to libhydrogen we can use.
// Don't even create wrapper types, as we do that at a higher level.

mod libhydrogen {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    #![allow(dead_code)]
    include!(concat!(env!("OUT_DIR"), "/hydrogen_bindings.rs"));
}

use std::ffi::c_void;

pub const HASH_BYTES: usize = libhydrogen::hydro_hash_BYTES as usize;
pub const HASH_KEYBYTES: usize = libhydrogen::hydro_hash_KEYBYTES as usize;
pub const KX_PUBLICKEYBYTES: usize = libhydrogen::hydro_kx_PUBLICKEYBYTES as usize;
pub const KX_SECRETKEYBYTES: usize = libhydrogen::hydro_kx_SECRETKEYBYTES as usize;
pub const KX_SESSIONKEYBYTES: usize = libhydrogen::hydro_kx_SESSIONKEYBYTES as usize;
pub const KX_N_PACKET1BYTES: usize = libhydrogen::hydro_kx_N_PACKET1BYTES as usize;
pub const KX_PSKBYTES: usize = libhydrogen::hydro_kx_PSKBYTES as usize;

pub fn kx_keygen() -> ([u8; KX_PUBLICKEYBYTES], [u8; KX_SECRETKEYBYTES]) {
    let mut k = libhydrogen::hydro_kx_keypair {
        pk: [0; KX_PUBLICKEYBYTES],
        sk: [0; KX_SECRETKEYBYTES],
    };
    unsafe {
        libhydrogen::hydro_kx_keygen(&mut k);
    }
    (k.pk, k.sk)
}

pub fn kx_n_1(
    psk: &[u8; KX_PSKBYTES],
    server_pk: &[u8; KX_PUBLICKEYBYTES],
) -> (
    [u8; KX_SESSIONKEYBYTES],
    [u8; KX_SESSIONKEYBYTES],
    [u8; KX_N_PACKET1BYTES],
) {
    let mut packet1 = [0; KX_N_PACKET1BYTES];
    let mut session_kp = libhydrogen::hydro_kx_session_keypair {
        tx: [0; KX_SESSIONKEYBYTES],
        rx: [0; KX_SESSIONKEYBYTES],
    };
    unsafe {
        libhydrogen::hydro_kx_n_1(
            &mut session_kp,
            (&mut packet1).as_mut_ptr(),
            psk as *const u8,
            server_pk as *const u8,
        );
    }
    (session_kp.tx, session_kp.rx, packet1)
}

pub fn kx_psk_keygen() -> [u8; KX_PSKBYTES] {
    let mut k = [0; KX_PSKBYTES];
    random_buf(&mut k);
    k
}

pub fn hash_keygen() -> [u8; HASH_KEYBYTES] {
    let mut k = [0; HASH_KEYBYTES];
    unsafe {
        libhydrogen::hydro_hash_keygen(k.as_mut_ptr());
    }
    k
}

pub fn random_buf(buf: &mut [u8]) {
    unsafe { libhydrogen::hydro_random_buf(buf.as_mut_ptr() as *mut c_void, buf.len() as usize) }
}

pub fn hash(message: &mut [u8], context: &[u8; 8], key: &[u8; HASH_KEYBYTES]) -> [u8; HASH_BYTES] {
    let mut h = [0; HASH_BYTES];
    unsafe {
        libhydrogen::hydro_hash_hash(
            (&mut h).as_mut_ptr(),
            h.len() as usize,
            message.as_mut_ptr() as *mut c_void,
            message.len(),
            context.as_ptr() as *const i8,
            key.as_ptr(),
        );
    }
    h
}

pub unsafe fn init() {
    libhydrogen::hydro_init();
}
