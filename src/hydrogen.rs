mod libhydrogen {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    #![allow(dead_code)]
    include!(concat!(env!("OUT_DIR"), "/hydrogen_bindings.rs"));
}
use std::ffi::c_void;

pub const SECRETBOX_KEYBYTES: usize = libhydrogen::hydro_secretbox_KEYBYTES as usize;
pub const SECRETBOX_HEADERBYTES: usize = libhydrogen::hydro_secretbox_HEADERBYTES as usize;
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

pub fn kx_n_2(
    packet1: &[u8; KX_N_PACKET1BYTES],
    psk: &[u8; KX_PSKBYTES],
    pk: &[u8; KX_PUBLICKEYBYTES],
    sk: &[u8; KX_SECRETKEYBYTES],
) -> Option<([u8; KX_SESSIONKEYBYTES], [u8; KX_SESSIONKEYBYTES])> {
    let kp = libhydrogen::hydro_kx_keypair { pk: *pk, sk: *sk };
    let mut session_kp = libhydrogen::hydro_kx_session_keypair {
        tx: [0; KX_SESSIONKEYBYTES],
        rx: [0; KX_SESSIONKEYBYTES],
    };
    let rc = unsafe {
        libhydrogen::hydro_kx_n_2(&mut session_kp, packet1.as_ptr(), psk as *const u8, &kp)
    };
    if rc == 0 {
        Some((session_kp.tx, session_kp.rx))
    } else {
        None
    }
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

pub fn random(sz: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(sz);
    unsafe {
        v.set_len(sz);
        libhydrogen::hydro_random_buf((&mut v).as_mut_ptr() as *mut c_void, v.len() as usize);
    };
    v
}

pub fn hash(
    message: &[u8],
    context: [u8; 8],
    key: Option<&[u8; HASH_KEYBYTES]>,
    output: &mut [u8],
) {
    unsafe {
        libhydrogen::hydro_hash_hash(
            output.as_mut_ptr(),
            output.len() as usize,
            message.as_ptr() as *mut c_void,
            message.len(),
            context.as_ptr() as *const i8,
            if let Some(k) = key {
                k.as_ptr() as *const u8
            } else {
                std::ptr::null()
            },
        );
    }
}

pub struct Hash {
    st: libhydrogen::hydro_hash_state,
}

impl Hash {
    pub fn init(context: [u8; 8], key: Option<&[u8; HASH_KEYBYTES]>) -> Hash {
        let mut h = Hash {
            st: unsafe {
                std::mem::MaybeUninit::<libhydrogen::hydro_hash_state>::uninit().assume_init()
            },
        };

        unsafe {
            libhydrogen::hydro_hash_init(
                &mut h.st as *mut libhydrogen::hydro_hash_state,
                context.as_ptr() as *const i8,
                if let Some(k) = key {
                    k.as_ptr() as *const u8
                } else {
                    std::ptr::null()
                },
            )
        };

        h
    }

    pub fn update(&mut self, data: &[u8]) {
        unsafe {
            libhydrogen::hydro_hash_update(
                &mut self.st as *mut libhydrogen::hydro_hash_state,
                data.as_ptr() as *const std::ffi::c_void,
                data.len() as usize,
            )
        };
    }

    pub fn finish(mut self, out: &mut [u8]) {
        assert!(out.len() >= libhydrogen::hydro_hash_BYTES_MIN as usize);
        assert!(out.len() <= libhydrogen::hydro_hash_BYTES_MAX as usize);
        unsafe {
            libhydrogen::hydro_hash_update(
                &mut self.st as *mut libhydrogen::hydro_hash_state,
                out.as_mut_ptr() as *const std::ffi::c_void,
                out.len() as usize,
            )
        };
    }
}

pub fn secretbox_keygen() -> [u8; SECRETBOX_KEYBYTES] {
    let mut k = [0; SECRETBOX_KEYBYTES];
    unsafe {
        libhydrogen::hydro_secretbox_keygen(k.as_mut_ptr());
    }
    k
}

#[inline(always)]
pub fn secretbox_encrypt(
    ct: &mut [u8],
    pt: &[u8],
    tag: u64,
    context: [u8; 8],
    k: &[u8; SECRETBOX_KEYBYTES],
) {
    if ct.len() < pt.len() + SECRETBOX_HEADERBYTES {
        panic!();
    }
    if unsafe {
        libhydrogen::hydro_secretbox_encrypt(
            ct.as_mut_ptr(),
            pt.as_ptr() as *const c_void,
            pt.len(),
            tag,
            context.as_ptr() as *const i8,
            k as *const u8,
        )
    } != 0
    {
        panic!();
    }
}

#[inline(always)]
pub fn secretbox_decrypt(
    pt: &mut [u8],
    ct: &[u8],
    tag: u64,
    context: [u8; 8],
    k: &[u8; SECRETBOX_KEYBYTES],
) -> bool {
    if pt.len() < ct.len() - SECRETBOX_HEADERBYTES {
        panic!();
    }

    unsafe {
        libhydrogen::hydro_secretbox_decrypt(
            pt.as_mut_ptr() as *mut c_void,
            ct.as_ptr(),
            ct.len(),
            tag,
            context.as_ptr() as *const i8,
            k as *const u8,
        ) == 0
    }
}

/// # Safety
///
/// This function should only be called once at the beginning of a program using libhydrogen.
pub unsafe fn init() {
    libhydrogen::hydro_init();
}

#[cfg(test)]
mod tests {
    use super::*;
    use test::Bencher;

    #[bench]
    fn bench_encrypt_1_m_bytes(b: &mut Bencher) {
        let pt = vec![0; 1000000];
        let mut ct = vec![0; 1000000 + SECRETBOX_HEADERBYTES];
        let k = secretbox_keygen();
        b.iter(|| secretbox_encrypt(&mut ct, &pt, 0, *b"_bench_\0", &k))
    }

    #[bench]
    fn bench_decrypt_1_m_bytes(b: &mut Bencher) {
        let mut pt = vec![0; 1000000];
        let mut ct = vec![0; 1000000 + SECRETBOX_HEADERBYTES];
        let k = secretbox_keygen();
        secretbox_encrypt(&mut ct, &pt, 0, *b"_bench_\0", &k);
        b.iter(|| assert!(secretbox_decrypt(&mut pt, &ct, 0, *b"_bench_\0", &k)))
    }

    #[bench]
    fn bench_kx_n2(b: &mut Bencher) {
        let (pk, sk) = kx_keygen();
        let psk: [u8; KX_PSKBYTES] = [0; KX_PSKBYTES];
        let (_, _, pkt1) = kx_n_1(&psk, &pk);
        b.iter(|| kx_n_2(&pkt1, &psk, &pk, &sk).unwrap())
    }
}
