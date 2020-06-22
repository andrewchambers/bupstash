use serde::{Deserialize, Serialize};
use std::convert::TryInto;

mod sodium {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    #![allow(dead_code)]
    include!(concat!(env!("OUT_DIR"), "/sodium_bindings.rs"));
}

pub fn init() {
    unsafe {
        sodium::sodium_init();
    };
}

#[inline(always)]
pub fn randombytes(buf: &mut [u8]) {
    unsafe {
        sodium::randombytes_buf(
            buf.as_mut_ptr() as *mut std::ffi::c_void,
            buf.len().try_into().unwrap(),
        );
    }
}

#[inline(always)]
pub fn memzero(buf: &mut [u8]) {
    unsafe {
        sodium::sodium_memzero(
            buf.as_mut_ptr() as *mut std::ffi::c_void,
            buf.len().try_into().unwrap(),
        );
    }
}

pub struct SecretBoxNonce {
    bytes: [u8; sodium::crypto_secretbox_NONCEBYTES as usize],
}

impl SecretBoxNonce {
    pub fn new() -> Self {
        let mut bytes: [u8; sodium::crypto_secretbox_NONCEBYTES as usize] =
            unsafe { std::mem::MaybeUninit::uninit().assume_init() };
        randombytes(&mut bytes[..]);
        SecretBoxNonce { bytes }
    }

    pub fn inc(&mut self) {
        for i in 0..self.bytes.len() {
            if self.bytes[i] == 255 {
                self.bytes[i] = 0;
                continue;
            } else {
                self.bytes[i] += 1;
                break;
            }
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Clone)]
pub struct SecretBoxKey {
    bytes: [u8; sodium::crypto_secretbox_KEYBYTES as usize],
}

impl SecretBoxKey {
    pub fn new() -> Self {
        let mut bytes = [0; sodium::crypto_secretbox_KEYBYTES as usize];
        randombytes(&mut bytes[..]);
        SecretBoxKey { bytes }
    }
}

impl Drop for SecretBoxKey {
    fn drop(&mut self) {
        memzero(&mut self.bytes[..]);
    }
}

#[inline(always)]
pub fn secretbox(pt: &[u8], nonce: &mut SecretBoxNonce, key: &SecretBoxKey) -> Vec<u8> {
    let ct_len = pt.len() + nonce.bytes.len() + (sodium::crypto_secretbox_MACBYTES as usize);
    let mut ct = Vec::with_capacity(ct_len);
    ct.extend_from_slice(&nonce.bytes[..]);
    /* extend size to capacity, we know this is valid as we created it with ct_len */
    unsafe { ct.set_len(ct_len) }
    if unsafe {
        sodium::crypto_secretbox_easy(
            ct[nonce.bytes.len()..].as_mut_ptr(),
            pt.as_ptr() as *const u8,
            pt.len().try_into().unwrap(),
            nonce.bytes[..].as_ptr() as *const u8,
            key.bytes[..].as_ptr() as *const u8,
        )
    } != 0
    {
        panic!();
    }
    nonce.inc();
    ct
}

#[inline(always)]
pub fn secretbox_open(ct: &[u8], key: &SecretBoxKey) -> Option<Vec<u8>> {
    if ct.len()
        < (sodium::crypto_secretbox_NONCEBYTES as usize)
            + (sodium::crypto_secretbox_MACBYTES as usize)
    {
        return None;
    }
    let pt_len = ct.len()
        - (sodium::crypto_secretbox_NONCEBYTES as usize)
        - (sodium::crypto_secretbox_MACBYTES as usize);
    let mut pt = Vec::with_capacity(pt_len);
    unsafe { pt.set_len(pt_len) }

    if unsafe {
        sodium::crypto_secretbox_open_easy(
            pt.as_mut_ptr(),
            ct[(sodium::crypto_secretbox_NONCEBYTES as usize)..].as_ptr() as *const u8,
            (ct.len() - (sodium::crypto_secretbox_NONCEBYTES as usize))
                .try_into()
                .unwrap(),
            ct[0..(sodium::crypto_secretbox_NONCEBYTES as usize)].as_ptr() as *const u8,
            key.bytes[..].as_ptr() as *const u8,
        )
    } != 0
    {
        return None;
    }
    Some(pt)
}

#[derive(Serialize, Deserialize, PartialEq, Clone)]
pub struct SealedBoxSecretKey {
    bytes: [u8; sodium::crypto_box_SECRETKEYBYTES as usize],
}

impl SealedBoxSecretKey {
    /* nothing */
}

impl Drop for SealedBoxSecretKey {
    fn drop(&mut self) {
        memzero(&mut self.bytes[..]);
    }
}

#[derive(Serialize, Deserialize, PartialEq, Clone)]
pub struct SealedBoxPublicKey {
    bytes: [u8; sodium::crypto_box_PUBLICKEYBYTES as usize],
}

impl SealedBoxPublicKey {
    /* nothing */
}

pub fn sealedbox_keypair() -> (SealedBoxPublicKey, SealedBoxSecretKey) {
    let mut pk = SealedBoxPublicKey {
        bytes: [0; sodium::crypto_box_PUBLICKEYBYTES as usize],
    };
    let mut sk = SealedBoxSecretKey {
        bytes: [0; sodium::crypto_box_SECRETKEYBYTES as usize],
    };
    unsafe {
        sodium::crypto_box_keypair(pk.bytes[..].as_mut_ptr(), sk.bytes[..].as_mut_ptr());
    }
    (pk, sk)
}

#[inline(always)]
pub fn sealedbox(pt: &[u8], pk: &SealedBoxPublicKey) -> Vec<u8> {
    let ct_len = pt.len() + (sodium::crypto_box_SEALBYTES as usize);
    let mut ct = Vec::with_capacity(ct_len);
    unsafe { ct.set_len(ct_len) }
    if unsafe {
        sodium::crypto_box_seal(
            ct.as_mut_ptr(),
            pt.as_ptr() as *const u8,
            pt.len().try_into().unwrap(),
            pk.bytes[..].as_ptr() as *const u8,
        )
    } != 0
    {
        panic!();
    }
    ct
}

#[inline(always)]
pub fn sealedbox_open(
    ct: &[u8],
    pk: &SealedBoxPublicKey,
    sk: &SealedBoxSecretKey,
) -> Option<Vec<u8>> {
    if ct.len() < (sodium::crypto_box_SEALBYTES as usize) {
        return None;
    }
    let pt_len = ct.len() - (sodium::crypto_box_SEALBYTES as usize);

    let mut pt = Vec::with_capacity(pt_len);
    unsafe { pt.set_len(pt_len) }

    if unsafe {
        sodium::crypto_box_seal_open(
            pt.as_mut_ptr(),
            ct.as_ptr(),
            ct.len().try_into().unwrap(),
            pk.bytes.as_ptr(),
            sk.bytes.as_ptr(),
        )
    } != 0
    {
        return None;
    }
    Some(pt)
}

pub struct HashState {
    st: sodium::crypto_generichash_state,
}

impl HashState {
    pub fn new(key: Option<&[u8; sodium::crypto_generichash_KEYBYTES as usize]>) -> HashState {
        let mut h = HashState {
            st: unsafe { std::mem::MaybeUninit::uninit().assume_init() },
        };

        if unsafe {
            sodium::crypto_generichash_init(
                &mut h.st as *mut sodium::crypto_generichash_state,
                if let Some(k) = key {
                    k.as_ptr() as *const u8
                } else {
                    std::ptr::null()
                },
                if let Some(k) = key {
                    k.len().try_into().unwrap()
                } else {
                    0
                },
                sodium::crypto_generichash_BYTES.try_into().unwrap(),
            )
        } != 0
        {
            panic!()
        }
        h
    }

    pub fn update(&mut self, data: &[u8]) {
        if unsafe {
            sodium::crypto_generichash_update(
                &mut self.st as *mut sodium::crypto_generichash_state,
                data.as_ptr() as *const u8,
                data.len().try_into().unwrap(),
            )
        } != 0
        {
            panic!();
        };
    }

    pub fn finish(mut self) -> [u8; sodium::crypto_generichash_BYTES as usize] {
        let mut out: [u8; sodium::crypto_generichash_BYTES as usize] =
            unsafe { std::mem::MaybeUninit::uninit().assume_init() };
        if unsafe {
            sodium::crypto_generichash_final(
                &mut self.st as *mut sodium::crypto_generichash_state,
                out.as_mut_ptr(),
                out.len().try_into().unwrap(),
            )
        } != 0
        {
            panic!();
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secretbox_round_trip() {
        init();
        let key = SecretBoxKey::new();
        let mut nonce = SecretBoxNonce::new();
        let pt1 = vec![1, 2, 3];
        let ct = secretbox(&pt1, &mut nonce, &key);
        let pt2 = secretbox_open(&ct, &key).unwrap();
        assert_eq!(pt1, pt2);
    }

    #[test]
    fn sealedbox_round_trip() {
        init();
        let (pk, sk) = sealedbox_keypair();
        let pt1 = vec![1, 2, 3];
        let ct = sealedbox(&pt1, &pk);
        let pt2 = sealedbox_open(&ct, &pk, &sk).unwrap();
        assert_eq!(pt1, pt2);
    }

    #[test]
    fn secretbox_nonce_inc() {
        init();
        let mut nonce = SecretBoxNonce::new();
        nonce.bytes = [0; sodium::crypto_secretbox_NONCEBYTES as usize];
        for _i in 0..255 {
            nonce.inc()
        }
        assert_eq!(nonce.bytes[0], 255);
        assert_eq!(nonce.bytes[1], 0);
        nonce.inc();
        assert_eq!(nonce.bytes[0], 0);
        assert_eq!(nonce.bytes[1], 1);
        nonce.bytes = [255; sodium::crypto_secretbox_NONCEBYTES as usize];
        nonce.inc();
        for b in nonce.bytes.iter() {
            assert_eq!(*b, 0);
        }
    }
}
