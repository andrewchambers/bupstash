use serde::{Deserialize, Serialize};
use std::convert::TryInto;

mod sodium {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    #![allow(dead_code)]
    include!(concat!(env!("OUT_DIR"), "/sodium_bindings.rs"));
}

const BOX_NONCEBYTES: usize = sodium::crypto_box_curve25519xchacha20poly1305_NONCEBYTES as usize;
const BOX_PUBLICKEYBYTES: usize =
    sodium::crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES as usize;
const BOX_SECRETKEYBYTES: usize =
    sodium::crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES as usize;
const BOX_BEFORENMBYTES: usize =
    sodium::crypto_box_curve25519xchacha20poly1305_BEFORENMBYTES as usize;
const BOX_MACBYTES: usize = sodium::crypto_box_curve25519xchacha20poly1305_MACBYTES as usize;

const CHUNK_FOOTER_NO_COMPRESSION: u8 = 0;
const CHUNK_FOOTER_ZSTD_COMPRESSED: u8 = 1;

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

pub struct BoxNonce {
    bytes: [u8; BOX_NONCEBYTES as usize],
}

impl BoxNonce {
    pub fn new() -> Self {
        let mut bytes: [u8; BOX_NONCEBYTES as usize] =
            unsafe { std::mem::MaybeUninit::uninit().assume_init() };
        randombytes(&mut bytes[..]);
        BoxNonce { bytes }
    }

    pub fn inc(&mut self) {
        unsafe {
            sodium::sodium_increment(
                self.bytes.as_mut_ptr(),
                self.bytes.len().try_into().unwrap(),
            )
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Clone)]
pub struct BoxSecretKey {
    bytes: [u8; BOX_SECRETKEYBYTES],
}

impl BoxSecretKey {
    /* nothing */
}

impl Drop for BoxSecretKey {
    fn drop(&mut self) {
        memzero(&mut self.bytes[..]);
    }
}

#[derive(Serialize, Deserialize, PartialEq, Clone)]
pub struct BoxPublicKey {
    bytes: [u8; BOX_PUBLICKEYBYTES as usize],
}

impl BoxPublicKey {
    /* nothing */
}

pub fn box_keypair() -> (BoxPublicKey, BoxSecretKey) {
    let mut pk = BoxPublicKey {
        bytes: [0; BOX_PUBLICKEYBYTES],
    };
    let mut sk = BoxSecretKey {
        bytes: [0; BOX_SECRETKEYBYTES],
    };
    unsafe {
        sodium::crypto_box_curve25519xchacha20poly1305_keypair(
            pk.bytes.as_mut_ptr(),
            sk.bytes.as_mut_ptr(),
        );
    }
    (pk, sk)
}

pub struct BoxKey {
    bytes: [u8; BOX_BEFORENMBYTES],
}

impl BoxSecretKey {
    /* nothing */
}

impl Drop for BoxKey {
    fn drop(&mut self) {
        memzero(&mut self.bytes[..]);
    }
}

#[inline(always)]
pub fn box_compute_key(pk: &BoxPublicKey, sk: &BoxSecretKey) -> BoxKey {
    let mut bytes: [u8; BOX_BEFORENMBYTES] =
        unsafe { std::mem::MaybeUninit::uninit().assume_init() };
    if unsafe {
        sodium::crypto_box_curve25519xchacha20poly1305_beforenm(
            bytes.as_mut_ptr(),
            pk.bytes.as_ptr(),
            sk.bytes.as_ptr(),
        )
    } != 0
    {
        BoxKey {
            bytes: [0; BOX_BEFORENMBYTES],
        }
    } else {
        BoxKey { bytes }
    }
}

#[inline(always)]
pub fn box_encrypt(bt: &mut [u8], pt: &[u8], nonce: &mut BoxNonce, bk: &BoxKey) {
    if bt.len() != pt.len() + BOX_NONCEBYTES + BOX_MACBYTES {
        panic!("box_encrypt output slice wrong size")
    }
    bt[..BOX_NONCEBYTES].clone_from_slice(&nonce.bytes[..]);
    if unsafe {
        sodium::crypto_box_curve25519xchacha20poly1305_easy_afternm(
            bt[nonce.bytes.len()..].as_mut_ptr(),
            pt.as_ptr(),
            pt.len().try_into().unwrap(),
            nonce.bytes.as_ptr(),
            bk.bytes.as_ptr(),
        )
    } != 0
    {
        panic!();
    }
    nonce.inc();
}

#[inline(always)]
pub fn box_decrypt(pt: &mut [u8], bt: &[u8], bk: &BoxKey) -> bool {
    if bt.len() < BOX_NONCEBYTES + BOX_MACBYTES {
        return false;
    }
    if pt.len() != bt.len() - BOX_NONCEBYTES - BOX_MACBYTES {
        return false;
    }
    let nonce = &bt[..BOX_NONCEBYTES];
    let ct = &bt[BOX_NONCEBYTES..];
    if unsafe {
        sodium::crypto_box_curve25519xchacha20poly1305_open_easy_afternm(
            pt.as_mut_ptr(),
            ct.as_ptr(),
            ct.len().try_into().unwrap(),
            nonce.as_ptr(),
            bk.bytes.as_ptr(),
        )
    } != 0
    {
        return false;
    }
    true
}

fn zstd_compress_chunk(mut data: Vec<u8>) -> Vec<u8> {
    // Our max chunk size means this should never happen.
    assert!(data.len() <= 0xffffffff);
    let mut compressed_data = zstd::block::compress(&data, 0).unwrap();
    if (compressed_data.len() + 4) >= data.len() {
        data.push(CHUNK_FOOTER_NO_COMPRESSION);
        data
    } else {
        compressed_data.reserve(5);
        let sz = data.len() as u32;
        compressed_data.push((sz & 0x000000ff) as u8);
        compressed_data.push(((sz & 0x0000ff00) >> 8) as u8);
        compressed_data.push(((sz & 0x00ff0000) >> 16) as u8);
        compressed_data.push(((sz & 0xff000000) >> 24) as u8);
        compressed_data.push(CHUNK_FOOTER_ZSTD_COMPRESSED);
        compressed_data
    }
}

fn decompress_chunk(mut data: Vec<u8>) -> Result<Vec<u8>, failure::Error> {
    if data.is_empty() {
        failure::bail!("data chunk was too small, missing footer");
    }

    let data = match data[data.len() - 1] {
        footer if footer == CHUNK_FOOTER_NO_COMPRESSION => {
            data.pop();
            data
        }
        footer if footer == CHUNK_FOOTER_ZSTD_COMPRESSED => {
            data.pop();
            if data.len() < 4 {
                failure::bail!("data footer missing decompressed size");
            }
            let data_len = data.len();
            let decompressed_sz = ((data[data_len - 1] as u32) << 24)
                | ((data[data_len - 2] as u32) << 16)
                | ((data[data_len - 3] as u32) << 8)
                | (data[data_len - 4] as u32);
            data.truncate(data.len() - 4);
            let decompressed_data = zstd::block::decompress(&data, decompressed_sz as usize)?;
            decompressed_data
        }
        _ => failure::bail!("unknown footer type type"),
    };
    Ok(data)
}

pub enum ChunkCompression {
    None,
    Zstd,
}

pub struct EncryptionContext {
    nonce: BoxNonce,
    ephemeral_pk: BoxPublicKey,
    ephemeral_bk: BoxKey,
}

impl EncryptionContext {
    pub fn new(recipient: &BoxPublicKey) -> EncryptionContext {
        let nonce = BoxNonce::new();
        let (ephemeral_pk, ephemeral_sk) = box_keypair();
        let ephemeral_bk = box_compute_key(recipient, &ephemeral_sk);
        EncryptionContext {
            nonce,
            ephemeral_pk,
            ephemeral_bk,
        }
    }

    pub fn encrypt_chunk(&mut self, mut pt: Vec<u8>, compression: ChunkCompression) -> Vec<u8> {
        let pt = match compression {
            ChunkCompression::None => {
                pt.push(CHUNK_FOOTER_NO_COMPRESSION);
                pt
            }
            ChunkCompression::Zstd => zstd_compress_chunk(pt),
        };
        let ct_len = pt.len() + BOX_NONCEBYTES + BOX_MACBYTES + self.ephemeral_pk.bytes.len();
        let mut ct = Vec::with_capacity(ct_len);
        unsafe { ct.set_len(ct_len) };
        box_encrypt(
            &mut ct[..ct_len - self.ephemeral_pk.bytes.len()],
            &pt,
            &mut self.nonce,
            &self.ephemeral_bk,
        );
        ct[ct_len - self.ephemeral_pk.bytes.len()..].clone_from_slice(&self.ephemeral_pk.bytes[..]);
        ct
    }
}

pub struct DecryptionContext {
    sk: BoxSecretKey,
    ephemeral_pk: BoxPublicKey,
    ephemeral_bk: BoxKey,
}

impl DecryptionContext {
    pub fn new(sk: BoxSecretKey) -> DecryptionContext {
        DecryptionContext {
            sk,
            ephemeral_pk: BoxPublicKey {
                bytes: [0; BOX_PUBLICKEYBYTES],
            },
            ephemeral_bk: BoxKey {
                bytes: [0; BOX_BEFORENMBYTES],
            },
        }
    }

    pub fn decrypt_chunk(&mut self, ct: Vec<u8>) -> Result<Vec<u8>, failure::Error> {
        if ct.len() < BOX_PUBLICKEYBYTES + BOX_NONCEBYTES + BOX_MACBYTES {
            failure::bail!("data chunk corrupt");
        }

        {
            let pk_slice = &ct[ct.len() - BOX_PUBLICKEYBYTES..];
            for i in 0..BOX_PUBLICKEYBYTES {
                if pk_slice[i] != self.ephemeral_pk.bytes[i] {
                    self.ephemeral_pk.bytes[..].clone_from_slice(pk_slice);
                    self.ephemeral_bk = box_compute_key(&self.ephemeral_pk, &self.sk);
                    break;
                }
            }
        }

        let pt_len = ct.len() - BOX_NONCEBYTES - BOX_MACBYTES - BOX_PUBLICKEYBYTES;
        let mut pt = Vec::with_capacity(pt_len);
        unsafe { pt.set_len(pt_len) };

        if !box_decrypt(
            &mut pt,
            &ct[..ct.len() - BOX_PUBLICKEYBYTES],
            &self.ephemeral_bk,
        ) {
            failure::bail!("data chunk corrupt");
        }

        decompress_chunk(pt)
    }
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
    fn box_round_trip() {
        init();
        let mut nonce = BoxNonce::new();
        let (pk, sk) = box_keypair();
        let bk = box_compute_key(&pk, &sk);
        let pt1 = vec![1, 2, 3];
        let mut bt = Vec::new();
        bt.resize_with(pt1.len() + BOX_NONCEBYTES + BOX_MACBYTES, Default::default);
        box_encrypt(&mut bt, &pt1, &mut nonce, &bk);
        let mut pt2 = Vec::<u8>::new();
        pt2.resize_with(pt1.len(), Default::default);
        assert!(box_decrypt(&mut pt2, &bt, &bk));
        assert_eq!(pt1, pt2);
    }

    #[test]
    fn chunk_round_trip() {
        init();
        let (pk, sk) = box_keypair();
        let pt1 = vec![1, 2, 3];
        let mut ectx1 = EncryptionContext::new(&pk);
        let mut ectx2 = EncryptionContext::new(&pk);
        let ct1 = ectx1.encrypt_chunk(pt1.clone(), ChunkCompression::None);
        let ct2 = ectx2.encrypt_chunk(pt1.clone(), ChunkCompression::Zstd);
        let mut dctx = DecryptionContext::new(sk);
        let pt2 = dctx.decrypt_chunk(ct1).unwrap();
        let pt3 = dctx.decrypt_chunk(ct2).unwrap();
        assert_eq!(pt1, pt2);
        assert_eq!(pt1, pt3);
    }

    #[test]
    fn box_nonce_inc() {
        init();
        let mut nonce = BoxNonce::new();
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
