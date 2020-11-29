use super::address::*;
use super::compression;
use super::rollsum;
use super::sodium;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;

pub const HASH_BYTES: usize = 32;

pub const BOX_NONCEBYTES: usize =
    sodium::crypto_box_curve25519xchacha20poly1305_NONCEBYTES as usize;
pub const BOX_PUBLICKEYBYTES: usize =
    sodium::crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES as usize;
pub const BOX_SECRETKEYBYTES: usize =
    sodium::crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES as usize;
pub const BOX_BEFORENMBYTES: usize =
    sodium::crypto_box_curve25519xchacha20poly1305_BEFORENMBYTES as usize;
pub const BOX_MACBYTES: usize = sodium::crypto_box_curve25519xchacha20poly1305_MACBYTES as usize;

pub const BOX_PRE_SHARED_KEY_BYTES: usize = 32;

pub const RANDOM_SEED_BYTES: usize = 32;

pub fn init() {
    unsafe {
        sodium::sodium_init();
    };
}

#[inline(always)]
pub fn randombytes(buf: &mut [u8]) {
    unsafe {
        sodium::randombytes_buf(buf.as_mut_ptr() as *mut std::ffi::c_void, buf.len());
    }
}

#[inline(always)]
pub fn randombytes_buf_deterministic(seed: &[u8; RANDOM_SEED_BYTES], buf: &mut [u8]) {
    unsafe {
        sodium::randombytes_buf_deterministic(
            buf.as_mut_ptr() as *mut std::ffi::c_void,
            buf.len(),
            seed.as_ptr() as *const u8,
        );
    }
}

#[inline(always)]
pub fn memzero(buf: &mut [u8]) {
    unsafe {
        sodium::sodium_memzero(buf.as_mut_ptr() as *mut std::ffi::c_void, buf.len());
    }
}

#[derive(Clone)]
pub struct BoxNonce {
    pub bytes: [u8; BOX_NONCEBYTES as usize],
}

impl BoxNonce {
    pub fn new() -> Self {
        let mut bytes: [u8; BOX_NONCEBYTES as usize] = [0; BOX_NONCEBYTES];
        randombytes(&mut bytes[..]);
        BoxNonce { bytes }
    }

    pub fn inc(&mut self) {
        unsafe { sodium::sodium_increment(self.bytes.as_mut_ptr(), self.bytes.len()) }
    }
}

impl Default for BoxNonce {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct BoxSecretKey {
    pub bytes: [u8; BOX_SECRETKEYBYTES],
}

impl BoxSecretKey {
    /* nothing */
}

impl Drop for BoxSecretKey {
    fn drop(&mut self) {
        memzero(&mut self.bytes[..]);
    }
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct BoxPublicKey {
    pub bytes: [u8; BOX_PUBLICKEYBYTES as usize],
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

#[derive(Clone)]
pub struct BoxKey {
    pub bytes: [u8; BOX_BEFORENMBYTES],
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
pub fn box_compute_key(pk: &BoxPublicKey, sk: &BoxSecretKey, psk: &BoxPreSharedKey) -> BoxKey {
    let mut unmixed_key_bytes: [u8; BOX_BEFORENMBYTES] =
        unsafe { std::mem::MaybeUninit::uninit().assume_init() };
    if unsafe {
        sodium::crypto_box_curve25519xchacha20poly1305_beforenm(
            unmixed_key_bytes.as_mut_ptr(),
            pk.bytes.as_ptr(),
            sk.bytes.as_ptr(),
        )
    } == 0
    {
        /*
          XXX TODO FIXME REVIEWME:
          Integrate the preshared key bytes with the computed secret so the
          decrypting party must have had access to one of our keys. Post
          quantum is a threat to our asymmetric key security, the PSK is
          intended to help us gracefully degrade to symmetric key security,
          even if the asymmetric key is broken.

          This key mixing relies on the implementation of the crypto box, the
          result of crypto_box_curve25519xchacha20poly1305_beforenm is the precomputed
          crypto_secretbox_xsalsa20poly1305 key, which are simply random keys. Using
          generic hash to mix the psk with this key should result is another random key.

          We need advice from experts on how to do this appropriately, and if
          what even we are doing is right at all.
        */
        BoxKey {
            bytes: blake3::keyed_hash(&psk.bytes, &unmixed_key_bytes[..]).into(),
        }
    } else {
        BoxKey {
            bytes: [0; BOX_BEFORENMBYTES],
        }
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

#[derive(Clone)]
pub struct EncryptionContext {
    nonce: BoxNonce,
    ephemeral_pk: BoxPublicKey,
    ephemeral_bk: BoxKey,
}

impl EncryptionContext {
    pub fn new(recipient: &BoxPublicKey, psk: &BoxPreSharedKey) -> EncryptionContext {
        let nonce = BoxNonce::new();
        let (ephemeral_pk, ephemeral_sk) = box_keypair();
        let ephemeral_bk = box_compute_key(recipient, &ephemeral_sk, &psk);
        EncryptionContext {
            nonce,
            ephemeral_pk,
            ephemeral_bk,
        }
    }

    pub fn encrypt_data(&mut self, pt: Vec<u8>, compression: compression::Scheme) -> Vec<u8> {
        let pt = compression::compress(compression, pt);
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

#[derive(Clone)]
pub struct DecryptionContext {
    sk: BoxSecretKey,
    psk: BoxPreSharedKey,
    ephemeral_pk: BoxPublicKey,
    ephemeral_bk: BoxKey,
}

impl DecryptionContext {
    pub fn new(sk: BoxSecretKey, psk: BoxPreSharedKey) -> DecryptionContext {
        DecryptionContext {
            sk,
            psk,
            ephemeral_pk: BoxPublicKey {
                bytes: [0; BOX_PUBLICKEYBYTES],
            },
            ephemeral_bk: BoxKey {
                bytes: [0; BOX_BEFORENMBYTES],
            },
        }
    }

    pub fn decrypt_data(&mut self, ct: Vec<u8>) -> Result<Vec<u8>, anyhow::Error> {
        if ct.len() < BOX_PUBLICKEYBYTES + BOX_NONCEBYTES + BOX_MACBYTES {
            anyhow::bail!("data corrupt (too small)");
        }

        {
            let pk_slice = &ct[ct.len() - BOX_PUBLICKEYBYTES..];
            for i in 0..BOX_PUBLICKEYBYTES {
                if pk_slice[i] != self.ephemeral_pk.bytes[i] {
                    self.ephemeral_pk.bytes[..].clone_from_slice(pk_slice);
                    self.ephemeral_bk = box_compute_key(&self.ephemeral_pk, &self.sk, &self.psk);
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
            anyhow::bail!("data corrupt");
        }

        compression::decompress(pt)
    }
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct PartialHashKey {
    pub bytes: [u8; 32],
}

impl PartialHashKey {
    pub fn new() -> Self {
        let mut bytes = [0; 32];
        randombytes(&mut bytes[..]);
        PartialHashKey { bytes }
    }
}

impl Default for PartialHashKey {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for PartialHashKey {
    fn drop(&mut self) {
        memzero(&mut self.bytes[..]);
    }
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct BoxPreSharedKey {
    pub bytes: [u8; 32],
}

impl BoxPreSharedKey {
    pub fn new() -> Self {
        let mut bytes: [u8; 32] = [0; 32];
        randombytes(&mut bytes[..]);
        BoxPreSharedKey { bytes }
    }
}

impl Default for BoxPreSharedKey {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for BoxPreSharedKey {
    fn drop(&mut self) {
        memzero(&mut self.bytes[..]);
    }
}

pub fn derive_hash_key(part1: &PartialHashKey, part2: &PartialHashKey) -> HashKey {
    let mut hs = HashState::new(None);
    hs.update(&part1.bytes[..]);
    hs.update(&part2.bytes[..]);
    let bytes = hs.finish();
    HashKey {
        part1: part1.clone(),
        part2: part2.clone(),
        bytes,
    }
}

#[derive(Serialize, Deserialize, PartialEq, Clone)]
pub struct HashKey {
    pub part1: PartialHashKey,
    pub part2: PartialHashKey,
    pub bytes: [u8; 32],
}

impl Drop for HashKey {
    fn drop(&mut self) {
        memzero(&mut self.bytes[..]);
    }
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct RollsumKey {
    pub bytes: [u8; RANDOM_SEED_BYTES],
}

impl RollsumKey {
    pub fn new() -> Self {
        let mut bytes = [0; RANDOM_SEED_BYTES];
        randombytes(&mut bytes[..]);
        RollsumKey { bytes }
    }

    pub fn gear_tab(&self) -> rollsum::GearTab {
        let mut tab_bytes = [0; 256 * (rollsum::WINDOW_SIZE / 8)];
        randombytes_buf_deterministic(&self.bytes, &mut tab_bytes[..]);
        let mut tab = [0; 256];
        for (i, sl) in tab_bytes.chunks(rollsum::WINDOW_SIZE / 8).enumerate() {
            tab[i] = u32::from_le_bytes(sl.try_into().unwrap());
        }
        tab
    }
}

impl Default for RollsumKey {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for RollsumKey {
    fn drop(&mut self) {
        memzero(&mut self.bytes[..]);
    }
}

pub struct HashState {
    st: blake3::Hasher,
}

impl HashState {
    #[inline(always)]
    pub fn new(key: Option<&HashKey>) -> HashState {
        match key {
            Some(k) => HashState {
                st: blake3::Hasher::new_keyed(&k.bytes),
            },
            None => HashState {
                st: blake3::Hasher::new(),
            },
        }
    }

    #[inline(always)]
    pub fn update(&mut self, data: &[u8]) {
        self.st.update(data);
    }

    #[inline(always)]
    pub fn finish(self) -> [u8; HASH_BYTES] {
        self.st.finalize().into()
    }
}

pub fn keyed_content_address(data: &[u8], key: &HashKey) -> Address {
    let mut hs = HashState::new(Some(key));
    hs.update(data);
    let bytes = hs.finish();
    Address { bytes }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn box_round_trip() {
        init();
        let mut nonce = BoxNonce::new();
        let (pk, sk) = box_keypair();
        let psk = BoxPreSharedKey::new();
        let bk = box_compute_key(&pk, &sk, &psk);
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
    fn data_round_trip() {
        init();
        let (pk, sk) = box_keypair();
        let psk = BoxPreSharedKey::new();
        let pt1 = vec![1, 2, 3];
        let mut ectx1 = EncryptionContext::new(&pk, &psk);
        let mut ectx2 = EncryptionContext::new(&pk, &psk);
        let ct1 = ectx1.encrypt_data(pt1.clone(), compression::Scheme::None);
        let ct2 = ectx2.encrypt_data(pt1.clone(), compression::Scheme::Lz4);
        let mut dctx = DecryptionContext::new(sk, psk);
        let pt2 = dctx.decrypt_data(ct1).unwrap();
        let pt3 = dctx.decrypt_data(ct2).unwrap();
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

    #[test]
    fn random_seed_bytes_size() {
        init();
        assert_eq!(
            unsafe { sodium::randombytes_seedbytes() },
            RANDOM_SEED_BYTES
        );
    }
}
