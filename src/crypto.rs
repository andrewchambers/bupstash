use super::address;
use super::hydrogen;
use super::keys;
use failure::bail;
use serde::{Deserialize, Serialize};

pub struct EncryptContext {
    pub k: keys::Key,
    pub session_tx_key: [u8; hydrogen::KX_SESSIONKEYBYTES],
    pub packet1: [u8; hydrogen::KX_N_PACKET1BYTES],
    pub hash_key: [u8; hydrogen::HASH_KEYBYTES],
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct EncryptionHeader {
    pub master_key_id: [u8; keys::KEYID_SZ],
    pub hash_key2: [u8; hydrogen::HASH_KEYBYTES],
    // FIXME... Slight hack, we use a vector so serde derive works.
    pub packet1: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum VersionedEncryptionHeader {
    V1(EncryptionHeader),
}

impl VersionedEncryptionHeader {
    pub fn master_key_id(&self) -> [u8; keys::KEYID_SZ] {
        match self {
            VersionedEncryptionHeader::V1(hdr) => hdr.master_key_id,
        }
    }
}

fn combined_hashkey(
    k1: &[u8; hydrogen::HASH_KEYBYTES],
    k2: &[u8; hydrogen::HASH_KEYBYTES],
) -> [u8; hydrogen::HASH_KEYBYTES] {
    let mut hash_key = [0; hydrogen::HASH_KEYBYTES];
    for (i, b) in hash_key.iter_mut().enumerate() {
        *b = k1[i] ^ k2[i];
    }
    hash_key
}

impl EncryptContext {
    pub fn new(k: &keys::Key) -> Self {
        let (psk, pk, hash_key1, hash_key2) = match k {
            keys::Key::MasterKeyV1(k) => (k.data_psk, k.data_pk, k.hash_key1, k.hash_key2),
            keys::Key::SendKeyV1(k) => (k.data_psk, k.master_data_pk, k.hash_key1, k.hash_key2),
        };
        let (session_tx_key, _session_rx_key, packet1) = hydrogen::kx_n_1(&psk, &pk);
        EncryptContext {
            k: *k,
            session_tx_key,
            packet1,
            hash_key: combined_hashkey(&hash_key1, &hash_key2),
        }
    }

    #[inline(always)]
    pub fn encrypt_chunk(&self, pt: &[u8]) -> Vec<u8> {
        let n = pt.len() + hydrogen::SECRETBOX_HEADERBYTES;
        let mut ct = Vec::with_capacity(n);
        // This is safe as u8 is primitive, and capacity is valid by definition.
        unsafe { ct.set_len(n) };
        hydrogen::secretbox_encrypt(&mut ct, pt, 0, *b"_chunk_\0", &self.session_tx_key);
        ct
    }

    #[inline(always)]
    pub fn keyed_content_address(&self, pt: &[u8]) -> address::Address {
        address::Address::from_bytes(&hydrogen::hash_with_key(pt, *b"_address", &self.hash_key))
    }

    pub fn encryption_header(&self) -> VersionedEncryptionHeader {
        let (master_key_id, hash_key2) = match self.k {
            keys::Key::MasterKeyV1(k) => (k.id, k.hash_key2),
            keys::Key::SendKeyV1(k) => (k.master_key_id, k.hash_key2),
        };
        VersionedEncryptionHeader::V1(EncryptionHeader {
            master_key_id,
            hash_key2,
            packet1: Vec::from(&self.packet1[..]),
        })
    }
}

pub struct DecryptContext {
    pub k: keys::MasterKey,
    pub session_rx_key: [u8; hydrogen::KX_SESSIONKEYBYTES],
    pub hash_key: [u8; hydrogen::HASH_KEYBYTES],
}

impl DecryptContext {
    pub fn open(
        k: &keys::MasterKey,
        hdr: &VersionedEncryptionHeader,
    ) -> Result<Self, failure::Error> {
        match hdr {
            VersionedEncryptionHeader::V1(ref hdr) => {
                if hdr.master_key_id != k.id {
                    bail!("provided master key does not match master key used to encrypt data");
                }

                if hdr.packet1.len() != hydrogen::KX_N_PACKET1BYTES {
                    bail!("provided encryption header is corrupt");
                }

                let mut packet1: [u8; hydrogen::KX_N_PACKET1BYTES] =
                    [0; hydrogen::KX_N_PACKET1BYTES];
                packet1.clone_from_slice(&hdr.packet1);

                match hydrogen::kx_n_2(&packet1, &k.data_psk, &k.data_pk, &k.data_sk) {
                    Some((_session_tx_key, session_rx_key)) => Ok(DecryptContext {
                        k: *k,
                        session_rx_key,
                        hash_key: combined_hashkey(&k.hash_key1, &hdr.hash_key2),
                    }),
                    None => bail!("tampering or corruption detected while deriving decryption key"),
                }
            }
        }
    }

    #[inline(always)]
    pub fn keyed_content_address(&self, pt: &[u8]) -> address::Address {
        address::Address::from_bytes(&hydrogen::hash_with_key(pt, *b"_address", &self.hash_key))
    }

    #[inline(always)]
    pub fn decrypt_chunk(&self, ct: &[u8]) -> Option<Vec<u8>> {
        let n = ct.len() - hydrogen::SECRETBOX_HEADERBYTES;
        let mut pt = Vec::with_capacity(n);
        // This us safe ai u8 is primitive, and capacity is valid by definition.
        unsafe { pt.set_len(n) };
        if hydrogen::secretbox_decrypt(&mut pt, ct, 0, *b"_chunk_\0", &self.session_rx_key) {
            Some(pt)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn master_key_round_trip_encrypt() {
        let master_key = keys::MasterKey::gen();
        let ectx = EncryptContext::new(&keys::Key::MasterKeyV1(master_key));
        let ehdr = ectx.encryption_header();
        let dctx = DecryptContext::open(&master_key, &ehdr).unwrap();
        let pt = [1, 2, 3];
        let ct = ectx.encrypt_chunk(&pt);
        let pt2 = dctx.decrypt_chunk(&ct).unwrap();
        assert_eq!(pt2, [1, 2, 3]);
    }

    #[test]
    fn send_key_round_trip_encrypt() {
        let master_key = keys::MasterKey::gen();
        let send_key = keys::SendKey::gen(&master_key);
        let ectx = EncryptContext::new(&keys::Key::SendKeyV1(send_key));
        let ehdr = ectx.encryption_header();
        let dctx = DecryptContext::open(&master_key, &ehdr).unwrap();
        let pt = [1, 2, 3];
        let ct = ectx.encrypt_chunk(&pt);
        let pt2 = dctx.decrypt_chunk(&ct).unwrap();
        assert_eq!(pt2, [1, 2, 3]);
    }
}
