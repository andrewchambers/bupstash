use super::hydrogen;
use super::keys;
use failure::bail;
use serde::{Deserialize, Serialize};

pub struct EncryptContext {
    pub k: keys::ClientKey,
    pub session_tx_key: [u8; hydrogen::KX_SESSIONKEYBYTES],
    pub packet1: [u8; hydrogen::KX_N_PACKET1BYTES],
    pub hash_key: [u8; hydrogen::HASH_KEYBYTES],
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptionHeader {
    pub master_key_id: [u8; keys::KEYID_SZ],
    pub hash_key2: [u8; hydrogen::HASH_KEYBYTES],
    // FIXME... Slight hack, we use a vector so serde derive works.
    pub packet1: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum VersionedEncryptionHeader {
    V1(EncryptionHeader),
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
    pub fn new(k: &keys::ClientKey) -> Self {
        let (session_tx_key, _session_rx_key, packet1) =
            hydrogen::kx_n_1(&k.data_psk, &k.master_data_pk);
        EncryptContext {
            k: *k,
            session_tx_key,
            packet1,
            hash_key: combined_hashkey(&k.hash_key1, &k.hash_key2),
        }
    }

    #[inline(always)]
    pub fn encrypt_chunk(&self, pt: &[u8], ct: &mut [u8]) {
        hydrogen::secretbox_encrypt(ct, pt, 0, *b"_chunk_\0", &self.session_tx_key)
    }

    pub fn encryption_header(&self) -> VersionedEncryptionHeader {
        VersionedEncryptionHeader::V1(EncryptionHeader {
            master_key_id: self.k.master_key_id,
            hash_key2: self.k.hash_key2,
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
    pub fn decrypt_chunk(&self, ct: &[u8], pt: &mut [u8]) -> bool {
        hydrogen::secretbox_decrypt(pt, ct, 0, *b"_chunk_\0", &self.session_rx_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_encrypt() {
        let mk = keys::MasterKey::gen();
        let ck = keys::ClientKey::gen(&mk);
        let ectx = EncryptContext::new(&ck);
        let ehdr = ectx.encryption_header();
        let dctx = DecryptContext::open(&mk, &ehdr).unwrap();
        let mut pt = [1, 2, 3];
        let mut ct = [0; hydrogen::SECRETBOX_HEADERBYTES + 3];
        ectx.encrypt_chunk(&pt, &mut ct);
        assert!(dctx.decrypt_chunk(&ct, &mut pt));
        assert_eq!(pt[0], 1);
        assert_eq!(pt[1], 2);
        assert_eq!(pt[2], 3);
    }
}
