use super::address;
use super::hydrogen;
use super::keys;
use failure::bail;
use serde::{Deserialize, Serialize};

const CHUNK_FOOTER_NO_COMPRESSION: u8 = 0;
const CHUNK_FOOTER_ZSTD_COMPRESSED: u8 = 1;

pub struct EncryptContext {
    pub k: keys::Key,
    pub session_tx_key: [u8; hydrogen::KX_SESSIONKEYBYTES],
    pub packet1: [u8; hydrogen::KX_N_PACKET1BYTES],
    pub hash_key: [u8; hydrogen::HASH_KEYBYTES],
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct EncryptionHeader {
    pub master_key_id: [u8; keys::KEYID_SZ],
    pub hash_key_part_2: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
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

fn combined_hashkey(k1: &[u8], k2: &[u8]) -> [u8; hydrogen::HASH_KEYBYTES] {
    let mut k = [0; hydrogen::HASH_KEYBYTES];
    let mut h = hydrogen::Hash::init(*b"_hashkey", None);
    h.update(&k1[..]);
    h.update(&k2[..]);
    h.finish(&mut k);
    k
}

impl EncryptContext {
    pub fn new(k: &keys::Key) -> Self {
        let (psk, pk, hash_key_part_1, hash_key_part_2) = match k {
            keys::Key::MasterKeyV1(k) => (
                k.data_psk,
                k.data_pk,
                &k.hash_key_part_1,
                &k.hash_key_part_2,
            ),
            keys::Key::SendKeyV1(k) => (
                k.data_psk,
                k.master_data_pk,
                &k.hash_key_part_1,
                &k.hash_key_part_2,
            ),
        };
        let (session_tx_key, _session_rx_key, packet1) = hydrogen::kx_n_1(&psk, &pk);
        EncryptContext {
            k: k.clone(),
            session_tx_key,
            packet1,
            hash_key: combined_hashkey(hash_key_part_1, hash_key_part_2),
        }
    }

    #[inline(always)]
    fn compress_data(&self, mut data: Vec<u8>) -> Vec<u8> {
        // Our max chunk size means this should never happen.
        assert!(data.len() <= 0xffffffff);
        let mut compressed_data = zstd::block::compress(&data, 0).unwrap();
        if (compressed_data.len() + 4) >= data.len() {
            data.push(CHUNK_FOOTER_NO_COMPRESSION);
            data
        } else {
            compressed_data.reserve(5);
            let sz = data.len() as u32;
            compressed_data.push(((sz & 0xff000000) >> 24) as u8);
            compressed_data.push(((sz & 0x00ff0000) >> 16) as u8);
            compressed_data.push(((sz & 0x0000ff00) >> 8) as u8);
            compressed_data.push((sz & 0x000000ff) as u8);
            compressed_data.push(CHUNK_FOOTER_ZSTD_COMPRESSED);
            compressed_data
        }
    }

    #[inline(always)]
    pub fn encrypt_data(&self, compression: bool, mut data: Vec<u8>) -> Vec<u8> {
        let pt = if compression {
            self.compress_data(data)
        } else {
            data.push(CHUNK_FOOTER_NO_COMPRESSION);
            data
        };

        let n = pt.len() + hydrogen::SECRETBOX_HEADERBYTES + self.packet1.len();
        let mut ct = Vec::with_capacity(n);
        // This is safe as u8 is primitive, and capacity is valid by definition.
        unsafe { ct.set_len(n) };
        hydrogen::secretbox_encrypt(
            &mut ct[self.packet1.len()..],
            &pt,
            0,
            *b"_chunk_\0",
            &self.session_tx_key,
        );
        ct[..self.packet1.len()].clone_from_slice(&self.packet1);
        ct
    }

    #[inline(always)]
    pub fn keyed_content_address(&self, pt: &[u8]) -> address::Address {
        let mut addr = address::Address::default();
        hydrogen::hash(pt, *b"_address", Some(&self.hash_key), &mut addr.bytes[..]);
        addr
    }

    pub fn encryption_header(&self) -> VersionedEncryptionHeader {
        let (master_key_id, hash_key_part_2) = match &self.k {
            keys::Key::MasterKeyV1(k) => (k.id, &k.hash_key_part_2),
            keys::Key::SendKeyV1(k) => (k.master_key_id, &k.hash_key_part_2),
        };
        VersionedEncryptionHeader::V1(EncryptionHeader {
            master_key_id,
            hash_key_part_2: hash_key_part_2.clone(),
        })
    }
}

pub struct DecryptContext {
    pub k: keys::MasterKey,
    pub hash_key: [u8; hydrogen::HASH_KEYBYTES],
    cached_session_rx_key: [u8; hydrogen::KX_SESSIONKEYBYTES],
    cached_packet1: [u8; hydrogen::KX_N_PACKET1BYTES],
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

                Ok(DecryptContext {
                    k: k.clone(),
                    hash_key: combined_hashkey(&k.hash_key_part_1, &hdr.hash_key_part_2),
                    cached_session_rx_key: [0; hydrogen::KX_SESSIONKEYBYTES],
                    cached_packet1: [0; hydrogen::KX_N_PACKET1BYTES],
                })
            }
        }
    }

    #[inline(always)]
    pub fn keyed_content_address(&self, pt: &[u8]) -> address::Address {
        let mut addr = address::Address::default();
        hydrogen::hash(pt, *b"_address", Some(&self.hash_key), &mut addr.bytes[..]);
        addr
    }

    #[inline(always)]
    pub fn decrypt_data(&mut self, ct: &[u8]) -> Result<Vec<u8>, failure::Error> {
        const HDR_SZ: usize = hydrogen::KX_N_PACKET1BYTES + hydrogen::SECRETBOX_HEADERBYTES;
        if ct.len() < HDR_SZ {
            bail!("data is possibly corrupt, shorter than required encryption header");
        }
        let n = ct.len() - HDR_SZ;
        let mut pt = Vec::with_capacity(n);
        // This is safe as u8 is primitive, and capacity is valid by definition.
        unsafe { pt.set_len(n) };

        let mut packet1 = [0; hydrogen::KX_N_PACKET1BYTES];
        packet1[..].clone_from_slice(&ct[0..hydrogen::KX_N_PACKET1BYTES]);

        if packet1[..] != self.cached_packet1[..] {
            self.cached_packet1 = packet1;
            self.cached_session_rx_key = match hydrogen::kx_n_2(
                &packet1,
                &self.k.data_psk,
                &self.k.data_pk,
                &self.k.data_sk,
            ) {
                Some((_session_tx_key, session_rx_key)) => session_rx_key,
                None => bail!("tampering or corruption detected while deriving decryption key"),
            };
        }

        if !hydrogen::secretbox_decrypt(
            &mut pt,
            &ct[hydrogen::KX_N_PACKET1BYTES..],
            0,
            *b"_chunk_\0",
            &self.cached_session_rx_key,
        ) {
            failure::bail!("decryption failed due to data corruption or key mismatch");
        }

        if pt.is_empty() {
            failure::bail!("data chunk was too small, missing footer");
        }

        let pt = match pt[pt.len() - 1] {
            footer if footer == CHUNK_FOOTER_NO_COMPRESSION => {
                pt.pop();
                pt
            }
            footer if footer == CHUNK_FOOTER_ZSTD_COMPRESSED => {
                pt.pop();
                if pt.len() < 4 {
                    failure::bail!("data footer missing decompressed size");
                }
                let dlen = pt.len();
                let decompressed_sz = ((pt[dlen - 4] as u32) << 24)
                    | ((pt[dlen - 3] as u32) << 16)
                    | ((pt[dlen - 2] as u32) << 8)
                    | (pt[dlen - 1] as u32);
                pt.truncate(pt.len() - 4);
                let decompressed_data = zstd::block::decompress(&pt, decompressed_sz as usize)?;
                decompressed_data
            }
            _ => failure::bail!("unknown footer type type"),
        };

        Ok(pt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn master_key_round_trip_encrypt() {
        let master_key = keys::MasterKey::gen();
        let ectx = EncryptContext::new(&keys::Key::MasterKeyV1(master_key.clone()));
        let ehdr = ectx.encryption_header();
        let mut dctx = DecryptContext::open(&master_key, &ehdr).unwrap();
        let pt = [1, 2, 3];
        let ct = ectx.encrypt_data(true, (&pt).to_vec());
        let pt2 = dctx.decrypt_data(&ct).unwrap();
        assert_eq!(pt2, [1, 2, 3]);
    }

    #[test]
    fn send_key_round_trip_encrypt() {
        let master_key = keys::MasterKey::gen();
        let send_key = keys::SendKey::gen(&master_key);
        let ectx = EncryptContext::new(&keys::Key::SendKeyV1(send_key));
        let ehdr = ectx.encryption_header();
        let mut dctx = DecryptContext::open(&master_key, &ehdr).unwrap();
        let pt = [1, 2, 3];
        let ct = ectx.encrypt_data(true, (&pt).to_vec());
        let pt2 = dctx.decrypt_data(&ct).unwrap();
        assert_eq!(pt2, [1, 2, 3]);
    }
}
