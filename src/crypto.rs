use super::address;
use super::hydrogen;
use super::keys;
use failure::bail;
use std::convert::{From, TryFrom};

const CHUNK_FOOTER_NO_COMPRESSION: u8 = 0;
const CHUNK_FOOTER_ZSTD_COMPRESSED: u8 = 1;

pub struct EncryptContext {
    pub session_tx_key: [u8; hydrogen::KX_SESSIONKEYBYTES],
    pub packet1: [u8; hydrogen::KX_N_PACKET1BYTES],
}

pub struct KeyedHashContext {
    pub hash_key: [u8; hydrogen::HASH_KEYBYTES],
}

fn combined_hashkey(
    k1a: &[u8],
    k1b: &[u8],
    k2a: &[u8],
    k2b: &[u8],
) -> [u8; hydrogen::HASH_KEYBYTES] {
    let mut k = [0; hydrogen::HASH_KEYBYTES];
    let mut h = hydrogen::Hash::init(*b"_hashkey", None);
    h.update(&k1a[..]);
    h.update(&k1b[..]);
    h.update(&k2a[..]);
    h.update(&k2b[..]);
    h.finish(&mut k);
    k
}

impl KeyedHashContext {
    #[inline(always)]
    pub fn content_address(&self, pt: &[u8]) -> address::Address {
        let mut addr = address::Address::default();
        hydrogen::hash(pt, *b"_address", Some(&self.hash_key), &mut addr.bytes[..]);
        addr
    }
}

impl TryFrom<&keys::Key> for KeyedHashContext {
    type Error = failure::Error;

    fn try_from(k: &keys::Key) -> Result<Self, failure::Error> {
        let (hk_1a, hk_1b, hk_2a, hk_2b) = match k {
            keys::Key::MasterKeyV1(k) => (
                &k.hash_key_part_1a,
                &k.hash_key_part_1b,
                &k.hash_key_part_2a,
                &k.hash_key_part_2b,
            ),
            keys::Key::SendKeyV1(k) => (
                &k.hash_key_part_1a,
                &k.hash_key_part_1b,
                &k.hash_key_part_2a,
                &k.hash_key_part_2b,
            ),
            keys::Key::MetadataKeyV1(_k) => {
                failure::bail!("metadata key cannot be used for hashing data")
            }
        };
        Ok(KeyedHashContext {
            hash_key: combined_hashkey(hk_1a, hk_1b, hk_2a, hk_2b),
        })
    }
}

impl From<&keys::MasterKey> for KeyedHashContext {
    fn from(k: &keys::MasterKey) -> Self {
        KeyedHashContext {
            hash_key: combined_hashkey(
                &k.hash_key_part_1a,
                &k.hash_key_part_1b,
                &k.hash_key_part_2a,
                &k.hash_key_part_2b,
            ),
        }
    }
}

impl EncryptContext {
    pub fn data_context(k: &keys::Key) -> Result<Self, failure::Error> {
        let (psk, pk) = match k {
            keys::Key::MasterKeyV1(k) => (k.data_psk, k.data_pk),
            keys::Key::SendKeyV1(k) => (k.data_psk, k.data_pk),
            keys::Key::MetadataKeyV1(_k) => {
                failure::bail!("unable to encrypt data with a metadata key")
            }
        };
        let (session_tx_key, _session_rx_key, packet1) = hydrogen::kx_n_1(&psk, &pk);
        Ok(EncryptContext {
            session_tx_key,
            packet1,
        })
    }

    pub fn metadata_context(k: &keys::Key) -> Self {
        let (psk, pk) = match k {
            keys::Key::MasterKeyV1(k) => (k.metadata_psk, k.metadata_pk),
            keys::Key::SendKeyV1(k) => (k.metadata_psk, k.metadata_pk),
            keys::Key::MetadataKeyV1(k) => (k.metadata_psk, k.metadata_pk),
        };
        let (session_tx_key, _session_rx_key, packet1) = hydrogen::kx_n_1(&psk, &pk);
        EncryptContext {
            session_tx_key,
            packet1,
        }
    }

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
}

pub struct DecryptContext {
    psk: [u8; hydrogen::KX_PSKBYTES],
    pk: [u8; hydrogen::KX_PUBLICKEYBYTES],
    sk: [u8; hydrogen::KX_SECRETKEYBYTES],
    cached_session_rx_key: [u8; hydrogen::KX_SESSIONKEYBYTES],
    cached_packet1: [u8; hydrogen::KX_N_PACKET1BYTES],
}

impl DecryptContext {
    pub fn metadata_context(k: &keys::Key) -> Result<Self, failure::Error> {
        let (psk, pk, sk) = match k {
            keys::Key::MasterKeyV1(k) => (k.metadata_psk, k.metadata_pk, k.metadata_sk),
            keys::Key::MetadataKeyV1(k) => (k.metadata_psk, k.metadata_pk, k.metadata_sk),
            keys::Key::SendKeyV1(_k) => failure::bail!("unable to decrypt data with a send key"),
        };

        Ok(DecryptContext {
            psk,
            pk,
            sk,
            cached_session_rx_key: [0; hydrogen::KX_SESSIONKEYBYTES],
            cached_packet1: [0; hydrogen::KX_N_PACKET1BYTES],
        })
    }

    pub fn data_context(k: &keys::Key) -> Result<Self, failure::Error> {
        let (psk, pk, sk) = match k {
            keys::Key::MasterKeyV1(k) => (k.data_psk, k.data_pk, k.data_sk),
            keys::Key::MetadataKeyV1(_k) => {
                failure::bail!("unable to decrypt data with a metadata key")
            }
            keys::Key::SendKeyV1(_k) => failure::bail!("unable to decrypt data with a send key"),
        };

        Ok(DecryptContext {
            psk,
            pk,
            sk,
            cached_session_rx_key: [0; hydrogen::KX_SESSIONKEYBYTES],
            cached_packet1: [0; hydrogen::KX_N_PACKET1BYTES],
        })
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
            self.cached_session_rx_key =
                match hydrogen::kx_n_2(&packet1, &self.psk, &self.pk, &self.sk) {
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
    fn master_key_round_trip_data_encrypt() {
        let master_key = keys::MasterKey::gen();
        let master_key = keys::Key::MasterKeyV1(master_key);
        let ectx = EncryptContext::data_context(&master_key).unwrap();
        let mut dctx = DecryptContext::data_context(&master_key).unwrap();
        let pt = [1, 2, 3];
        let ct = ectx.encrypt_data(true, (&pt).to_vec());
        let pt2 = dctx.decrypt_data(&ct).unwrap();
        assert_eq!(pt2, [1, 2, 3]);
    }

    #[test]
    fn send_key_round_trip_data_encrypt() {
        let master_key = keys::MasterKey::gen();
        let send_key = keys::SendKey::gen(&master_key);
        let master_key = keys::Key::MasterKeyV1(master_key);
        let ectx = EncryptContext::data_context(&keys::Key::SendKeyV1(send_key)).unwrap();
        let mut dctx = DecryptContext::data_context(&master_key).unwrap();
        let pt = [1, 2, 3];
        let ct = ectx.encrypt_data(true, (&pt).to_vec());
        let pt2 = dctx.decrypt_data(&ct).unwrap();
        assert_eq!(pt2, [1, 2, 3]);
    }

    #[test]
    fn master_key_round_trip_metadata_encrypt() {
        let master_key = keys::MasterKey::gen();
        let master_key = keys::Key::MasterKeyV1(master_key);
        let ectx = EncryptContext::metadata_context(&master_key);
        let mut dctx = DecryptContext::metadata_context(&master_key).unwrap();
        let pt = [1, 2, 3];
        let ct = ectx.encrypt_data(true, (&pt).to_vec());
        let pt2 = dctx.decrypt_data(&ct).unwrap();
        assert_eq!(pt2, [1, 2, 3]);
    }

    #[test]
    fn metadata_key_round_trip_data_encrypt() {
        let master_key = keys::MasterKey::gen();
        let metadata_key = keys::MetadataKey::gen(&master_key);
        let metadata_key = keys::Key::MetadataKeyV1(metadata_key);
        let master_key = keys::Key::MasterKeyV1(master_key);

        let ectx = EncryptContext::metadata_context(&metadata_key);
        let pt = [1, 2, 3];
        let ct = ectx.encrypt_data(true, (&pt).to_vec());
        let mut dctx = DecryptContext::metadata_context(&metadata_key).unwrap();
        let pt2 = dctx.decrypt_data(&ct).unwrap();
        assert_eq!(pt2, [1, 2, 3]);
        let mut dctx = DecryptContext::metadata_context(&master_key).unwrap();
        let pt3 = dctx.decrypt_data(&ct).unwrap();
        assert_eq!(pt3, [1, 2, 3]);
    }
}
