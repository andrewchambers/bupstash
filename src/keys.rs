use super::hydrogen;
use failure::{Error, ResultExt};
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;

pub const KEYID_SZ: usize = 32;
pub const PARTIAL_HASH_KEY_SZ: usize = 32;

#[derive(Serialize, Deserialize, PartialEq, Clone)]
pub struct MasterKey {
    pub id: [u8; KEYID_SZ],
    /*
       Hash key is used for content addressing, similar
       to git, but with an HMAC. This means plaintext
       does not leak via known hashes. It also means
       attacks by uploading corrupt chunks won't
       cause data corruption across client keys because
       they use different hash keys.

       The hash key is divided into 2 parts so the server
       never knows the hash key and is unable to use this
       to guess file contents.

       FIXME: Each hash key part is divded into parts a/b
       so rusts trait #derive works. It only works for
       hard coded sizes. We tested the marshalled key size
       explicitly so if someone can recombine parts a/b in a pleasant
       way it will still be backwards compatible.
    */
    pub hash_key_part_1a: [u8; PARTIAL_HASH_KEY_SZ],
    pub hash_key_part_1b: [u8; PARTIAL_HASH_KEY_SZ],
    pub hash_key_part_2a: [u8; PARTIAL_HASH_KEY_SZ],
    pub hash_key_part_2b: [u8; PARTIAL_HASH_KEY_SZ],
    /* Key set used for encrypting data/ */
    pub data_psk: [u8; hydrogen::KX_PSKBYTES],
    pub data_pk: [u8; hydrogen::KX_PUBLICKEYBYTES],
    pub data_sk: [u8; hydrogen::KX_SECRETKEYBYTES],
    /* Key set used for encrypting metadata. */
    pub metadata_psk: [u8; hydrogen::KX_PSKBYTES],
    pub metadata_pk: [u8; hydrogen::KX_PUBLICKEYBYTES],
    pub metadata_sk: [u8; hydrogen::KX_SECRETKEYBYTES],
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SendKey {
    pub id: [u8; KEYID_SZ],
    pub master_key_id: [u8; KEYID_SZ],
    pub hash_key_part_1a: [u8; PARTIAL_HASH_KEY_SZ],
    pub hash_key_part_1b: [u8; PARTIAL_HASH_KEY_SZ],
    pub hash_key_part_2a: [u8; PARTIAL_HASH_KEY_SZ],
    pub hash_key_part_2b: [u8; PARTIAL_HASH_KEY_SZ],
    pub data_psk: [u8; hydrogen::KX_PSKBYTES],
    pub data_pk: [u8; hydrogen::KX_PUBLICKEYBYTES],
    pub metadata_psk: [u8; hydrogen::KX_PSKBYTES],
    pub metadata_pk: [u8; hydrogen::KX_PUBLICKEYBYTES],
}

#[derive(Serialize, Deserialize, Clone)]
pub struct MetadataKey {
    pub id: [u8; KEYID_SZ],
    pub master_key_id: [u8; KEYID_SZ],
    pub metadata_psk: [u8; hydrogen::KX_PSKBYTES],
    pub metadata_pk: [u8; hydrogen::KX_PUBLICKEYBYTES],
    pub metadata_sk: [u8; hydrogen::KX_SECRETKEYBYTES],
}

#[derive(Serialize, Deserialize, Clone)]
pub enum Key {
    MasterKeyV1(MasterKey),
    SendKeyV1(SendKey),
    MetadataKeyV1(MetadataKey),
}

impl Key {
    pub fn write_to_file(&self, path: &str) -> Result<(), Error> {
        let mut file = OpenOptions::new()
            .mode(0o600)
            .write(true)
            .create_new(true)
            .open(path)
            .with_context(|e| format!("error opening {}: {}", path, e))?; // Give read/write for owner and read for others.
        let j = serde_json::to_string(self)?;
        file.write_all(j.as_bytes())
            .with_context(|e| format!("writing key file failed: {}", e))?;
        Ok(())
    }

    pub fn load_from_file(path: &str) -> Result<Key, Error> {
        let mut file = OpenOptions::new()
            .mode(0o600)
            .read(true)
            .open(path)
            .with_context(|e| format!("error opening {}: {}", path, e))?; // Give read/write for owner and read for others.
        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .with_context(|e| format!("reading key file failed: {}", e))?;
        let k: Key = serde_json::from_str(&contents)?;
        Ok(k)
    }

    pub fn master_key_id(&self) -> [u8; KEYID_SZ] {
        match self {
            Key::MasterKeyV1(k) => k.id,
            Key::SendKeyV1(k) => k.master_key_id,
            Key::MetadataKeyV1(k) => k.master_key_id,
        }
    }
}

fn keyid_gen() -> [u8; KEYID_SZ] {
    let mut id = [0; KEYID_SZ];
    hydrogen::random_buf(&mut id[..]);
    id
}

impl MasterKey {
    pub fn gen() -> MasterKey {
        let id = keyid_gen();
        let mut hash_key_part_1a = [0; PARTIAL_HASH_KEY_SZ];
        let mut hash_key_part_1b = [0; PARTIAL_HASH_KEY_SZ];
        let mut hash_key_part_2a = [0; PARTIAL_HASH_KEY_SZ];
        let mut hash_key_part_2b = [0; PARTIAL_HASH_KEY_SZ];
        let data_psk = hydrogen::kx_psk_keygen();
        let (data_pk, data_sk) = hydrogen::kx_keygen();
        let metadata_psk = hydrogen::kx_psk_keygen();
        let (metadata_pk, metadata_sk) = hydrogen::kx_keygen();
        hydrogen::random_buf(&mut hash_key_part_1a);
        hydrogen::random_buf(&mut hash_key_part_1b);
        hydrogen::random_buf(&mut hash_key_part_2a);
        hydrogen::random_buf(&mut hash_key_part_2b);

        MasterKey {
            id,
            hash_key_part_1a,
            hash_key_part_1b,
            hash_key_part_2a,
            hash_key_part_2b,
            data_psk,
            data_pk,
            data_sk,
            metadata_psk,
            metadata_pk,
            metadata_sk,
        }
    }
}

impl SendKey {
    pub fn gen(mk: &MasterKey) -> SendKey {
        let mut hash_key_part_2a = [0; PARTIAL_HASH_KEY_SZ];
        let mut hash_key_part_2b = [0; PARTIAL_HASH_KEY_SZ];
        hydrogen::random_buf(&mut hash_key_part_2a);
        hydrogen::random_buf(&mut hash_key_part_2b);
        SendKey {
            id: keyid_gen(),
            master_key_id: mk.id,
            hash_key_part_1a: mk.hash_key_part_1a.clone(),
            hash_key_part_1b: mk.hash_key_part_1b.clone(),
            hash_key_part_2a: hash_key_part_2a.clone(),
            hash_key_part_2b: hash_key_part_2b.clone(),
            data_psk: mk.data_psk,
            data_pk: mk.data_pk,
            metadata_psk: mk.metadata_psk,
            metadata_pk: mk.metadata_pk,
        }
    }
}

impl MetadataKey {
    pub fn gen(mk: &MasterKey) -> MetadataKey {
        MetadataKey {
            id: keyid_gen(),
            master_key_id: mk.id,
            metadata_psk: mk.metadata_psk.clone(),
            metadata_pk: mk.metadata_pk.clone(),
            metadata_sk: mk.metadata_sk.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialized_key_sizes() {
        /* Verify output is what we expect for derived serialization code. */

        let master_key = MasterKey::gen();
        let send_key = SendKey::gen(&master_key);
        let metadata_key = MetadataKey::gen(&master_key);

        let master_key_buf = bincode::serialize(&master_key).unwrap();
        let send_key_buf = bincode::serialize(&send_key).unwrap();
        let metadata_key_buf = bincode::serialize(&metadata_key).unwrap();

        let master_key_size = KEYID_SZ
            + PARTIAL_HASH_KEY_SZ * 4
            + hydrogen::KX_PSKBYTES * 2
            + hydrogen::KX_PUBLICKEYBYTES * 2
            + hydrogen::KX_SECRETKEYBYTES * 2;

        let send_key_size = KEYID_SZ * 2
            + PARTIAL_HASH_KEY_SZ * 4
            + hydrogen::KX_PSKBYTES * 2
            + hydrogen::KX_PUBLICKEYBYTES * 2;

        let metadata_key_size = KEYID_SZ * 2
            + hydrogen::KX_PUBLICKEYBYTES
            + hydrogen::KX_SECRETKEYBYTES
            + hydrogen::KX_PSKBYTES;

        assert_eq!(master_key_buf.len(), master_key_size);
        assert_eq!(send_key_buf.len(), send_key_size);
        assert_eq!(metadata_key_buf.len(), metadata_key_size);
    }
}
