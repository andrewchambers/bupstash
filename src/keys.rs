use super::crypto2;
use failure::{Error, ResultExt};
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;

pub const KEYID_SZ: usize = 32;

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
       and metadata key never knows the hash key and is unable to use this
       to guess file contents.

       FIXME: Each hash key part is divded into parts a/b
       so rusts trait #derive works. It only works for
       hard coded sizes. We tested the marshalled key size
       explicitly so if someone can recombine parts a/b in a pleasant
       way it will still be backwards compatible.
    */
    pub hash_key_part_1: crypto2::PartialHashKey,
    pub hash_key_part_2: crypto2::PartialHashKey,
    /* Key set used for encrypting data/ */
    pub data_pk: crypto2::BoxPublicKey,
    pub data_sk: crypto2::BoxSecretKey,
    /* Key set used for encrypting metadata. */
    pub metadata_pk: crypto2::BoxPublicKey,
    pub metadata_sk: crypto2::BoxSecretKey,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SendKey {
    pub id: [u8; KEYID_SZ],
    pub master_key_id: [u8; KEYID_SZ],
    pub hash_key_part_1: crypto2::PartialHashKey,
    pub hash_key_part_2: crypto2::PartialHashKey,
    pub data_pk: crypto2::BoxPublicKey,
    pub metadata_pk: crypto2::BoxPublicKey,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct MetadataKey {
    pub id: [u8; KEYID_SZ],
    pub master_key_id: [u8; KEYID_SZ],
    pub metadata_pk: crypto2::BoxPublicKey,
    pub metadata_sk: crypto2::BoxSecretKey,
}

#[derive(Serialize, Deserialize, Clone)]
pub enum Key {
    MasterKeyV1(MasterKey),
    SendKeyV1(SendKey),
    MetadataKeyV1(MetadataKey),
}

fn pem_tag(k: &Key) -> &str {
    match k {
        Key::MasterKeyV1(_) => "ARCHIVIST MASTER KEY",
        Key::SendKeyV1(_) => "ARCHIVIST SEND KEY",
        Key::MetadataKeyV1(_) => "ARCHIVIST METADATA KEY",
    }
}

impl Key {
    pub fn write_to_file(&self, path: &str) -> Result<(), Error> {
        let mut f = OpenOptions::new()
            .mode(0o600)
            .write(true)
            .create_new(true)
            .open(path)
            .with_context(|e| format!("error opening {}: {}", path, e))?; // Give read/write for owner and read for others.

        let pem_data = pem::encode(&pem::Pem {
            tag: String::from(pem_tag(self)),
            contents: bincode::serialize(self)?,
        });

        f.write_all(pem_data.as_bytes())
            .with_context(|e| format!("writing key file failed: {}", e))?;
        Ok(())
    }

    pub fn load_from_file(path: &str) -> Result<Key, Error> {
        let mut f = OpenOptions::new()
            .read(true)
            .open(path)
            .with_context(|e| format!("error opening {}: {}", path, e))?;

        let mut pem_data = Vec::new();
        f.read_to_end(&mut pem_data)?;
        let pem_data = pem::parse(pem_data)?;
        let k: Key = bincode::deserialize(&pem_data.contents)?;
        if pem_tag(&k) != pem_data.tag {
            failure::bail!("key type does not match pem tag")
        }
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
    crypto2::randombytes(&mut id[..]);
    id
}

impl MasterKey {
    pub fn gen() -> MasterKey {
        let id = keyid_gen();
        let hash_key_part_1 = crypto2::PartialHashKey::new();
        let hash_key_part_2 = crypto2::PartialHashKey::new();
        let (data_pk, data_sk) = crypto2::box_keypair();
        let (metadata_pk, metadata_sk) = crypto2::box_keypair();
        MasterKey {
            id,
            hash_key_part_1,
            hash_key_part_2,
            data_pk,
            data_sk,
            metadata_pk,
            metadata_sk,
        }
    }
}

impl SendKey {
    pub fn gen(mk: &MasterKey) -> SendKey {
        let hash_key_part_2 = crypto2::PartialHashKey::new();
        SendKey {
            id: keyid_gen(),
            master_key_id: mk.id,
            hash_key_part_1: mk.hash_key_part_1.clone(),
            hash_key_part_2,
            data_pk: mk.data_pk.clone(),
            metadata_pk: mk.metadata_pk.clone(),
        }
    }
}

impl MetadataKey {
    pub fn gen(mk: &MasterKey) -> MetadataKey {
        MetadataKey {
            id: keyid_gen(),
            master_key_id: mk.id,
            metadata_pk: mk.metadata_pk.clone(),
            metadata_sk: mk.metadata_sk.clone(),
        }
    }
}
