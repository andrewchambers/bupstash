use super::crypto;
use super::xid::*;
use failure::{Error, ResultExt};
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;

#[derive(Serialize, Deserialize, PartialEq, Clone)]
pub struct MasterKey {
    pub id: Xid,
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
    */
    pub hash_key_part_1: crypto::PartialHashKey,
    pub hash_key_part_2: crypto::PartialHashKey,
    /* Key set used for encrypting data/ */
    pub data_pk: crypto::BoxPublicKey,
    pub data_sk: crypto::BoxSecretKey,
    /* Key set used for encrypting metadata. */
    pub metadata_pk: crypto::BoxPublicKey,
    pub metadata_sk: crypto::BoxSecretKey,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SendKey {
    pub id: Xid,
    pub master_key_id: Xid,
    pub hash_key_part_1: crypto::PartialHashKey,
    pub hash_key_part_2: crypto::PartialHashKey,
    pub data_pk: crypto::BoxPublicKey,
    pub metadata_pk: crypto::BoxPublicKey,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct MetadataKey {
    pub id: Xid,
    pub master_key_id: Xid,
    pub metadata_pk: crypto::BoxPublicKey,
    pub metadata_sk: crypto::BoxSecretKey,
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

    pub fn master_key_id(&self) -> Xid {
        match self {
            Key::MasterKeyV1(k) => k.id,
            Key::SendKeyV1(k) => k.master_key_id,
            Key::MetadataKeyV1(k) => k.master_key_id,
        }
    }
}

impl MasterKey {
    pub fn gen() -> MasterKey {
        let id = Xid::new();
        let hash_key_part_1 = crypto::PartialHashKey::new();
        let hash_key_part_2 = crypto::PartialHashKey::new();
        let (data_pk, data_sk) = crypto::box_keypair();
        let (metadata_pk, metadata_sk) = crypto::box_keypair();
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
        let hash_key_part_2 = crypto::PartialHashKey::new();
        SendKey {
            id: Xid::new(),
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
            id: Xid::new(),
            master_key_id: mk.id,
            metadata_pk: mk.metadata_pk.clone(),
            metadata_sk: mk.metadata_sk.clone(),
        }
    }
}
