use super::crypto;
use super::pem;
use super::xid::*;
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct PrimaryKey {
    pub id: Xid,
    /* key used to make the rollsum unique to this key. */
    pub rollsum_key: crypto::GearHashKey,
    /*
       Hash keys are used for content addressing, similar
       to git, but with an HMAC. This means plaintext
       does not leak via known hashes. It also means
       attacks by uploading corrupt chunks won't
       cause data corruption across client keys because
       they use different hash keys.

       The hash key is divided into 2 parts so the server
       and metadata key never knows the hash key and is unable to use this
       to guess file contents.
    */
    pub data_hash_key_part_1: crypto::PartialHashKey,
    pub data_hash_key_part_2: crypto::PartialHashKey,
    /* Key set used for encrypting data. */
    pub data_pk: crypto::BoxPublicKey,
    pub data_sk: crypto::BoxSecretKey,
    pub data_psk: crypto::BoxPreSharedKey,

    /* Key set used for encrypting indicies. */
    pub idx_hash_key_part_1: crypto::PartialHashKey,
    pub idx_hash_key_part_2: crypto::PartialHashKey,
    pub idx_pk: crypto::BoxPublicKey,
    pub idx_sk: crypto::BoxSecretKey,
    pub idx_psk: crypto::BoxPreSharedKey,

    /* Key set used for encrypting metadata. */
    pub metadata_pk: crypto::BoxPublicKey,
    pub metadata_sk: crypto::BoxSecretKey,
    pub metadata_psk: crypto::BoxPreSharedKey,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SubKey {
    pub id: Xid,
    pub primary_key_id: Xid,
    pub rollsum_key: Option<crypto::GearHashKey>,
    pub data_hash_key_part_1: Option<crypto::PartialHashKey>,
    pub data_hash_key_part_2: Option<crypto::PartialHashKey>,
    pub data_pk: Option<crypto::BoxPublicKey>,
    pub data_sk: Option<crypto::BoxSecretKey>,
    pub data_psk: Option<crypto::BoxPreSharedKey>,
    pub idx_hash_key_part_1: Option<crypto::PartialHashKey>,
    pub idx_hash_key_part_2: Option<crypto::PartialHashKey>,
    pub idx_pk: Option<crypto::BoxPublicKey>,
    pub idx_sk: Option<crypto::BoxSecretKey>,
    pub idx_psk: Option<crypto::BoxPreSharedKey>,
    pub metadata_pk: Option<crypto::BoxPublicKey>,
    pub metadata_sk: Option<crypto::BoxSecretKey>,
    pub metadata_psk: Option<crypto::BoxPreSharedKey>,
}

#[derive(Serialize, Deserialize, Clone)]
pub enum Key {
    PrimaryKeyV1(PrimaryKey),
    SubKeyV1(SubKey),
    Reserved1,
    Reserved2,
    Reserved3,
    Reserved4,
}

fn pem_tag(k: &Key) -> &str {
    match k {
        Key::PrimaryKeyV1(_) => "BUPSTASH KEY",
        Key::SubKeyV1(_) => "BUPSTASH SUB KEY",
        _ => unreachable!(),
    }
}

impl Key {
    pub fn write_to_file(&self, path: &str) -> Result<(), anyhow::Error> {
        let mut f = match OpenOptions::new()
            .mode(0o600)
            .write(true)
            .create_new(true)
            .open(path)
        {
            Ok(f) => f,
            Err(err) => anyhow::bail!("error opening {}: {}", path, err),
        };

        f.write_all("# This file contains a cryptographic key used by 'bupstash' to encrypt and decrypt data.\n#\n".to_string().as_bytes())?;
        f.write_all(format!("# key-id={}\n", self.id()).as_bytes())?;

        match self {
            Key::PrimaryKeyV1(_) => (),
            Key::SubKeyV1(_) => {
                f.write_all(
                    format!("# derived-from-key-id={}\n", self.primary_key_id(),).as_bytes(),
                )?;
                f.write_all(format!("# is-put-key={}\n", self.is_put_key()).as_bytes())?;
                f.write_all(format!("# is-list-key={}\n", self.is_list_key()).as_bytes())?;
                f.write_all(
                    format!("# is-list-contents-key={}\n", self.is_list_contents_key()).as_bytes(),
                )?;
            }
            _ => unreachable!(),
        }
        f.write_all("\n".to_string().as_bytes())?;

        let pem_data = pem::encode(&pem::Pem {
            tag: String::from(pem_tag(self)),
            contents: serde_bare::to_vec(self)?,
        });
        f.write_all(pem_data.as_bytes())?;

        f.flush()?;

        Ok(())
    }

    pub fn from_slice(pem_data: &[u8]) -> Result<Key, anyhow::Error> {
        let pem_data = pem::parse(pem_data)?;
        let k: Key = serde_bare::from_slice(&pem_data.contents)?;

        match k {
            Key::PrimaryKeyV1(_) => (),
            Key::SubKeyV1(_) => (),
            _ => anyhow::bail!("unable to load key from a future version of bupstash"),
        }

        if pem_tag(&k) != pem_data.tag {
            anyhow::bail!("key type does not match pem tag")
        }
        Ok(k)
    }

    pub fn load_from_file(path: &str) -> Result<Key, anyhow::Error> {
        let mut f = match OpenOptions::new().read(true).open(path) {
            Ok(f) => f,
            Err(err) => anyhow::bail!("error opening {}: {}", path, err),
        };

        let mut pem_data = Vec::new();
        f.read_to_end(&mut pem_data)?;
        Key::from_slice(&pem_data)
    }

    pub fn primary_key_id(&self) -> Xid {
        match self {
            Key::PrimaryKeyV1(k) => k.id,
            Key::SubKeyV1(k) => k.primary_key_id,
            _ => panic!("key is from a future version of bupstash"),
        }
    }

    pub fn id(&self) -> Xid {
        match self {
            Key::PrimaryKeyV1(k) => k.id,
            Key::SubKeyV1(k) => k.id,
            _ => panic!("key is from a future version of bupstash"),
        }
    }

    pub fn is_put_key(&self) -> bool {
        match self {
            Key::PrimaryKeyV1(_) => true,
            Key::SubKeyV1(k) => {
                k.rollsum_key.is_some()
                    && k.data_hash_key_part_1.is_some()
                    && k.data_hash_key_part_2.is_some()
                    && k.idx_hash_key_part_1.is_some()
                    && k.idx_hash_key_part_2.is_some()
                    && k.data_pk.is_some()
                    && k.data_psk.is_some()
                    && k.idx_pk.is_some()
                    && k.idx_psk.is_some()
                    && k.metadata_pk.is_some()
                    && k.metadata_psk.is_some()
            }
            _ => false,
        }
    }

    pub fn is_list_key(&self) -> bool {
        match self {
            Key::PrimaryKeyV1(_) => true,
            Key::SubKeyV1(k) => {
                k.metadata_pk.is_some() && k.metadata_sk.is_some() && k.metadata_psk.is_some()
            }
            _ => false,
        }
    }

    pub fn is_list_contents_key(&self) -> bool {
        match self {
            Key::PrimaryKeyV1(_) => true,
            Key::SubKeyV1(k) => {
                k.idx_hash_key_part_1.is_some()
                    && k.idx_pk.is_some()
                    && k.idx_sk.is_some()
                    && k.idx_psk.is_some()
                    && k.metadata_pk.is_some()
                    && k.metadata_sk.is_some()
                    && k.metadata_psk.is_some()
            }
            _ => false,
        }
    }

    pub fn is_get_key(&self) -> bool {
        match self {
            Key::PrimaryKeyV1(_) => true,
            Key::SubKeyV1(_) => false,
            _ => false,
        }
    }
}

impl PrimaryKey {
    pub fn gen() -> PrimaryKey {
        let id = Xid::new();
        let rollsum_key = crypto::GearHashKey::new();
        let data_hash_key_part_1 = crypto::PartialHashKey::new();
        let data_hash_key_part_2 = crypto::PartialHashKey::new();
        let (data_pk, data_sk) = crypto::box_keypair();
        let data_psk = crypto::BoxPreSharedKey::new();
        let idx_hash_key_part_1 = crypto::PartialHashKey::new();
        let idx_hash_key_part_2 = crypto::PartialHashKey::new();
        let (idx_pk, idx_sk) = crypto::box_keypair();
        let idx_psk = crypto::BoxPreSharedKey::new();
        let (metadata_pk, metadata_sk) = crypto::box_keypair();
        let metadata_psk = crypto::BoxPreSharedKey::new();
        PrimaryKey {
            id,
            rollsum_key,
            data_hash_key_part_1,
            data_hash_key_part_2,
            data_pk,
            data_sk,
            data_psk,
            idx_hash_key_part_1,
            idx_hash_key_part_2,
            idx_pk,
            idx_sk,
            idx_psk,
            metadata_pk,
            metadata_sk,
            metadata_psk,
        }
    }
}

impl SubKey {
    pub fn gen(k: &PrimaryKey, put: bool, list: bool, list_contents: bool) -> SubKey {
        SubKey {
            id: Xid::new(),
            primary_key_id: k.id,

            rollsum_key: if put {
                Some(crypto::GearHashKey::new())
            } else {
                None
            },

            data_hash_key_part_1: if put {
                Some(k.data_hash_key_part_1.clone())
            } else {
                None
            },

            data_hash_key_part_2: if put {
                Some(crypto::PartialHashKey::new())
            } else {
                None
            },

            idx_hash_key_part_1: if put || list_contents {
                Some(k.idx_hash_key_part_1.clone())
            } else {
                None
            },

            idx_hash_key_part_2: if put {
                Some(crypto::PartialHashKey::new())
            } else {
                None
            },

            data_pk: if put { Some(k.data_pk.clone()) } else { None },

            // For now no sub keys have the secret key.
            data_sk: None,

            data_psk: if put { Some(k.data_psk.clone()) } else { None },

            idx_pk: if list_contents || put {
                Some(k.idx_pk.clone())
            } else {
                None
            },

            idx_sk: if list_contents {
                Some(k.idx_sk.clone())
            } else {
                None
            },

            idx_psk: if list_contents || put {
                Some(k.idx_psk.clone())
            } else {
                None
            },

            metadata_pk: if list_contents || list || put {
                Some(k.metadata_pk.clone())
            } else {
                None
            },

            metadata_sk: if list_contents || list {
                Some(k.metadata_sk.clone())
            } else {
                None
            },

            metadata_psk: if list_contents || list || put {
                Some(k.metadata_psk.clone())
            } else {
                None
            },
        }
    }
}
