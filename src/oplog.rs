use super::address::*;
use super::crypto;
use super::xid::*;
use serde::{Deserialize, Serialize};

pub const MAX_TAG_SET_SIZE: usize = 32 * 1024;
// Tags plus some leeway, we can adjust this if we need to.
pub const MAX_METADATA_SIZE: usize = MAX_TAG_SET_SIZE + 2048;

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Copy)]
pub struct HTreeMetadata {
    pub height: serde_bare::Uint,
    pub data_chunk_count: serde_bare::Uint,
    pub address: Address,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct V1PlainTextItemMetadata {
    pub primary_key_id: Xid,
    pub data_tree: HTreeMetadata,
    pub index_tree: Option<HTreeMetadata>,
}

impl V1PlainTextItemMetadata {
    pub fn hash(&self) -> [u8; crypto::HASH_BYTES] {
        let mut hst = crypto::HashState::new(None);
        hst.update(&serde_bare::to_vec(&self).unwrap());
        hst.finish()
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct V2PlainTextItemMetadata {
    pub primary_key_id: Xid,
    pub unix_timestamp_millis: u64,
    pub data_tree: HTreeMetadata,
    pub index_tree: Option<HTreeMetadata>,
}

impl V2PlainTextItemMetadata {
    pub fn hash(&self) -> [u8; crypto::HASH_BYTES] {
        let mut hst = crypto::HashState::new(None);
        hst.update(&serde_bare::to_vec(&self).unwrap());
        hst.finish()
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct V1SecretItemMetadata {
    pub plain_text_hash: [u8; crypto::HASH_BYTES],
    pub send_key_id: Xid,
    pub index_hash_key_part_2: crypto::PartialHashKey,
    pub data_hash_key_part_2: crypto::PartialHashKey,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub tags: std::collections::BTreeMap<String, String>,
    pub data_size: serde_bare::Uint,
    pub index_size: serde_bare::Uint,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct V2SecretItemMetadata {
    pub plain_text_hash: [u8; crypto::HASH_BYTES],
    pub send_key_id: Xid,
    pub index_hash_key_part_2: crypto::PartialHashKey,
    pub data_hash_key_part_2: crypto::PartialHashKey,
    pub tags: std::collections::BTreeMap<String, String>,
    pub data_size: serde_bare::Uint,
    pub index_size: serde_bare::Uint,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct V1ItemMetadata {
    pub plain_text_metadata: V1PlainTextItemMetadata,
    pub encrypted_metadata: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct V2ItemMetadata {
    pub plain_text_metadata: V2PlainTextItemMetadata,
    pub encrypted_metadata: Vec<u8>,
}

#[non_exhaustive]
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub enum VersionedItemMetadata {
    V1(V1ItemMetadata), // Note, we are considering removing this version in the future and removing support.
    V2(V2ItemMetadata),
}

// This type is the result of decrypting and validating either V1 metadata or V2 metadata
// It is the lowest common denominator of all metadata.
#[derive(Debug, PartialEq, Clone)]
pub struct DecryptedItemMetadata {
    pub primary_key_id: Xid,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub data_tree: HTreeMetadata,
    pub index_tree: Option<HTreeMetadata>,
    pub plain_text_hash: [u8; crypto::HASH_BYTES],
    pub send_key_id: Xid,
    pub index_hash_key_part_2: crypto::PartialHashKey,
    pub data_hash_key_part_2: crypto::PartialHashKey,
    pub tags: std::collections::BTreeMap<String, String>,
    pub data_size: serde_bare::Uint,
    pub index_size: serde_bare::Uint,
}

impl VersionedItemMetadata {
    pub fn primary_key_id(&self) -> &Xid {
        match self {
            VersionedItemMetadata::V1(ref md) => &md.plain_text_metadata.primary_key_id,
            VersionedItemMetadata::V2(ref md) => &md.plain_text_metadata.primary_key_id,
        }
    }

    pub fn index_tree(&self) -> Option<&HTreeMetadata> {
        match self {
            VersionedItemMetadata::V1(ref md) => md.plain_text_metadata.index_tree.as_ref(),
            VersionedItemMetadata::V2(ref md) => md.plain_text_metadata.index_tree.as_ref(),
        }
    }

    pub fn data_tree(&self) -> &HTreeMetadata {
        match self {
            VersionedItemMetadata::V1(ref md) => &md.plain_text_metadata.data_tree,
            VersionedItemMetadata::V2(ref md) => &md.plain_text_metadata.data_tree,
        }
    }

    pub fn decrypt_metadata(
        &self,
        dctx: &mut crypto::DecryptionContext,
    ) -> Result<DecryptedItemMetadata, anyhow::Error> {
        match self {
            VersionedItemMetadata::V1(ref md) => {
                let data = dctx.decrypt_data(md.encrypted_metadata.clone())?;
                let emd: V1SecretItemMetadata = serde_bare::from_slice(&data)?;
                if md.plain_text_metadata.hash() != emd.plain_text_hash {
                    anyhow::bail!("item metadata is corrupt or tampered with");
                }
                Ok(DecryptedItemMetadata {
                    primary_key_id: md.plain_text_metadata.primary_key_id,
                    data_tree: md.plain_text_metadata.data_tree,
                    index_tree: md.plain_text_metadata.index_tree,
                    plain_text_hash: emd.plain_text_hash,
                    send_key_id: emd.send_key_id,
                    index_hash_key_part_2: emd.index_hash_key_part_2,
                    data_hash_key_part_2: emd.data_hash_key_part_2,
                    timestamp: emd.timestamp,
                    tags: emd.tags,
                    data_size: emd.data_size,
                    index_size: emd.index_size,
                })
            }
            VersionedItemMetadata::V2(ref md) => {
                let data = dctx.decrypt_data(md.encrypted_metadata.clone())?;
                let emd: V2SecretItemMetadata = serde_bare::from_slice(&data)?;
                if md.plain_text_metadata.hash() != emd.plain_text_hash {
                    anyhow::bail!("item metadata is corrupt or tampered with");
                }
                let ts_millis = md.plain_text_metadata.unix_timestamp_millis as i64;
                let ts_secs = ts_millis / 1000;
                let ts_nsecs = ((ts_millis % 1000) * 1000000) as u32;
                let ts = chrono::DateTime::<chrono::Utc>::from_utc(
                    chrono::NaiveDateTime::from_timestamp(ts_secs, ts_nsecs),
                    chrono::Utc,
                );
                Ok(DecryptedItemMetadata {
                    primary_key_id: md.plain_text_metadata.primary_key_id,
                    plain_text_hash: emd.plain_text_hash,
                    data_tree: md.plain_text_metadata.data_tree,
                    index_tree: md.plain_text_metadata.index_tree,
                    send_key_id: emd.send_key_id,
                    index_hash_key_part_2: emd.index_hash_key_part_2,
                    data_hash_key_part_2: emd.data_hash_key_part_2,
                    timestamp: ts,
                    tags: emd.tags,
                    data_size: emd.data_size,
                    index_size: emd.index_size,
                })
            }
        }
    }
}

#[non_exhaustive]
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum LogOp {
    AddItem((Xid, VersionedItemMetadata)),
    // Note: There is an asymmetry here in that we can delete many items with one log op.
    // This is because batch deleting is possible, but batch add makes less sense.
    RemoveItems(Vec<Xid>),

    RecoverRemoved,
}

pub fn checked_serialize_metadata(md: &VersionedItemMetadata) -> Result<Vec<u8>, anyhow::Error> {
    let serialized_op = serde_bare::to_vec(&md)?;
    if serialized_op.len() > MAX_METADATA_SIZE {
        anyhow::bail!("itemset log item metadata too big!");
    }
    Ok(serialized_op)
}
