use super::address::*;
use super::compression;
use super::crypto;
use super::xid::*;
use serde::{Deserialize, Serialize};

pub const MAX_TAG_SET_SIZE: usize = 32 * 1024;
// Tags plus some leeway, we can adjust this if we need to.
pub const MAX_METADATA_SIZE: usize = MAX_TAG_SET_SIZE + 2048;

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Clone, Copy)]
pub struct HTreeMetadata {
    pub height: serde_bare::Uint,
    pub data_chunk_count: serde_bare::Uint,
    pub address: Address,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Clone)]
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

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Clone)]
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

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Clone)]
pub struct V3PlainTextItemMetadata {
    pub primary_key_id: Xid,
    pub unix_timestamp_millis: u64,
    pub data_tree: HTreeMetadata,
    pub index_tree: Option<HTreeMetadata>,
}

impl V3PlainTextItemMetadata {
    pub fn hash(&self, item_id: &Xid) -> [u8; crypto::HASH_BYTES] {
        let mut hst = crypto::HashState::new(None);
        hst.update(&[3]); // We now encode the version in this hash.
        hst.update(&item_id.bytes[..]); // The metadata is tied to the item id.
        hst.update(&serde_bare::to_vec(&self).unwrap());
        hst.finish()
    }
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Clone)]
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

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Clone)]
pub struct V2SecretItemMetadata {
    pub plain_text_hash: [u8; crypto::HASH_BYTES],
    pub send_key_id: Xid,
    pub index_hash_key_part_2: crypto::PartialHashKey,
    pub data_hash_key_part_2: crypto::PartialHashKey,
    pub tags: std::collections::BTreeMap<String, String>,
    pub data_size: serde_bare::Uint,
    pub index_size: serde_bare::Uint,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Clone)]
pub struct V3SecretItemMetadata {
    pub plain_text_hash: [u8; crypto::HASH_BYTES],
    pub send_key_id: Xid,
    pub index_hash_key_part_2: crypto::PartialHashKey,
    pub data_hash_key_part_2: crypto::PartialHashKey,
    pub tags: std::collections::BTreeMap<String, String>,
    pub data_size: serde_bare::Uint,
    pub index_size: serde_bare::Uint,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Clone)]
pub struct V1ItemMetadata {
    pub plain_text_metadata: V1PlainTextItemMetadata,
    pub encrypted_metadata: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Clone)]
pub struct V2ItemMetadata {
    pub plain_text_metadata: V2PlainTextItemMetadata,
    pub encrypted_metadata: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Clone)]
pub struct V3ItemMetadata {
    pub plain_text_metadata: V3PlainTextItemMetadata,
    pub encrypted_metadata: Vec<u8>,
}

#[non_exhaustive]
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Clone)]
pub enum VersionedItemMetadata {
    V1(V1ItemMetadata), // Note, we are considering removing this version in the future and removing support.
    V2(V2ItemMetadata),
    V3(V3ItemMetadata),
    // Forward compatibility.
    Reserved1,
    Reserved2,
    Reserved3,
}

// This type is the result of decrypting and validating either V1 metadata or V2 metadata
// It is the lowest common denominator of all metadata.
#[derive(Debug, Eq, PartialEq, Clone)]
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
            VersionedItemMetadata::V3(ref md) => &md.plain_text_metadata.primary_key_id,
            _ => panic!("item metadata is from a future version of bupstash"),
        }
    }

    pub fn index_tree(&self) -> Option<&HTreeMetadata> {
        match self {
            VersionedItemMetadata::V1(ref md) => md.plain_text_metadata.index_tree.as_ref(),
            VersionedItemMetadata::V2(ref md) => md.plain_text_metadata.index_tree.as_ref(),
            VersionedItemMetadata::V3(ref md) => md.plain_text_metadata.index_tree.as_ref(),
            _ => panic!("item metadata is from a future version of bupstash"),
        }
    }

    pub fn data_tree(&self) -> &HTreeMetadata {
        match self {
            VersionedItemMetadata::V1(ref md) => &md.plain_text_metadata.data_tree,
            VersionedItemMetadata::V2(ref md) => &md.plain_text_metadata.data_tree,
            VersionedItemMetadata::V3(ref md) => &md.plain_text_metadata.data_tree,
            _ => panic!("item metadata is from a future version of bupstash"),
        }
    }

    pub fn decrypt_metadata(
        &self,
        item_id: &Xid,
        dctx: &mut crypto::DecryptionContext,
    ) -> Result<DecryptedItemMetadata, anyhow::Error> {
        match self {
            VersionedItemMetadata::V1(ref md) => {
                let data =
                    compression::decompress(dctx.decrypt_data(md.encrypted_metadata.clone())?)?;
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
                let data =
                    compression::decompress(dctx.decrypt_data(md.encrypted_metadata.clone())?)?;
                let emd: V2SecretItemMetadata = serde_bare::from_slice(&data)?;
                if md.plain_text_metadata.hash() != emd.plain_text_hash {
                    anyhow::bail!("item metadata is corrupt or tampered with");
                }
                let ts_millis = md.plain_text_metadata.unix_timestamp_millis as i64;
                let ts_secs = ts_millis / 1000;
                let ts_nsecs = ((ts_millis % 1000) * 1000000) as u32;
                let ts = chrono::DateTime::<chrono::Utc>::from_utc(
                    chrono::NaiveDateTime::from_timestamp_opt(ts_secs, ts_nsecs)
                        .ok_or(anyhow::format_err!("invalid timestamp"))?,
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
            VersionedItemMetadata::V3(ref md) => {
                let data =
                    compression::decompress(dctx.decrypt_data(md.encrypted_metadata.clone())?)?;
                let emd: V2SecretItemMetadata = serde_bare::from_slice(&data)?;
                if md.plain_text_metadata.hash(item_id) != emd.plain_text_hash {
                    anyhow::bail!("item metadata is corrupt or tampered with");
                }
                let ts_millis = md.plain_text_metadata.unix_timestamp_millis as i64;
                let ts_secs = ts_millis / 1000;
                let ts_nsecs = ((ts_millis % 1000) * 1000000) as u32;
                let ts = chrono::DateTime::<chrono::Utc>::from_utc(
                    chrono::NaiveDateTime::from_timestamp_opt(ts_secs, ts_nsecs)
                        .ok_or(anyhow::format_err!("invalid timestamp"))?,
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
            _ => panic!("item metadata is from a future version of bupstash"),
        }
    }
}

#[non_exhaustive]
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub enum LogOp {
    AddItem((Xid, VersionedItemMetadata)),
    // Note: There is an asymmetry here in that we can delete many items with one log op.
    // This is because batch deleting is possible, but batch add makes less sense.
    RemoveItems(Vec<Xid>),
    RecoverRemoved,
    Reserved1,
    Reserved2,
    Reserved3,
}

pub fn checked_serialize_metadata(md: &VersionedItemMetadata) -> Result<Vec<u8>, anyhow::Error> {
    const MAX_HTREE_HEIGHT: u64 = 10;
    if md.data_tree().height.0 > MAX_HTREE_HEIGHT {
        anyhow::bail!("item has invalid data hash tree");
    }
    if let Some(index_tree) = md.index_tree() {
        if index_tree.height.0 > MAX_HTREE_HEIGHT {
            anyhow::bail!("item has invalid index hash tree");
        }
    }
    let serialized_op = serde_bare::to_vec(&md)?;
    if serialized_op.len() > MAX_METADATA_SIZE {
        anyhow::bail!("itemset log item metadata too big!");
    }
    Ok(serialized_op)
}
