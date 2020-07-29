bupstash-keyfiles(7)
====================

## SYNOPSIS

Overview of the bupstash key format.

## DESCRIPTION

Bupstash key files are PEM encoded with one of the following tags:

- BUPSTASH PRIMARY KEY
- BUPSTASH METADATA KEY
- BUPSTASH PUT KEY

The binary data after decoding the PEM data are [bare](https://baremessages.org/) Key structures, shown below.

```
// Rust notation.

pub struct PrimaryKey {
    pub id: Xid,
    pub hash_key_part_1: crypto::PartialHashKey,
    pub hash_key_part_2: crypto::PartialHashKey,
    pub data_pk: crypto::BoxPublicKey,
    pub data_sk: crypto::BoxSecretKey,
    pub metadata_pk: crypto::BoxPublicKey,
    pub metadata_sk: crypto::BoxSecretKey,
}

pub struct PutKey {
    pub id: Xid,
    pub primary_key_id: Xid,
    pub hash_key_part_1: crypto::PartialHashKey,
    pub hash_key_part_2: crypto::PartialHashKey,
    pub data_pk: crypto::BoxPublicKey,
    pub metadata_pk: crypto::BoxPublicKey,
}

pub struct MetadataKey {
    pub id: Xid,
    pub primary_key_id: Xid,
    pub metadata_pk: crypto::BoxPublicKey,
    pub metadata_sk: crypto::BoxSecretKey,
}

pub enum Key {
    PrimaryKeyV1(PrimaryKey),
    PutKeyV1(PutKey),
    MetadataKeyV1(MetadataKey),
}
```

## SEE ALSO

bupstash(1)
