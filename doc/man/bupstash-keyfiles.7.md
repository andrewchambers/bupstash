bupstash-keyfiles(7)
====================

## SYNOPSIS

Overview of the bupstash key format.

## DESCRIPTION

Bupstash key files are PEM encoded with one of the following tags:

- BUPSTASH PRIMARY KEY
- BUPSTASH METADATA KEY
- BUPSTASH PUT KEY

The binary data after decoding the PEM data consists of [bare](https://baremessages.org/) key structures, described below.

```
// Rust type notation.

struct PrimaryKey {
  id: [u8; 16],
  hash_key_part_1: [u8; XXX],
  hash_key_part_2: [u8; XXX],
  data_pk: [u8; XXX],
  data_sk: [u8; XXX],
  data_psk: [u8; XXX],
  metadata_pk: [u8; XXX],
  metadata_sk: [u8; XXX],
  metadata_psk: [u8; XXX],
}

struct PutKey {
  id: [u8; 16],
  primary_key_id: [u8; 16],
  hash_key_part_1: [u8; 16],
  hash_key_part_2: [u8; 16],
  data_pk: [u8; XXX],
  data_psk: [u8; XXX],
  metadata_pk: [u8; XXX],
  metadata_psk: [u8; XXX],
}

struct MetadataKey {
  id: [u8; 16],
  primary_key_id: [u8; 16],
  metadata_pk: [u8; XXX],
  metadata_sk: [u8; XXX],
  metadata_psk: [u8; XXX],
}

enum Key {
  PrimaryKeyV1(PrimaryKey),
  PutKeyV1(PutKey),
  MetadataKeyV1(MetadataKey),
}
```

## SEE ALSO

bupstash(1)
