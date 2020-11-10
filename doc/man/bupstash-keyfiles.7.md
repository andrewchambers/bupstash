bupstash-keyfiles(7)
====================

## SYNOPSIS

Overview of the bupstash key format.

## DESCRIPTION

Bupstash key files are PEM encoded with one of the following tags:

- BUPSTASH KEY
- BUPSTASH METADATA KEY
- BUPSTASH PUT KEY

The binary data after decoding the PEM data consists of [bare](https://baremessages.org/) key structures, described below.


Binary encoding of keys:
```

type PrimaryKey {
  id: Data<16>,
  hash_key_part_1: Data<16>,
  hash_key_part_2: Data<16>,
  data_pk: Data<32>,
  data_sk: Data<32>,
  data_psk: Data<32>,
  metadata_pk: Data<32>,
  metadata_sk: Data<32>,
  metadata_psk: Data<32>,
}

type PutKey {
  id: Data<16>,
  primary_key_id: Data<16>,
  hash_key_part_1: Data<16>,
  hash_key_part_2: Data<16>,
  data_pk: Data<32>,
  data_psk: Data<32>,
  metadata_pk: Data<32>,
  metadata_psk: Data<32>,
}

type MetadataKey {
  id: Data<16>,
  primary_key_id: Data<16>,
  metadata_pk: Data<32>,
  metadata_sk: Data<32>,
  metadata_psk: Data<32>,
}

type Key (PrimaryKey | PutKey | MetadataKey)
```

# EXAMPLE

```
$ bupstash new-key -o bupstash.key
$ cat bupstash.key
# This file contains a cryptographic key used by 'bupstash' to encrypt and decrypt data.
#
# key-id=55f32e9db43a1fa3cf65bb3705230898

-----BEGIN BUPSTASH KEY-----
AFXzLp20Oh+jz2W7NwUjCJgS7VhqV37771UhSRo7LZUIxJCbEZkm27AcYylSL5T2
bxAE4g0rukxRhloPqWT+s1Yr2cPNEHymMzJzm+V4QiDMzE4K4k548bsrMoQMGXc8
LRpNiqVzwRRvibkdf9RdnyYPQ5IlvQN395YJVCfiD6nEOY90plDH20UgiGiNLRYK
xH+MfIoFA1X59UFdto0B/CJW9R98OgQeJNP91NQloFA17mbzhqUvwnHDjatzkxht
CJWScQm6PTwEFEYRSzLTWgpFXjnpF09quzZenw/jEn6nPAyjb11u+Ohe7pkfxacv
QZ5qhBMqJ7+H3VpvOLW7mTmXL3T6gB5W7u2Lg6Y/AwkE
-----END BUPSTASH KEY-----

```

## SEE ALSO

bupstash(1)
