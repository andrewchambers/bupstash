bupstash-repository(7)
======================

## SYNOPSIS

Overview of the bupstash repository format.

## DESCRIPTION

The most important part of bupstash is the repository. It is where all data is stored in a mostly
encrypted form. The bupstash client interacts via the repository over stdin/stdout of the bupstash-serve(1)
process. This may be locally, or via a protocol such as ssh.

Because most data is encrypted, the repository structure is quite simple.

Files:

```
repo
├── data
│   ├── ...
│   └── 5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03
├── items
│   ├── 031d91b342fc76b8a4b32e2a8d12e4d0
│   └── ffaa0127fd9938aa0a3eaf6070aa947d
├── meta
│   ├── gc_generation
│   ├── gc_dirty
│   ├── schema_version
│   └── storage_engine
├── repo.oplog
├── repo.lock
├── tx.lock
└── rollback.journal

```

### repo.oplog

This file is an append only ledger where each entry is a [bare](https://baremessages.org/) encoded log op of the following format:


```

type Xid data<16>;
type Address data<32>;

type LogOp  (AddItem | RemoveItems | RecoverRemoved);
  
type AddItem {
  id: Xid
  metadata: VersionedItemMetadata 
}

type RemoveItems {
  items: []Xid
}

type RecoverRemoved {}

type VersionedItemMetadata = (V1VersionedItemMetadata | V2VersionedItemMetadata | V2VersionedItemMetadata)

type V1VersionedItemMetadata {
  // deprecated
}

type V2VersionedItemMetadata {
  // deprecated
}

type V3VersionedItemMetadata {
  primary_key_id: Xid,
  unix_timestamp_millis: u64,
  tree_height: usize,
  address: Address,
  encryped_metadata: data
}

struct V3SecretItemMetadata {
  plain_text_hash: data<32>
  send_key_id: Xid,
  hash_key_part_2: data<32>,
  tags: Map[String]String,
}

```

It is important to note, all metadata like search tags are stored encrypted and are not 
readable without a master key or metadata key.

### repo.lock

This lock is held exclusively during garbage collection and in a shared fashion
during operations that modify the repository.

### tx.lock

Bupstash uses `tx.lock` and `rollback.journal` to coordinate crash safe edits across multiple files.

### rollback.journal

This file is a [bare](https://baremessages.org/) encoded rollback log with the following schema:

```

type RollbackOp = RollbackComplete | RemoveFile | WriteFile | TruncateFile | RenameFile;

type RollbackComplete {};

type RemoveFile {
  path: String,
};

// This entry is trailed by size bytes of data to write.
type WriteFile {
  path: String,
  size: Uint,
};

type TruncateFile {
  path: String,
  size: Uint,
};

type RenameFile {
  from: String,
  to: String,
};
```

The final 32 bytes of the rollback log are the blake3 hash of the previous file contents.

Do not delete a rollback journal if find one, it is critical for data integrity.

### meta/storage_engine

Contains the JSON storage engine specification, which allows storage of data chunks
in external or alternative storage formats. This file is human editable to assist
manual data migrations between supported formats.

### meta/schema_version

This file contains schema version of a repository.

### meta/gc_generation

Each time a garbage collection happens, this file is changed and is used to invalidate
client side caches.

### meta/gc_dirty

This file marks if a garbage collection was interrupted prematurely and is used for crash
recovery. This file not always present.


### items/

This directory contains one file for each item, where the contents of the file is an encoded
`VersionedItemMetadata` as described in the repo.oplog section. When an item is removed and is 
pending garbage collection it is given the .removed suffix.

### data/

This directory contains a set of encrypted and deduplicated data chunks.
The name of the file corresponds to the an HMAC hash of the unencrypted contents, as such
if two chunks are added to the repository with the same hmac, they only need to be stored once.

This directory is not used when the repository is configured for storage engines other than "Dir" storage.

## The hash tree structure

Bupstash stores arbitrary streams of data in the repository by splitting the stream into chunks,
hmac addressing the chunks, then compressing and encrypting the chunks with the public key portion of a bupstash key.
Each chunk is then stored in the data directory in a file named after the hmac hash of the contents.
As we generate a sequence of chunks with a corresponding hmac addresses,
we can build a tree structure out of these addresses. Leaf nodes of the tree are simply the encrypted data. 
Other nodes in the tree are simply unencrypted lists of hmac hashes, which may point to encrypted leaf nodes,
or other subtrees. The key idea behind the hash tree, is we can convert an arbitrary stream of data
into a single HMAC address with approximately equal sized chunks.
When multiple hash trees are added to the repository, they share structure and enable deduplication.

This addressing and encryption scheme has some important properties:

- The repository owner *cannot* guess chunk contents as the HMAC key is unknown to him.
- The repository owner *cannot* decrypt leaves of the hash tree, as they are encrypted.
- The repository owner *can* iterate the hash tree for garbage collection purposes.
- The repository owner *can* run garbage collection without retrieving the leaf nodes from cold storage.
- The repository owner *can* push stream a of hash tree nodes to a client with no network round trips.
- A client *can* send data streams to a repository without sharing the encryption key.
- A client *can* retrieve and verify a datastream by checking hmacs.

These properties are desirable for enabling high performance garbage collection and data streaming
with prefetch on the repository side.

## Chunking and deduplication

Data is deduplicated by splitting a data stream into small chunks, and never storing the same chunk twice.
The performance of this deduplication is thus determined by how chunks split points are defined. For curious
readers - bupstash uses something known as 'content defined chunking' to find efficient chunk splits.

## Chunk formats

Chunks in the database are one of the following types, in general we know the type of a chunk
based on the item metadata and the hash tree height.

### Encrypted data chunk

These chunks form the roots of our hash trees, they contain encrypted data. They contain
a key exchange packet, with enough information for the master key to derive the session key.

```
KEY_EXCHANGE_PACKET1_BYTES[PACKET1_SZ] || ENCRYPTED_BYTES[...]
```

After decryption, the chunk is optionally compressed, so is either compressed data, or data with a null footer byte.

```
COMPRESSED_DATA[...] || DECOMPRESSED_SIZE[4] || COMPRESSION_TYPE[1]
```

or 

```
DATA[...] || 0x00
```

Valid compression types are:

- 1 == lz4 compression.
- 2 == zstd compression.

### Hash tree node chunk

These chunks form non leaf nodes in our hash tree, they consist of an array of addresses prefixed
with the total number of data chunks that are beneath them in the tree.

```
NUM_DATA_CHUNKS[8] ADDRESS[ADDRESS_SZ]
NUM_DATA_CHUNKS[8] ADDRESS[ADDRESS_SZ]
NUM_DATA_CHUNKS[8] ADDRESS[ADDRESS_SZ]
NUM_DATA_CHUNKS[8] ADDRESS[ADDRESS_SZ]
...
```

These addresses must be recursively followed to read our data chunks, these addresses correspond
to data chunks when the tree height is 0. The chunk counts can be used to efficiently seek to address offsets
in the tree.

### Format of key exchange bytes

Coming soon...

## SEE ALSO

bupstash(1)
