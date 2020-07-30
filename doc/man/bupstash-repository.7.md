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
repo/
├── bupstash.sqlite3
├── data
│   ├── 079ef643e50a060b9302258a6af745d90637b3ef34d79fa889f3fd8d90f207ce
│   └── ...
├── gc.lock
└── storage-engine.json
```

### bupstash.sqlite3

An sqlite repository, with the following schema:

```
RepositoryMeta(Key primary key, Value) without rowid;
ItemOpLog(OpId INTEGER PRIMARY KEY AUTOINCREMENT, ItemId, OpData)
Items(ItemId PRIMARY KEY, Metadata) WITHOUT ROWID
```

The metadata table has the follows key/value pairs:

```
# Unique identifier for this repository.
id=$UNIQUE_ID 

# Version marker for future upgrades.
schema-version=$NUMBER 

# Marker for client side cache invalidation after gc.
gc-generation=$RANDOM_UNIQUE_ID 

# Marker that a garbage collection was interrupted.
gc-dirty=$BOOL

```

The `ItemOpLog` is an append only ledger where each OpData entry is a [bare](https://baremessages.org/) LogOp
of the following format:


```
// Rust type notation.

enum LogOp {
  AddItem(VersionedItemMetadata),
  RemoveItems(Vec<Xid>),
}

enum VersionedItemMetadata {
  V1(ItemMetadata),
}

struct ItemMetadata {
  plain_text_metadata: PlainTextItemMetadata,
  encrypted_metadata: Vec<u8>,
}

struct PlainTextItemMetadata {
  primary_key_id: Xid,
  tree_height: usize,
  address: Address,
}

struct EncryptedItemMetadata {
  plain_text_hash: [u8; 32],
  send_key_id: Xid,
  hash_key_part_2: [u8; 16],
  timestamp: String,
  tags: Map<String, String>,
}



```

It is important to note, all metadata like search tags are stored encrypted and are not 
readable without a master key or metadata key.

The `Items` table is an aggregated view of current items which have not be marked for removal.

### data directory

This directory contains a set of encrypted and deduplicated data chunks.
The name of the file corresponds to the an HMAC hash of the unencrypted contents, as such
if two chunks are added to the repository with the same hmac, they only need to be stored once.

This directory is not used when the repository is configured for storage engines other than "Dir" storage.

### gc.lock

A lockfile allowing concurrent repository access.

This lock is held exclusively during garbage collection, and held in a shared way during
all other operations.

### storage-engine.json

Contains the the storage engine specification, which allows storage of data chunks
in external or alternative storage formats.

## The hash tree structure

Bupstash stores arbitrary streams of data in the repository by splitting the stream into chunks,
hmac addressing the chunks, then compressing and encrypting the chunks with the a public key portion of a master key.
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
The performance of this deduplication is thus determined by how chunks split points are defined.

One way to chunk data would be to split the data stream every N bytes, this works in some cases, but
you will find your data is not deduplicated when similar, but offset data streams are chunked. The
chunks will often not match up as data insertion/removal quickly desynchronizes the chunk streams.
A good example of this problem is inserting a file into the middle of a tarball. No deduplication
will occur after that file, as the data streams have been shifted by an offset.

To avoid this problem we need to find a way to resync the chunk streams when they diverge from eachother
but then reconverge. One way to do this is via content defined chunking.
The most intuitive way to think about content defined chunking is splitting a tarball into a chunk
representing every file or directory, this means storing the same file in multiple tarballs will only ever be stored in the
repository once.

Another way to do content defined chunking might be to split every time you see the sequence 0xffff in your data stream.
Your chunks streams will always resync on the 0xffff byte after diverging, but relies on your data containing 0xffff in
 evenly spaced places. What we really want is a way to pseudorandomly
detect good split points, so the chunking does not really depend on byte values within the chunk. Luckily we have such 
functions, they are called hash functions. If we split a chunk whenever the hash of the last N bytes is 0xff, we might
get a good enough pseudorandom set of chunks, which also resynchronize with mostly similar data.

So what does bupstash use? Bupstash uses a combination of tar splitting on directory boundaries and content defined chunking when uploading a
directory directly, and purely content defined chunking with a hash function when chunking arbitrary data.

It should be noted the chunking algorithms can be changed and mixed at any time and will 
not affect the bupstash repository or reading data streams back.

## Chunk formats

Chunks in the database are one of the following types, in general we know the type of a chunk
based on the item metadata and the hash tree height.

### Encrypted data chunk

These chunks form the roots of our hash trees, they contain encrypted data. They contain
a key exchange packet, with enough information for the master key to derive the ephemeral key.

```
KEY_EXCHANGE_PACKET1_BYTES[PACKET1_SZ] || ENCRYPTED_BYTES[...]
```

After decryption, the chunk is optionally compressed, so is either compressed data, or data with a null footer byte.

```
COMPRESSED_DATA[...] || DECOMPRESSED_SIZE[4] || COMPRESSION_FLAGS[1]
```

or 

```
DATA[...] || 0x00
```

Valid compression flags are:

- 1 << 0 == zstd compression.

### Hash tree node chunk

These chunks form non leaf nodes in our hash tree, and consist of an array of addresses.

```
ADDRESS[ADDRESS_SZ]
ADDRESS[ADDRESS_SZ]
ADDRESS[ADDRESS_SZ]
ADDRESS[ADDRESS_SZ]
...
```

These addresses must be recursively followed to read our data chunks, these addresses correspond
to data chunks when the tree height is 0.

### Format of key exchange bytes

Coming soon...

## SEE ALSO

bupstash(1)
