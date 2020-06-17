# Technical overview

This document explains the datastructures and details of the archivist backup/storage system.

First, lets cover the basics of using archivist for context:

```
$ export ARCHIVIST_REPOSTIORY=/external/archivist-repo

# Create a new repository
$ archivist init $ARCHIVIST_REPOSTIORY

# Create a master key
$ archivist new-master-key -o ./master.key

# Store a backup of a directory
$ archivist put date=$(date +%Y/%m/%d) host=$(hostname) --dir ./my-files -k ./master.key

# Store a backup of a postgres database
$ pgdump ... |  archivist put date=$(date +%Y/%m/%d) name=db.sql --file - -k ./master.key

# list backups
$ archivist list -k ./master.key date=2020/* and name=*.sql
id="2" date="2020/06/17" "name=db.dql"

# Get a backup
$ archivist get -k ./master.key id=1  | tar -x

# Remove old backups
$ archivist rm -k ./master.key --allow-many date=2018/*
$ archivist gc

# Less privileged keys
$ archivist new-send-key -m ./master.key -o ./send.key
$ archivist new-metadata-key -m ./master.key -o ./metadata.key

# Put the master key somewhere secure.
$ scp master.key $SECUREHOST
$ shred master.key

# We can only send with the send key, not decrypt or list.
$ pgdump ... |  archivist put date=$(date +%Y/%m/%d) name=db.sql --file - -k ./send.key

# We can only list/rm with the metadata key, not decrypt or put.
$ archivist list -k ./metadata.key
```


N.B. The following cli interface will almost certainly change.

N.B. Archivist can operate over ssh with ssh:// style repositories.

## Repository

The most important part of archivist is the repository. It is where all data is stored, in a mostly
encrypted form. The archivist client interacts via the repository over stdin/stdout of the archivist
serve process. This may be locally, or via a protocol such as ssh.

Because most data is encrypted, the repository structure is quite simple.

Files:

```
repo/
├── archivist.db
├── data
│   ├── 079ef643e50a060b9302258a6af745d90637b3ef34d79fa889f3fd8d90f207ce
│   └── ...
└── gc.lock
```

### archivist.db

An sqlite repository, with the following schema:

```
RepositoryMeta(Key, Value, UNIQUE(key, value));
ItemOpLog(Id INTEGER PRIMARY KEY AUTOINCREMENT, OpData);
Items(LogOpId, Unique(LogOpId), FOREIGN KEY(LogOpId) REFERENCES ItemOpLog(Id));
```

The metadata table has the follows key/value pairs:

```
# Unique identifier for this repository.
id=$UNIQUE_ID 

# Version marker for future upgrades.
schema-version=$NUMBER 

# Marker for client side cache invalidation after gc.
gc-generation=$RANDOM_UNIQUE_ID 

# JSON encoded specification of where to store data.
storage-engine=$SPEC 
```

The `ItemOpLog` is an append only ledger of the following structure:

```
pub struct ItemMetadata {
    pub tree_height: usize,
    pub master_key_id: [u8; keys::KEYID_SZ],
    pub address: Address,
    pub hash_key_part_2a: [u8; keys::PARTIAL_HASH_KEY_SZ],
    pub hash_key_part_2b: [u8; keys::PARTIAL_HASH_KEY_SZ],
    pub encrypted_tags: Vec<u8>,
}

pub enum VersionedItemMetadata {
    V1(ItemMetadata),
}

pub enum LogOp {
    AddItem(VersionedItemMetadata),
    RemoveItems(Vec<i64>),
}
```

Each element in the ItemOpLog table is a [bincoded](https://github.com/servo/bincode) LogOp. This structure is defined in itemset.rs. It is important to note, all metadata like search tags are stored encrypted and are not 
readable without a master key or metadata key.

The `Items` table is the set of Items that have not been marked for garbage collection via a RemoveItems LogOp. 

### data directory

This directory contains a set of encrypted and deduplicated data chunks. The name of the file corresponds to
the an HMAC hash of the unencrypted contents.

This directory is not used when the repository is configured for external data storage.

### gc.lock

A lockfile allowing concurrent repository access.

This lock is held exclusively during garbage collection, and held in a shared way during
all other operations.

## The hash tree structure

Archivist stores arbitrary streams of data in the repository by splitting the stream into chunks,
hmac addressing the chunks, then compressing and encrypting the chunks with the a public key portion of a master key.
Each chunk is then stored in the data directory.

Once there is a list of chunks with a corresponding hmac address,
we can build a tree structure out of these chunks. Leaf nodes of the tree are simply the encrypted data. 
Other nodes in the tree are simply unencrypted lists of hashes, which may point to encrypted leaf nodes,
or other subtrees. The key idea behind the hash tree, is we can convert an arbitrary stream of data
into a single HMAC address. When multiple hash trees are added to the repository,
they automatically share structure saving space.

This addressing and encryption scheme has some important properties:

- The storage server *cannot* guess chunk contents as the HMAC key is unknown.
- The storage server *cannot* decrypt leaves of the hash tree, as they are encrypted.
- The storage server *can* iterate the hash tree for garbage collection purposes.
- The storage server *can* run garbage collection without retrieving the leaf nodes from cold storage.
- The storage server *can* push stream a hash tree to a client with no network round trips.

These properties are desirable for enabling high performance garbage collection and data streaming
with prefetch, that many other backup tools are missing.

## Chunking and deduplication

Data is deduplicated by splitting a data stream into small chunks, and never storing the same chunk twice.
The performance of this deduplication is thus determined by how chunks split points are defined.

One way to chunk data would be to split the data stream every N bytes, though
you will find your data is not deduplicated when similar, but offset data streams are chunked. The
chunks will often not match up as data insertion/removal quickly desynchronizes the chunk streams.

To avoid this problem we need to find a way to resync the chunk streams when they diverge from eachother,
one way to do this is via content defined chunking.

The most intuitive way to think about content defined chunking is splitting a tarball into a chunk
representing every file, this means storing the same in multiple tarballs will only ever be stored in the repository once.
This is one form of content defined chunking, though not the only one.

Another way to do content defined chunking might be to split ever time you see the byte 0xff in your data stream.
Your chunks streams will always resync on the 0xff byte after diverging, but relies on your data containing 0xff in
appropriate evently spaced places. What we really want is a way to pseudorandomly
detect good split points, so the chunking does not really depend on byte values within the chunk. Luckily we have such 
functions, they are called hash functions. If we split a chunk whenever the hash of the last N bytes is 0xff, we might
get a good enough pseudorandom set of chunks, which also resynchronize with mostly similar data.

So what does archivist use? Archivist uses a combination of tar splitting and content defined chunking when uploading a
directory directly, and purely content defined chunking with a hash function when uploading arbitrary data.

It should be noted the chunking algorithms can be changed and mixed at any time and will 
not affect the archivist repository or reading data streams back.

## Chunk formats

TODO... Describe the exact byte layout of the 2 chunk types.

## Key files

Archivist is designed to allow the user to create backups and cycle old backups while
keeping the decryption key offline. It does this by having three distinct (but optional) key types.

### Master key

A key capable of encrypting/decrypting chunk data, encrypting/decrypting metdata. A master
key can be used in any role, but can also be kept in offline storage.

### Metadata key

A key derived from a master key only capable of reading/writing metadata. These keys are primarily used
for things like automated backup rotation without 

### Send key

A send key is always derived and is capable of only encrypting chunk data and encrypting metdata. 
Any data encrypted with a send key can only be decrypted by a master key.
Metadata encrypted by a send key can be decrypted by a metadata key and a master key.

### Key disk format

Keys are stored as [bincoded](https://github.com/servo/bincode) byte arrays. When stored on disk keys
are pem encoded.

```

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
       never knows the hash key and is unable to use this
       to guess file contents.
    */
    pub hash_key_part_1a: [u8; PARTIAL_HASH_KEY_SZ],
    pub hash_key_part_1b: [u8; PARTIAL_HASH_KEY_SZ],
    pub hash_key_part_2a: [u8; PARTIAL_HASH_KEY_SZ],
    pub hash_key_part_2b: [u8; PARTIAL_HASH_KEY_SZ],
    /* Key set used for encrypting data/ */
    pub data_psk: [u8; hydrogen::KX_PSKBYTES],
    pub data_pk: [u8; hydrogen::KX_PUBLICKEYBYTES],
    pub data_sk: [u8; hydrogen::KX_SECRETKEYBYTES],
    /* Key set used for encrypting metadata. */
    pub metadata_psk: [u8; hydrogen::KX_PSKBYTES],
    pub metadata_pk: [u8; hydrogen::KX_PUBLICKEYBYTES],
    pub metadata_sk: [u8; hydrogen::KX_SECRETKEYBYTES],
}

pub struct SendKey {
    pub id: [u8; KEYID_SZ],
    pub master_key_id: [u8; KEYID_SZ],
    pub hash_key_part_1a: [u8; PARTIAL_HASH_KEY_SZ],
    pub hash_key_part_1b: [u8; PARTIAL_HASH_KEY_SZ],
    pub hash_key_part_2a: [u8; PARTIAL_HASH_KEY_SZ],
    pub hash_key_part_2b: [u8; PARTIAL_HASH_KEY_SZ],
    pub data_psk: [u8; hydrogen::KX_PSKBYTES],
    pub data_pk: [u8; hydrogen::KX_PUBLICKEYBYTES],
    pub metadata_psk: [u8; hydrogen::KX_PSKBYTES],
    pub metadata_pk: [u8; hydrogen::KX_PUBLICKEYBYTES],
}

pub struct MetadataKey {
    pub id: [u8; KEYID_SZ],
    pub master_key_id: [u8; KEYID_SZ],
    pub metadata_psk: [u8; hydrogen::KX_PSKBYTES],
    pub metadata_pk: [u8; hydrogen::KX_PUBLICKEYBYTES],
    pub metadata_sk: [u8; hydrogen::KX_SECRETKEYBYTES],
}

pub enum Key {
    MasterKeyV1(MasterKey),
    SendKeyV1(SendKey),
    MetadataKeyV1(MetadataKey),
}
```

## Access controls

Archivist uses ssh forced commands to enforce permissions on a per ssh key basis.

The `archivist serve` command and be passed flags --allow-add, --allow-edit, --allow-gc, --allow-read 
to control what actions an ssh key can perform.

As an example, a send key, sending data to a repository where the --allow-add option has been set, means
only new backups can be made, and none can be deleted.

## Send logging

Archivist attempts to avoid resending data when it has already been sent. On the client side, archivist
maintains a cache of the last N hmac addresses that have been sent. On cache hit, we are able to skip the
sending of the given chunk. This works in practice because during backups, we are often sending the same data many times sequentially.

The send log is invalidated when the repository gc-generation changes.

By default this cache is at `$HOME/.cache/archivist/send-log.sqlite3`. But users are given the ability
to override the send log path when they with to optimize cache invalidation.

## Stat caching

When storing directories as tarballs in the repository, archivist attempts to avoid rereading the contents
of files on disk when contructing the tarball hash tree.
It accompishes this by maintaining a stat cache, which is a lookup table of absolute path and stat information 
to a list of HMAC addresses representing the chunked tarball contents for that simple file.
On cache hit archivist is able to skip sending a tar header, or file contents, instead directly adding those chunk addresses
to the hash tree that is being written.

By default this cache is at `$HOME/.cache/archivist/stat-cache.sqlite3`. But users are given the ability
to override the stat cache path when they with to optimize cache invalidation.

## Search and query

All repository search and query is performed via a small query language. The query language performs
filtering on item metadata based on a simply grammar.

example query:
```
archivist list date=2018/* and hostname=mypc
```

The question then arises, if all metadata is encrypted, how does search work?  The answer is that we are able to sync the encrypted ItemLogOp ledger to the client machine, and perform search and decryption there.

By default the synced query cache resides at `$HOME/.cache/archivist/query-cache.sqlite3`. But users are given the ability
to override the query cache path when they with to optimize cache invalidation.

## Forward secrecy

When encrypting data chunks, archivist uses an ephemeral key, that only the master key can recover. This ephemeral
key is deleted by a send client on 'put' completion, so a client cannot decrypt historic data. This protects users
from compromised malicious clients that wish to read historic backups from a repository stored on the same computer.
