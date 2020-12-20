# High level implementation overview

## What does bupstash do?

Bupstash ingests arbitrary data streams, deduplicates, encrypts and saves them in a local or remote repository.
Bupstash also can convert filesystems on disk into a data stream transparently for the user.

The bupstash repository contains very little unencrypted data, it stores only encrypted data chunks, and encrypted
metadata.

## Deduplication

- Bupstash splits an input stream into data chunks less than 8 MiB.
- Each chunk has a keyed blake3 hash computed, this is the address of the chunk.
- Previous sends are tracked in the client side 'send log', an sqlite database, backing up the same data
  twice in a row only transmits new data chunks.
- If the server sees repeat hash address, it does not persist the repeat data either.

Quality of deduplication depends on how we split the data stream into chunks.
We want our data chunks to be resilient to byte insertions or removals, so we use
a rolling hash function to identify common split points between upload sessions.

We currently use a rolling hash function called 'gear hash'. It hashes a 32 byte rolling window on
the data stream and we form a new chunk if the gear hash matches an 'interestingness' property (see rollsum.rs for details).

## Encryption

- We use libsodium cryptobox to encrypt each data chunk.
- Each upload session encrypts chunks with an ephemeral public/private key pair.
- The encryption is addressed at the private portion of the decryption key, think of this like
  sending an encrypted email to someone when you know their public key.
- Each chunk has the ephemeral public key attached such that the session key can be derived
  by the master key. 
- A bupstash key is actually multiple libsodium key pairs and some preshared secrets, allowing us to divide decryption
  capabilities amongst sub keys.
- We also encrypt metadata before sending it to the repository in an append only log.
- Client side query works by syncing the metadata log then decrypting it client side.

## Hash tree

When uploading data streams larger than a single chunk, we must group them. To do this we 
form a merkle tree, only the leaf data nodes are encrypted.

- Each non leaf chunk in the hash tree is simply a list of addresses.
- Because the hash tree is mostly unencrypted, server can push stream the tree.
- Because the hash tree is mostly unencrypted, server can perform garbage collection.
- Data is still encrypted so server only knows approximate data stream size.

## Content index

Pure data streams are not efficient enough to allow a file 'browsing' user interface, to
solve this, each data stream has an optional auxillary index data stream.
The index is a hash tree containing an efficient index of the data.

- A client can fetch and decrypt the index quickly.
- The index allows partial data requests of the files withing a data stream.
- When the user requests a data stream, we first check if there is an index,
  if there is, we synthesize a tarball stream client side out of the index and data stream.

## Stat cache

When converting a filesystem to a data stream and index, we can cache the hashes of a given
file/directory based on stat information, allowing us to skip the expensive compression and encryption step.
This cache information is stored in the send log.

## Repository locking

- Read operations do not lock the repository.
- Write operations get a shared lock on the repository.
- Garbage collection operations get a shared lock for most of the mark phase,
  and an exclusive lock on the repository for the final parts of the mark phase,
  and also the sweep phase.

## Repository Garbage collection

- Garbage collection is a partially concurrent mark and sweep collector.
- Garbage collections invalidate client side caches, except for when the client checks if a previous backup item still exists.