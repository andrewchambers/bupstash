bupstash(1) 
===========

## SYNOPSIS

Bupstash encrypted and deduplicated backups.

Run one of the following `bupstash` subcommands.

`bupstash init ...`<br>
`bupstash new-key ...`<br>
`bupstash new-put-key ...`<br>
`bupstash new-metadata-key ...`<br>
`bupstash put ...`<br>
`bupstash list ...`<br>
`bupstash get ...`<br>
`bupstash rm ...`<br>
`bupstash gc ...`<br>
`bupstash serve ...`<br>

## DESCRIPTION

```bupstash``` is a tool for storing (and retrieving)
arbitrary data in an encrypted bupstash-repostory(7).

Some notable features of ```bupstash``` include:

* Automatic deduplication of stored data.
* Client side encryption of data.
* A simple and powerful query language.
* Optional role based encryption and decryption key separation.
* Easy setup, all you need is bupstash and optionally ssh.
* Optional, per ssh key access repository controls.
* A multi layered approach to security.

The ```bupstash``` tool itself is divided into subcommands
that can each have their own documentation.


## SUBCOMMANDS

* bupstash-init(1):
  Initialize a package store.
* bupstash-new-key(1):
  Create a new primary key for creating/reading repository items.
* bupstash-new-put-key(1):
  Derive a put only key from a primary key. 
* bupstash-new-metadata-key(1):
  Derive a list/rm only key from a primary key. 
* bupstash-put(1):
  Add data to a bupstash repository.
* bupstash-get(1):
  Fetch data from the bupstash repository matching a query.
* bupstash-list(1):
  List repository items matching a given query.
* bupstash-rm(1):
  Remove repository items matching a given query.
* bupstash-gc(1):
  Reclaim diskspace in a repository.
* bupstash-serve(1):
  Serve a repository over stdin/stdout using the bupstash-protocol(7).

## EXAMPLE

### Standard usage

```
# Initialize the repository and create keys.
$ ssh $SERVER bupstash init /home/me/backups
$ bupstash new-key -o backups.key

# Tell bupstash about our repository and keys.
$ export BUPSTASH_REPOSITORY=ssh://$SERVER/home/me/backups
$ export BUPSTASH_KEY=backups.key

# Save a directory as a tarball snapshot.
$ bupstash put hostname=$(hostname) :: ./some-data
ebb66f3baa5d432e9f9a28934888a23d

# Save a file, with arbitrary key/value tags.
$ bupstash put mykey=myvalue :: ./some-file.txt
bcb8684e6bf5cb453e77486decf61685

# Save the output of a command, checking for errors.
$ bupstash put --exec name=database.sql :: pgdump ...
14ebd2073b258b1f55c5bbc889c49db4

# List items matching a query.
$ bupstash list name=*.txt and hostname=$(hostname)
id="bcb8684e6bf5cb453e77486decf61685" name="some-file.txt" hostname="black" timestamp="2020-07-27 11:26:16"

# Get an item matching a query.
$ bupstash get id=bcb8684e6bf5cb453e77486decf61685
some data.

# Remove items matching a query.
$ bupstash rm name=some-data.txt

# Remove everything.
$ bupstash rm --allow-many id=*

# Run the garbage collector to reclaim disk space.
$ bupstash gc

```

### Offline decryption key
```
# Create a primary key, and a put only key.
$ bupstash new-key -o backups.key
$ bupstash new-put-key -k backups.key -o backups-put.key

... Copy backups.key to secure offline storage ...

# Remove primary key
$ shred backups.key

$ bupstash put -k backups-put.key :: ./data
14ebd2073b258b1f55c5bbc889c49db4
... After emergency, get decryption key from offline storage ...

$ bupstash get -k backups.key id=14ebd2073b258b1f55c5bbc889c49db4 | tar -C ./restore -xf - 
```


## SEE ALSO

bupstash-repository(7), bupstash-protocol(7), bupstash-keyfiles(7)