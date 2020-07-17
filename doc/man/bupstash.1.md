bupstash(1) - Encrypted and deduplicated backups.
=================================================

## SYNOPSIS

Run one of the following `bupstash` subcommands.

`bupstash init ...`<br>
`bupstash new-key ...`<br>
`bupstash new-put-key ...`<br>
`bupstash new-metadata-key ...`<br>
`bupstash put ...`<br>
`bupstash get ...`<br>
`bupstash list ...`<br>
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
* Optional secure offline storage of decryption keys.
* Easy setup, all you need is bupstash and optionally ssh.
* Optional, per ssh key access repository controls.
* A multi layered approach to security.

The ```bupstash``` tool itself is divided into subcommands
that can each have their own documentation.


## SUBCOMMANDS

* bupstash-init(1):
  Initialize a package store.
* bupstash-new-key(1):
  Create a new primary key for creating/reading data entries.
* bupstash-new-put-key(1):
  Derive a put only key from a primary key that cannot read data or metadata. 
* bupstash-new-metadata-key(1):
  Derive a list/rm only key from a primary key that cannot read data. 
* bupstash-put(1):
  Add a tagged snapshot to a bupstash repository.
* bupstash-get(1):
  Fetch a tagged snapshot from the bupstash repository.
* bupstash-list(1):
  List repository entries matching a given query.
* bupstash-rm(1):
  Remove repository entries matching a given query.
* bupstash-gc(1):
  Reclaim diskspace in a repository.
* bupstash-serve(1):
  Serve a repository over stdin/stdout using the bupstash-protocol(7).

## EXAMPLE

### Simple usage

```
# Initialize the repository and create keys.
$ ssh $SERVER bupstash init /home/me/backups
$ bupstash new-key -o backups.key

# Tell bupstash about our repository and keys.
$ export BUPSTASH_REPOSITORY=ssh://$SERVER/home/me/backups
$ export BUPSTASH_KEY=backups.key

# Save a directory as a tarball snapshot.
$ bupstash put hostname=$(hostname) :: ./some-data
XXX

# Save a file.
$ bupstash put hostname=$(hostname) :: ./some-file.txt
XXX

# Save the output of a command, checking for errors 
$ bupstash put --exec hostname=$(hostname) name=database.sql :: pgdump ...

$ bupstash list name=*.txt and hostname=$(hostname)
XXX
$ bupstash get id=
...
$ bupstash rm id=
$ bupstash gc
XXX
```

### Offline decryption key
```
# Create a primary key, and a put only key.
$ bupstash new-key backups.key -o backups.key
$ bupstash new-put-key -k backups.key -o backups-put.key

... Copy backups.key to secure offline storage ...

# Remove primary key
$ shred backups.key

$ bupstash put -k backups-put.key :: ./data

... After emergency, get decryption key from offline storage ...
```


## SEE ALSO

bupstash-repository(7), bupstash-protocol(7), bupstash-keyfiles(7)