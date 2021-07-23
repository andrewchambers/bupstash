bupstash(1) 
===========

## SYNOPSIS

Bupstash encrypted and deduplicated backups.

Run one of the following `bupstash` subcommands.

`bupstash init ...`<br>
`bupstash new-key ...`<br>
`bupstash new-sub-key ...`<br>
`bupstash put ...`<br>
`bupstash list ...`<br>
`bupstash list-contents ...`<br>
`bupstash diff ...`<br>
`bupstash get ...`<br>
`bupstash restore ...`<br>
`bupstash rm ...`<br>
`bupstash recover-removed ...`<br>
`bupstash gc ...`<br>
`bupstash serve ...`<br>
`bupstash help ...`<br>
`bupstash version ...`<br>

## DESCRIPTION

```bupstash``` is a tool for storing (and retrieving)
files and data in an encrypted bupstash-repostory(7).

Some notable features of ```bupstash``` include:

* Automatic deduplication of stored data.
* Client side encryption of data.
* Incremental file uploads.
* A tag based query language.
* Optional role based encryption and decryption key separation.
* Remote repositories over ssh ssh.
* Optional, per ssh key access repository controls.
* A multi layered approach to security.

The ```bupstash``` tool itself is divided into subcommands
that each have their own documentation.

## SUBCOMMANDS

* bupstash-init(1):
  Initialize a bupstash repository.
* bupstash-new-key(1):
  Create a new primary key for creating/reading repository items.
* bupstash-new-sub-key(1):
  Derive a sub key for a subset of operations.
* bupstash-put(1):
  Add data to a bupstash repository.
* bupstash-get(1):
  Fetch data from the bupstash repository matching a query.
* bupstash-restore(1):
  Restore a snapshot into a local directory.
* bupstash-list(1):
  List repository items matching a given query.
* bupstash-list-contents(1):
  List directory snapshot contents.
* bupstash-diff(1):
  Diff snapshot contents.
* bupstash-rm(1):
  Remove repository items matching a given query.
* bupstash-recover-removed(1):
  Recover removed items that are pending garbage collection.
* bupstash-gc(1):
  Reclaim diskspace in a repository.
* bupstash-serve(1):
  Serve a repository over stdin/stdout using the bupstash-protocol(7).

## EXAMPLES


### Initialize a repository and create keys
```
$ bupstash init -r ssh://$SERVER/home/me/backups
$ bupstash new-key -o backups.key
```

### Tell bupstash to use our repository and key by default

```
$ export BUPSTASH_REPOSITORY=ssh://$SERVER/home/me/backups
$ export BUPSTASH_KEY=backups.key
```

### Directory snapshots

```
$ bupstash put ./some-data
ebb66f3baa5d432e9f9a28934888a23d

$ bupstash list-contents id=ebb66f3baa5d432e9f9a28934888a23d
drwxr-xr-x 0    2020/11/05 10:42:48 .
-rw-r--r-- 177B 2020/07/12 17:13:42 data.txt
```

### List items matching a query

```
$ bupstash list hostname=$(hostname)
id="bcb8684e6bf5cb453e77486decf61685" name="some-file.txt" hostname="my-server" timestamp="2020-07-27 11:26:16"
...
```

### Incremental uploads

```
$ bupstash put --send-log /var/backup.sendlog ./some-data
ebb66f3baa5d432e9f9a28934888a23d

# Second backup is much faster when it reads the send log.
$ bupstash put --send-log /var/backup.sendlog ./some-data
ebb66f3baa5d432e9f9a28934888a23d
```

### Capture and save command output

```
# Checks for errors before saving new item.
$ bupstash put --exec name=database.sql pgdump mydatabase
14ebd2073b258b1f55c5bbc889c49db4
```

### Get an item matching a query
```
$ bupstash get id=bcb8684e6bf5cb453e77486decf61685
some data.
```

### Restore a directory to a previous snapshot

```
$ bupstash restore --to ./dir name=dir.tar
```

### Remove items matching a query.
```
$ bupstash rm name=some-data.txt
```

### Wipe a repository

```
$ bupstash rm --allow-many id=*
```

### Reclaim disk space
```
$ bupstash gc
```

### Offline decryption keys
```
# Create a key, a put only key, and a metadata (list/rm only) key.
$ bupstash new-key -o backups.key
$ bupstash new-sub-key --put -k backups.key -o backups-put.key
$ bupstash new-sub-key --list -k backups.key -o backups-metadata.key

... Copy backups.key to secure offline storage ...

# Remove primary key
$ shred backups.key

$ bupstash put -k backups-put.key ./data
14ebd2073b258b1f55c5bbc889c49db4

... When you need to list or remove backups, you may use the metadata key ...

$ bupstash list -k backups-metadata.key
...
$ bupstash rm -k backups-metadata.key 

... After emergency, get decryption key from offline storage ...

# Restore by getting an item and decrypting it using the decryption key.
$ bupstash get -k backups.key id=14ebd2073b258b1f55c5bbc889c49db4 | tar -C ./restore -xf - 
```

## SEE ALSO

bupstash-repository(7), bupstash-keyfiles(7)