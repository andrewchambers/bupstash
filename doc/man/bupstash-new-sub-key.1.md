bupstash-new-sub-key(1) 
============================

## SYNOPSIS

Generate a new bupstash sub key with lesser
capabilities derived from a bupstash key.

`bupstash new-sub-key -k KEY -o SUB_KEY`

## DESCRIPTION

`bupstash new-sub-key` creates a new bupstash key capable of
a subset of the operations of a main key.

Capabilities are any of 'put', 'list' and 'list-contents'. Put
keys can create new backups, list keys can decrypt tags and other metadata,
while 'list-contents' keys can list the contents of tarballs created by 'bupstash put'.

A typical use of a list only key would be to allow a cron job to rotate old backups by
their search tags, without exposing the data decryption key.

The generated key will be marked readable only for the creating user.

If a sub-key is lost, the original key will still be able to decrypt any data in the repository
encrypted by that sub-key.

## OPTIONS

* -k, --key PATH:
  Key to derive the new sub-key from.
* -o, --output PATH:
  Path to where the sub-key will be written.
* --put:
  The key is able to encrypt data for 'put' operations.
* --list:
  The key will be able to decrypt metadata and perform queries.
* --list-contents:
  The key will be able to list item contents with 'list-contents' (implies --list).

## EXAMPLES

### Create a new put only key

```
$ bupstash new-sub-key --put -k backups.key -o ./put.key
$ bupstash put -k ./backups-put.key ./data
```

### Create a new listing key

```
$ bupstash new-sub-key -k ./backups.key -o ./list.key --list
$ bupstash list -k ./list.key
```

### Create a new content listing key

```
$ bupstash new-sub-key -k ./backups.key -o ./list-contents.key --list-contents
$ bupstash list-contents -k ./list-contents.key name=some-backup.tar
```

## SEE ALSO

bupstash(1), bupstash-keyfiles(7)
