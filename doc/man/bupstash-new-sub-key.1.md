bupstash-new-sub-key(1) 
=======================

## SYNOPSIS

Generate a bupstash sub key with lesser encryption and decryption capabilities.

`bupstash new-sub-key -k KEY -o SUB_KEY`

## DESCRIPTION

`bupstash new-sub-key` creates a new bupstash key capable of
a subset of the encryption and decryption operations of the main key.

Capabilities are any of 'put', 'list' and 'list-contents'. 'put' keys can
create new backups but not decrypt data, 'list' keys can decrypt tags and other metadata,
while 'list-contents' keys can decrypt the contents of items created by 'bupstash put'.

A typical use of a list only key would be to allow a cron job to rotate old backups by
their search tags, without exposing the data decryption key.

The generated key will be marked readable only for the creating user.

If a sub-key is lost, the original key will still be able to decrypt any data in the repository
encrypted by that sub-key.

*NOTE*: decryption differs from access - An attacker may still delete data by simply deleting the
 items or files they have access to. Use bupstash-serve(1) access controls to restrict which
 operations a user can perform and prevent unauthorized deletion of data. This can be done via an
 ssh authorized_keys file, or through mechanisms such as `sudo` or `doas` configuration.

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
