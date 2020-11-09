bupstash-new-metadata-key(1) 
============================

## SYNOPSIS

Generate a new bupstash metadata key derived from a bupstash key.

`bupstash new-metadata-key -k KEY -o METADATA_KEY`

## DESCRIPTION

`bupstash new-metadata-key` creates a new bupstash put-key capable of listing 
repository entries, but not creating new ones, or decrypting their data. The 
key is derived from a primary key, and can only decrypt metadata for entries
created by that key, or put-keys derived from it.

A typical use of a metadata key is to allow a cron job to rotate old backups by
their metadata, without being able to access the contents.

The generated key will be marked readable only for the creating user.

If a metadata-key is lost, the primary key will still be able to decrypt
any data saved with the original primary key, or a put-key derived from that
primary key.

## OPTIONS

* -k, --key PATH:
  Key to derive the new put-key from.
* -o, --output PATH:
  Path to where the put-key will be written.

## EXAMPLES

### Create a new put key
```
$ bupstash new-key -o ./backups.key
$ bupstash new-metadata-key -o ./backups-put.key
$ bupstash put -k ./backups.key ./data
$ bupstash list -k ./backups-metadata.key
```

## SEE ALSO

bupstash(1), bupstash-keyfiles(7)
