bupstash-new-put-key(1) 
=======================

## SYNOPSIS

Generate a new bupstash put-key derived from a primary key.

`bupstash new-put-key -k PRIMARY_KEY -o PUT_KEY`

## DESCRIPTION

`bupstash new-put-key` creates a new bupstash put-key capable of writing
new repository entries, but not decrypting them again.

A typical use of a put-key, is to distribute them to clients you wish to
make backups, but do not wish to grant them read access to the contents
of backups.

The generated key will be marked readable only for the creating user.

If a put-key is lost, the primary key will still be able to decrypt
any data saved with this put key.

Each put-key has its own 'deduplication space' with a repository, meaning
multiple put-keys do not deduplicate data sent by eachother put-key.
This is done for enhanced security, as it prevents an attacker with access
to a put key from corrupting uploads made by other keys.

## OPTIONS

* -k, --key:
  Primary key to derive the new put-key from.
* -o, --output:
  Path to where the put-key will be written.

## EXAMPLES

### Create a new put key
```
$ bupstash new-key -o ./backups.key
$ bupstash new-put-key -o ./backups-put.key
$ ID=$(bupstash put -k ./backups-put.key :: ./data)
$ bupstash get -k ./backups.key id=$ID
```

## SEE ALSO

bupstash(1), bupstash-keyfiles(7)
