# Secure offline keys

In a secure computer systems we do not want our decryption keys stored online where they could 
inadvertently be leaked. To support this use case, bupstash allows creating keys which do not support
decrypting backups. Bupstash allows users to create 'put keys' that can only create new backups, or 'list keys' that can list backups, but not decrypt data.

Using a 'put key' lets you create backups without exposing your decryption key, while using a 'list key'
let's the key rotate old backups based on queries, but without exposing the sensitive decryption key. This
guide will show how to create use these key types.


## Generating put and list keys

Generating and using these keys is simple, we use bupstash to create a new 'put key' or 'list key' 
that is derived from a regular bupstash key using the `new-sub-key`command.

```
$ bupstash new-sub-key -k ./backups.key -o put-backups.key --put
$ bupstash new-sub-key -k ./backups.key -o list-backups.key --list
```

## Using put and list keys

Using these keys is the same as a regular key:

```
$ bupstash put --key ./put-backups.key ./data.txt
$ bupstash list --key ./list-backups.key
```

With the important difference that these keys cannot decrypt the contents of the snapshots.
Only the original key is able to decrypt these snapshots.

```
$ bupstash get --key ./put-backups.key id=$id 
bupstash get: provided key is not a decryption key

$ bupstash get --key ./list-backups.key id=$id
bupstash get: provided key is not a decryption key

$ bupstash get --key ./backups.key id=$id
data...
```

We can now put the main key into secure offline storage for use in case of emergency,
but continue to make and administer our backups using the put key and list key.

Neither the storage server, nor the devices uploading new snapshots 
have access to your existing snapshots.

Note that we recommend creating a new put key for every backup client if you have a shared bupstash
repository.