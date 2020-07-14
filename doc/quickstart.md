# bupstash 

bupstash is an easy to use tool for making encrypted space efficient backups. Bupstash
is special because it is open source, and stores all data AND metadata in an ecrypted format.

 Typical
users are people familiar with the command line, such as developers and system administrators.


This guide covers installation and basic usage of bupstash.
Everything in this guide is also covered in our introduction to bupstash video (make line XXX).

## Install bupstash

### Precompiled version 

We offer statically linked precompiled versions at our releases page (make link XXX).

Simply extract the desired bupstash binary, and add it your path:
```
wget TODO
tar xvf ./bupstash-*.tar.gz
export PATH=$(pwd):$PATH
```

### Via rust cargo

If you have a rust compiler installed, you can install the latest release
directly from crates.io using cargo, the rust programming language package manager.

```
cargo install bupstash
```

# Initializing your repository

Local repository:
```
export BUPSTASH_REPO=./bupstash-repo
$ bupstash init
```

Remote repository:

```
export BUPSTASH_REPO=ssh://$SERVER/home/me/bupstash-repo
$ bupstash init
```

# Generating an ecryption key

All data stored in a bupstash repository is encrypted, so first we need to generate an encryption key.

```
$ bupstash new-key -o backups.key
```

This key can be used to make, view and edit encrypted snapshots. 
KEEP THIS KEY SAFE, if you lose it, you will have lost all your backups made with this key.

Later sections will explain how to create and use secure offline keys.

# Making snapshots

First we must tell bupstash which encryption key to use.
```
export BUPSTASH_KEY=./backups.key
```

Now we can start making snapshots, here we save a file:

```
$ bupstash put :: ./my-data.txt
```

We can also save a directory:

```
$ bupstash put :: ./my-dir
```

Finally, we can save the output of commands:

```
$ echo hello | bupstash put

# This form is able to detect command failures.
$ bupstash put --exec :: echo hello
```

Note that bupstash automatically applies compression and deduplicates your data, compressing data yourself can actually make deduplication perform worse, taking more space.

# Listing snapshots

```
$ bupstash list 
... TODO
```

```
$ bupstash list --format=jsonl 
... TODO
```

We can do more sophisticated queries when we list:

```
bupstash list date=2020/* and content-type=*/binsy
```

For a full description of the query language see the query language manual here XXX TODO.

# Snapshot tags

When we make snapshots, we can add our own arbitrary tags in addition to the default tags:

```
$ bupstash put mykey=value :: ./my-important-files 
$ bupstash list mykey=value
```

# Fetching snapshots

Once we have snapshots, we must can fetch them again with `bupstash get` using arbitrary 
queries.

```
$ bupstash get id=TODO | tar -xvf
$ bupstash get name=my-important-files | tar -xvf -
```

# Removing snapshots

We can remove snapshots via the same query language and the `bupstash rm` command.

```
$ bupstash rm id=TODO
```

Removing a snapshot does not immediately reclaim disk space, to do that you must run the 
garbage collector.

```
$ bupstash gc
```


# Secure offline keys

In a high security setting, we do not want our decryption keys stored online where they could 
inadvertantly be leaked. To support this bupstash has the notion of put keys and metadata keys.

Generating and using these keys is simple:

```
$ bupstash new-put-key -k ./backups.key -o put-backups.key
$ bupstash new-metadata-key -k ./backups.key -o metadata-backups.key
```

Using these keys is the same as before:

```
$ bupstash put --key ./put-backups.key :: ./data.txt
$ bupstash list --key ./metadata-backups.key :: ./data.txt
```

But these keys cannot decrypt the contents of the snapshots. Only the original primary key 
is able to these snapshots.

```
$ bupstash get --key ./put-backups.key id=TODO 
XXX show error.
$ bupstash get --key ./metadata-backups.key id=TODO 
XXX show error.
$ bupstash get --key ./backups.key id=TODO 
XXX show success.
```

We can now put the primary key into secure offline storage for use in case of emergency,
but continue to make and administer our backups using the put key and metadata key.

The storage server, nor the devices uploading new snapshots 
have access to your existing snapshots.

Note that we recommend creating a new put key for every server in your network if you have a shared bupstash repository.


# Access controls

In a high security setting, we must be able to restrict what clients have permission to do.
It makes little 
Bupstash supports fine grained backup capabilities that can be configured on a per ssh key bases.

XXX TODO


## More resources

All bupstash commands and file formats are fully documented in the user manuals.

Optional, managed hosting is offered ay bupstash.io.