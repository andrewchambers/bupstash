# Getting started

bupstash is an easy to use tool for making encrypted space efficient backups.
It is special because it is open source, and stores all data and metadata in an encrypted
and deduplicated format.

Typical users of bupstash are people familiar with the command line, such as software developers,
system administrators and other technical users.

This guide covers installation and basic usage of bupstash.

## Install bupstash

### Precompiled version 

Head to the [releases page](https://github.com/andrewchambers/bupstash/releases) and download a
build for for your platform. Simply extract the archive and add the single bupstash binary to
your PATH.

### Via rust and cargo

If you have a rust compiler installed, you can install the latest release
using cargo (the rust programming language package manager).

Install `libsodium-dev` and `pkg-config` for your platform, and run:


```
$ git clone https://github.com/andrewchambers/bupstash
$ cd bupstash
$ cargo build --release
$ cp ./target/release/bupstash "$INSTALL_DIR"
```

or simply:

```
$ cargo install bupstash
$ cp "$HOME/.cargo/bin/bupstash" "$INSTALL_DIR"
```

## Initializing your repository

First we must initialize a repository to save data into.  We do this with the `bupstash init` command.

To initialize a local repository run:
```
export BUPSTASH_REPOSITORY="$(pwd)/bupstash-repo"
$ bupstash init
```

For remote repositories, install bupstash on both the local and the remote machine and run the following:

```
export BUPSTASH_REPOSITORY=ssh://$SERVER/home/me/bupstash-repo
$ bupstash init
```

Note that you can avoid some retyping by setting certain environment variables (e.g.
BUPSTASH_REPOSITORY) in your .bashrc or other equivalent file.

## Generating an encryption key

All data stored in a bupstash repository is encrypted, so first we need to generate an encryption key.

```
$ bupstash new-key -o backups.key
```

This key can be used to make, view and edit encrypted snapshots. 
KEEP THIS KEY SAFE, if you lose it, you will have lost all your backups made with this key.

Later sections will explain how to create and use secure offline keys.

## Making snapshots

First we must tell bupstash which encryption key to use.
```
export BUPSTASH_KEY=$(pwd)/backups.key
```

Now we can start making snapshots, here we save a file:

```
$ bupstash put ./my-data.txt
811a0f5c61656b5f494a014ce46d3549
```

The printed text is the id of this put, which can be used 
to retrieve the data again with a query:

```
$ bupstash get id="811*"
your data!
```

We can also save a directory:

```
$ bupstash put ./my-dir
...
```

Directories are automatically converted to tarballs, which can be extracted with the tar command:

```
$ mkdir restored
$ bupstash get name=my-dir.tar | tar -C ./restored -xvf -
```

We can also save the output of commands:

```
$ echo hello | bupstash put -

# This form is able to detect command failures.
$ bupstash put --exec echo hello
...
```

Note that bupstash automatically applies compression and deduplicates your data so you 
do not need to do this manually.

## Listing snapshots

```
$ bupstash list 
id="dbca49b072c0f94b9e72bf81e7716ff9" name="backup.tar" size="10.23MB" timestamp="2020/08/03 15:47:32"
...
```

We can do more sophisticated queries when we list:

```
$ bupstash list timestamp="2020/*"
...
$ bupstash list name=backup.tar and older-than 7d
$ bupstash list newer-than 1h
...
```

For a full description of the query language see the query language manual page.

## Snapshot tags

When we make snapshots, we can add our own arbitrary tags in addition to the default tags:

```
$ bupstash put mykey=value ./my-important-files 
$ bupstash list mykey=value
```

## Listing and fetching snapshots

Once we have directory snapshots, we can list the contents using bupstash `list-contents`:

```
$ bupstash list-contents id=$id
drwxr-xr-x 0 2020/10/30 13:32:04 .
-rw-r--r-- 9 2020/10/30 13:32:04 data.txt
...
```

We can also extract individual directories, subdirectories, or the whole snapshot.

```
$ bupstash get --pick data.txt id=$id
my data!
$ bupstash get --pick subdir id=$id | tar -C ./subdir-restore -xvf -
$ bupstash get id=$id | tar -C ./restore -xvf -
```

## Removing snapshots

We can remove snapshots via the same query language and the `bupstash rm` command:

```
$ bupstash rm older-than 90d and name=backup.tar and host=my-server
```

Removing a snapshot does not immediately reclaim disk space.  To do that, you must run the 
garbage collector.

```
$ bupstash gc
```

# Learning more

Feel free to browse the manual pages for each command to get a feel for how to interact and administer with your bupstash backups.