# Bupstash

[![Gitter](https://badges.gitter.im/bupstash/community.svg)](https://gitter.im/bupstash/community?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)

Bupstash is a tool for encrypted backups - if you need secure backups, Bupstash is the tool for you.


Bupstash was designed to have:

- Efficient deduplication - Bupstash can store thousands of encrypted directory snapshots using a fraction of the space encrypted tarballs would require.

- Strong privacy - Data is encrypted client side and the repository never needs has access to the decryption keys.

- Offline decryption keys - Backups do not require the decryption key be anywhere near an at-risk server or computer.

- Key/value tagging with search - all while keeping the tags fully encrypted.

- Great performance on slow networks - Bupstash really strives to work well on high latency networks like cellular and connections to far-off lands.

- Secure remote access controls - Ransomware, angry spouses, and disgruntled business partners will be powerless to delete your remote backups.

- Efficient incremental backups - Bupstash knows what it backed up last time and skips that work.

- Fantastic performance with low ram usage - Bupstash won't bog down your production servers.

- Safety against malicious attacks - Bupstash is written in a memory safe language to dramatically reduce the attack surface over the network.

## Stability and Backwards Compatibility

Bupstash is alpha software, while all efforts are made to keep bupstash bug free, we currently recommend
using bupstash for making *REDUNDANT* backups where failure can be tolerated.

The repository format is approaching stability, and will not be changed
in a backwards incompatible way unless there is *very* strong justification. Future changes will most likely be backwards compatible, or come with a migration path if it is needed at all.

# Guides, documentation and support

- Visit the [project website](https://bupstash.io).
- Visit the [quickstart guide](https://bupstash.io/doc/guides/Getting%20Started.html) for an introductory tutorial.
- Visit the [filesystem backups guide](https://bupstash.io/doc/guides/Filesystem%20Backups.html) for examples of making backups.
- Visit the [man pages](https://bupstash.io/doc/man/bupstash.html) for more comprehensive documentation.
- Visit the [community chat](https://gitter.im/bupstash/community?utm_source=share-link&utm_medium=link&utm_campaign=share-link) or the [community forum](https://github.com/andrewchambers/bupstash/discussions) to ask questions.
- Read the introductory [blog post](https://acha.ninja/blog/introducing_bupstash/).
- Read the [technical overview](./doc/technical_overview.md) to understand how it works.

# Typical usage

Initialize a new Bupstash repository via ssh.
```
$ export BUPSTASH_REPOSITORY=ssh://$SERVER/home/me/backups
$ # Ensure bupstash is on the $PATH of both machines.
$ bupstash init
```

Create a new encryption key, and tell bupstash to use it.
```
$ bupstash new-key -o backups.key
$ export BUPSTASH_KEY="$(pwd)/backups.key"
```

Save a directory as a tarball snapshot.
```
$ bupstash put hostname="$(hostname)" ./some-data
ebb66f3baa5d432e9f9a28934888a23d
```
Save the output of a command, checking for errors.
```
$ bupstash put --exec name=database.sql pgdump mydatabase
14ebd2073b258b1f55c5bbc889c49db4
```

List items matching a query.
```
$ bupstash list name="backup.tar" and hostname="server-1"
id="bcb8684e6bf5cb453e77486decf61685" name="some-file.txt" hostname="server-1" timestamp="2020/07/27 11:26:16"
```

List files in a backup.
```
$ bupstash list-contents id=bcb86*
drwxr-xr-x 0B 2020/10/30 13:32:04 .
-rw-r--r-- 7B 2020/10/30 13:32:04 hello.txt
```

Get an item matching a query.
```
$ bupstash get id=bcb8684e6bf5cb453e77486decf61685
some data...

$ bupstash get id="ebb66*" | tar -C ./restore -xf -
```

Fetch a single file from a backup.
```
$ bupstash get --pick hello.txt id="bcb86*"
hello!
```

Diff backups, with local directories or other backups.
```
$ bupstash diff /home/ac :: id="a4b8f*"
...
- -rw------- 14.50KiB    2021/08/01 02:36:19 .bash_history
+ -rw------- 13.66KiB    2021/08/01 11:51:23 .bash_history
```

Restore backups to a local directory.

```
$ mkdir restore-dir
$ bupstash restore --into ./restore-dir id="a4b8f*"
```

Remove items matching a query.
```
$ bupstash rm name=some-data.txt and older-than 30d
```

Run the garbage collector to reclaim disk space.
```
$ bupstash gc
```

# Installation

## From source

First ensure you have a recent rust+cargo, pkg-config and libsodium-dev package installed.

Next clone the repository and run cargo build.
```
$ git clone https://github.com/andrewchambers/bupstash
$ cd bupstash
$ cargo build --release
$ cp ./target/release/bupstash $INSTALL_DIR
```

## Building man pages

The man pages are currently build using a markdown to man page renderer called [ronn](https://github.com/rtomayko/ronn).

```
$ cd doc/man
$ ronn -r *.md
```

## Generating release tarballs

```
$ sh support/src-release.sh $tag
$ echo bupstash-*.tar.gz
bupstash-v0.7.0-man.tar.gz
bupstash-v0.7.0-src+deps.tar.gz
```

## Test suites

Install bash automated test framework and run the following to run both the unit tests, and cli integration test suite.

```
$ cargo test
$ cargo build --release
$ export PATH=`pwd`/target/release:$PATH
$ bats ./cli-tests
```

## Precompiled releases

Head to the [releases page](https://github.com/andrewchambers/bupstash/releases) and download for 
a build for your platform. Simply extract the archive and add the single bupstash binary to your PATH.

Currently we only precompile for linux (help wanted for more platforms).



