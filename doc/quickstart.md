# bupstash 

bupstash is an easy to use tool for making encrypted space efficient backups. Bupstash
is special because it is open source, and stores all data AND metadata in an ecrypted 
AND deduplicated format.

Typical users of bupstash are people familiar with the command line, such as software developers,
system administrators and other technical users.


This guide covers installation and basic usage of bupstash.
Everything in this guide is also covered in our introduction to bupstash video (make line XXX).

## Install bupstash

### Precompiled version 

We offer statically linked precompiled versions at our releases page (make link XXX).

Simply extract the bupstash binary for your platform, and add it your system PATH:

```
wget TODO
tar xvf ./bupstash-*.tar.gz
export PATH=$(pwd):$PATH
```

### Via rust and cargo

If you have a rust compiler installed, you can install the latest release
directly from crates.io using cargo, the rust programming language package manager.

Install `libsodium` and `pkg-config` for your platform, and run:

```
$ git clone https://git.sr.ht/~ach/bupstash
$ cd bupstash
$ cargo build --release
$ cp ./target/release/bupstash $BINDIR
```

# Initializing your repository

First we must initialize a repository to save data into, for that we use the `bupstash init` command.

Initializing a local repository:
```
export BUPSTASH_REPOSITORY=$(pwd)/bupstash-repo
$ bupstash init
```

Initializing a remote repository:

```
export BUPSTASH_REPOSITORY=ssh://$SERVER/home/me/bupstash-repo
$ bupstash init
```

As a side note, because bupstash accepts some commonly typed options from environment variables, you can
add them your .bashrc or other equivalent file to avoid retyping them.

# Generating an encryption key

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

Finally, we can save the output of commands:

```
$ echo hello | bupstash put -

# This form is able to detect command failures.
$ bupstash put --exec echo hello
...
```

Note that bupstash automatically applies compression and deduplicates your data, compressing data yourself can actually make deduplication perform worse, taking more space.

# Listing snapshots

```
$ bupstash list 
id="dbca49b072c0f94b9e72bf81e7716ff9" name="backup.tar" timestamp="2020/08/03 15:47:32"
...
```

```
$ bupstash list --format=jsonl 
{"id":"dbca49b072c0f94b9e72bf81e7716ff9", "name":"backup.tar", "timestamp":"2020/08/03 15:47:32"}
...
```

We can do more sophisticated queries when we list:

```
$ bupstash list timestamp="2020/*"
...
$ bupstash list name=backup.tar and newer-than 7d
...
```

For a full description of the query language see the query language manual pages.

# Snapshot tags

When we make snapshots, we can add our own arbitrary tags in addition to the default tags:

```
$ bupstash put mykey=value ./my-important-files 
$ bupstash list mykey=value
```

# Fetching snapshots

Once we have snapshots, we must can fetch them again with `bupstash get` using arbitrary 
queries.

```
$ id=$(bupstash put ./dir)
$ bupstash get id=$id | tar -xvf -
```

# Removing snapshots

We can remove snapshots via the same query language and the `bupstash rm` command.

```
$ bupstash rm older-than 90d and name=backup.tar and host=my-server
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
$ bupstash put --key ./put-backups.key ./data.txt
$ bupstash list --key ./metadata-backups.key
```

But these keys cannot decrypt the contents of the snapshots. Only the original primary key 
is able to these snapshots.

```
$ bupstash get --key ./put-backups.key id=$id 
bupstash get: provided key is not a decryption key

$ bupstash get --key ./metadata-backups.key id=$id
bupstash get: provided key is not a decryption key

$ bupstash get --key ./backups.key id=$id
data...
```

We can now put the primary key into secure offline storage for use in case of emergency,
but continue to make and administer our backups using the put key and metadata key.

The storage server, nor the devices uploading new snapshots 
have access to your existing snapshots.

Note that we recommend creating a new put key for every server in your network if you have a shared bupstash repository.


# Access controls

When designing a backup plan, we must remember that if ransomware or some other malicious agent compromises your computer,
it may be able to delete your backups too. 

To solve this issue bupstash supports access controls on remote backups that can be configured on a per ssh key basis.
We can utilize ssh force commands to restrict a backup client to only run an instance of `bupstash serve` that 
has a limited permissions.

The following guide assumes you have a backup server with a user called `backups` that has openssh sshd running,
and a client computer with an ssh client installed.

In an your sshd config file in your server add the following lines:

```
Match User backups
    ForceCommand "bupstash serve --allow-put /home/backups/bupstash-repository"
```

This means the backups user is only able to run the bupstash serve command with a hard coded set of permissions and repository
path.

Next add an ssh key to `$SERVER/home/backups/.ssh/authorized_keys` such that the a user can connect to the remote server
using ssh based login.

Now the client is only authorized to create new backups, but not list or remote them:
```
export BUPSTASH_REPOSITORY="ssh://backups@$SERVER/backups"
$ bupstash put ./files
...
$ bupstash list
server has disabled query and search for this client
```

The `bupstash serve` command also supports allowing fetching data, entry removal and garbage collection. With these
options we can create a backup plan where clients can create new backups, and an administrator is able to cycle old backups
while keeping the decryption key offline.

## More resources

All bupstash commands, protocols and file formats are fully documented in the user manuals here (TODO).

