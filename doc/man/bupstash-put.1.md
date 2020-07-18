bupstash-put(1) 
===============

## SYNOPSIS

Put a new entry into a bupstash repository.

`bupstash put [OPTIONS] TAG=VAL... [:: WHAT] `

## DESCRIPTION

`bupstash put` encrypts `WHAT`, then stores it in a bupstash repository
such that only the primary key can decrypt it.
`WHAT` can be a PATH to a file or directory, or a command to run if the `--exec`
flag is specified. For files, the data is saved directly, for directories, the data
is converted to a tar archive, and for commands the command is executed, and
stdout is saved.

All puts can associated with a set of arbitrary encrypted metadata tags, which
can be queried using bupstash-list(1). Tags are specified in a simple
`KEY=VALUE` format on the command line.

Data stored in a bupstash repository is automatically deduplicated
such that the same or similar snapshots do not take additional space.

## Put caching

When sending data, `bupstash` records what was sent in the previous
'put' operation in a file known as the put-cache. 

The put-cache serves two main purposes, the first
is that it remembers a set of data chunks that were previously sent to the repository,
allowing us to avoid resending those chunks over the network repeatedly. The second
purpose is to store a mapping of file paths, to a set of data chunk addresses,
allowing bupstash to skip processing files when snapshotting the same
directory many times repeatedly.

The path to the put-cache file, defaults to one of the following, in order, provided
the appropriate environment variables are set, `$BUPSTASH_PUTCACHE`,
`$XDG_CACHE_HOME/.cache/bupstash/putcache.sqlite3` or `$HOME/.cache/bupstash/putcache.sqlite3`.

## Default tags

When putting data, `bupstash` automatically sets a small set of default tags.

Currently they are:

- timestamp, set to utc time in the form 'YYYY:MM:DD HH:MM:SS'
- name, set to the file name, or .tar , or omitted for --exec mode.

Default tags can be overidden manually by simply specifying them.

## OPTIONS

* -r, --repository:
  The repository to connect to, may be prefixed with `ssh://$SERVER/$PATH` for
  remote repositories. If not specified, is set to `BUPSTASH_REPOSITORY`.

* -k, --key:
  Primary key or put-key to encrypt data and metadata with. If not set, defaults
  to `BUPSTASH_KEY`.

* -e, --exec:
  WHAT is a command to execute, where stdout is saved as an entry
  in the bupstash repository. Only create the entry if the command
  exited with a successful status code.

* --cache:
  Path to the put-cache file, defaults to one of the following, in order, provided
  the appropriate environment variables are set, `$BUPSTASH_PUTCACHE`,
  `$XDG_CACHE_HOME/.cache/bupstash/putcache.sqlite3` or `$HOME/.cache/bupstash/putcache.sqlite3`.

* --no-cache:
  Disable use of the put-cache, all data will be written over the network.

* --no-stat-caching:
  Disable the caching of file attributes to encrypted chunks. Only used
  when `WHAT` is a directory.

* --no-default-tags:
  Do no set default tags.

* --no-compression:
  Disable compression of data chunks, generally should only be used
  if the input data is uncompressible and you wish to increase throughput.

## ENVIRONMENT

* BUPSTASH_REPOSITORY:
  The repository to connect to, may be prefixed with `ssh://` for
  remote repositories (see examples).

* BUPSTASH_REPOSITORY_COMMAND:
  A command to run to connect to an instance of bupstash-serve(1). This 
  allows more complex connections to the repository for specialist cases,
  see examples below.

* BUPSTASH_KEY:
  Path to a primary key, or a put-key, that will be used to encrypt
  the data. Only the associated primary key will be able to decrypt
  the data once sent.

* BUPSTASH_KEY_COMMAND:
  A command to run that must print the key data, can be used instead of BUPSTASH_KEY
  to fetch the key from arbitrary locations such as the network or other secret storage.

* BUPSTASH_PUTCACHE:
  Path to the cache file to use.

## EXAMPLES

### Save a file to a repository over ssh

```
$ bupstash put -r "ssh://$SERVER/home/me/repo" :: ./data.file
```

### Snapshot a directory

The builtin directory put creates a tarball from a directory, while
deduplicating repeated files.

```
# Snapshot a directory.
$ bupstash put host=$(hostname) :: ./data

# Repeated snapshots reuse the put cache so are much faster.
$ ID=$(bupstash put host=$(hostname) :: ./data)

# Fetch the contents of a snapshot and list contents with tar -t
$ bupstash get id=$ID | tar -tf -
```
### Snapshot the output of a command

```
# Snapshot a postgres database with pgdump
$ bupstash put --exec name=dbdump.sql :: pgdump mydb
```

### Connecting to an ssh server with a specific ssh config.

```
$ export BUPSTASH_REPOSITORY_COMMAND="ssh -F ./my-ssh-config me@$SERVER bupstash serve"
$ bupstash put :: ./files
```

### Manually specifying the cache path

```
$ bupstash put --cache ~/backupjob.putcache :: /data
```

## TIPS

- The cache only stores information about the previous put operation, so 
  for each operation you expect to repeat periodically (such as backups), you can ensure
  good cache performance by specifying a cache for each operation 
  and dramatically reduce network and disk access and greatly speed up snapshots.

- `bupstash put` deduplicates and compresses data automatically, so avoid putting compressed
  or encrypted data if you want optimal deduplication and compression. 

- Combine `bupstash serve --allow-put` with ssh force commands to create restricted ssh keys that can
  only add new backups but not list or remove old ones.

- The differences between piping `tar` command output into `bupstash put`, and using `bupstash put` directly
  on a directory, is the latter is able to use a stat cache and also ensure files are more precisely deduplicated
  by storing each unique file in a single encrypted data chunk.

## SEE ALSO

bupstash(1), bupstash-keyfiles(7)
