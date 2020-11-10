bupstash-put(1) 
===============

## SYNOPSIS

Put a new entry into a bupstash repository.

`bupstash put [OPTIONS] [TAG=VAL...] FILE`<br>
`bupstash put [OPTIONS] [TAG=VAL...] DIR`<br>
`bupstash put --exec [OPTIONS] [TAG=VAL...] COMMAND`<br>

## DESCRIPTION

`bupstash put` encrypts a file, directory, or command output and stores it in a bupstash repository
such that only the decryption key can decrypt it.

For files, the data is saved directly, for directories, the data
is converted to a tar archive, and for commands the command is executed, and
stdout is sent to the database.

Data stored in a bupstash repository is automatically deduplicated
such that the same or similar snapshots take minimal additional disk space.
For efficient incremental backups, use the --send-log option described in the usage notes section.

All puts can associated with a set of arbitrary encrypted metadata tags, which
can be queried using bupstash-list(1). Tags are specified in a simple
`KEY=VALUE` format on the command line. Valid tag keys *must* match the
regular expression `^([a-zA-Z0-9\\-_]+)=(.+)$`, that means tag keys must be alpha numeric 
with the addition of `-` and `_`. Tag processing ends at the first argument that does not match the pattern.

The special marker argument `::` may be used to force the end of tag parsing, but is usually not necessary.


## USAGE NOTES

### Incremental backups

When sending data, `bupstash` records metadata about what was sent in the previous
'put' operation in a file known as the send log. 

The send log serves two main purposes:

- it remembers the ids of data chunks that were sent to the repository in the last 'put',
  allowing `bupstash` to avoid resending those chunks over the network repeatedly.
- It stores a mapping of file paths, to data that has already been sent, allowing bupstash
  to skip processing files when snapshotting the same directory many times repeatedly.

The send log only remembers the data previously sent, so for efficient 'put' use, give each backup job
a unique send log file. As an example, if you have a backup script that saves a 
directory as a cron job, it is best to give that script its own send log so that all subsequent
runs with similar input data will share the same send log.

Example: 

```
$ bupstash put --send-log /root/bupstash-backups.sendlog /home/
# Second backup is incremental and fast because it uses the send log.
$ bupstash put --send-log /root/bupstash-backups.sendlog /home/
```

### Default tags

`bupstash` automatically sets default tags.

Currently they are:

- name, set to the `FILENAME`, or `DIRNAME.tar`, omitted when putting in --exec mode.

Default tags can be overidden manually by simply specifying them.


## OPTIONS

* -r, --repository REPO:
  The repository to connect to. May be of the form `ssh://$SERVER/$PATH` for
  remote repositories if ssh access is configured. If not specified, is set to `BUPSTASH_REPOSITORY`.

* -k, --key KEY:
  Primary key or put-key to encrypt data and metadata with. If not set, defaults
  to `BUPSTASH_KEY`.

* -e, --exec:
  WHAT is a command to execute, where stdout is saved as an entry
  in the bupstash repository. Only create the entry if the command
  exited with a successful status code.

* --exclude PATTERN:
  Add an exclusion glob pattern to filter entries from the resulting tarball.
  The glob is matched against the absolute path of the directory entry.
  This option may be passed multiple times, and is ignored if WHAT is not a directory.

* --send-log PATH:
  Path to the send log file, defaults to one of the following, in order, provided
  the appropriate environment variables are set, `$BUPSTASH_SEND_LOG`,
  `$XDG_CACHE_HOME/.cache/bupstash/bupstash.sendlog` or `$HOME/.cache/bupstash/bupstash.sendlog`.

* --no-send-log:
  Disable use of a send log, all data will be written over the network. Implies --no-stat-caching.

* --no-stat-caching:
  Disable the caching of file attributes to encrypted chunks. Only used
  when `WHAT` is a directory. 

* --no-default-tags:
  Do no set default tags.

* --no-compression:
  Disable compression of data chunks, generally should only be used
  if the input data is uncompressible and you wish to increase throughput.

* -q, --quiet:
  Suppress progress indicators (Progress indicators are also suppressed when stderr
  is not an interactive terminal).

## ENVIRONMENT

* BUPSTASH_REPOSITORY:
  The repository to connect to. May be of the form `ssh://$SERVER/$PATH` for
  remote repositories if ssh access is configured.

* BUPSTASH_REPOSITORY_COMMAND:
  A command to run to connect to an instance of bupstash-serve(1). This 
  allows more complex connections to the repository for less common use cases.

* BUPSTASH_KEY:
  Path to a primary key, or a put-key, that will be used to encrypt
  the data. Only the associated primary key will be able to decrypt
  the data once sent.

* BUPSTASH_KEY_COMMAND:
  A command to run that must print the key data, can be used instead of BUPSTASH_KEY
  to fetch the key from arbitrary locations such as the network or other secret storage.

* BUPSTASH_SEND_LOG:
  Path to the send log, overridden by --send-log. See the section 'Incremental backups'
  for a description of how to use send logging for efficient incremental uploads.

* BUPSTASH_CHECKPOINT_BYTES:
  When send logging is enabled bupstash will checkpoint the log every BUPSTASH_CHECKPOINT_BYTES
  of data that is sent. If an upload is interrupted after a successful checkpoint, data will not need
  to be resent over the network. The default value of this option is 1073741824, which is 1 GiB.

## EXAMPLES

### Save a file or directory to a repository over ssh

```
export BUPSTASH_KEY="/backups/backups-secret.key"
export BUPSTASH_REPOSITORY="ssh://$SERVER/home/me/bupstash-repository"

$ bupstash put ./data.file
$ bupstash put ./directory

```

### Snapshot a directory

The builtin directory put creates a tarball from a directory, while
deduplicating repeated files.

```
# Snapshot a directory.
$ ID="$(bupstash put ./data)"
# List snapshot contents.
$ bupstash list-contents id="$ID"
```

### Snapshot the output of a command

```
# Snapshot a postgres database with pgdump
$ bupstash put --exec name=dbdump.sql pgdump mydb
```

### Connecting to an ssh server with a specific ssh config.

```
$ export BUPSTASH_REPOSITORY_COMMAND="ssh -F ./my-ssh-config me@$SERVER bupstash serve /my/repo"
$ bupstash put ./files
```

## TIPS

- `bupstash put` deduplicates and compresses data automatically, so avoid putting compressed
  or encrypted data if you want optimal deduplication and compression. 

- Combine `bupstash serve --allow-put` with ssh force commands to create restricted ssh keys that can
  only add new backups but not list or remove old ones.

- The difference between piping `tar` command output into `bupstash put`, and using `bupstash put` directly
  on a directory, is the latter is able to use a send log and avoid reading files that has already
  been sent to the server, and is able to create a snapshot listing for use with bupstash-list-contents(1).

## SEE ALSO

bupstash(1), bupstash-keyfiles(7)
