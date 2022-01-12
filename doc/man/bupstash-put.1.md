bupstash-put(1) 
===============

## SYNOPSIS

Put data into a bupstash repository.

`bupstash put [OPTIONS] [TAG=VAL...] FILE`<br>
`bupstash put [OPTIONS] [TAG=VAL...] DIRS...`<br>
`bupstash put --exec [OPTIONS] [TAG=VAL...] COMMAND`<br>

## DESCRIPTION

`bupstash put` encrypts a file, directory, or command output and stores it in a bupstash repository
such that only the decryption key can decrypt it.

For files, the data is saved directly, for directories, the data
is converted to a tar archive containing each of the specified directories,
and for commands the command is executed, and stdout is sent to the database.

Data stored in a bupstash repository is automatically deduplicated
such that the same or similar snapshots take minimal additional disk space.
For efficient incremental backups, use the --send-log option described in the usage notes section.

All puts can associated with a set of arbitrary encrypted metadata tags, which
can be queried using bupstash-list(1). Tags are specified in a simple
`KEY=VALUE` format on the command line. Valid tag keys *must* match the
regular expression `^([a-zA-Z0-9\\-_]+)=(.+)$`, that means tag keys must be alpha numeric 
with the addition of `-` and `_`. Tag processing ends at the first argument that does not match the pattern.

The special marker argument `::` may be used to force the end of tag parsing, but is usually not necessary.

Note that multiple concurrent uploads to the same repository are safe and supported provided that all clients
are accessing the repository from the same server and thus respect the repository file locks.
Some network filesystems (like NFS and sshfs) do not always respect remote file locks and are therefore not supported.
Always prefer connecting to a remote repository via an `ssh://` style url or an instance of `bupstash serve`.

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

### Concurrent filesystem modification

Bupstash supports uploading a filesystem that is concurrently being modified with
the caveat that bupstash cannot guarantee the filesystem is in a consistent state. If bupstash
is reading a file or directory while it is concurrently being modified by an application, it may
be the case the bupstash snapshot contains data from multiple points in time with the combination potentially being invalid and/or corrupt.

The only sure way to ensure data consistency is to use in a filesystem with snapshot capabilities.
Using filesystem snapshots you can create a consistent filesystem view and then perform a bupstash 
backup on that snapshot. On linux some options for performing consistent
snapshots include ZFS, BTRFS and also LVM snapshots 

Another choice is to perform a put operation at a time when the files are less likely to be modified,
this will provide backups that are good enough for many people without extra complications.

### Default tags

`bupstash` automatically sets default tags.

Currently they are:

- name, set to the `FILENAME`, or `DIRNAME.tar`, omitted when putting in --exec mode.

Default tags can be overidden manually by simply specifying them.

### Reserved tags

The following tags are reserved and cannot be set manually:

- id
- decryption-key-id
- size
- timestamp

### File actions

`bupstash put` will print a line to stderr for each directory entry
processed when the --print-file-actions option is set.

Each output line has the form:

```
$action $type $PATH
```

With possible actions:

- `+` A file was added to the snapshot.
- `~` A stat cache hit let us skip sending a file.
- `x` A path was excluded from the snapshot due to an exclusion rule.

With possible types:

- `f` file
- `l` symlink
- `c` char device
- `b` block device
- `d` directory
- `p` fifo

### TIPS

- `bupstash put` deduplicates and compresses data automatically, so avoid putting compressed
  or encrypted data if you want optimal deduplication and compression. 

- Combine `bupstash serve --allow-put` with ssh force commands to create restricted ssh keys that can
  only add new backups but not list or remove old ones.

- The difference between piping `tar` command output into `bupstash put`, and using `bupstash put` directly
  on a directory, is the latter is able to use a send log and avoid reading files that has already
  been sent to the server, and is able to create a snapshot listing for other commands like bupstash-list-contents(1).

## OPTIONS

* -r, --repository REPO:
  The repository to connect to. May be of the form `ssh://$SERVER/$PATH` for
  remote repositories if ssh access is configured. If not specified, is set to `BUPSTASH_REPOSITORY`.

* -k, --key KEY:
  Key used to encrypt data and metadata. If not set, defaults
  to `BUPSTASH_KEY`.

* -e, --exec:
  COMMAND is a command to execute, where stdout is saved as an entry
  in the bupstash repository. Only create the entry if the command
  exited with a successful status code.

* --exclude PATTERN:
  Add an exclusion glob pattern to filter entries from the resulting tarball.
  This option may be passed multiple times, and is ignored if not
  uploading a directory snapshot.
  The glob is matched against the absolute path of the directory entry.
  It thus must start with a `/` and not end on one. It must also be normalized.
  Globs without a leading slash are matched against file names in each directory.
  Usual globbing rules apply: `*` matches everything on a level, `**` matches any
  number of levels, `?` matches a single character, `[…]` matches a single character from
  a given character set (and can also be used to escape the other special characters: `[?]`).

* --send-log PATH:
  Path to the send log file, defaults to one of the following, in order, provided
  the appropriate environment variables are set, `$BUPSTASH_SEND_LOG`,
  `$XDG_CACHE_HOME/.cache/bupstash/bupstash.sendlog` or `$HOME/.cache/bupstash/bupstash.sendlog`.

* --no-send-log:
  Disable use of a send log, all data will be written over the network. Implies --no-stat-caching.

* --no-stat-caching:
  Do not use stat caching to skip sending files to the repository.

* --no-default-tags:
  Do no set default tags.

* --compression ALGO:
  Compression algorithm, one of 'none', 'lz4' or 'zstd[:$level]'.
  Defaults to 'zstd:3'.

* --one-file-system:
  Do not traverse mount points in the file system.

* --xattrs:
  Save directory entry xattrs, only used when saving a directory.

* --print-file-actions:
  Print file actions in the form '$a $t $path' to stderr when processing directories, the section 'File Actions' for details.

* --print-stats:
  Print put statistics to stderr on completion.

* --no-progress:
  Suppress progress indicators (Progress indicators are also suppressed when stderr
  is not an interactive terminal).

* -q, --quiet:
  Be quiet, implies --no-progress.

* -v, --verbose:
  Be verbose, implies --print-file-actions and --print-stats.

## ENVIRONMENT

* BUPSTASH_REPOSITORY:
  The repository to connect to. May be of the form `ssh://$SERVER/$PATH` for
  remote repositories if ssh access is configured.

* BUPSTASH_REPOSITORY_COMMAND:
  A command to run to connect to an instance of bupstash-serve(1). This 
  allows more complex connections to the repository for less common use cases.

* BUPSTASH_KEY:
  Path to the key that will be used to encrypt
  the data. Only the associated primary key will be able to decrypt
  the data once sent.

* BUPSTASH_KEY_COMMAND:
  A command to run that must print the key data, can be used instead of BUPSTASH_KEY
  to fetch the key from arbitrary locations such as the network or other secret storage.

* BUPSTASH_SEND_LOG:
  Path to the send log, overridden by --send-log. See the section 'Incremental backups'
  for a description of how to use send logging for efficient incremental uploads.

* BUPSTASH_CHECKPOINT_BYTES:
  When send logging is enabled, bupstash will checkpoint the log every BUPSTASH_CHECKPOINT_BYTES
  of data that is sent. If an upload is interrupted after a successful checkpoint, data will not need
  to be resent over the network. The default value of this option is 21474836480, which is 20 GiB.

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

## SEE ALSO

bupstash(1), bupstash-keyfiles(7)
