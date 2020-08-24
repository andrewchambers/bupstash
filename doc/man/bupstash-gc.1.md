bupstash-gc(1) 
==============

## SYNOPSIS

Run the garbage collector against a repository, removing
unreferenced data and freeing disk space.

`bupstash gc [OPTIONS]`

## DESCRIPTION

`bupstash gc` walks the repository contents attempting to find
unreachable data chunks and removing them, potentially reclaiming disk space.

When garbage collection is in process, get and put operations are paused for the
duration.

The garbage collector only relies on unencrypted metadata, so does not need
access to decryption keys to operate, and can thus be run on a storage server
without access to any keys.


## OPTIONS

* -r, --repository REPO:
  The repository to connect to and operate one.
  May be of the form `ssh://$SERVER/$PATH` for 
  remote repositories if ssh access is configured.
  If not specified, is set to `BUPSTASH_REPOSITORY`.
* -q, --quiet:
  Suppress progress bars (Progress bars are also suppressed when stderr is not a tty).

## ENVIRONMENT

* BUPSTASH_REPOSITORY:
  The repository to connect to. May be of the form `ssh://$SERVER/$PATH` for
  remote repositories if ssh access is configured.

* BUPSTASH_REPOSITORY_COMMAND:
  A command to run to connect to an instance of bupstash-serve(1). This 
  allows more complex connections to the repository for less common use cases.

## SEE ALSO

bupstash(1), bupstash-repository(7)
