bupstash-recover-removed(1) 
==============

## SYNOPSIS

Recover repository items that were removed, but that have not
yet been deleted via garbage collection.

`bupstash recover-removed [OPTIONS]`

## DESCRIPTION

`bupstash recover-removed` allows a user to undo all 'rm' operations that
have taken place since the last invocation of bupstash-gc(1).
In other words, this command provides a way to correct errors and accidental
invocations of bupstash-rm(1).

`bupstash recover-removed` requires 'put' and 'get' permissions for the repository being operated on.

## OPTIONS

* -r, --repository REPO:
  The repository to connect to and operate on.
  May be of the form `ssh://$SERVER/$PATH` for 
  remote repositories if ssh access is configured.
  If not specified, is set to `BUPSTASH_REPOSITORY`.

* --no-progress:
  Suppress progress indicators (Progress indicators are also suppressed when stderr
  is not an interactive terminal).

* -q, --quiet:
  Be quiet, implies --no-progress.

## ENVIRONMENT

* BUPSTASH_REPOSITORY:
  The repository to connect to. May be of the form `ssh://$SERVER/$PATH` for
  remote repositories if ssh access is configured.

* BUPSTASH_REPOSITORY_COMMAND:
  A command to run to connect to an instance of bupstash-serve(1). This 
  allows more complex connections to the repository for less common use cases.

## SEE ALSO

bupstash(1), bupstash-rm(1), bupstash-gc(1)
