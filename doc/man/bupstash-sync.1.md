bupstash-sync(1) 
================

## SYNOPSIS

Sync items and data from one bupstash repository to another.

`bupstash sync [OPTIONS] --to $REMOTE [QUERY...]`

## DESCRIPTION

`bupstash sync` copies items and data from one repository to another while
attempting to minimize unnecessary bandwidth usage.

A typical use of this command is to backup files to a local repository (e.g. and external drive) while also efficiently
uploading them to an offsite location for safe storage.

Note that when no query is specified all items are synced, even those that do not match the current bupstash key.


## QUERY LANGUAGE

For full documentation on the query language, see bupstash-query-language(7).

## QUERY CACHING

The sync command uses the same query caching mechanisms as bupstash-list(1), check that page for
more information on the query cache.

## OPTIONS

* -r, --repository REPO:
  The repository to sync from. May be of the form `ssh://$SERVER/$PATH` for
  remote repositories if ssh access is configured. If not specified, is set to `BUPSTASH_REPOSITORY`.

* --to REPO:
  The destination repository to sync items to. May be of the form `ssh://$SERVER/$PATH` for
  remote repositories if ssh access is configured. If not specified, is set to `BUPSTASH_TO_REPOSITORY`.

* -k, --key KEY:
  Key used to decrypt metadata when executing a query. If not set, defaults
  to `BUPSTASH_KEY`.

* --query-cache PATH:
  Path to the query-cache file, defaults to one of the following, in order, provided
  the appropriate environment variables are set, `$BUPSTASH_QUERY_CACHE`,
  `$XDG_CACHE_HOME/.cache/bupstash/bupstash.qcache` or `$HOME/.cache/bupstash/bupstash.qcache`.

* --query-encrypted:
  The query will not decrypt any metadata, allowing you to
  list items you do not have a decryption key for.
  This option inserts the pseudo query tag 'decryption-key-id'.

* --ids-from-stdin:
  Sync items with IDs read from stdin, one per line, instead of executing a query.

* --utc-timestamps:
  Display and search against timestamps in utc time instead of local time.

* --no-progress:
  Suppress progress indicators (Progress indicators are also suppressed when stderr
  is not an interactive terminal).

* -q, --quiet:
  Be quiet, implies --no-progress.

## ENVIRONMENT

* BUPSTASH_REPOSITORY:
  The repository to pull items from. May be of the form `ssh://$SERVER/$PATH` for
  remote repositories if ssh access is configured.

* BUPSTASH_REPOSITORY_COMMAND:
  A command to run to connect to an instance of bupstash-serve(1). This 
  allows more complex connections to the repository for less common use cases.

* BUPSTASH_TO_REPOSITORY:
  The repository to sync items to. May be of the form `ssh://$SERVER/$PATH` for
  remote repositories if ssh access is configured.

* BUPSTASH_TO_REPOSITORY_COMMAND:
  A command to run to connect to an instance of bupstash-serve(1). This 
  allows more complex connections to the repository for less common use cases.

* BUPSTASH_KEY:
  Path to a primary key that will be used for decrypting data and metadata.

* BUPSTASH_KEY_COMMAND:
  A command to run that must print the key data, can be used instead of BUPSTASH_KEY
  to fetch the key from arbitrary locations such as the network or other secret storage.

* BUPSTASH_QUERY_CACHE:
  Path to the query cache file to use.

## EXAMPLES

### Push all items from a local repository to a remote repository

```
$ bupstash sync --repository ./local-repository --to ssh://$REMOTE
```

### Perform a backup locally then sync a copy to a remote repository

```
$ export BUPSTASH_REPOSITORY=./local-repository
$ id="$(bupstash put ./some-files)"
$ bupstash sync --to ssh://$REMOTE id="$id"
```

## SEE ALSO

bupstash(1), bupstash-query-language(7)
