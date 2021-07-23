bupstash-sync(1) 
================

## SYNOPSIS

Efficiently checkout the contents of a snapshot into a local directory.

`bupstash checkout [OPTIONS] --into $PATH QUERY... `

## DESCRIPTION

`bupstash checkout` performs an efficient set of incremental changes to
a directory such that it becomes identical to the requested snapshot.
The incremental nature of `bupstash checkout` makes it well suited for
cycling between multiple similar snapshots. Note that this operation is dangerous
as it deletes extra files already present in the destination directory.

In order to aid file browsing as unprivileged users, `bupstash sync` does
not attempt to restore users, groups and xattrs by default. To set
these you must specify the flags --ownership and --xattrs respectively.

The item that is checked out is chosen based on a simple query against the 
tags specified when saving data with `bupstash put`.

## QUERY LANGUAGE

For full documentation on the query language, see bupstash-query-language(7).

## QUERY CACHING

The checkout command uses the same query caching mechanisms as bupstash-list(1), check that page for
more information on the query cache.

## OPTIONS

* --into PATH:
  Directory to checkout files into, defaults to $BUPSTASH_CHECKOUT_DIR.

* -r, --repository REPO:
  The repository to connect to, , may be of the form `ssh://$SERVER/$PATH` for
  remote repositories if ssh access is configured. If not specified, is set to `BUPSTASH_REPOSITORY`.

* -k, --key KEY:
  Key that will be used to decrypt data and metadata. If not set, defaults
  to `BUPSTASH_KEY`.

* --pick PATH:
  Pick a sub-directory of the snapshot to checkout..

* --ownership:
  Set uid's and gid's.

* --xattrs:
  Set xattrs.

* --query-cache PATH:
  Path to the query-cache file, defaults to one of the following, in order, provided
  the appropriate environment variables are set, `$BUPSTASH_QUERY_CACHE`,
  `$XDG_CACHE_HOME/.cache/bupstash/bupstash.qcache` or `$HOME/.cache/bupstash/bupstash.qcache`.

* -q, --quiet:
  Suppress progress indicators (Progress indicators are also suppressed when stderr
  is not an interactive terminal).

* --utc-timestamps:
  Display and search against timestamps in utc time instead of local time.

## ENVIRONMENT

* BUPSTASH_REPOSITORY:
  The repository to connect to. May be of the form `ssh://$SERVER/$PATH` for
  remote repositories if ssh access is configured.

* BUPSTASH_REPOSITORY_COMMAND:
  A command to run to connect to an instance of bupstash-serve(1). This 
  allows more complex connections to the repository for less common use cases.

* BUPSTASH_KEY:
  Path to the key that will be used for decrypting data and metadata.

* BUPSTASH_KEY_COMMAND:
  A command to run that must print the key data, can be used instead of BUPSTASH_KEY
  to fetch the key from arbitrary locations such as the network or other secret storage.

* BUPSTASH_QUERY_CACHE:
  Path to the query cache file to use.

* BUPSTASH_CHECKOUT_DIR:
  Path to checkout into.

## EXAMPLES

### Checkout a snapshot into a local directory

```
$ bupstash checkout --into ./dir id=ad8*
```

### Checkout including users and groups

```
$ bupstash checkout --ownership --into ./dir id=ad8*
```

### Checkout a sub directory of the snapshot

```
$ bupstash checkout --into ./dir --pick sub/dir id=ad8*
```

## SEE ALSO

bupstash(1), bupstash-get(1), bupstash-list(1), bupstash-keyfiles(7), bupstash-query-language(7)
