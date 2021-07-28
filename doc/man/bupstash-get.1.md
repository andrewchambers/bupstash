bupstash-get(1) 
===============

## SYNOPSIS

Get data from a bupstash repository.

`bupstash get [OPTIONS] QUERY... `

## DESCRIPTION

`bupstash get` fetches and decrypts data stored in a bupstash repository, sending
it to stdout.

The item that is fetched is chosen based on a simple query against the 
tags specified when saving data with `bupstash put`.

## QUERY LANGUAGE

For full documentation on the query language, see bupstash-query-language(7).

## QUERY CACHING

The get command uses the same query caching mechanisms as bupstash-list(1), check that page for
more information on the query cache.

## OPTIONS

* -r, --repository REPO:
  The repository to connect to, , may be of the form `ssh://$SERVER/$PATH` for
  remote repositories if ssh access is configured. If not specified, is set to `BUPSTASH_REPOSITORY`.

* -k, --key KEY:
  Key that will be used to decrypt data and metadata. If not set, defaults
  to `BUPSTASH_KEY`.

* --pick PATH:
  Fetch an individual file or sub-directory from a snapshot.

* --query-cache PATH:
  Path to the query-cache file, defaults to one of the following, in order, provided
  the appropriate environment variables are set, `$BUPSTASH_QUERY_CACHE`,
  `$XDG_CACHE_HOME/.cache/bupstash/bupstash.qcache` or `$HOME/.cache/bupstash/bupstash.qcache`.

* --utc-timestamps:
  Display and search against timestamps in utc time instead of local time.

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

* BUPSTASH_KEY:
  Path to the key that will be used for decrypting data and metadata.

* BUPSTASH_KEY_COMMAND:
  A command to run that must print the key data, can be used instead of BUPSTASH_KEY
  to fetch the key from arbitrary locations such as the network or other secret storage.

* BUPSTASH_QUERY_CACHE:
  Path to the query cache file to use.


## EXAMPLES

### Get an item with a specific id 

```
$ bupstash get id=14ebd2073b258b1f55c5bbc889c49db4 > ./data.file
```

### Get an item by name and timestamp

```
$ bupstash get name=backup.tar and timestamp=2020/19/* > ./restore.tar
```

### Get a file or sub-tar from a directory snapshot

```
$ bupstash get --pick=path/to/file.txt id=$id
$ bupstash get --pick=path/to/dir id=$id | tar ...
```

### Get a tarball

The builtin directory put creates a tarball from a directory, so to extract 
it we use tar.

```
# Snapshot a directory.
$ id=$(bupstash put ./data)

# Fetch the contents of a snapshot and extract the contents with tar
$ mkdir restore
$ bupstash get id=$id | tar -C ./restore -xvf -
```

## SEE ALSO

bupstash(1), bupstash-put(1), bupstash-list(1), bupstash-restore(1), bupstash-rm(1), bupstash-keyfiles(7),
bupstash-query-language(7)
