bupstash-list-contents(1) 
=========================

## SYNOPSIS

List repositorn.

`bupstash list-contents [OPTIONS] QUERY... `

## DESCRIPTION

`bupstash list-contents` lists the contents of the item matching the given query.

Items created by using `bupstash put` on a directory will have an associated index, other items
are not listable.

## OUTPUT FORMATS

### Human

When `--format` is set to `human` Outputs aligned rows consisting of:

```
PERMS SIZE YYYY/MM/DD HH:MM:SS PATH...
```

The included date is the time of the last change to a given file as reported by the
operating system at the time of the snapshot.

### Jsonl

The output format consists of a series of json encoded liness. The output json object is not stable
yet so is not docuemented here.

## QUERY LANGUAGE

The bupstash query language is shared by many commands such as bupstash-get(1), bupstash-list(1) and bupstash-rm(1) and others.
For full documentation on the query language, see bupstash-query-language(7). 

## Query caching

The list-contents command uses the same query caching mechanisms as bupstash-list(1), check that page for
more information on the query cache.

## OPTIONS

* -r, --repository REPO:
  The repository to connect to, , may be of the form `ssh://$SERVER/$PATH` for
  remote repositories if ssh access is configured. If not specified, is set to `BUPSTASH_REPOSITORY`.

* -k, --key KEY:
  Primary key used to decrypt data and metadata. If not set, defaults
  to `BUPSTASH_KEY`.

* --format FORMAT:
  Set output format to one of the following 'human', 'jsonl'.

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
  Path to a primary key that will be used for decrypting data and metadata.

* BUPSTASH_KEY_COMMAND:
  A command to run that must print the key data, can be used instead of BUPSTASH_KEY
  to fetch the key from arbitrary locations such as the network or other secret storage.

* BUPSTASH_QUERY_CACHE:
  Path to the query cache file to use.


## EXAMPLES

### Get an item with a specific id from the repository

```
$ bupstash get id=14ebd2073b258b1f55c5bbc889c49db4 > ./data.file
```

### Get an item by name and timestamp from the repository

```
$ bupstash get name=backup.tar and timestamp=2020/19/* > ./restore.tar
```

### Get a tarball

The builtin directory put creates a tarball from a directory, so to extract 
it we use tar.

```
# Snapshot a directory.
$ id=$(bupstash put ./data)

$ mkdir restore
$ cd restore 

# Fetch the contents of a snapshot and extract the contents with tar
$ bupstash get id=$id | tar -xvf -
```

## SEE ALSO

bupstash(1), bupstash-put(1), bupstash-list(1), bupstash-rm(1), bupstash-keyfiles(7),
bupstash-query-language(7)
