bupstash-put(1) 
===============

## SYNOPSIS

Get data from a bupstash repository.

`bupstash get [OPTIONS] QUERY... `

## DESCRIPTION

`bupstash get` fetches and decrypts data stored in a bupstash repository. The
item that is fetched is chosen based on a simple query against the 
tags specified when saving data with `bupstash put`.

## Query language

The bupstash query language is shared by commands such as bupstash-get(1), bupstash-list(1) and bupstash-rm(1).

Get examples:
```
$ id=$(bupstash put  :: ./some-data)

# Get an item by id.
$ bupstash get id=$id

# If you are feeling lazy, get using globbing.
$ bupstash get id=ab834*

# When a query only returns a single item, we can use that.
$ bupstash get name=backups.tar and date=2020/14
```

For full documentation on the query language, see bupstash-query-language(7). 

## Query caching

Because all data is stored encrypted on the server, item metadata must first be synchronized to the local machine,
and then decrypted on the client side to run a query. The file containing the synced and encrypted metadata
is called the query cache.

The path to the put-cache file, defaults to one of the following, in order, provided
the appropriate environment variables are set, `$BUPSTASH_SEND_LOG`,
`$XDG_CACHE_HOME/.cache/bupstash/query-cache.sqlite3` or `$HOME/.cache/bupstash/query-cache.sqlite3`.

## OPTIONS

* -r, --repository REPO:
  The repository to connect to, may be prefixed with `ssh://$SERVER/$PATH` for
  remote repositories. If not specified, is set to `BUPSTASH_REPOSITORY`.

* -k, --key KEY:
  Primary key decrypt data and metadata with. If not set, defaults
  to `BUPSTASH_KEY`.

* --query-cache PATH:
  Path to the query-cache file, defaults to one of the following, in order, provided
  the appropriate environment variables are set, `$BUPSTASH_QUERY_CACHE`,
  `$XDG_CACHE_HOME/.cache/bupstash/query-cache.sqlite3` or `$HOME/.cache/bupstash/query-cache.sqlite3`.

## ENVIRONMENT

* BUPSTASH_REPOSITORY:
  The repository to connect to, may be prefixed with `ssh://` for
  remote repositories (see examples).

* BUPSTASH_REPOSITORY_COMMAND:
  A command to run to connect to an instance of bupstash-serve(1). This 
  allows more complex connections to the repository for specialist cases,

* BUPSTASH_KEY:
  Path to a primary key that will be used for decrypting data and metadata.

* BUPSTASH_KEY_COMMAND:
  A command to run that must print the key data, can be used instead of BUPSTASH_KEY
  to fetch the key from arbitrary locations such as the network or other secret storage.

* BUPSTASH_PUT_CACHE:
  Path to the cache file to use.

## EXAMPLES

### Get an item with a specific id from the repository

```
$ bupstash get id=14ebd2073b258b1f55c5bbc889c49db4 > ./data.file
```

### Get an item by name and date date from the repository

```
$ bupstash get name=backup.tar and date=2020/19/* > ./restore.tar
```

### Get a tarball

The builtin directory put creates a tarball from a directory, so to extract 
it we use tar.

```
# Snapshot a directory.
$ id=$(bupstash put :: ./data)

# Fetch the contents of a snapshot and extract the contents with tar -t
$ mkdir restore
$ cd restore 

# e(x)tract the (f)ile from stdin (v)erbosely.
$ bupstash get id=$id | tar -xvf -
```

## SEE ALSO

bupstash(1), bupstash-put(1), bupstash-list(1), bupstash-rm(1), bupstash-keyfiles(7),
bupstash-query-language(7)
