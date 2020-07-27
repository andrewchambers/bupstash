bupstash-list(1) 
===============

## SYNOPSIS

List entries in a bupstash repository

`bupstash list [OPTIONS] QUERY... `

## DESCRIPTION

`bupstash list` fetches, decrypts and prints metadata of items stored
in the bupstash repository. It can be used for searching the database
with the bupstash query language. 

Only the metadata needs to be decrypted to list items, so a metadata key is sufficient
for item queries, even without access to the data decryption key.


## QUERY LANGUAGE

The bupstash query language is shared by commands such as bupstash-get(1), bupstash-list(1) and bupstash-rm(1).
For full documentation on the query language, see bupstash-query-language(7).

### List query examples:

```
$ bupstash list name=*.tar
...
$ bupstash list timestamp=2020/*
...
```

## Query caching

Because all data is stored encrypted on the server, item metadata must first be synchronized to the local machine,
and then decrypted on the client side to run a query. The file containing the synced and encrypted metadata
is called the query cache.

The path to the put-cache file, defaults to one of the following, in order, provided
the appropriate environment variables are set, `$BUPSTASH_SEND_LOG`,
`$XDG_CACHE_HOME/.cache/bupstash/query-cache.sqlite3` or `$HOME/.cache/bupstash/query-cache.sqlite3`.

## OPTIONS

* -r, --repository REPO:
  The repository to connect to may be of the form `ssh://$SERVER/$PATH` for
  remote repositories if ssh access is configured. If not specified, is set to `BUPSTASH_REPOSITORY`.

* -k, --key KEY:
  Primary key used to decrypt data and metadata. If not set, defaults
  to `BUPSTASH_KEY`.

* --query-cache PATH:
  Path to the query-cache file, defaults to one of the following, in order, provided
  the appropriate environment variables are set, `$BUPSTASH_QUERY_CACHE`,
  `$XDG_CACHE_HOME/.cache/bupstash/query-cache.sqlite3` or `$HOME/.cache/bupstash/query-cache.sqlite3`.

* --format FORMAT:
  Set output format to one of the following 'human', 'jsonl'.

## ENVIRONMENT

* BUPSTASH_REPOSITORY:
  The repository to connect to, may be of the form `ssh://$SERVER/$PATH` for
  remote repositories if ssh access is configured.

* BUPSTASH_REPOSITORY_COMMAND:
  A command to run to connect to an instance of bupstash-serve(1). This 
  allows more complex connections to the repository for specialist cases,

* BUPSTASH_KEY:
  Path to a primary key that will be used for decrypting data and metadata.

* BUPSTASH_KEY_COMMAND:
  A command to run that must print the key data, can be used instead of BUPSTASH_KEY
  to fetch the key from arbitrary locations such as the network or other secret storage.

* BUPSTASH_QUERY_CACHE:
  Path to the query cache file to use.


## EXAMPLES

### Get an item by name and date date from the repository

```
$ bupstash list name=backup.tar and date=2020/19/* > ./restore.tar
XXX
```

### List the repository contents as json, one entry per line

```
$ bupstash list --format=jsonl
XXX
```

## SEE ALSO

bupstash(1),bupstash-query-language(7)