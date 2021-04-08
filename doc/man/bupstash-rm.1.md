bupstash-rm(1) 
==============

## SYNOPSIS

Remove items from a bupstash repository.

`bupstash rm [OPTIONS] QUERY... `

## DESCRIPTION

`bupstash rm` removes items from a bupstash repository.

Items that are removed are not immediately deleted, instead the deletion and 
space reclamation is scheduled for the next time the garbage collector bupstash-gc(1)
is run.

Only the metadata needs to be decrypted to remove items, so a metadata key is sufficient
for item deletion, even without access to the data decryption key.

## QUERY LANGUAGE

For full documentation on the query language, see bupstash-query-language(7).

### Remove query examples
```
$ id=$(bupstash put ./some-data)

$ bupstash rm id=$id

$ bupstash rm name=backups.tar

$ bupstash rm --allow-many name='*.tar' and older-than 30d

$ bupstash rm --allow-many id="*"
```

For full documentation on the query language, see bupstash-query-language(7). 

## QUERY CACHING

The rm command uses the same query caching mechanisms as bupstash-list(1), check that page for
more information on the query cache.

## OPTIONS

* -r, --repository REPO:
  The repository to connect to. May be of the form `ssh://$SERVER/$PATH` for
  remote repositories if ssh access is configured. If not specified, is set to `BUPSTASH_REPOSITORY`.

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
  Remove items with IDs read from stdin, one per line, instead of executing a query.

* --allow-many:
  By default bupstash refuses to remove multiple items from a single query, this flag
  disables that safety feature.

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

### remove an item with a specific id from the repository

```
$ bupstash rm id=14ebd2073b258b1f55c5bbc889c49db4 
```

### remove all items from the respository

```
$ bupstash rm id="*" 
```

### remove items with name backup.tar that are older than 30 days

```
$ bupstash rm name=backup.tar and older-than 30d
```

### remove items with a custom script

```
 $ bupstash list --format=jsonl1 \
    | custom-json-filter \
    | bupstash rm --ids-from-stdin
```

## SEE ALSO

bupstash(1), bupstash-list(1),  bupstash-gc(1),  bupstash-query-language(7)
