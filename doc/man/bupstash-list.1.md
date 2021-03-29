bupstash-list(1) 
===============

## SYNOPSIS

List items in a bupstash repository.

`bupstash list [OPTIONS] QUERY... `

## DESCRIPTION

`bupstash list` fetches, decrypts and prints metadata of items stored
in the bupstash repository. It can be used for searching the database
with the bupstash query language. 

Only the metadata needs to be decrypted to list items, so a metadata key is sufficient
for item queries, even without access to the data decryption key.

## QUERY LANGUAGE

For full documentation on the query language, see bupstash-query-language(7).

### List query examples:

```
$ bupstash list name='*.tar'
...
$ bupstash list timestamp='2020*'
...
```

## SPECIAL TAGS

Bupstash automatically inserts special tags that can be viewed and queried against, they are outlined below.

### decryption-key-id

This special tag is inserted when the `--query-encrypted` option is used, it allows searching against the
key id that would be uesd for decrypting the given item. This tag is mostly useful for pruning
backups for which you do not have the decryption key.

### size

This tag is the size of the data stream and any index metadata associated with the snapshot. This
means the size may not exactly match the size of the data stream retrieved by bupstash-get(1) for the case
of snapshots.

### timestamp

The time the item was created formatted as `YYYY/MM/DD HH:MM:SS`.

## QUERY CACHING

Because all data is stored encrypted on the server, item metadata must first be synchronized to the local machine,
and then decrypted on the client side to run a query. The file containing the synced and encrypted metadata
is called the query cache.

The path to the query-cache file, defaults to one of the following, in order, provided
the appropriate environment variables are set, `$BUPSTASH_QUERY_CACHE`,
`$XDG_CACHE_HOME/.cache/bupstash/bupstash.qcache` or `$HOME/.cache/bupstash/bupstash.qcache`.

As a special case, a query that consists only of a fully specified id (e.g. `id=$FULL_ID`) will not require use 
of the query cache, instead the query can be passed directly to the server. This means
it is always more efficient to fully specify an id when running any command that expects a query.


## OUTPUT FORMATS

### Human

When `--format` is set to `human`, `bupstash list` outputs rows consisting of:

```
KEY=VALUE KEY=VALUE KEY=VALUE ....
```

Where each key and value corresponds to a tag that may be searched against.

### Jsonl

When `--format` is set to `jsonl`, `bupstash list` outputs one json object per line.
The output json object format is pending stabilization so is not documented.

## OPTIONS

* -r, --repository REPO:
  The repository to connect to may be of the form `ssh://$SERVER/$PATH` for
  remote repositories if ssh access is configured. If not specified, is set to `BUPSTASH_REPOSITORY`.

* -k, --key KEY:
  Primary key used to decrypt data and metadata. If not set, defaults
  to `BUPSTASH_KEY`.

* --query-encrypted:
  The query will not decrypt any metadata, allowing you to
  list items you do not have a decryption key for.
  This option inserts the pseudo query tag 'decryption-key-id'.
  
* --query-cache PATH:
  Path to the query-cache file, defaults to one of the following, in order, provided
  the appropriate environment variables are set, `$BUPSTASH_QUERY_CACHE`,
  `$XDG_CACHE_HOME/.cache/bupstash/bupstash.qcache` or `$HOME/.cache/bupstash/bupstash.qcache`.

* --format FORMAT:
  Set output format to one of the following 'human', 'jsonl'.

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

### List items matching a query

```
$ bupstash list name=backup.tar and timestamp=2020/07/* 
id="aa87fdbc72241f363568bbb888c0834e" name="backup.tar" size="106.34MB" timestamp="2020-07-24 15:25:00"
id="d271ec0b989cfc20e10d01380115747e" name="backup.tar" size="146.38MB" timestamp="2020-07-29 15:25:24"
...
```

## SEE ALSO

bupstash(1), bupstash-list-contents(1), bupstash-keyfiles(7), bupstash-query-language(7)
