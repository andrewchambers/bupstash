bupstash-diff(1) 
================

## SYNOPSIS

Diff two snapshots printing the summary to stdout.

`bupstash diff [OPTIONS] QUERY1... :: QUERY2... `

## DESCRIPTION

`bupstash diff` fetches two snapshot listings from the remote server and compares them, printing
the diff line output to stdout. 

`bupstash diff` is preferred over running traditional `diff` against the output of `bupstash list-contents`
because it takes the full precision of timestamps and also the stored file hash into account when performing
the diff operation.

Bupstash supports ignoring items in the diff comparison to aid in analysis. Most useful are the `--ignore` values
`times` to ignore file modification timestamps and `content` to ignore file size and hash changes.

## OUTPUT FORMAT

Output is consistent with that of `bupstash list-contents`, except each line is
prefixed with either `+` or `-` representing removed or added items respectively.

Specifying `--format` alters the underlying output format as described by bupstash-list-contents(1). Lines are still prefixed with either `+` or `-` regardless of the output format.

## QUERY LANGUAGE

For full documentation on the query language, see bupstash-query-language(7).

## QUERY CACHING

The diff command uses the same query caching mechanisms as bupstash-list(1), check that page for
more information on the query cache.

## OPTIONS

* -r, --repository REPO:
  The repository to connect to, , may be of the form `ssh://$SERVER/$PATH` for
  remote repositories if ssh access is configured. If not specified, is set to `BUPSTASH_REPOSITORY`.

* -k, --key KEY:
  Key used to decrypt data and metadata. If not set, defaults
  to `BUPSTASH_KEY`.

* --query-cache PATH:
  Path to the query-cache file, defaults to one of the following, in order, provided
  the appropriate environment variables are set, `$BUPSTASH_QUERY_CACHE`,
  `$XDG_CACHE_HOME/.cache/bupstash/bupstash.qcache` or `$HOME/.cache/bupstash/bupstash.qcache`.

* -i, --ignore:
  Comma separated list of file attributes to ignore in comparisons.
  Valid items are 'content,times,mode'

* --format FORMAT:
  Set output format to one of the following 'human', 'jsonl'.

* --utc-timestamps:
  Display and search against timestamps in utc time instead of local time.

* -q, --quiet:
  Suppress progress indicators (Progress indicators are also suppressed when stderr
  is not an interactive terminal).

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

### Compare two snapshots by query

```
$ bupstash diff id="14eb*" :: id="57de"
- -rw-r--r-- 1.1kB hello.txt
+ -rw-r--r-- 1.3kB goodbye.txt
```

## SEE ALSO

bupstash(1), bupstash-list(1), bupstash-keyfiles(7), bupstash-query-language(7)
