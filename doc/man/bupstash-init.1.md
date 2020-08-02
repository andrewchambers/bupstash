bupstash-init(1) 
================

## SYNOPSIS

Initialize a bupstash repository.

`bupstash init [OPTIONS] REPOSITORY`

## DESCRIPTION

`bupstash init` initializes a repository at the path `REPOSITORY`.
If `REPOSITORY` already exists, the command fails.

For details about the contents of the package store after initialization, see bupstash-repository(7).


## OPTIONS

* --storage SPEC:
  Bupstash supports plugin and alternative storage plugins via a
  json storage specification. The default storage stores encrypted
  data blocks in a repository local data directory.

  See the storage specs section for supported specifications and examples.

## EXAMPLES

```
$ bupstash init ./my-repository
```

## STORAGE SPECS

Each storage specification consists of a type designator and a set
of type specific parameters.

### Dir storage

The "Dir" storage engine stores encrypted data in a directory relative
to the repository.

Parameters:

- dir_path: The path to the data directory

Example:

```
$ bupstash init --storage '{"Dir": {"dir_path":"./data"}'
```

### Sqlite3 storage

The "Sqlite3" storage engine stores encrypted data in an sqlite3 database relative
to the repository. This storage engine only supports a single writer at a time,
so generally the directory storage engine is a better choice.

Parameters:

- db_path: The path to the sqlite3.

Example:

```
$ bupstash init --storage '{"Sqlite3": {"db_path":"./data.sqlite3"}'
```

### External storage

Coming soon.

## SEE ALSO

bupstash(1), bupstash-repository(7)
