bupstash-init(1) 
================

## SYNOPSIS

Initialize a bupstash repository.

`bupstash init [OPTIONS]`

## DESCRIPTION

`bupstash init` initializes a repository.
If `REPOSITORY` already exists, the command fails.

For details about the contents of the package store after initialization, see bupstash-repository(7).

## OPTIONS

* -r, --repository REPO:
  The repository to connect to. May be of the form `ssh://$SERVER/$PATH` for
  remote repositories if ssh access is configured. If not specified, is set to `BUPSTASH_REPOSITORY`.

* --storage SPEC:
  Accepts 'dir' or a json storage specification.
  The default storage is 'dir' and stores encrypted data blocks in a 
  repository local data directory.

  See the storage specs section for supported json specifications and examples.

## ENVIRONMENT

* BUPSTASH_REPOSITORY:
  The repository to connect to. May be of the form `ssh://$SERVER/$PATH` for
  remote repositories if ssh access is configured.

* BUPSTASH_REPOSITORY_COMMAND:
  A command to run to connect to an instance of bupstash-serve(1). This 
  allows more complex connections to the repository for less common use cases.

## EXAMPLES

```
$ export BUPSTASH_REPOSITORY=./my-repository
$ bupstash init

$ export BUPSTASH_REPOSITORY=ssh://$SERVER/home/backups/bupstash-backups
$ bupstash init
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
$ bupstash init --storage dir
```

### External storage

Coming soon.

## SEE ALSO

bupstash(1), bupstash-repository(7)
