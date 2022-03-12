bupstash-exec-with-locks(1)
===========================

## SYNOPSIS

Execute a command with exclusive locks on the repository.

`bupstash init -r REPO COMMAND...`

## DESCRIPTION

`bupstash exec-with-locks` executes a command with exclusive locks held on
the bupstash repository, preventing concurrent modification to the repository 
for the duration of the command.

## OPTIONS

* -r, --repository REPO:
  Repository to lock. Defaults to BUPSTASH_REPOSITORY if not set.
  Unlike other commands, does not support remote repository access.

## ENVIRONMENT

* BUPSTASH_REPOSITORY:
  Repository to lock.

## EXAMPLES

```
$ bupstash exec-with-locks -r ./repo -- cp -r ./repo ./repo-backup
```

## SEE ALSO

bupstash(1), bupstash-repository(7)
