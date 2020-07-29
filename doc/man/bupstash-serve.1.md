bupstash-serve(1) 
================

## SYNOPSIS

Serve the bupstash protocol over stdin/stdout.

`bupstash serve [OPTIONS] REPOSITORY`

## DESCRIPTION

`bupstash serve` serves the bupstash protocol over stdin/stdout allowing
interaction with a repository. Most bupstash commands operate via an instance of bupstash serve.

The serve command has flags that can be set to restrict access permissions, by default
all access is permitted.

Typically users won't need to interact with `bupstash serve` unless they want
to create

## OPTIONS

* --allow-put:
  Allow client to put more entries into the repository.
* --allow-remove:
  Allow client to remove repository entries.
* --allow-gc:
  Allow client to run the repository garbage collector.
* --allow-get:
  Allow client to get data from the repository.
* --allow-list:
  Allow client to list repository entries.


## EXAMPLES

Using BUPSTASH_REPOSITORY_COMMAND:

```
$ export BUPSTASH_REPOSITORY_COMMAND="ssh $SERVER bupstash serve /data/repository"
$ bupstash list
```

Using ssh force commands:

In an your sshd config file in your server...
```
Match User backups
    ForceCommand "bupstash server --allow-put /backups"
```

Now the client is only authorized to create new backups:
```
export BUPSTASH_REPOSITORY="ssh://backups@$SERVER/backups"
$ bupstash list
server has disabled query and search for this client
```


## SEE ALSO

bupstash(1), bupstash-repository(7)
