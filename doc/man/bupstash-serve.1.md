bupstash-serve(1) 
================

## SYNOPSIS

Serve the bupstash protocol over stdin/stdout.

`bupstash serve [OPTIONS] REPOSITORY`

## DESCRIPTION

`bupstash serve` serves the bupstash protocol over stdin/stdout allowing
interaction with a repository. Most bupstash commands operate via an instance of bupstash serve.

The serve command has flags that can be set to restrict access permissions, by default
all access is permitted until the first --allow-* option is provided.

Typically users won't need to interact with `bupstash serve` unless they want
to create

## OPTIONS

* --allow-init:
  Allow the client to initialize new repositories.
* --allow-put:
  Allow client to put more entries into the repository.
* --allow-get:
  Allow client to list and retrieve data from the repository.
* --allow-remove:
  Allow client to list and remove repository entries.
* --allow-gc:
  Allow client to run the repository garbage collector.

## EXAMPLES


### Using BUPSTASH_REPOSITORY_COMMAND

```
$ export BUPSTASH_REPOSITORY_COMMAND="ssh $SERVER bupstash serve /data/repository"
$ bupstash list
```

### Setup SSH access controls

Create a 'backups' user on your server.

In an your sshd config file in your server add the line:

```
Match User backups
    ForceCommand "/bin/bupstash-put-force-command.sh"
```

Create /bin/bupstash-put-force-command.sh on your server:

```
$ echo 'exec bupstash serve --allow-put /home/backups/bupstash-backups' > bupstash-put-force-command.sh
$ sudo cp bupstash-put-force-command.sh /bin/bupstash-put-force-command.sh
$ sudo chown root:root /bin/bupstash-put-force-command.sh
$ sudo chmod +x /bin/bupstash-put-force-command.sh
```

Now any client with ssh access to the 'backups' user will only be able to add new backups to one repository:
```
export BUPSTASH_REPOSITORY="ssh://backups@$SERVER"
$ bupstash put ./data
d1659c3f56f744c7767fc57da003ee5d
$ bupstash list
server has disabled query and search for this client
```

Logging into the server via other means will have full access to the backups repository. Different 
permissions can be configured using similar concepts along side different ssh configurations and keys.

## SEE ALSO

bupstash(1), bupstash-repository(7)
