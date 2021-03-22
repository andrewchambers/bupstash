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

Clients with permission to read data will still not be able to decrypt it unless they 
have the correct client side decryption key.

Typically users won't need to interact with `bupstash serve` unless they need
to create a custom connection via an arbitrary command or they wish to configure
via an ssh forced command access controls.

Note that many errors are printed out of band via stderr, so alternative transports should consider
how to also forward stderr data.

## OPTIONS

* --allow-init:
  Allow the client to initialize new repositories.
* --allow-put:
  Allow client to put more items into the repository.
* --allow-list:
  Allow client to retrieve metadata and snapshot indexes for search and listing.
* --allow-get:
  Allow client to retrieve data from the repository, implies --allow-list.
* --allow-remove:
  Allow client to remove repository items, implies --allow-list.
* --allow-gc:
  Allow client to run the repository garbage collector.

## EXAMPLES


### Custom ssh flags using BUPSTASH_REPOSITORY_COMMAND

```
$ export BUPSTASH_REPOSITORY_COMMAND="ssh -p 2020 $SERVER bupstash serve /data/repository"
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
$ export BUPSTASH_REPOSITORY="ssh://backups@$SERVER"
$ bupstash put ./data
d1659c3f56f744c7767fc57da003ee5d
$ bupstash list
server has disabled query and search for this client
```

Logging into the server via other means will have full access to the backups repository. Different 
permissions can be configured using similar concepts along side different ssh configurations and keys.

## SEE ALSO

bupstash(1), bupstash-repository(7)
