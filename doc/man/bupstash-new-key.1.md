bupstash-new-key(1) 
===================

## SYNOPSIS

Generate a new bupstash key.

`bupstash new-key -o KEY`

## DESCRIPTION

`bupstash new-key` creates a new bupstash key capable of both
reading and writing repository entries.

The generated key will be marked readable only for the creating user.

Remember to keep your keys safe, as losing a key is the same as losing all
data stored using that key.

## OPTIONS

* -o, --output PATH:
  Path to where the new key will be written.

## EXAMPLES

### Create a new key
```
$ bupstash new-key -o ./backups.key
```

## SEE ALSO

bupstash(1), bupstash-keyfiles(7)
