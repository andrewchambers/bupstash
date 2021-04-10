# Network Filesystems

Currently we do not recommend using bupstash where the repository is mounted on a network filesystem. This is
because that we cannot guarantee the file locking semantics of the network filesystem is suitable for use with
bupstash and the bupstash sqlite3 metadata database.

When using a remote repository it is always recommended to use bupstash over ssh by setting BUPSTASH_REPOSITORY to an `ssh://`
style URL. This mode is optimized such that it avoids network round trips as much as possible, performs better 
and also enables the use of repository access controls.

For information on specific unsupported network filesystem configurations see the sections below.

## NFSv3

Currently we do no recommend using bupstash over NFSv3 in any configuration. This may change
with future releases.

## NFSv4

Currently we do no recommend using bupstash over NFSv4 in any configuration. This may change
with future releases.

## CephFS

Currently we do no recommend using bupstash over CephFS in any configuration. This may change
with future releases.

## SSHFS

Currently we do no recommend using bupstash over sshfs in any configuration.

This is especially true because if you have sshfs access, you almost certainly have the ability to set BUPSTASH_REPOSITORY
to an `ssh://` style url which enables safe concurrent repository access in all situations.

## 9P2000.L

9P2000.L mounts are not supported but may work with caching disabled and after disabling sqlite3 WAL mode. 

To disable the repository sqlite3 WAL mode run the command `sqlite3 /path/to/repository/bupstash.sqlite3 'PRAGMA journal_mode = DELETE;'`.
