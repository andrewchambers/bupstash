# Filesystem Backups

This guide will cover how to use bupstash for system backups, it is divided into
sections which cover different use cases.

For all of the guides the shown commands can be put into a cron job or other tool for running background tasks
for automated backups.

The guides below can also be combined with remote repositories with access controls to allow 'upload only' for secure deployments.

## Simple directory snapshots

The simplest use of bupstash is to simply snapshot your home directory to a repository on an external drive.

Create the file backup.sh:

```
set -eu
export BUPSTASH_KEY=/root/backup-put.key
export BUPSTASH_REPOSITORY=/mnt/external-drive/bupstash-backups

bupstash put \
   --send-log /root/backup.sendlog \
   --exclude "/home/*/.cache" \
   hostname=$(hostname) \
   name=home-backup.tar \
   /home/
```

Then running a backup is as simple as:

```
$ sudo sh ./backup.sh
```

Now to restore files or sub directories we can use `bupstash get`:

```
$ bupstash list name=home-backup.tar
...
id="aa87fdbc72241f363568bbb888c0834e" name="backup.tar" timestamp="2020-07-24 15:25:00"
...
$ bupstash get id="aa8*" | tar -C restore ...
$ bupstash get --pick some/sub-dir id="aa8*" | tar -C restore ...
$ bupstash get --pick some/file.txt id="aa8*" > file.txt
```

Some points to consider about this snapshot method:

- The use of --exclude to omit the user cache directories, we can save a lot of space in backups by ignoring things
  like out web browser cache, at the expense of less complete backups. You can specify --exclude more than once to
  skip more than one directory or file. See the man page for more details.

- Bupstash incremental backups work best when the send log file used was last used for a snapshot of the same or similar input data.
  Manually specifying a send log path with --send-log ensures subsequent similar snapshots use the same send log, often dramatically increasing efficiency.

- This method of backup is simple, but does not account for files being modified during upload. The simplest way to to think about this problem, is files will be changing while 
  the backup is uploading, so you might capture different directories at different points in time.

- In this command we are also using a 'put' key (see the offline keys guide) so that backups cannot be decrypted even if someone was to steal your external drive.


## Btrfs directory snapshots

If you are running linux with btrfs, (or any other operating system + filesystem that supports snapshots), you can
use this to get stable snapshots that won't be modified during upload.


Create the file backup.sh:

```
set -eu
export BUPSTASH_KEY=/root/backup-put.key
export BUPSTASH_REPOSITORY=/mnt/external-drive/bupstash-backups


if test -e /rootsnap
then
    echo "removing snapshot, it already existed."
    btrfs subvolume delete /rootsnap
fi
btrfs subvolume snapshot -r / /rootsnap > /dev/null

bupstash put \
   --send-log /root/backup.sendlog \
   --exclude "/home/*/.cache" \
   hostname=$(hostname) \
   name=backup.tar \
   /rootsnap

btrfs subvolume delete /rootsnap > /dev/null
```

Then running a backup is as simple as:

```
$ sudo sh ./backup.sh
```

Filesystem enabled snapshots do not suffer from 'time smear'. All points about '--send-log', '--exclude' and backup restore from simple directory snapshots also apply to this snapshot method.


## Btrfs send snapshots


If you are running linux with btrfs, (or any other operating system + filesystem that supports exporting directories as a stream), you can
directly save the output of such a command into a bupstash repository.


Create the file backup.sh:

```
set -eu
export BUPSTASH_KEY=/root/backup-put.key
export BUPSTASH_REPOSITORY=/mnt/external-drive/bupstash-backups


if test -e /rootsnap
then
    echo "removing snapshot, it already existed."
    btrfs subvolume delete /rootsnap
fi

btrfs subvolume snapshot -r / /rootsnap > /dev/null

bupstash put \
   --exec
   --send-log /root/backup.sendlog \
   hostname=$(hostname) \
   name=backup.btrfs \
   btrfs send  /rootsnap

btrfs subvolume delete /rootsnap > /dev/null
```
Then running a backup is as simple as:

```
$ sudo sh ./backup.sh
```

Restoration of the backup is done via the `btrfs receive` command:

```
$ bupstash get name=backup.btrfs | sudo btrfs receive  ./restore
```
