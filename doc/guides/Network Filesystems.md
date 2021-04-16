# Network Filesystems

Bupstash relies on fcntl style POSIX file locking across multiple files to work in a concurrent context. Do not use bupstash with any network filesystem that does not support fcntl style locking unless you understand the potential consequences of such a decision.

When using bupstash with a remote repository it is always recommended to use bupstash over ssh by setting BUPSTASH_REPOSITORY to an `ssh://`
style URL. This mode is safe for concurrent use, faster and better in the majority of use cases.

For information on specific network filesystem configurations see the sections below.

## NFSv3/NFSv4

We do no recommend using bupstash over NFSv3 in any configuration.

If you are stubborn, ensure locking is enabled or only access the repository from one bupstash process as a time.

NFSv4 has a more sound network locking protocol, so given the choice between NFSv3 and NFSv4 always
choose NFSv4 with locking enabled.

## CephFS

Using bupstash over Cephfs is untested so is currently not recommended.

## SSHFS

Currently we do no recommend using bupstash over sshfs in any configuration due to the lack
of file lock support across multiple machines.

If you have sshfs access, you almost certainly have the ability to set BUPSTASH_REPOSITORY
to an `ssh://` style url which enables safe concurrent repository access in all situations.

## 9P2000.L

Uncached 9P2000.L mounts of repositories exported via the diod 9P2000.L server will likely
work without issue, though use at your own risk.


