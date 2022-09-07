# Bupstash v0.11.1

This release is a primarily a bug fix and maintenance release in preparation
for an upcoming bupstash 1.0 release. While this release tweaks the repository
format, the network protocol remains unchanged and interoperable.

## New features

- Added a new --ignore-permission-errors option to `bupstash put`.
- Added a new advanced environment variable BUPSTASH_KEEP_WAL=1 for 
 'bupstash serve' (See WAL section below).

## Notable Bug fixes

- Fixed some cases where non utf8 paths caused bupstash to reject files.
- Fixed a bug that caused using --pick on directories larger 15-20GiB to fail.

## Incompatibilities

- The repository format has changed, repositories will be automatically migrated
  by bupstash and cannot be used with older versions of bupstash after migration
  (access across the network is still compatible).
- Bupstash now performs upload checkpoints based on elapsed time instead of upload byte count.
- BUPSTASH_CHECKPOINT_BYTES has been replaced by BUPSTASH_CHECKPOINT_SECONDS.

## WAL

Bupstash now writes all changes it makes to the repository to a WAL (write ahead log)
file for crash recovery purposes. If the 'bupstash serve' command is run with the new
BUPSTASH_KEEP_WAL=1 environment variable set, then WAL entries are accumulated in the
repository `wal` directory instead of being removed when they are no longer needed.

The main purpose of the wal directory is incremental replication of the repository
metadata and history. Future bupstash versions may include tools to interact with
these WAL files to do operations like point in time recovery or recovery from external storage engines.

For now this feature is only for advanced users with specialist use cases.

## Signed releases

From this point on git tags and downloads will be signed by a gpg key from developers at the
bupstash.io domain. The PGP signing keys can be found at https://bupstash.io/doc/man/bupstash-authors.html
or via the source code repository itself in the file `doc/man/bupstash-authors.7.md`.

## Supporting bupstash

Bupstash.io managed repositories now are in open beta and anyone can create an account.
If you enjoy bupstash then please consider creating a managed repository at https://bupstash.io/managed.html
to support the project.

One handy way of using bupstash.io is in conjunction with `bupstash sync` and an external drive to
keep a local and remote copy of your backups for extra assurance.

Another great way to help the project is to just tell your friends to give bupstash a try.