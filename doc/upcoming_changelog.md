# Bupstash v0.11.0

This release adds new commands, improves repository compression, reduces bandwidth usage, and improves support for paths that are invalid unicode.

New features:

- Added the new `bupstash sync` command for efficiently transferring data between repositories.
- Added the new `--allow-sync` permission to `bupstash serve`.
- Added the new `bupstash exec-with-locks` command for running commands with exclusive repository write access.
- Added the zstandard compression algorithm, decreasing repository sizes 30 percent in some benchmarks.
- Added an optional `--compression` flag has been added to specify the compression algorithm and level during puts.

Improvements:

- The put and restore command can now preserve sparse file holes, improving the accuracy of backups.
- The restore command now restores mtime timestamps on restored files.
- FreeBSD support has been improved.

Notable Bug fixes:

- Support for paths that are not valid unicode but are still valid unix paths has been improved.
- `*` no longer matches `/` in put exclusions.

Incompatibilities:

- Repositories will be automatically migrated by bupstash and cannot be used with older versions of bupstash after migration.
- The bupstash remote protocol version has been incremented to support new features and does not interoperate with older bupstash versions.
- The `--no-compression` flag has been removed (use `--compression=none` instead).
- The list-contents command json output now uses 'null' instead of undefined values for missing fields.
- The list-contents command json output will emit paths as byte arrays if they are not representable as json strings.
- The send log now stores chunk addresses in more situations so will grow in size in many cases.
- Put exclusions have slightly different matching semantics and should be reviewed.