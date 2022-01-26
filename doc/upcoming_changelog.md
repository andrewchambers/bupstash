# Bupstash v0.11.0

This release shrinks repository sizes, reduces bandwidth usage, while also
improving the accuracy of filesystem restores in less common scenarios.

New features:

- Support for the zstandard compression algorithm has been added, decreasing repository sizes 30 percent in some benchmarks.
- An optional `--compression` flag has been added to specify the compression algorithm and level during puts.
- The default compression algorithm has changed to zstandard (equivalent to passing `--compression=zstd:3` to `bupstash put`).
- The put and restore command can now preserve sparse file holes, improving the accuracy of backups.
- The restore command now restores mtime timestamps on restored files.

Bug fixes:

- Support for paths that are not valid unicode but are still valid unix paths has been improved.

Incompatibilities:

- Repositories will be automatically migrated by bupstash and cannot be used with older versions of bupstash after migration.
- The bupstash remote protocol version has been incremented to support new features and does not interoperate with older bupstash versions.
- The `--no-compression` flag has been removed (use `--compression=none` instead).
- The list-contents command json output now uses 'null' instead of undefined values for missing fields.
- The list-contents command json output will emit paths as byte arrays if they are not representable as json strings.