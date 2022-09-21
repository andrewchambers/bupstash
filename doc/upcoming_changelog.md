# Bupstash v0.11.2

## New features

- The deduplication rolling hash algorithm has been improved and is now faster 30 to 50 percent faster.
  Those willing to compile bupstash from source using an unstable rust compiler will also gain access to SIMD (even faster) implementations of the algorithms.

## Notable Bug fixes

## Incompatibilities

- It is likely your repositories will temporarily grow in size if they contain data chunks from previous
  versions of bupstash. This is because the new version of bupstash will map the same data to a different set
  of chunks. If this is a problem for you, it be solved by cycling older data out over time, or
  recreating your backups.

## Supporting bupstash

Bupstash.io managed repositories are in open beta and anyone can create an account.
If you enjoy bupstash then please consider creating a managed repository at https://bupstash.io/managed.html
to support the project.

Another great way to help the project is to just tell your friends to give bupstash a try.