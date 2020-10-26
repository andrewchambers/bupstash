#! /bin/sh

set -eux

cargo clean
rm -rf ./pgo
mkdir pgo
mkdir pgo/data

export BUPSTASH_REPOSITORY="$(pwd)/pgo/repo"
export BUPSTASH_SEND_LOG="$(pwd)/pgo/bupstash.sendlog"
export BUPSTASH_QUERY_CACHE="$(pwd)/pgo/bupstash.querycache"
export BUPSTASH_KEY=$(pwd)/pgo/repo.key

RUSTFLAGS="-Cprofile-generate=$(pwd)/pgo/data" \
    cargo build --release

./target/release/bupstash init
./target/release/bupstash new-key -o ./pgo/repo.key
./target/release/bupstash put ./target
id=$(./target/release/bupstash put ./target)
./target/release/bupstash list "id=*" > /dev/null
./target/release/bupstash get "id=$id" > /dev/null
./target/release/bupstash rm --allow-many "id=*" > /dev/null

llvm-profdata merge -o ./pgo/merged.profdata ./pgo/data

RUSTFLAGS="-Cprofile-use=$(pwd)/pgo/merged.profdata" \
    cargo build --release
