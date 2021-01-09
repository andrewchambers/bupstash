#!/bin/sh
exit_code=0

cargo fmt --all -- --quiet --check
if [ $? -ne 0 ]; then
    echo "Please run 'cargo fmt --all' before committing"
    exit_code=1
fi

cargo clippy -- -D warnings 2> /dev/null
if [ $? -ne 0 ]; then
    echo "Please run 'cargo clippy' and fix all issues before committing"
    exit_code=1
fi

if [ $exit_code -ne 0 ]; then
    exit $exit_code
fi
