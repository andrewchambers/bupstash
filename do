#! /bin/sh

set -eux

case $1 in
  fmt)
    cargo fmt

    for md in $(find ./doc/ -type f -name "*.md")
    do
      pandoc -f gfm -t gfm -o $md.tmp-fmt $md
      mv $md.tmp-fmt $md
    done
  ;;

  *)
    echo "dont know how to do '$1'."
    exit 1
  ;;
esac
