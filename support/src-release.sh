set -eux

version="$1"

rm -rf ./release/
mkdir ./release
mkdir release/src
mkdir release/src/.cargo
git archive $version | tar -C release/src -x -f -
cd release/src

cargo vendor > .cargo/config

tar -cvf - . | gzip -9 > ../../bupstash-$1-src.tar.gz

cd ..
mkdir man
cd man
cp ../src/doc/man/*.md ./
ronn -r *.md
rm *.md

tar -cvf - . | gzip -9 > ../../bupstash-$1-man.tar.gz