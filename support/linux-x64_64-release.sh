set -eux

rm -rf ./release
mkdir release
mkdir release/staging

bupstash=$(hermes build ./support/linux-musl-hpkgs/bupstash-$1.hpkg -e bupstash --no-out-link)

cp $bupstash/bin/bupstash ./release/staging
chmod +w ./release/staging/bupstash

tar -C ./release/staging/ -cf - bupstash | gzip -9 > ./bupstash-$1-linux-x86_64.tar.gz
