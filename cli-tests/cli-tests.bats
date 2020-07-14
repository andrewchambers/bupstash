

unset ARCHIVIST_CONNECT_COMMAND
export SCRATCH="$BATS_TMPDIR/archivist-test-scratch"
export REPO="$SCRATCH/archivist-test-repo"
export PRIMARY_KEY="$SCRATCH/archivist-test-primary.key"
export SEND_KEY="$SCRATCH/archivist-test-send.key"
export METADATA_KEY="$SCRATCH/archivist-test-metadata.key"
export ARCHIVIST_REPOSITORY="$REPO"
export ARCHIVIST_SEND_LOG="$SCRATCH/send-log.sqlite3"
export ARCHIVIST_QUERY_CACHE="$SCRATCH/query-cache.sqlite3"
export ARCHIVIST_STAT_CACHE="$SCRATCH/stat-cache.sqlite3"

setup () {
  mkdir "$SCRATCH"
  archivist init "$REPO"
  archivist new-key -o "$PRIMARY_KEY"
  archivist new-send-key -k "$PRIMARY_KEY" -o "$SEND_KEY"
  archivist new-metadata-key -k "$PRIMARY_KEY" -o "$METADATA_KEY"
}

teardown () {
  rm -rf $SCRATCH
}

@test "init repository" {
  test -d "$REPO"
  test -d "$REPO/data"
  test -f "$REPO/archivist.sqlite3"
  test -f "$REPO/gc.lock"
  test -f "$PRIMARY_KEY"
  test -f "$SEND_KEY"
  test -f "$METADATA_KEY"
}

@test "simple send recv primary key" {
  data="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
  echo -n "$data" > "$SCRATCH/foo.txt"
  id="$(archivist send -k "$PRIMARY_KEY" :: "$SCRATCH/foo.txt")"
  test "$data" = "$(archivist get -k "$PRIMARY_KEY" id=$id )"
}

@test "simple send recv send key" {
  data="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
  echo -n "$data" > "$SCRATCH/foo.txt"
  id="$(archivist send -k "$SEND_KEY" :: "$SCRATCH/foo.txt")"
  test "$data" = "$(archivist get -k "$PRIMARY_KEY" id=$id )"
}

@test "simple send recv no compression" {
  data="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
  echo -n "$data" > "$SCRATCH/foo.txt"
  id="$(archivist send --no-compression -k "$SEND_KEY" :: "$SCRATCH/foo.txt")"
  test "$data" = "$(archivist get -k "$PRIMARY_KEY" id=$id )"
}

@test "random data" {
  for i in $(echo 0 1024 4096 1000000 100000000)
  do
    rm -f "$SCRATCH/rand.dat"
    head -c $i /dev/urandom > "$SCRATCH/rand.dat"
    id="$(archivist send -k "$SEND_KEY" :: "$SCRATCH/rand.dat")"
    archivist get -k "$PRIMARY_KEY" id=$id > "$SCRATCH/got.dat"
    archivist gc
    cmp --silent "$SCRATCH/rand.dat" "$SCRATCH/got.dat"
  done
}

@test "highly compressible data" {
  for i in $(echo 0 1024 4096 1000000 100000000)
  do
    rm -f "$SCRATCH/rand.dat"
    yes | head -c $i > "$SCRATCH/yes.dat"
    id="$(archivist send -k "$SEND_KEY" :: "$SCRATCH/yes.dat")"
    archivist get -k "$PRIMARY_KEY" id=$id > "$SCRATCH/got.dat"
    archivist gc
    cmp --silent "$SCRATCH/yes.dat" "$SCRATCH/got.dat"
  done
}

@test "key mismatch" {
  data="abc123"
  echo -n "$data" > "$SCRATCH/foo.txt"
  id="$(archivist send -k "$PRIMARY_KEY" :: "$SCRATCH/foo.txt")"
  archivist new-key -o "$SCRATCH/wrong.key"
  run archivist get -k "$SCRATCH/wrong.key" id=$id
  echo "$output" | grep -q "key does not match"
  if test $status = 0
  then
    exit 1
  fi
}

@test "corruption detected" {
  data="abc123"
  echo -n "$data" > "$SCRATCH/foo.txt"
  id="$(archivist send -k "$PRIMARY_KEY" :: "$SCRATCH/foo.txt")"
  echo -n x >> "$REPO/data/"*
  run archivist get -k "$PRIMARY_KEY" id=$id
  echo "$output" | grep -q "corrupt"
  if test $status = 0
  then
    exit 1
  fi
}

_concurrent_send_test_worker () {
  set -e
  for i in $(seq 10)
  do
    id="$(archivist send -e --no-send-log -k "$PRIMARY_KEY" :: echo $i)"
    test "$i" = "$(archivist get -k "$PRIMARY_KEY" id=$id)"
  done
}

@test "concurrent send" {
  for i in $(seq 10)
  do
    _concurrent_send_test_worker &
  done
  wait
  test 100 = $(archivist list -k "$PRIMARY_KEY" | wc -l)
}

@test "simple search and listing" {
  for i in $(seq 100) # Enough to trigger more than one sync packet.
  do
    archivist send -e -k "$PRIMARY_KEY"  "i=$i" :: echo $i
  done
  for k in $PRIMARY_KEY $METADATA_KEY
  do
    test 100 = $(archivist list -k "$k" | wc -l)
    test 1 = $(archivist list -k "$k" i=100 | wc -l)
    test 0 = $(archivist list -k "$k" i=101 | wc -l)
  done
}

@test "rm and gc" {
  archivist list -k "$PRIMARY_KEY"
  test 0 = "$(sqlite3 "$SCRATCH/query-cache.sqlite3" 'select count(*) from ItemOpLog;')"
  id1="$(archivist send -k "$PRIMARY_KEY" -e :: echo hello1)"
  id2="$(archivist send -k "$PRIMARY_KEY" -e :: echo hello2)"
  archivist list -k "$PRIMARY_KEY"
  test 2 = "$(sqlite3 "$SCRATCH/query-cache.sqlite3" 'select count(*) from ItemOpLog;')"
  test 2 = "$(sqlite3 "$REPO/archivist.sqlite3" 'select count(*) from ItemOpLog;')"
  test 2 = "$(sqlite3 "$REPO/archivist.sqlite3" 'select count(*) from Items;')"
  test 2 = "$(ls "$REPO/data" | wc -l)"
  archivist rm id=$id1
  archivist list -k "$PRIMARY_KEY"
  test 3 = "$(sqlite3 "$SCRATCH/query-cache.sqlite3" 'select count(*) from ItemOpLog;')"
  test 3 = "$(sqlite3 "$REPO/archivist.sqlite3" 'select count(*) from ItemOpLog;')"
  test 1 = "$(sqlite3 "$REPO/archivist.sqlite3" 'select count(*) from Items;')"
  test 2 = "$(ls "$REPO/data" | wc -l)"
  archivist gc
  archivist list -k "$PRIMARY_KEY"
  test 1 = "$(sqlite3 "$SCRATCH/query-cache.sqlite3" 'select count(*) from ItemOpLog;')"
  test 1 = "$(sqlite3 "$REPO/archivist.sqlite3" 'select count(*) from ItemOpLog;')"
  test 1 = "$(sqlite3 "$REPO/archivist.sqlite3" 'select count(*) from Items;')"
  test 1 = "$(ls "$REPO/data" | wc -l)"
  archivist rm id=$id2
  archivist gc
  archivist list -k "$PRIMARY_KEY"
  test 0 = "$(sqlite3 "$SCRATCH/query-cache.sqlite3" 'select count(*) from ItemOpLog;')"
  test 0 = "$(sqlite3 "$REPO/archivist.sqlite3" 'select count(*) from ItemOpLog;')"
  test 0 = "$(sqlite3 "$REPO/archivist.sqlite3" 'select count(*) from Items;')"
  test 0 = "$(ls "$REPO/data" | wc -l)"
}

@test "query sync" {
  id1="$(archivist send -k "$PRIMARY_KEY" -e :: echo hello1)"
  test 1 = $(archivist list -k "$PRIMARY_KEY" | wc -l)
  id2="$(archivist send -k "$PRIMARY_KEY" -e :: echo hello2)"
  test 2 = $(archivist list -k "$PRIMARY_KEY" | wc -l)
  archivist rm id=$id1
  test 1 = $(archivist list -k "$PRIMARY_KEY" | wc -l)
  archivist gc
  test 1 = $(archivist list -k "$PRIMARY_KEY" | wc -l)
  archivist rm id=$id2
  test 0 = $(archivist list -k "$PRIMARY_KEY" | wc -l)
  archivist gc
  test 0 = $(archivist list -k "$PRIMARY_KEY" | wc -l)
}

@test "get via query" {
  archivist send -e -k "$PRIMARY_KEY" foo=bar ::  echo -n hello1 
  archivist send -e -k "$PRIMARY_KEY" foo=baz ::  echo -n hello2 
  archivist send -e -k "$PRIMARY_KEY" foo=bang :: echo -n hello2 
  test "hello2" = $(archivist get -k "$PRIMARY_KEY" "foo=ban*")
}

@test "rm via query" {
  archivist send -e -k "$PRIMARY_KEY"  foo=bar :: echo -n hello1 
  archivist send -e -k "$PRIMARY_KEY"  foo=baz :: echo -n hello2
  archivist send -e -k "$PRIMARY_KEY"  foo=bang :: echo -n hello2
  test 3 = $(archivist list -k "$PRIMARY_KEY" | wc -l)
  if archivist rm -k "$PRIMARY_KEY" "foo=*"
  then
    exit 1
  fi
  archivist rm -k "$PRIMARY_KEY" "foo=bar"
  test 2 = $(archivist list -k "$PRIMARY_KEY" | wc -l)
  archivist rm --allow-many -k "$METADATA_KEY" "foo=*"
  test 0 = $(archivist list -k "$PRIMARY_KEY" | wc -l)
}

@test "send directory sanity" {
  mkdir "$SCRATCH/foo"
  echo a > "$SCRATCH/foo/a.txt"
  echo b > "$SCRATCH/foo/b.txt"
  mkdir "$SCRATCH/foo/bar"
  echo c > "$SCRATCH/foo/bar/c.txt"
  id=$(archivist send -k "$PRIMARY_KEY" :: "$SCRATCH/foo")
  test 5 = "$(archivist get -k "$PRIMARY_KEY" id=$id | tar -tf - | wc -l)"
  # Test again to excercise stat caching.
  id=$(archivist send -k "$PRIMARY_KEY" :: "$SCRATCH/foo")
  test 5 = "$(archivist get -k "$PRIMARY_KEY" id=$id | tar -tf - | wc -l)"
}

@test "send directory no stat cache" {
  mkdir "$SCRATCH/foo"
  echo a > "$SCRATCH/foo/a.txt"
  echo b > "$SCRATCH/foo/b.txt"
  mkdir "$SCRATCH/foo/bar"
  echo c > "$SCRATCH/foo/bar/c.txt"
  id=$(archivist send -k "$PRIMARY_KEY" --no-send-log :: "$SCRATCH/foo")
  test 5 = "$(archivist get -k "$PRIMARY_KEY" id=$id | tar -tf - | wc -l)"
  id=$(archivist send -k "$PRIMARY_KEY" --no-stat-cache :: "$SCRATCH/foo")
  test 5 = "$(archivist get -k "$PRIMARY_KEY" id=$id | tar -tf - | wc -l)"
}

@test "stat cache invalidated" {
  mkdir "$SCRATCH/foo"
  echo a > "$SCRATCH/foo/a.txt"
  id=$(archivist send -k "$PRIMARY_KEY" :: "$SCRATCH/foo")
  archivist rm -k "$PRIMARY_KEY" id=$id
  archivist gc
  id=$(archivist send -k "$PRIMARY_KEY" :: "$SCRATCH/foo")
  archivist get -k "$PRIMARY_KEY" id=$id > /dev/null
}

@test "connect command" {
  export ARCHIVIST_CONNECT_COMMAND="archivist serve $ARCHIVIST_REPOSITORY"
  unset ARCHIVIST_REPOSITORY
  data="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
  echo -n "$data" > "$SCRATCH/foo.txt"
  id="$(archivist send -k "$PRIMARY_KEY" :: "$SCRATCH/foo.txt")"
  test "$data" = "$(archivist get -k "$PRIMARY_KEY" id=$id )"
}

@test "key command" {
  export ARCHIVIST_KEY_COMMAND="cat $PRIMARY_KEY"
  data="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
  echo -n "$data" > "$SCRATCH/foo.txt"
  id="$(archivist send :: "$SCRATCH/foo.txt")"
  test "$data" = "$(archivist get id=$id )"
}
