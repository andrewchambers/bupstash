

unset BUPSTASH_REPOSITORY_COMMAND
export SCRATCH="$BATS_TMPDIR/bupstash-test-scratch"
export REPO="$SCRATCH/bupstash-test-repo"
export PRIMARY_KEY="$SCRATCH/bupstash-test-primary.key"
export SEND_KEY="$SCRATCH/bupstash-test-send.key"
export METADATA_KEY="$SCRATCH/bupstash-test-metadata.key"
export BUPSTASH_REPOSITORY="$REPO"
export BUPSTASH_SEND_LOG="$SCRATCH/send-log.sqlite3"
export BUPSTASH_QUERY_CACHE="$SCRATCH/query-cache.sqlite3"
export BUPSTASH_STAT_CACHE="$SCRATCH/stat-cache.sqlite3"

setup () {
  mkdir "$SCRATCH"
  bupstash init "$REPO"
  bupstash new-key -o "$PRIMARY_KEY"
  bupstash new-send-key -k "$PRIMARY_KEY" -o "$SEND_KEY"
  bupstash new-metadata-key -k "$PRIMARY_KEY" -o "$METADATA_KEY"
}

teardown () {
  rm -rf $SCRATCH
}

@test "init repository" {
  test -d "$REPO"
  test -d "$REPO/data"
  test -f "$REPO/bupstash.sqlite3"
  test -f "$REPO/gc.lock"
  test -f "$PRIMARY_KEY"
  test -f "$SEND_KEY"
  test -f "$METADATA_KEY"
}

@test "simple send recv primary key" {
  data="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
  echo -n "$data" > "$SCRATCH/foo.txt"
  id="$(bupstash send -k "$PRIMARY_KEY" :: "$SCRATCH/foo.txt")"
  test "$data" = "$(bupstash get -k "$PRIMARY_KEY" id=$id )"
}

@test "simple send recv send key" {
  data="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
  echo -n "$data" > "$SCRATCH/foo.txt"
  id="$(bupstash send -k "$SEND_KEY" :: "$SCRATCH/foo.txt")"
  test "$data" = "$(bupstash get -k "$PRIMARY_KEY" id=$id )"
}

@test "simple send recv no compression" {
  data="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
  echo -n "$data" > "$SCRATCH/foo.txt"
  id="$(bupstash send --no-compression -k "$SEND_KEY" :: "$SCRATCH/foo.txt")"
  test "$data" = "$(bupstash get -k "$PRIMARY_KEY" id=$id )"
}

@test "random data" {
  for i in $(echo 0 1024 4096 1000000 100000000)
  do
    rm -f "$SCRATCH/rand.dat"
    head -c $i /dev/urandom > "$SCRATCH/rand.dat"
    id="$(bupstash send -k "$SEND_KEY" :: "$SCRATCH/rand.dat")"
    bupstash get -k "$PRIMARY_KEY" id=$id > "$SCRATCH/got.dat"
    bupstash gc
    cmp --silent "$SCRATCH/rand.dat" "$SCRATCH/got.dat"
  done
}

@test "highly compressible data" {
  for i in $(echo 0 1024 4096 1000000 100000000)
  do
    rm -f "$SCRATCH/rand.dat"
    yes | head -c $i > "$SCRATCH/yes.dat"
    id="$(bupstash send -k "$SEND_KEY" :: "$SCRATCH/yes.dat")"
    bupstash get -k "$PRIMARY_KEY" id=$id > "$SCRATCH/got.dat"
    bupstash gc
    cmp --silent "$SCRATCH/yes.dat" "$SCRATCH/got.dat"
  done
}

@test "key mismatch" {
  data="abc123"
  echo -n "$data" > "$SCRATCH/foo.txt"
  id="$(bupstash send -k "$PRIMARY_KEY" :: "$SCRATCH/foo.txt")"
  bupstash new-key -o "$SCRATCH/wrong.key"
  run bupstash get -k "$SCRATCH/wrong.key" id=$id
  echo "$output" | grep -q "key does not match"
  if test $status = 0
  then
    exit 1
  fi
}

@test "corruption detected" {
  data="abc123"
  echo -n "$data" > "$SCRATCH/foo.txt"
  id="$(bupstash send -k "$PRIMARY_KEY" :: "$SCRATCH/foo.txt")"
  echo -n x >> "$REPO/data/"*
  run bupstash get -k "$PRIMARY_KEY" id=$id
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
    id="$(bupstash send -e --no-send-log -k "$PRIMARY_KEY" :: echo $i)"
    test "$i" = "$(bupstash get -k "$PRIMARY_KEY" id=$id)"
  done
}

@test "concurrent send" {
  for i in $(seq 10)
  do
    _concurrent_send_test_worker &
  done
  wait
  test 100 = $(bupstash list -k "$PRIMARY_KEY" | wc -l)
}

@test "simple search and listing" {
  for i in $(seq 100) # Enough to trigger more than one sync packet.
  do
    bupstash send -e -k "$PRIMARY_KEY"  "i=$i" :: echo $i
  done
  for k in $PRIMARY_KEY $METADATA_KEY
  do
    test 100 = $(bupstash list -k "$k" | wc -l)
    test 1 = $(bupstash list -k "$k" i=100 | wc -l)
    test 0 = $(bupstash list -k "$k" i=101 | wc -l)
  done
}

@test "rm and gc" {
  bupstash list -k "$PRIMARY_KEY"
  test 0 = "$(sqlite3 "$SCRATCH/query-cache.sqlite3" 'select count(*) from ItemOpLog;')"
  id1="$(bupstash send -k "$PRIMARY_KEY" -e :: echo hello1)"
  id2="$(bupstash send -k "$PRIMARY_KEY" -e :: echo hello2)"
  bupstash list -k "$PRIMARY_KEY"
  test 2 = "$(sqlite3 "$SCRATCH/query-cache.sqlite3" 'select count(*) from ItemOpLog;')"
  test 2 = "$(sqlite3 "$REPO/bupstash.sqlite3" 'select count(*) from ItemOpLog;')"
  test 2 = "$(sqlite3 "$REPO/bupstash.sqlite3" 'select count(*) from Items;')"
  test 2 = "$(ls "$REPO/data" | wc -l)"
  bupstash rm id=$id1
  bupstash list -k "$PRIMARY_KEY"
  test 3 = "$(sqlite3 "$SCRATCH/query-cache.sqlite3" 'select count(*) from ItemOpLog;')"
  test 3 = "$(sqlite3 "$REPO/bupstash.sqlite3" 'select count(*) from ItemOpLog;')"
  test 1 = "$(sqlite3 "$REPO/bupstash.sqlite3" 'select count(*) from Items;')"
  test 2 = "$(ls "$REPO/data" | wc -l)"
  bupstash gc
  bupstash list -k "$PRIMARY_KEY"
  test 1 = "$(sqlite3 "$SCRATCH/query-cache.sqlite3" 'select count(*) from ItemOpLog;')"
  test 1 = "$(sqlite3 "$REPO/bupstash.sqlite3" 'select count(*) from ItemOpLog;')"
  test 1 = "$(sqlite3 "$REPO/bupstash.sqlite3" 'select count(*) from Items;')"
  test 1 = "$(ls "$REPO/data" | wc -l)"
  bupstash rm id=$id2
  bupstash gc
  bupstash list -k "$PRIMARY_KEY"
  test 0 = "$(sqlite3 "$SCRATCH/query-cache.sqlite3" 'select count(*) from ItemOpLog;')"
  test 0 = "$(sqlite3 "$REPO/bupstash.sqlite3" 'select count(*) from ItemOpLog;')"
  test 0 = "$(sqlite3 "$REPO/bupstash.sqlite3" 'select count(*) from Items;')"
  test 0 = "$(ls "$REPO/data" | wc -l)"
}

@test "query sync" {
  id1="$(bupstash send -k "$PRIMARY_KEY" -e :: echo hello1)"
  test 1 = $(bupstash list -k "$PRIMARY_KEY" | wc -l)
  id2="$(bupstash send -k "$PRIMARY_KEY" -e :: echo hello2)"
  test 2 = $(bupstash list -k "$PRIMARY_KEY" | wc -l)
  bupstash rm id=$id1
  test 1 = $(bupstash list -k "$PRIMARY_KEY" | wc -l)
  bupstash gc
  test 1 = $(bupstash list -k "$PRIMARY_KEY" | wc -l)
  bupstash rm id=$id2
  test 0 = $(bupstash list -k "$PRIMARY_KEY" | wc -l)
  bupstash gc
  test 0 = $(bupstash list -k "$PRIMARY_KEY" | wc -l)
}

@test "get via query" {
  bupstash send -e -k "$PRIMARY_KEY" foo=bar ::  echo -n hello1 
  bupstash send -e -k "$PRIMARY_KEY" foo=baz ::  echo -n hello2 
  bupstash send -e -k "$PRIMARY_KEY" foo=bang :: echo -n hello2 
  test "hello2" = $(bupstash get -k "$PRIMARY_KEY" "foo=ban*")
}

@test "rm via query" {
  bupstash send -e -k "$PRIMARY_KEY"  foo=bar :: echo -n hello1 
  bupstash send -e -k "$PRIMARY_KEY"  foo=baz :: echo -n hello2
  bupstash send -e -k "$PRIMARY_KEY"  foo=bang :: echo -n hello2
  test 3 = $(bupstash list -k "$PRIMARY_KEY" | wc -l)
  if bupstash rm -k "$PRIMARY_KEY" "foo=*"
  then
    exit 1
  fi
  bupstash rm -k "$PRIMARY_KEY" "foo=bar"
  test 2 = $(bupstash list -k "$PRIMARY_KEY" | wc -l)
  bupstash rm --allow-many -k "$METADATA_KEY" "foo=*"
  test 0 = $(bupstash list -k "$PRIMARY_KEY" | wc -l)
}

@test "send directory sanity" {
  mkdir "$SCRATCH/foo"
  echo a > "$SCRATCH/foo/a.txt"
  echo b > "$SCRATCH/foo/b.txt"
  mkdir "$SCRATCH/foo/bar"
  echo c > "$SCRATCH/foo/bar/c.txt"
  id=$(bupstash send -k "$PRIMARY_KEY" :: "$SCRATCH/foo")
  test 5 = "$(bupstash get -k "$PRIMARY_KEY" id=$id | tar -tf - | wc -l)"
  # Test again to excercise stat caching.
  id=$(bupstash send -k "$PRIMARY_KEY" :: "$SCRATCH/foo")
  test 5 = "$(bupstash get -k "$PRIMARY_KEY" id=$id | tar -tf - | wc -l)"
}

@test "send directory no stat cache" {
  mkdir "$SCRATCH/foo"
  echo a > "$SCRATCH/foo/a.txt"
  echo b > "$SCRATCH/foo/b.txt"
  mkdir "$SCRATCH/foo/bar"
  echo c > "$SCRATCH/foo/bar/c.txt"
  id=$(bupstash send -k "$PRIMARY_KEY" --no-send-log :: "$SCRATCH/foo")
  test 5 = "$(bupstash get -k "$PRIMARY_KEY" id=$id | tar -tf - | wc -l)"
  id=$(bupstash send -k "$PRIMARY_KEY" --no-stat-cache :: "$SCRATCH/foo")
  test 5 = "$(bupstash get -k "$PRIMARY_KEY" id=$id | tar -tf - | wc -l)"
}

@test "stat cache invalidated" {
  mkdir "$SCRATCH/foo"
  echo a > "$SCRATCH/foo/a.txt"
  id=$(bupstash send -k "$PRIMARY_KEY" :: "$SCRATCH/foo")
  bupstash rm -k "$PRIMARY_KEY" id=$id
  bupstash gc
  id=$(bupstash send -k "$PRIMARY_KEY" :: "$SCRATCH/foo")
  bupstash get -k "$PRIMARY_KEY" id=$id > /dev/null
}

@test "repository command" {
  export BUPSTASH_REPOSITORY_COMMAND="bupstash serve $BUPSTASH_REPOSITORY"
  unset BUPSTASH_REPOSITORY
  data="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
  echo -n "$data" > "$SCRATCH/foo.txt"
  id="$(bupstash send -k "$PRIMARY_KEY" :: "$SCRATCH/foo.txt")"
  test "$data" = "$(bupstash get -k "$PRIMARY_KEY" id=$id )"
}

@test "key command" {
  export BUPSTASH_KEY_COMMAND="cat $PRIMARY_KEY"
  data="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
  echo -n "$data" > "$SCRATCH/foo.txt"
  id="$(bupstash send :: "$SCRATCH/foo.txt")"
  test "$data" = "$(bupstash get id=$id )"
}
