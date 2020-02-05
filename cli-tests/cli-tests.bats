

export SCRATCH="$BATS_TMPDIR/archivist-test-scratch"
export REPO="$SCRATCH/archivist-test-repo"
export MASTER_KEY="$SCRATCH/archivist-test-master.key"
export SEND_KEY="$SCRATCH/archivist-test-send.key"
export ARCHIVIST_REPOSITORY="$REPO"
export ARCHIVIST_SEND_LOG="$SCRATCH/send-log.sqlite3"
export ARCHIVIST_QUERY_CACHE="$SCRATCH/query-cache.sqlite3"

setup () {
  mkdir "$SCRATCH"
  archivist init "$REPO"
  archivist new-master-key -o "$MASTER_KEY"
  archivist new-send-key -m "$MASTER_KEY" -o "$SEND_KEY"
}

teardown () {
  rm -rf $SCRATCH
}

@test "init repository" {
  test -d "$REPO"
  test -d "$REPO/data"
  test -f "$REPO/archivist.db"
  test -f "$REPO/gc.lock"
  test -f "$MASTER_KEY"
  test -f "$SEND_KEY"
}

@test "simple send recv master key" {
  data="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
  echo -n "$data" > "$SCRATCH/foo.txt"
  id="$(archivist send -k "$MASTER_KEY" -f "$SCRATCH/foo.txt")"
  test "$data" = "$(archivist get -k "$MASTER_KEY" --id "$id" )"
}

@test "simple send recv send key" {
  data="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
  echo -n "$data" > "$SCRATCH/foo.txt"
  id="$(archivist send -k "$SEND_KEY" -f "$SCRATCH/foo.txt")"
  test "$data" = "$(archivist get -k "$MASTER_KEY" --id "$id" )"
}

@test "simple send recv no compression" {
  data="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
  echo -n "$data" > "$SCRATCH/foo.txt"
  id="$(archivist send --no-compression -k "$SEND_KEY" -f "$SCRATCH/foo.txt")"
  test "$data" = "$(archivist get -k "$MASTER_KEY" --id "$id" )"
}

@test "random data" {
  for i in $(echo 0 1024 4096 1000000)
  do
    rm -f "$SCRATCH/rand.dat"
    head -c $i /dev/urandom > "$SCRATCH/rand.dat"
    id="$(archivist send -k "$SEND_KEY" -f "$SCRATCH/rand.dat")"
    archivist get -k "$MASTER_KEY" --id "$id" > "$SCRATCH/got.dat"
    cmp --silent "$SCRATCH/rand.dat" "$SCRATCH/got.dat"
  done
}

@test "highly compressible data" {
  for i in $(echo 0 1024 4096 1000000)
  do
    rm -f "$SCRATCH/rand.dat"
    yes | head -c $i > "$SCRATCH/yes.dat"
    id="$(archivist send -k "$SEND_KEY" -f "$SCRATCH/yes.dat")"
    archivist get -k "$MASTER_KEY" --id "$id" > "$SCRATCH/got.dat"
    cmp --silent "$SCRATCH/yes.dat" "$SCRATCH/got.dat"
  done
}

@test "key mismatch" {
  data="abc123"
  echo -n "$data" > "$SCRATCH/foo.txt"
  id="$(archivist send -k "$MASTER_KEY" -f "$SCRATCH/foo.txt")"
  archivist new-master-key -o "$SCRATCH/wrong.key"
  run archivist get -k "$SCRATCH/wrong.key" --id "$id"
  echo "$output" | grep -q "key does not match"
  if test $status = 0
  then
    exit 1
  fi
}

@test "corruption detected" {
  data="abc123"
  echo -n "$data" > "$SCRATCH/foo.txt"
  id="$(archivist send -k "$MASTER_KEY" -f "$SCRATCH/foo.txt")"
  echo -n x >> "$REPO/data/"*
  run archivist get -k "$MASTER_KEY" --id "$id"
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
    id="$(archivist send --send-log ":memory:" -k "$MASTER_KEY" -f <(echo $i))"
    test "$i" = "$(archivist get -k "$MASTER_KEY" --id "$id")"
  done
}

@test "concurrent send" {
  for i in $(seq 10)
  do
    _concurrent_send_test_worker &
  done
  wait
  test 100 = $(archivist list -k "$MASTER_KEY" | wc -l)
}

@test "simple search and listing" {
  for i in $(seq 100) # Enough to trigger more than one sync packet.
  do
    archivist send -k "$MASTER_KEY" -f <(echo $i) "i=$i"
  done

  test 100 = $(archivist list -k "$MASTER_KEY" | wc -l)
  test 1 = $(archivist list -k "$MASTER_KEY" i=100 | wc -l)
  test 0 = $(archivist list -k "$MASTER_KEY" i=101 | wc -l)
}

@test "rm and gc" {
  id1="$(archivist send -k "$MASTER_KEY" -f <(echo hello1))"
  id2="$(archivist send -k "$MASTER_KEY" -f <(echo hello2))"
  test 2 = "$(sqlite3 "$REPO/archivist.db" 'select count(*) from ItemOpLog;')"
  test 2 = "$(sqlite3 "$REPO/archivist.db" 'select count(*) from Items;')"
  test 2 = "$(ls "$REPO/data" | wc -l)"
  archivist rm --id "$id1"
  test 3 = "$(sqlite3 "$REPO/archivist.db" 'select count(*) from ItemOpLog;')"
  test 1 = "$(sqlite3 "$REPO/archivist.db" 'select count(*) from Items;')"
  test 2 = "$(ls "$REPO/data" | wc -l)"
  archivist gc
  test 1 = "$(sqlite3 "$REPO/archivist.db" 'select count(*) from ItemOpLog;')"
  test 1 = "$(sqlite3 "$REPO/archivist.db" 'select count(*) from Items;')"
  test 1 = "$(ls "$REPO/data" | wc -l)"
  archivist rm --id "$id2"
  archivist gc
  test 0 = "$(sqlite3 "$REPO/archivist.db" 'select count(*) from ItemOpLog;')"
  test 0 = "$(sqlite3 "$REPO/archivist.db" 'select count(*) from Items;')"
  test 0 = "$(ls "$REPO/data" | wc -l)"
}

@test "query sync" {
  id1="$(archivist send -k "$MASTER_KEY" -f <(echo hello1))"
  test 1 = $(archivist list -k "$MASTER_KEY" | wc -l)
  id2="$(archivist send -k "$MASTER_KEY" -f <(echo hello2))"
  test 2 = $(archivist list -k "$MASTER_KEY" | wc -l)
  archivist rm --id "$id1"
  test 1 = $(archivist list -k "$MASTER_KEY" | wc -l)
  archivist gc
  test 1 = $(archivist list -k "$MASTER_KEY" | wc -l)
  archivist rm --id "$id2"
  test 0 = $(archivist list -k "$MASTER_KEY" | wc -l)
  archivist gc
  test 0 = $(archivist list -k "$MASTER_KEY" | wc -l)
}

@test "get via query" {
  archivist send -k "$MASTER_KEY" -f <(echo -n hello1) foo=bar
  archivist send -k "$MASTER_KEY" -f <(echo -n hello2) foo=baz
  archivist send -k "$MASTER_KEY" -f <(echo -n hello2) foo=bang
  test "hello2" = $(archivist get -k "$MASTER_KEY" "foo=ban*")
}

@test "rm via query" {
  archivist send -k "$MASTER_KEY" -f <(echo -n hello1) foo=bar
  archivist send -k "$MASTER_KEY" -f <(echo -n hello2) foo=baz
  archivist send -k "$MASTER_KEY" -f <(echo -n hello2) foo=bang
  test 3 = $(archivist list -k "$MASTER_KEY" | wc -l)
  if archivist rm -k "$MASTER_KEY" "foo=*"
  then
    exit 1
  fi
  archivist rm -k "$MASTER_KEY" "foo=bar"
  test 2 = $(archivist list -k "$MASTER_KEY" | wc -l)
  archivist rm --all -k "$MASTER_KEY" "foo=*"
  test 0 = $(archivist list -k "$MASTER_KEY" | wc -l)
}

