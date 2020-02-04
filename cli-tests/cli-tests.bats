

export SCRATCH="$BATS_TMPDIR/archivist-test-scratch"
export REPO="$SCRATCH/archivist-test-repo"
export MASTER_KEY="$SCRATCH/archivist-test-master.key"
export SEND_KEY="$SCRATCH/archivist-test-send.key"
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
  id="$(archivist send -r "$REPO" -k "$MASTER_KEY" -f "$SCRATCH/foo.txt")"
  test "$data" = "$(archivist get -r "$REPO" -k "$MASTER_KEY" --id "$id" )"
}

@test "simple send recv send key" {
  data="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
  echo -n "$data" > "$SCRATCH/foo.txt"
  id="$(archivist send -r "$REPO" -k "$SEND_KEY" -f "$SCRATCH/foo.txt")"
  test "$data" = "$(archivist get -r "$REPO" -k "$MASTER_KEY" --id "$id" )"
}

@test "simple send recv no compression" {
  data="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
  echo -n "$data" > "$SCRATCH/foo.txt"
  id="$(archivist send --no-compression -r "$REPO" -k "$SEND_KEY" -f "$SCRATCH/foo.txt")"
  test "$data" = "$(archivist get -r "$REPO" -k "$MASTER_KEY" --id "$id" )"
}

@test "random data" {
  for i in $(echo 0 1024 4096 1000000)
  do
    rm -f "$SCRATCH/rand.dat"
    head -c $i /dev/urandom > "$SCRATCH/rand.dat"
    id="$(archivist send -r "$REPO" -k "$SEND_KEY" -f "$SCRATCH/rand.dat")"
    archivist get -r "$REPO" -k "$MASTER_KEY" --id "$id" > "$SCRATCH/got.dat"
    cmp --silent "$SCRATCH/rand.dat" "$SCRATCH/got.dat"
  done
}

@test "highly compressible data" {
  for i in $(echo 0 1024 4096 1000000)
  do
    rm -f "$SCRATCH/rand.dat"
    yes | head -c $i > "$SCRATCH/yes.dat"
    id="$(archivist send -r "$REPO" -k "$SEND_KEY" -f "$SCRATCH/yes.dat")"
    archivist get -r "$REPO" -k "$MASTER_KEY" --id "$id" > "$SCRATCH/got.dat"
    cmp --silent "$SCRATCH/yes.dat" "$SCRATCH/got.dat"
  done
}

@test "key mismatch" {
  data="abc123"
  echo -n "$data" > "$SCRATCH/foo.txt"
  id="$(archivist send -r "$REPO" -k "$MASTER_KEY" -f "$SCRATCH/foo.txt")"
  archivist new-master-key -o "$SCRATCH/wrong.key"
  run archivist get -r "$REPO" -k "$SCRATCH/wrong.key" --id "$id"
  echo "$output" | grep -q "key does not match"
  if test $status = 0
  then
    exit 1
  fi
}

@test "corruption detected" {
  data="abc123"
  echo -n "$data" > "$SCRATCH/foo.txt"
  id="$(archivist send -r "$REPO" -k "$MASTER_KEY" -f "$SCRATCH/foo.txt")"
  echo -n x >> "$REPO/data/"*
  run archivist get -r "$REPO" -k "$MASTER_KEY" --id "$id"
  echo "$output" | grep -q "corrupt"
  if test $status = 0
  then
    exit 1
  fi
}

_concurrent_send_test_worker () {
  for i in $(seq 10)
  do
    id="$(archivist send -r "$REPO" -k "$MASTER_KEY" -f <(echo $i))"
    test "$i" = $(archivist get -r "$REPO" -k "$MASTER_KEY" --id "$id")
  done
}

@test "concurrent send" {
  for i in $(seq 10)
  do
    _concurrent_send_test_worker &
  done
  wait
}

@test "simple search and listing" {
  for i in $(seq 100) # Enough to trigger more than one sync packet.
  do
    archivist send -r "$REPO" -k "$MASTER_KEY" -f <(echo $i) "i=$i"
  done

  test 100 = $(archivist list -r "$REPO" -k "$MASTER_KEY" | wc -l)
  test 1 = $(archivist list -r "$REPO" -k "$MASTER_KEY" i=100 | wc -l)
  test 0 = $(archivist list -r "$REPO" -k "$MASTER_KEY" i=101 | wc -l)
}

