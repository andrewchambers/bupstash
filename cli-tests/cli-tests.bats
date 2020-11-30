
# Be extra careful to not mess with a user repository
unset BUPSTASH_REPOSITORY
unset BUPSTASH_REPOSITORY_COMMAND
unset BUPSTASH_KEY
unset BUPSTASH_KEY_COMMAND

export SCRATCH="$BATS_TMPDIR/bupstash-test-scratch"
export BUPSTASH_KEY="$SCRATCH/bupstash-test-primary.key"
export SEND_KEY="$SCRATCH/bupstash-test-send.key"
export METADATA_KEY="$SCRATCH/bupstash-test-metadata.key"
export BUPSTASH_SEND_LOG="$SCRATCH/send-log.sqlite3"
export BUPSTASH_QUERY_CACHE="$SCRATCH/query-cache.sqlite3"

# We have two modes for running the tests...
# 
# When BUPSTASH_TEST_REPOSITORY_COMMAND is set, we are running
# against an external repository, otherwise we are running against
# a test repository.

if test -z ${BUPSTASH_TEST_REPOSITORY_COMMAND+x}
then
  export BUPSTASH_REPOSITORY="$SCRATCH/bupstash-test-repo"
else
  unset BUPSTASH_REPOSITORY
  export BUPSTASH_REPOSITORY_COMMAND="$BUPSTASH_TEST_REPOSITORY_COMMAND"
fi

setup () {
  rm -rf "$SCRATCH"
  mkdir "$SCRATCH"
  bupstash new-key -o "$BUPSTASH_KEY"
  bupstash new-put-key -o "$SEND_KEY"
  bupstash new-metadata-key -o "$METADATA_KEY"
  if test -z "$BUPSTASH_REPOSITORY"
  then
    bupstash rm --query-encrypted --allow-many id="*"
    bupstash gc
    rm -f "$BUPSTASH_QUERY_CACHE"
    rm -f "$BUPSTASH_SEND_LOG"
  else
    bupstash init --repository="$BUPSTASH_REPOSITORY"
  fi
}

teardown () {
  rm -rf $SCRATCH
}

@test "simple put/get primary key" {
  data="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
  echo -n "$data" > "$SCRATCH/foo.txt"
  id="$(bupstash put :: "$SCRATCH/foo.txt")"
  test "$data" = "$(bupstash get id=$id )"
}

@test "simple put/get put key" {
  data="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
  echo -n "$data" > "$SCRATCH/foo.txt"
  id="$(bupstash put -k "$SEND_KEY" :: "$SCRATCH/foo.txt")"
  test "$data" = "$(bupstash get id=$id )"
}

@test "simple put/get no compression" {
  data="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
  echo -n "$data" > "$SCRATCH/foo.txt"
  id="$(bupstash put --no-compression -k "$SEND_KEY" :: "$SCRATCH/foo.txt")"
  test "$data" = "$(bupstash get id=$id )"
}

@test "random data" {
  for i in $(echo 0 1024 4096 1000000 100000000)
  do
    rm -f "$SCRATCH/rand.dat"
    head -c $i /dev/urandom > "$SCRATCH/rand.dat"
    id="$(bupstash put -k "$SEND_KEY" :: "$SCRATCH/rand.dat")"
    bupstash get id=$id > "$SCRATCH/got.dat"
    bupstash gc
    cmp --silent "$SCRATCH/rand.dat" "$SCRATCH/got.dat"
  done
}

@test "highly compressible data" {
  for i in $(echo 0 1024 4096 1000000 100000000)
  do
    rm -f "$SCRATCH/rand.dat"
    yes | head -c $i > "$SCRATCH/yes.dat"
    id="$(bupstash put -k "$SEND_KEY" :: "$SCRATCH/yes.dat")"
    bupstash get id=$id > "$SCRATCH/got.dat"
    bupstash gc
    cmp --silent "$SCRATCH/yes.dat" "$SCRATCH/got.dat"
  done
}

@test "key mismatch" {
  data="abc123"
  echo -n "$data" > "$SCRATCH/foo.txt"
  id="$(bupstash put :: "$SCRATCH/foo.txt")"
  bupstash new-key -o "$SCRATCH/wrong.key"
  run bupstash get -k "$SCRATCH/wrong.key" id=$id
  echo "$output" | grep -q "key does not match"
  if test $status = 0
  then
    exit 1
  fi
}

@test "corruption detected" {
  if test -z "$BUPSTASH_REPOSITORY"
  then
    skip
  fi
  data="abc123"
  echo -n "$data" > "$SCRATCH/foo.txt"
  id="$(bupstash put :: "$SCRATCH/foo.txt")"
  echo 'XXXXXXXXXXXXXXXXXXXXX' > "$BUPSTASH_REPOSITORY/data/"*;
  run bupstash get id=$id
  echo "$output"
  echo "$output" | grep -q "corrupt"
  if test $status = 0
  then
    exit 1
  fi
}

_concurrent_send_test_worker () {
  set -e
  for i in $(seq 50)
  do
    id="$(bupstash put -e --no-send-log :: echo $i)"
    test "$i" = "$(bupstash get id=$id)"
  done
}

@test "concurrent send" {
  for i in $(seq 10)
  do
    _concurrent_send_test_worker &
  done
  for i in $(seq 5)
  do
    bupstash list > /dev/null
    bupstash gc > /dev/null
  done
  wait
  count=$(bupstash list | wc -l)
  echo "count is $count"
  test 500 = $count
}

@test "simple search and listing" {
  for i in $(seq 100) # Enough to trigger more than one sync packet.
  do
    bupstash put -e "i=$i" :: echo $i
  done
  for k in $BUPSTASH_KEY $METADATA_KEY
  do
    test 100 = $(bupstash list -k "$k" | wc -l)
    test 1 = $(bupstash list -k "$k" i=100 | wc -l)
    test 0 = $(bupstash list -k "$k" i=101 | wc -l)
  done
}

@test "rm and gc" {
  test 0 = $(bupstash list | wc -l)
  test 0 = "$(sqlite3 "$SCRATCH/query-cache.sqlite3" 'select count(*) from ItemOpLog;')"
  id1="$(bupstash put -e :: echo hello1)"
  id2="$(bupstash put -e :: echo hello2)"
  test 2 = $(bupstash list | wc -l)
  test 2 = "$(sqlite3 "$SCRATCH/query-cache.sqlite3" 'select count(*) from ItemOpLog;')"
  if test -n "$BUPSTASH_REPOSITORY"
  then
    test 2 = "$(sqlite3 "$BUPSTASH_REPOSITORY/bupstash.sqlite3" 'select count(*) from ItemOpLog;')"
    test 2 = "$(sqlite3 "$BUPSTASH_REPOSITORY/bupstash.sqlite3" 'select count(*) from Items;')"
    test 2 = "$(ls "$BUPSTASH_REPOSITORY"/data | wc -l)"
  fi
  bupstash rm id=$id1
  test 1 = $(bupstash list | wc -l)
  test 3 = "$(sqlite3 "$SCRATCH/query-cache.sqlite3" 'select count(*) from ItemOpLog;')"
  if test -n "$BUPSTASH_REPOSITORY"
  then
    test 3 = "$(sqlite3 "$BUPSTASH_REPOSITORY/bupstash.sqlite3" 'select count(*) from ItemOpLog;')"
    test 1 = "$(sqlite3 "$BUPSTASH_REPOSITORY/bupstash.sqlite3" 'select count(*) from Items;')"
    test 2 = "$(ls "$BUPSTASH_REPOSITORY"/data | wc -l)"
  fi
  bupstash gc
  test 1 = $(bupstash list | wc -l)
  test 1 = "$(sqlite3 "$SCRATCH/query-cache.sqlite3" 'select count(*) from ItemOpLog;')"
  if test -n "$BUPSTASH_REPOSITORY"
  then
    test 1 = "$(sqlite3 "$BUPSTASH_REPOSITORY/bupstash.sqlite3" 'select count(*) from ItemOpLog;')"
    test 1 = "$(sqlite3 "$BUPSTASH_REPOSITORY/bupstash.sqlite3" 'select count(*) from Items;')"
    test 1 = "$(ls "$BUPSTASH_REPOSITORY"/data | wc -l)"
  fi
  bupstash rm id=$id2
  bupstash gc
  test 0 = $(bupstash list | wc -l)
  test 0 = "$(sqlite3 "$SCRATCH/query-cache.sqlite3" 'select count(*) from ItemOpLog;')"
  if test -n "$BUPSTASH_REPOSITORY"
  then
    test 0 = "$(sqlite3 "$BUPSTASH_REPOSITORY/bupstash.sqlite3" 'select count(*) from ItemOpLog;')"
    test 0 = "$(sqlite3 "$BUPSTASH_REPOSITORY/bupstash.sqlite3" 'select count(*) from Items;')"
    test 0 = "$(ls "$BUPSTASH_REPOSITORY"/data | wc -l)"
  fi
}

@test "rm and restore-removed" {
  test 0 = $(bupstash list | wc -l)
  test 0 = "$(sqlite3 "$SCRATCH/query-cache.sqlite3" 'select count(*) from ItemOpLog;')"
  id1="$(bupstash put -e :: echo hello1)"
  id2="$(bupstash put -e :: echo hello2)"
  test 2 = "$(bupstash list | wc -l)"
  test 2 = "$(sqlite3 "$SCRATCH/query-cache.sqlite3" 'select count(*) from ItemOpLog;')"
  if test -n "$BUPSTASH_REPOSITORY"
  then
    test 2 = "$(sqlite3 "$BUPSTASH_REPOSITORY/bupstash.sqlite3" 'select count(*) from ItemOpLog;')"
    test 2 = "$(sqlite3 "$BUPSTASH_REPOSITORY/bupstash.sqlite3" 'select count(*) from Items;')"
    test 2 = "$(ls "$BUPSTASH_REPOSITORY"/data | wc -l)"
  fi
  bupstash rm id=$id1
  bupstash restore-removed
  test 2 = "$(bupstash list | wc -l)"
  test 4 = "$(sqlite3 "$SCRATCH/query-cache.sqlite3" 'select count(*) from ItemOpLog;')"
  if test -n "$BUPSTASH_REPOSITORY"
  then
    test 4 = "$(sqlite3 "$BUPSTASH_REPOSITORY/bupstash.sqlite3" 'select count(*) from ItemOpLog;')"
    test 2 = "$(sqlite3 "$BUPSTASH_REPOSITORY/bupstash.sqlite3" 'select count(*) from Items;')"
    test 2 = "$(ls "$BUPSTASH_REPOSITORY"/data | wc -l)"
  fi
  bupstash rm id=$id1
  bupstash gc
  bupstash restore-removed
  test 1 = "$(bupstash list | wc -l)"
  test 1 = "$(sqlite3 "$SCRATCH/query-cache.sqlite3" 'select count(*) from ItemOpLog;')"
  if test -n "$BUPSTASH_REPOSITORY"
  then
    test 1 = "$(sqlite3 "$BUPSTASH_REPOSITORY/bupstash.sqlite3" 'select count(*) from ItemOpLog;')"
    test 1 = "$(sqlite3 "$BUPSTASH_REPOSITORY/bupstash.sqlite3" 'select count(*) from Items;')"
    test 1 = "$(ls "$BUPSTASH_REPOSITORY"/data | wc -l)"
  fi
  bupstash rm id=$id2
  bupstash gc
  bupstash restore-removed
  test 0 = "$(bupstash list | wc -l)"
  test 0 = "$(sqlite3 "$SCRATCH/query-cache.sqlite3" 'select count(*) from ItemOpLog;')"
  if test -n "$BUPSTASH_REPOSITORY"
  then
    test 0 = "$(sqlite3 "$BUPSTASH_REPOSITORY/bupstash.sqlite3" 'select count(*) from ItemOpLog;')"
    test 0 = "$(sqlite3 "$BUPSTASH_REPOSITORY/bupstash.sqlite3" 'select count(*) from Items;')"
    test 0 = "$(ls "$BUPSTASH_REPOSITORY"/data | wc -l)"
  fi
}

@test "query sync" {
  id1="$(bupstash put -e :: echo hello1)"
  test 1 = $(bupstash list | wc -l)
  id2="$(bupstash put -e :: echo hello2)"
  test 2 = $(bupstash list | wc -l)
  bupstash rm id=$id1
  test 1 = $(bupstash list | wc -l)
  bupstash gc
  test 1 = $(bupstash list | wc -l)
  bupstash rm id=$id2
  test 0 = $(bupstash list | wc -l)
  bupstash gc
  test 0 = $(bupstash list | wc -l)
}

@test "get via query" {
  bupstash put -e foo=bar  echo -n hello1 
  bupstash put -e foo=baz  echo -n hello2 
  bupstash put -e foo=bang echo -n hello2 
  test "hello2" = $(bupstash get "foo=ban*")
}

@test "rm via query" {
  bupstash put -e  foo=bar  echo -n hello1 
  bupstash put -e  foo=baz  echo -n hello2
  bupstash put -e  foo=bang echo -n hello2
  test 3 = $(bupstash list | wc -l)
  if bupstash rm "foo=*"
  then
    exit 1
  fi
  bupstash rm "foo=bar"
  test 2 = $(bupstash list | wc -l)
  bupstash rm --allow-many -k "$METADATA_KEY" "foo=*"
  test 0 = $(bupstash list | wc -l)
}

@test "send directory sanity" {
  mkdir "$SCRATCH/foo"
  echo a > "$SCRATCH/foo/a.txt"
  echo b > "$SCRATCH/foo/b.txt"
  mkdir "$SCRATCH/foo/bar"
  echo c > "$SCRATCH/foo/bar/c.txt"
  id=$(bupstash put :: "$SCRATCH/foo")
  test 5 = "$(bupstash get id=$id | tar -tf - | wc -l)"
  # Test again to excercise stat caching.
  id=$(bupstash put :: "$SCRATCH/foo")
  test 5 = "$(bupstash get id=$id | tar -tf - | wc -l)"
}

@test "send directory no stat cache" {
  mkdir "$SCRATCH/foo"
  echo a > "$SCRATCH/foo/a.txt"
  echo b > "$SCRATCH/foo/b.txt"
  mkdir "$SCRATCH/foo/bar"
  echo c > "$SCRATCH/foo/bar/c.txt"
  id=$(bupstash put --no-send-log :: "$SCRATCH/foo")
  test 5 = "$(bupstash get id=$id | tar -tf - | wc -l)"
  id=$(bupstash put --no-stat-caching :: "$SCRATCH/foo")
  test 5 = "$(bupstash get id=$id | tar -tf - | wc -l)"
}

@test "stat cache invalidated" {
  mkdir "$SCRATCH/foo"
  echo a > "$SCRATCH/foo/a.txt"
  id=$(bupstash put :: "$SCRATCH/foo")
  bupstash rm id=$id
  bupstash gc
  id=$(bupstash put :: "$SCRATCH/foo")
  bupstash get id=$id > /dev/null
}

@test "repository command" {
  if test -z "$BUPSTASH_REPOSITORY"
  then
    skip
  fi
  export BUPSTASH_REPOSITORY_COMMAND="bupstash serve $BUPSTASH_REPOSITORY"
  unset BUPSTASH_REPOSITORY
  data="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
  echo -n "$data" > "$SCRATCH/foo.txt"
  id="$(bupstash put :: "$SCRATCH/foo.txt")"
  test "$data" = "$(bupstash get id=$id )"
}

@test "key command" {
  export BUPSTASH_KEY_COMMAND="cat $BUPSTASH_KEY"
  data="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
  echo -n "$data" > "$SCRATCH/foo.txt"
  id="$(bupstash put :: "$SCRATCH/foo.txt")"
  test "$data" = "$(bupstash get id=$id )"
}

@test "long path" {
  mkdir "$SCRATCH/foo"
  mkdir -p "$SCRATCH/foo/"aaaaaaaaaaaaaaaaaaa/aaaaaaaaaaaaaaaaaaaaaaa\
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/aaaaaaaaaaaaaaaaaaaaaaa\
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/aaaaaaaaaaaaaaaaaaaaaaa\
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/aaaaaaaaaaaaaaaaaaaaaaa\
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/aaaaaaaaaaaaaaaaaaaaaaa
  id=$(bupstash put :: "$SCRATCH/foo")
  bupstash get id=$id | tar -tf - | wc -l
  test 7 = "$(bupstash get id=$id | tar -tf - | wc -l)"
}

@test "long link target" {
  mkdir "$SCRATCH/foo"
  ln -s llllllllllllllllllllllllllllllllllllllllllllllllllllllllllll\
llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll\
llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll\
llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll\
llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll\
    "$SCRATCH/foo/l"
  id=$(bupstash put :: "$SCRATCH/foo")
  test 2 = "$(bupstash get id=$id | tar -tf - | wc -l)"
}

@test "directory exclusions" {
  mkdir "$SCRATCH/foo"
  mkdir "$SCRATCH/foo/bar"
  mkdir "$SCRATCH/foo/bar/baz"
  touch "$SCRATCH/foo/bang"

  id=$(bupstash put :: "$SCRATCH/foo")
  test 4 = "$(bupstash get id=$id | tar -tf - | wc -l)"

  id=$(bupstash put --exclude="*/bang" :: "$SCRATCH/foo")
  test 3 = "$(bupstash get id=$id | tar -tf - | wc -l)"

  id=$(bupstash put --exclude="*/bar" :: "$SCRATCH/foo")
  test 2 = "$(bupstash get id=$id | tar -tf - | wc -l)"
}

@test "checkpoint plain data" {
  # Excercise the checkpointing code, does not check
  # cache invalidation, that is covered via unit tests.
  n=32000000
  export BUPSTASH_CHECKPOINT_BYTES=1
  head -c $n /dev/urandom > "$SCRATCH/rand.dat"
  id="$(bupstash put :: "$SCRATCH/rand.dat")"
  bupstash get id=$id > "$SCRATCH/got.dat"
  bupstash gc
  cmp --silent "$SCRATCH/rand.dat" "$SCRATCH/got.dat"
}

@test "checkpoint directories" {
  # Excercise the checkpointing code, does not check
  # cache invalidation, that is covered via unit tests.

  mkdir "$SCRATCH/foo"
  mkdir "$SCRATCH/foo/bar"
  mkdir "$SCRATCH/foo/bar/baz"
  touch "$SCRATCH/foo/bang"

  export BUPSTASH_CHECKPOINT_BYTES=1

  id=$(bupstash put :: "$SCRATCH/foo")
  test 4 = "$(bupstash get id=$id | tar -tf - | wc -l)"
}

@test "rm from stdin" {
  id1="$(bupstash put -e echo hello1)"
  id2="$(bupstash put -e echo hello2)"
  id3="$(bupstash put -e echo hello3)"
  test 3 = "$(bupstash list | wc -l)"
  echo "${id1}" | bupstash rm --ids-from-stdin
  test 2 = "$(bupstash list | wc -l)"
  echo -e "${id2}\n${id3}" | bupstash rm --ids-from-stdin
  bupstash list
  bupstash list | wc -l
  test 0 = "$(bupstash list | wc -l)"
}

_concurrent_modify_worker () {
  set -e
  while test $(date "+%s") -lt "$1"
  do
    touch $SCRATCH/t/a$2
    touch $SCRATCH/t/b$2
    touch $SCRATCH/t/c$2
    mkdir $SCRATCH/t/d$2
    touch $SCRATCH/t/d$2/e$2
    ln -s a $SCRATCH/t/f$2

    echo a >> $SCRATCH/t/a$2
    echo b >> $SCRATCH/t/b$2
    echo c >> $SCRATCH/t/c$2
    echo e >> $SCRATCH/t/d$2/e$2

    rm $SCRATCH/t/a$2
    rm $SCRATCH/t/b$2
    rm $SCRATCH/t/c$2
    rm -rf $SCRATCH/t/d$2
    rm $SCRATCH/t/f$2
  done
}

@test "concurrent dir modify during put" {
  now=$(date "+%s")
  test_end=$(($now + 5))
  mkdir $SCRATCH/t
  for i in $(seq 10)
  do
    _concurrent_modify_worker $test_end $i &
  done

  while test $(date "+%s") -lt "$test_end"
  do
    bupstash put "$SCRATCH/t"
  done

  wait

  for id in $(bupstash list --format=jsonl | jq -r .id)
  do
    bupstash get id=$id | tar -t > /dev/null
  done
}

@test "list and rm no key" {
  bupstash put -e echo hello1
  bupstash put -e echo hello2
  unset BUPSTASH_KEY
  test 2 = "$(bupstash list --query-encrypted | wc -l)"
  bupstash rm --allow-many --query-encrypted id='*'
  test 0 = "$(bupstash list --query-encrypted | wc -l)"
}

@test "pick and index" {
  
  mkdir $SCRATCH/foo
  mkdir $SCRATCH/foo/baz
  
  for n in `seq 5`
  do
    # Create some test files scattered in two directories.
    # Small files
    head -c "$(shuf -i 10-1000 -n 1)" /dev/urandom > "$SCRATCH/foo/$(uuidgen)"
    head -c "$(shuf -i 10-1000 -n 1)" /dev/urandom > "$SCRATCH/foo/baz/$(uuidgen)"
    # Large files
    head -c "$(shuf -i 10000-10000000 -n 1)" /dev/urandom > "$SCRATCH/foo/$(uuidgen)"
    head -c "$(shuf -i 10000-10000000 -n 1)" /dev/urandom > "$SCRATCH/foo/baz/$(uuidgen)"
  done

  # Loop so we test cache code paths
  for i in `seq 2`
  do
    id="$(bupstash put $SCRATCH/foo)"
    for f in $(sh -c "cd $SCRATCH/foo && find . -type f | cut -c 3-")
    do
      cmp <(bupstash get --pick "$f" id=$id) "$SCRATCH/foo/$f"
    done
    test $(bupstash get id=$id | tar -t | wc -l) = 22
    test $(bupstash get --pick . id=$id | tar -t | wc -l) = 22
    test $(bupstash get --pick baz id=$id | tar -t | wc -l) = 11
    test $(bupstash list-contents  id=$id | wc -l) = 22
  done
}

@test "multi dir put" {
  mkdir "$SCRATCH/foo"
  mkdir "$SCRATCH/foo/bar"
  mkdir "$SCRATCH/foo/bar/baz"
  mkdir "$SCRATCH/foo/bang"
  echo foo > "$SCRATCH/foo/bar/baz/a.txt"

  id=$(bupstash put :: "$SCRATCH/foo/bar" "$SCRATCH/foo/bar/baz" "$SCRATCH/foo/bang")
  bupstash get id=$id | tar -tf -
  test 5 = "$(bupstash get id=$id | tar -tf - | wc -l)"
}

@test "pick torture" {
  if test -z "$PICK_TORTURE_DIR"
  then
    skip "Set PICK_TORTURE_DIR to run this test."
  fi

  # Put twice so we test caching code paths.
  id1=$(bupstash put :: "$PICK_TORTURE_DIR")
  id2=$(bupstash put :: "$PICK_TORTURE_DIR")

  for id in $(echo $id1 $id2)
  do
    for f in $(sh -c "cd $PICK_TORTURE_DIR ; find . -type f | cut -c 3- ")
    do
      echo file "'$f'"
      cmp <(bupstash get --pick "$f"  "id=$id") "$PICK_TORTURE_DIR/$f"
    done

    for d in $(sh -c "cd $PICK_TORTURE_DIR ; find . -type d | sed 's,^\./,,g' ")
    do
      echo dir "'$d'"
      diff -u \
        <(bupstash get --pick "$d"  "id=$id" | tar -tf - | sort) \
        <(sh -c "cd \"$PICK_TORTURE_DIR\" ; find "$d" | sed 's,^\./,,g' | sort")
    done
  done
}