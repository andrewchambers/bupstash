
# Be extra careful to not mess with a user repository
unset BUPSTASH_REPOSITORY
unset BUPSTASH_REPOSITORY_COMMAND
unset BUPSTASH_KEY
unset BUPSTASH_KEY_COMMAND

export CLI_TEST_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
export SCRATCH="$BATS_TMPDIR/bupstash-test-scratch"
export BUPSTASH_KEY="$SCRATCH/bupstash-test-primary.key"
export PUT_KEY="$SCRATCH/bupstash-test-put.key"
export METADATA_KEY="$SCRATCH/bupstash-test-metadata.key"
export LIST_CONTENTS_KEY="$SCRATCH/bupstash-test-list-contents.key"
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
  bupstash new-sub-key --put -o "$PUT_KEY"
  bupstash new-sub-key --list -o "$METADATA_KEY"
  bupstash new-sub-key --list-contents -o "$LIST_CONTENTS_KEY"
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
  id="$(bupstash put -k "$PUT_KEY" :: "$SCRATCH/foo.txt")"
  test "$data" = "$(bupstash get id=$id )"
}

@test "simple put/get no compression" {
  data="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
  echo -n "$data" > "$SCRATCH/foo.txt"
  id="$(bupstash put --no-compression -k "$PUT_KEY" :: "$SCRATCH/foo.txt")"
  test "$data" = "$(bupstash get id=$id )"
}

@test "random data" {
  for i in $(echo 0 1024 4096 1000000 100000000)
  do
    rm -f "$SCRATCH/rand.dat"
    if test $i -gt 0
    then
      head -c $i /dev/urandom > "$SCRATCH/rand.dat"
    else
      # Workaround since macOS's head doesn't support a byte count of 0
      touch "$SCRATCH/rand.dat"
    fi
    id="$(bupstash put -k "$PUT_KEY" :: "$SCRATCH/rand.dat")"
    bupstash get id=$id > "$SCRATCH/got.dat"
    bupstash gc
    cmp --silent "$SCRATCH/rand.dat" "$SCRATCH/got.dat"
  done
}

@test "highly compressible data" {
  for i in $(echo 1024 4096 1000000 100000000)
  do
    rm -f "$SCRATCH/yes.dat"
    dd if=/dev/zero of="$SCRATCH/yes.dat" bs=$i count=1
    id="$(bupstash put -k "$PUT_KEY" :: "$SCRATCH/yes.dat")"
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
  wait
  count=$(bupstash list | expr $(wc -l))
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
    test 100 = $(bupstash list -k "$k" | expr $(wc -l))
    test 1 = $(bupstash list -k "$k" i=100 | expr $(wc -l))
    test 0 = $(bupstash list -k "$k" i=101 | expr $(wc -l))
  done
}

@test "rm and gc" {
  test 0 = $(bupstash list | expr $(wc -l))
  test 0 = "$(sqlite3 "$SCRATCH/query-cache.sqlite3" 'select count(*) from ItemOpLog;')"
  id1="$(bupstash put -e :: echo hello1)"
  id2="$(bupstash put -e :: echo hello2)"
  test 2 = $(bupstash list | expr $(wc -l))
  test 2 = "$(sqlite3 "$SCRATCH/query-cache.sqlite3" 'select count(*) from ItemOpLog;')"
  if test -n "$BUPSTASH_REPOSITORY"
  then
    test 2 = "$(ls "$BUPSTASH_REPOSITORY/items" | expr $(wc -l))"
    test 2 = "$(ls "$BUPSTASH_REPOSITORY"/data | expr $(wc -l))"
  fi
  bupstash rm id=$id1
  test 1 = $(bupstash list | expr $(wc -l))
  test 3 = "$(sqlite3 "$SCRATCH/query-cache.sqlite3" 'select count(*) from ItemOpLog;')"
  if test -n "$BUPSTASH_REPOSITORY"
  then
    test 1 = "$(ls "$BUPSTASH_REPOSITORY/items" | expr $(wc -l))"
    test 2 = "$(ls "$BUPSTASH_REPOSITORY"/data | expr $(wc -l))"
  fi
  bupstash gc
  test 1 = $(bupstash list | expr $(wc -l))
  test 1 = "$(sqlite3 "$SCRATCH/query-cache.sqlite3" 'select count(*) from ItemOpLog;')"
  if test -n "$BUPSTASH_REPOSITORY"
  then
    test 1 = "$(ls "$BUPSTASH_REPOSITORY/items" | expr $(wc -l))"
    test 1 = "$(ls "$BUPSTASH_REPOSITORY"/data | expr $(wc -l))"
  fi
  bupstash rm id=$id2
  bupstash gc
  test 0 = $(bupstash list | expr $(wc -l))
  test 0 = "$(sqlite3 "$SCRATCH/query-cache.sqlite3" 'select count(*) from ItemOpLog;')"
  if test -n "$BUPSTASH_REPOSITORY"
  then
    test 0 = "$(ls "$BUPSTASH_REPOSITORY"/data | expr $(wc -l))"
    test 0 = "$(ls "$BUPSTASH_REPOSITORY"/data | expr $(wc -l))"
  fi
}

@test "rm and restore-removed" {
  test 0 = $(bupstash list | expr $(wc -l))
  test 0 = "$(sqlite3 "$SCRATCH/query-cache.sqlite3" 'select count(*) from ItemOpLog;')"
  id1="$(bupstash put -e :: echo hello1)"
  id2="$(bupstash put -e :: echo hello2)"
  test 2 = "$(bupstash list | expr $(wc -l))"
  test 2 = "$(sqlite3 "$SCRATCH/query-cache.sqlite3" 'select count(*) from ItemOpLog;')"
  if test -n "$BUPSTASH_REPOSITORY"
  then
    test 2 = "$(ls "$BUPSTASH_REPOSITORY/items" | expr $(wc -l))"
    test 2 = "$(ls "$BUPSTASH_REPOSITORY"/data | expr $(wc -l))"
  fi
  bupstash rm id=$id1
  bupstash restore-removed
  test 2 = "$(bupstash list | expr $(wc -l))"
  test 4 = "$(sqlite3 "$SCRATCH/query-cache.sqlite3" 'select count(*) from ItemOpLog;')"
  if test -n "$BUPSTASH_REPOSITORY"
  then
    test 2 = "$(ls "$BUPSTASH_REPOSITORY/items" | expr $(wc -l))"
    test 2 = "$(ls "$BUPSTASH_REPOSITORY"/data | expr $(wc -l))"
  fi
  bupstash rm id=$id1
  bupstash gc
  bupstash restore-removed
  test 1 = "$(bupstash list | expr $(wc -l))"
  test 1 = "$(sqlite3 "$SCRATCH/query-cache.sqlite3" 'select count(*) from ItemOpLog;')"
  if test -n "$BUPSTASH_REPOSITORY"
  then
    test 1 = "$(ls "$BUPSTASH_REPOSITORY/items" | expr $(wc -l))"
    test 1 = "$(ls "$BUPSTASH_REPOSITORY"/data | expr $(wc -l))"
  fi
  bupstash rm id=$id2
  bupstash gc
  bupstash restore-removed
  test 0 = "$(bupstash list | expr $(wc -l))"
  test 0 = "$(sqlite3 "$SCRATCH/query-cache.sqlite3" 'select count(*) from ItemOpLog;')"
  if test -n "$BUPSTASH_REPOSITORY"
  then
    test 0 = "$(ls "$BUPSTASH_REPOSITORY/items" | expr $(wc -l))"
    test 0 = "$(ls "$BUPSTASH_REPOSITORY"/data | expr $(wc -l))"
  fi
}

@test "query sync" {
  id1="$(bupstash put -e :: echo hello1)"
  test 1 = $(bupstash list | expr $(wc -l))
  id2="$(bupstash put -e :: echo hello2)"
  test 2 = $(bupstash list | expr $(wc -l))
  bupstash rm id=$id1
  test 1 = $(bupstash list | expr $(wc -l))
  bupstash gc
  test 1 = $(bupstash list | expr $(wc -l))
  bupstash rm id=$id2
  test 0 = $(bupstash list | expr $(wc -l))
  bupstash gc
  test 0 = $(bupstash list | expr $(wc -l))
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
  test 3 = $(bupstash list | expr $(wc -l))
  if bupstash rm "foo=*"
  then
    exit 1
  fi
  bupstash rm "foo=bar"
  test 2 = $(bupstash list | expr $(wc -l))
  bupstash rm --allow-many -k "$METADATA_KEY" "foo=*"
  test 0 = $(bupstash list | expr $(wc -l))
}

@test "send directory sanity" {
  mkdir "$SCRATCH/foo"
  echo a > "$SCRATCH/foo/a.txt"
  echo b > "$SCRATCH/foo/b.txt"
  mkdir "$SCRATCH/foo/bar"
  echo c > "$SCRATCH/foo/bar/c.txt"
  id=$(bupstash put :: "$SCRATCH/foo")
  test 5 = "$(bupstash get id=$id | tar -tf - | expr $(wc -l))"
  # Test again to excercise stat caching.
  id=$(bupstash put :: "$SCRATCH/foo")
  test 5 = "$(bupstash get id=$id | tar -tf - | expr $(wc -l))"
}

@test "send directory no stat cache" {
  mkdir "$SCRATCH/foo"
  echo a > "$SCRATCH/foo/a.txt"
  echo b > "$SCRATCH/foo/b.txt"
  mkdir "$SCRATCH/foo/bar"
  echo c > "$SCRATCH/foo/bar/c.txt"
  id=$(bupstash put --no-send-log :: "$SCRATCH/foo")
  test 5 = "$(bupstash get id=$id | tar -tf - | expr $(wc -l))"
  id=$(bupstash put --no-stat-caching :: "$SCRATCH/foo")
  test 5 = "$(bupstash get id=$id | tar -tf - | expr $(wc -l))"
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
  test 7 = "$(bupstash get id=$id | tar -tf - | expr $(wc -l))"
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
  test 2 = "$(bupstash get id=$id | tar -tf - | expr $(wc -l))"
}

@test "directory exclusions" {
  mkdir "$SCRATCH/foo"
  mkdir "$SCRATCH/foo/bar"
  mkdir "$SCRATCH/foo/bar/baz"
  touch "$SCRATCH/foo/bang"

  id=$(bupstash put :: "$SCRATCH/foo")
  test 4 = "$(bupstash get id=$id | tar -tf - | expr $(wc -l))"

  id=$(bupstash put --exclude="*/bang" :: "$SCRATCH/foo")
  test 3 = "$(bupstash get id=$id | tar -tf - | expr $(wc -l))"

  id=$(bupstash put --exclude="*/bar" :: "$SCRATCH/foo")
  test 2 = "$(bupstash get id=$id | tar -tf - | expr $(wc -l))"
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
  test 4 = "$(bupstash get id=$id | tar -tf - | expr $(wc -l))"
}

@test "rm from stdin" {
  id1="$(bupstash put -e echo hello1)"
  id2="$(bupstash put -e echo hello2)"
  id3="$(bupstash put -e echo hello3)"
  test 3 = "$(bupstash list | expr $(wc -l))"
  echo "${id1}" | bupstash rm --ids-from-stdin
  test 2 = "$(bupstash list | expr $(wc -l))"
  echo -e "${id2}\n${id3}" | bupstash rm --ids-from-stdin
  test 0 = "$(bupstash list | expr $(wc -l))"
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

    echo "" > $SCRATCH/t/a$2
    echo "" > $SCRATCH/t/b$2
    echo "" > $SCRATCH/t/c$2
    echo "" > $SCRATCH/t/d$2/e$2

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

  for id in $(bupstash list --format=jsonl1 | jq -r .id)
  do
    bupstash get id=$id | tar -t > /dev/null
  done
}

@test "list and rm no key" {
  bupstash put -e echo hello1
  bupstash put -e echo hello2
  unset BUPSTASH_KEY
  test 2 = "$(bupstash list --query-encrypted | expr $(wc -l))"
  bupstash rm --allow-many --query-encrypted id='*'
  test 0 = "$(bupstash list --query-encrypted | expr $(wc -l))"
}

@test "pick and index" {
  
  mkdir $SCRATCH/foo
  mkdir $SCRATCH/foo/baz
  
  for n in `seq 5`
  do
    # Create some test files scattered in two directories.
    # Small files
    head -c $((10 + $(head -c 4 /dev/urandom | cksum | cut -f1 -d " " | head -c 3))) /dev/urandom > "$SCRATCH/foo/$(uuidgen)"
    head -c $((10 + $(head -c 4 /dev/urandom | cksum | cut -f1 -d " " | head -c 3))) /dev/urandom > "$SCRATCH/foo/baz/$(uuidgen)"
    # Large files
    head -c $((10000 + $(head -c 4 /dev/urandom | cksum | cut -f1 -d " " | head -c 7))) /dev/urandom > "$SCRATCH/foo/$(uuidgen)"
    head -c $((10000 + $(head -c 4 /dev/urandom | cksum | cut -f1 -d " " | head -c 7))) /dev/urandom > "$SCRATCH/foo/baz/$(uuidgen)"
  done

  # Loop so we test cache code paths
  for i in `seq 2`
  do
    id="$(bupstash put $SCRATCH/foo)"
    for f in $(sh -c "cd $SCRATCH/foo && find . -type f | cut -c 3-")
    do
      cmp <(bupstash get --pick "$f" id=$id) "$SCRATCH/foo/$f"
    done
    test $(bupstash get id=$id | tar -t | expr $(wc -l)) = 22
    test $(bupstash get --pick . id=$id | tar -t | expr $(wc -l)) = 22
    test $(bupstash get --pick baz id=$id | tar -t | expr $(wc -l)) = 11
    test $(bupstash list-contents  id=$id | expr $(wc -l)) = 22
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
  test 5 = "$(bupstash get id=$id | tar -tf - | expr $(wc -l))"
  test 5 = "$(bupstash list-contents id=$id | expr $(wc -l))"
  test 5 = "$(bupstash list-contents -k $LIST_CONTENTS_KEY id=$id | expr $(wc -l))"
}

@test "hard link short path" {
  mkdir "$SCRATCH/foo"
  touch "$SCRATCH/foo/a"
  ln "$SCRATCH/foo/a" "$SCRATCH/foo/b"

  id=$(bupstash put :: "$SCRATCH/foo")
  mkdir "$SCRATCH/restore"
  bupstash get id=$id | tar -C "$SCRATCH/restore" -xvf -

  echo -n 'x' >> "$SCRATCH/restore/a"
  test "x" = $(cat "$SCRATCH/restore/b")
}

@test "long hard link target" {
  if test $(uname) == "Darwin"
  then
    skip "Long symlinks are currently broken on macOS due to incompatible tar format"
  fi

  a="aaaaaaaaaa"
  name="$a$a$a$a$a$a$a$a$a$a$a$a$a$a$a$a$a$a$a$a"
  mkdir "$SCRATCH/foo"
  touch "$SCRATCH/foo/$name"
  ln "$SCRATCH/foo/$name" "$SCRATCH/foo/b"

  id=$(bupstash put :: "$SCRATCH/foo")
  mkdir "$SCRATCH/restore"
  bupstash get id=$id | tar -C "$SCRATCH/restore" -xvf -

  echo -n 'x' >> "$SCRATCH/restore/$name"
  test "x" = $(cat "$SCRATCH/restore/b")
}

@test "hard link to symlink" {
  # On macOS hard links to symlinks actually point to the original file
  if test $(uname) == "Darwin"
  then
    skip "Not applicable on macOS"
  fi

  mkdir "$SCRATCH/foo"
  touch "$SCRATCH/foo/a"
  ln -s "$SCRATCH/foo/a" "$SCRATCH/foo/b"
  ln "$SCRATCH/foo/b" "$SCRATCH/foo/c"

  id=$(bupstash put :: "$SCRATCH/foo")
  mkdir "$SCRATCH/restore"
  bupstash get id=$id | tar -C "$SCRATCH/restore" -xvf -

  readlink "$SCRATCH/restore/c"
}

@test "simple diff" {
  mkdir "$SCRATCH/d"
  echo -n "abc" > "$SCRATCH/d/a.txt"
  id1="$(bupstash put --no-send-log "$SCRATCH/d")"
  echo -n "def" > "$SCRATCH/d/b.txt"
  id2="$(bupstash put --no-send-log "$SCRATCH/d")"
  echo -n "hij" >> "$SCRATCH/d/b.txt"
  id3="$(bupstash put --no-send-log "$SCRATCH/d")"
  test 3 = "$(bupstash diff id=$id1 :: id=$id2 | expr $(wc -l))"
  test 2 = "$(bupstash diff id=$id1 :: id=$id2 | grep "^\\+" | expr $(wc -l))"
  test 2 = "$(bupstash diff id=$id2 :: id=$id3 | expr $(wc -l))"
  test 1 = "$(bupstash diff id=$id2 :: id=$id3 | grep "^\\+" | expr $(wc -l))"
}

@test "diff ignore" {
  mkdir "$SCRATCH/d"
  echo -n "abc" > "$SCRATCH/d/a.txt"
  id1="$(bupstash put --no-send-log "$SCRATCH/d")"
  echo -n "abc" > "$SCRATCH/d/a.txt"
  id2="$(bupstash put --no-send-log "$SCRATCH/d")"
  echo -n "def" > "$SCRATCH/d/a.txt"
  id3="$(bupstash put --no-send-log "$SCRATCH/d")"
  test 0 = "$(bupstash diff --ignore times id=$id1 :: id=$id2 | expr $(wc -l))"
  test 2 = "$(bupstash diff --ignore times id=$id2 :: id=$id3 | expr $(wc -l))"
  test 0 = "$(bupstash diff --ignore times,content id=$id2 :: id=$id3 | expr $(wc -l))"
}

@test "access controls" {
  if ! test -d "$BUPSTASH_REPOSITORY" || test -n "$BUPSTASH_REPOSITORY_COMMAND"
  then
    skip "test requires a local repository"
  fi

  mkdir "$SCRATCH/d"
  id="$(bupstash put "$SCRATCH/d")"

  REPO="$BUPSTASH_REPOSITORY"
  unset BUPSTASH_REPOSITORY

  export BUPSTASH_REPOSITORY_COMMAND="bupstash serve --allow-get $REPO"
  bupstash get id=$id > /dev/null
  bupstash list
  bupstash list-contents id=$id
  if bupstash init ; then exit 1 ; fi
  if bupstash put -e echo hi ; then exit 1 ; fi
  if bupstash rm id=$id ; then exit 1 ; fi
  if bupstash restore-removed ; then exit 1 ; fi
  if bupstash gc ; then exit 1 ; fi

  export BUPSTASH_REPOSITORY_COMMAND="bupstash serve --allow-put $REPO"
  bupstash put -e echo hi
  if bupstash init ; then exit 1 ; fi
  if bupstash get id=$id > /dev/null ; then exit 1 ; fi
  if bupstash list  ; then exit 1 ; fi
  if bupstash list-contents id=$id  ; then exit 1 ; fi
  if bupstash rm id=$id ; then exit 1 ; fi
  if bupstash restore-removed ; then exit 1 ; fi
  if bupstash gc ; then exit 1 ; fi

  export BUPSTASH_REPOSITORY_COMMAND="bupstash serve --allow-list $REPO"
  bupstash list
  bupstash list-contents id=$id
  if bupstash init ; then exit 1 ; fi
  if bupstash get id=$id > /dev/null ; then exit 1 ; fi
  if bupstash put -e echo hi ; then exit 1 ; fi
  if bupstash rm id=$id ; then exit 1 ; fi
  if bupstash restore-removed ; then exit 1 ; fi
  if bupstash gc ; then exit 1 ; fi

  export BUPSTASH_REPOSITORY_COMMAND="bupstash serve --allow-gc $REPO"
  if bupstash init ; then exit 1 ; fi
  if bupstash put -e echo hi ; then exit 1 ; fi
  if bupstash get id=$id > /dev/null ; then exit 1 ; fi
  if bupstash list  ; then exit 1 ; fi
  if bupstash list-contents id=$id  ; then exit 1 ; fi
  if bupstash rm id=$id ; then exit 1 ; fi
  if bupstash restore-removed ; then exit 1 ; fi
  bupstash gc

  export BUPSTASH_REPOSITORY_COMMAND="bupstash serve --allow-remove $REPO"
  bupstash list
  bupstash list-contents id=$id
  if bupstash init ; then exit 1 ; fi
  if bupstash get id=$id > /dev/null ; then exit 1 ; fi
  if bupstash put -e echo hi ; then exit 1 ; fi
  if bupstash restore-removed ; then exit 1 ; fi
  if bupstash gc ; then exit 1 ; fi
  # delete as the last test
  bupstash rm id=$id

  export BUPSTASH_REPOSITORY_COMMAND="bupstash serve --allow-get --allow-put $REPO"
  bupstash restore-removed
}

@test "pick fuzz torture" {
  
  rand_dir="$SCRATCH/random_dir"
  restore_dir="$SCRATCH/restore_dir"
  copy_dir="$SCRATCH/copy_dir"

  for i in `seq 100`
  do
    rm -rf "$rand_dir"

    "$BATS_TEST_DIRNAME/mk-random-dir.py" "$rand_dir"

    # Put twice so we test caching code paths.
    id1=$(bupstash put :: "$rand_dir")
    id2=$(bupstash put :: "$rand_dir")

    for id in $(echo $id1 $id2)
    do
      for f in $(cd "$rand_dir" ; find . -type f | cut -c 3-)
      do
        cmp <(bupstash get --pick "$f"  "id=$id") "$rand_dir/$f"
      done

      for d in $(cd "$rand_dir" ; find . -type d | sed 's,^\./,,g')
      do
        rm -rf "$copy_dir" "$restore_dir"
        mkdir "$copy_dir" "$restore_dir"

        tar -C "$rand_dir" -cf - $d | tar -C "$copy_dir" -xf -
        bupstash get --pick "$d" "id=$id" | tar -C "$restore_dir" -xf -

        diff -u \
          <(cd "$restore_dir" ; find . | sort) \
          <(cd "$copy_dir" ; find . | sort)

        for f in $(cd "$copy_dir" ; find . -type f | cut -c 3-)
        do
          cmp "$copy_dir/$f" "$restore_dir/$f"
        done
      done
    
      bupstash rm id=$id
    done

    bupstash gc
  done
}


@test "repo rollback torture" {
  if ! test -d "$BUPSTASH_REPOSITORY" || \
       test -n "$BUPSTASH_REPOSITORY_COMMAND"
  then
    skip "test requires a local repository"
  fi

  REPO="$BUPSTASH_REPOSITORY"
  unset BUPSTASH_REPOSITORY

  now=$(date "+%s")
  test_end=$(($now + 15))

  while test $(date "+%s") -lt "$test_end"
  do
    # XXX This timeout scheme is very brittle.
    export BUPSTASH_REPOSITORY_COMMAND="timeout -s KILL 0.0$(($RANDOM % 10)) bupstash serve $REPO"
    bupstash put -e echo $(uuidgen) || true
    bupstash gc > /dev/null || true
    bupstash rm --allow-many "id=f*" || true
    if test "$(($RANDOM % 2))" = 0
    then
      bupstash restore-removed || true
    fi
  done

  unset BUPSTASH_REPOSITORY_COMMAND
  export BUPSTASH_REPOSITORY="$REPO"

  bupstash gc > /dev/null
  bupstash list --query-cache="$SCRATCH/sanity.qcache" > /dev/null
}

@test "parallel thrash" {
  
  if ! ps --version | grep -q procps-ng
  then
    skip "test requires procps-ng"
  fi

  which bwrap > /dev/null || skip bwrap missing
  # Use bwrap to help ensure proper cleanup and protect the host processes from kills.
  bwrap \
    --die-with-parent \
    --unshare-net \
    --unshare-pid \
    --dev-bind / / \
    bash "$BATS_TEST_DIRNAME"/parallel-thrash.sh
}

@test "s3 parallel thrash" {
  if ! ps --version | grep -q procps-ng
  then
    skip "test requires procps-ng"
  fi
  which bwrap > /dev/null || skip bwrap missing
  which bupstash-s3-storage > /dev/null || skip "bupstash-s3-storage missing"
  which minio > /dev/null || skip "minio missing"
  which mc > /dev/null || skip "mc missing"
  
  # This test uses a lot of file descriptors.
  ulimit -n $(ulimit -Hn)
  # Use bwrap to help ensure proper cleanup and protect the host processes from kills.
  bwrap \
    --die-with-parent \
    --unshare-net \
    --unshare-pid \
    --dev-bind / / \
    -- $(which bash) "$BATS_TEST_DIRNAME"/s3-parallel-thrash.sh
}