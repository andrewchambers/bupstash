set -xu

export SCRATCH=/tmp/diod-thrash
export N_WORKERS=8
export DIOD_PORT=1888

cleanup () {
    for m in $(ls $SCRATCH/mnt/)
    do
      if mountpoint -q "$SCRATCH/mnt/$m"
      then
        sudo umount "$SCRATCH/mnt/$m"
      fi
    done
    killall bupstash
    killall diod
    trap - SIGTERM
    rm -rf "$SCRATCH"
}

cleanup
trap "cleanup" SIGINT SIGTERM EXIT

rm -rf "$SCRATCH"
mkdir -p "$SCRATCH/root"
export BUPSTASH_KEY="$SCRATCH/t.key"
export BUPSTASH_REPOSITORY="$SCRATCH/root/repo"

bupstash new-key -o "$BUPSTASH_KEY"
bupstash init -r "$SCRATCH/root/repo"

diod -l "127.0.0.1:$DIOD_PORT" -f -n -S -U $(whoami) -e "$SCRATCH/root" &
sleep 1

for i in $(seq $((N_WORKERS-1)))
do
  mountpoint="$SCRATCH/mnt/$i"
  mkdir -p "$SCRATCH/mnt/$i"
  if ! sudo diodmount \
      -n \
      -v \
      -o "port=$DIOD_PORT,uname=$(whoami)" \
      "127.0.0.1:$SCRATCH/root" \
      "$mountpoint"
  then
    exit 1
  fi
done

bupstash init -r "$SCRATCH/sync-source-repo"

rm -f "$SCRATCH/thrash.summary"
sqlite3 "$SCRATCH/thrash.summary" "create table thrash_results(name, count, unique(name));"

inc_result () {
  sqlite3 "$SCRATCH/thrash.summary" \
    "PRAGMA busy_timeout = 10000;
     begin immediate;
     insert into thrash_results(name, count) values('$1', 0)
     on conflict(name) do update set count=count+1 where name = '$1'; commit;" > /dev/null
}

thrash_worker () {

  export BUPSTASH_REPOSITORY="$1"

  for i in $(seq 15)
  do
    expected=$(uuidgen)
    id=$(bupstash put -q -e --no-send-log thrash_test=yes :: echo $expected)

    if test "$?" = 0
    then
      inc_result "put-ok"

      actual="$(bupstash get -q id=$id)"
      if test "$?" = 0
      then
        inc_result "get-ok"
        if test "$expected" != "$actual"
        then
          inc_result "get-corrupt"
        fi
      else
        inc_result "get-fail"
      fi

      bupstash rm -q id="$id" >&2
      if test "$?" = 0
      then
        inc_result "rm-ok"
      else
        inc_result "rm-fail"
      fi
    else
      inc_result "put-fail"
    fi

    expected=$(uuidgen)
    id=$(bupstash put -r "$SCRATCH/sync-source-repo" -q -e --no-send-log thrash_test=yes :: echo $expected)
    bupstash sync -r "$SCRATCH/sync-source-repo" --to "$BUPSTASH_REPOSITORY" -q id="$id" >&2
    if test "$?" = 0
    then
      inc_result "sync-ok"

      actual="$(bupstash get -q id=$id)"
      if test "$?" = 0
      then
        inc_result "sync-get-ok"
        if test "$expected" != "$actual"
        then
          inc_result "sync-get-corrupt"
        fi
      else
        inc_result "sync-get-fail"
      fi

      bupstash rm -q id="$id" >&2
      if test "$?" = 0
      then
        inc_result "rm-ok"
      else
        inc_result "rm-fail"
      fi
    else
      inc_result "sync-fail"
    fi
    bupstash rm -q -r "$SCRATCH/sync-source-repo" id="$id" >&2

    bupstash recover-removed -q >&2
    if test "$?" = 0
    then
      inc_result "recover-removed-ok"
    else
      inc_result "recover-removed-fail"
    fi

    bupstash gc -q >&2
    if test "$?" = 0
    then
      inc_result "gc-ok"
    else
      inc_result "gc-fail"
    fi
  done

  rm -f "$SCRATCH/want_chaos"
}

bupstash_serve_chaos_worker () {
  while test -f "$SCRATCH/want_chaos"
  do
    kill -9 $(ps -aux  | grep 'bupstash serve' | grep -v "grep" | awk '{print $2}' | shuf | head -n $(($RANDOM/$N_WORKERS)))
    sleep 1
  done
}

# This loop is to control the max size of the repository.
for i in $(seq 10)
do

  bupstash rm --allow-many thrash_test=yes >&2
  bupstash gc >&2

  background_workers=()
  # At least enough workers so the scheduler hopefully
  # interleaves them in interesting ways.
  for j in $(seq $(($N_WORKERS-1)))
  do
    thrash_worker "$SCRATCH/mnt/$j/repo" &
    background_workers+=($!)
  done
  # One worker not via diod.
  thrash_worker "$SCRATCH/root/repo" &
  background_workers+=($!)

  touch "$SCRATCH/want_chaos"
  bupstash_serve_chaos_worker &
  background_workers+=($!)

  wait ${background_workers[@]}

  for id in $(bupstash list -q --format=jsonl1 | jq -r .id)
  do
    bupstash get -q id=$id > /dev/null
    if test "$?" != 0
    then
      inc_result "get-corrupt"
    fi
  done

  if sqlite3 "$SCRATCH/thrash.summary" 'select * from thrash_results;' | grep -q 'get\-corrupt'
  then
    echo "invariant check failed, 'get' should never return a corrupt result"
    exit 1
  fi

  if sqlite3 "$SCRATCH/thrash.summary" 'select * from thrash_results;' | grep -q 'sync\-get\-corrupt'
  then
    echo "invariant check failed, 'sync' should never return a corrupt result"
    exit 1
  fi

done

if test "$(sqlite3 "$SCRATCH"/thrash.summary "select count from thrash_results where name='put-ok';")" = ""
then
  echo "at least one 'put' operation must succeed for the test to pass."
  exit 1
fi

if test "$(sqlite3 "$SCRATCH"/thrash.summary "select count from thrash_results where name='sync-ok';")" = ""
then
  echo "at least one 'sync' operation must succeed for the test to pass."
  exit 1
fi

if test "$(sqlite3 "$SCRATCH"/thrash.summary "select count from thrash_results where name='gc-ok';")" = ""
then
  echo "at least one 'gc' operation must succeed for the test to pass."
  exit 1
fi

trap - EXIT

set +x
echo "test results..."
sqlite3 "$SCRATCH/thrash.summary" 'select * from thrash_results order by name;'
echo "test passed"

