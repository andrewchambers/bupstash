set -xu

if test "${SCRATCH:-}" = ""
then
  export SCRATCH=/tmp
else
  export SCRATCH
fi

export N_WORKERS=$(nproc)

trap "trap - SIGTERM ; kill -9 -- -$$" SIGINT SIGTERM EXIT

if test -n "${BUPSTASH_REPOSITORY_COMMAND:-}"
then
  export BUPSTASH_TO_REPOSITORY_COMMAND="${BUPSTASH_REPOSITORY_COMMAND}"
fi
if test -n "${BUPSTASH_REPOSITORY:-}"
then
  export BUPSTASH_TO_REPOSITORY="${BUPSTASH_REPOSITORY}"
fi
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
    bupstash sync -r "$SCRATCH/sync-source-repo" -q id="$id" >&2
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
  for j in $(seq $N_WORKERS)
  do
    thrash_worker &
    background_workers+=($!)
  done

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
    echo "invariant check failed, 'get' should never return a corrupt result"
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

