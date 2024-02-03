set -xu

if test "${SCRATCH:-}" = ""
then
  export SCRATCH=/tmp
else
  export SCRATCH
fi

export BUPSTASH_REPOSITORY="$SCRATCH/thrash_repo"
export BUPSTASH_KEY="$SCRATCH/thrash.key"
export BUPSTASH_QUERY_CACHE="$SCRATCH/thrash.qcache"
export MINIO_ACCESS_KEY="thrash_access"
export MINIO_SECRET_KEY="thrash_secret"
export N_WORKERS=$(nproc)

trap "trap - SIGTERM ; kill -9 -- -$$" SIGINT SIGTERM EXIT

rm -rf "$BUPSTASH_REPOSITORY"
rm -f "$BUPSTASH_KEY"

bupstash new-key -o "$BUPSTASH_KEY"
bupstash init --storage \
"{\"ExternalStore\":{\"path\":\"s3://thrash_access:thrash_secret@thrashbucket?secure=false&endpoint=localhost%3A9000\",\"socket_path\":\"$SCRATCH/bupstash-s3-storage.sock\"}}"
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
  for i in $(seq 50)
  do
    expected=$(uuidgen)
    
    id=$(bupstash put -q -e --no-send-log -t thrash_test=yes -- echo $expected)
    
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

bupstash_s3_plugin_chaos_worker () {
  while test -f "$SCRATCH/want_chaos"
  do
    killall -s SIGKILL 'bupstash-s3-storage'
    sleep 1
  done
}

s3_plugin_supervisor () {
  cd "$SCRATCH"
  while true
  do
    rm -f "./bupstash-s3-storage.sock"
    bupstash-s3-storage -quiescent-period 10ms >&2
  done
}

minio server "$SCRATCH/miniodata" >&2 &
minio_pid="$!"
s3_plugin_supervisor &
s3_plugin_supervisor_pid="$!"
# give both some time to start.
sleep 1

# Configure the test minio instance.
rm -rf "$SCRATCH/mc"
mc config host add thrashminio http://127.0.0.1:9000 thrash_access thrash_secret >&2 

# Outer loop is to control the size of the gc set.
for i in $(seq 50)
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
  bupstash_s3_plugin_chaos_worker &
  background_workers+=($!)

  wait ${background_workers[@]}

  for id in $(bupstash list -q --format=jsonl | jq -r .id)
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

done

if test $(sqlite3 "$SCRATCH"/thrash.summary "select count from thrash_results where name='put-ok';") = ""
then
  echo "at least one 'put' operation must succeed for the test to pass."
  exit 1
fi

if test $(sqlite3 "$SCRATCH"/thrash.summary "select count from thrash_results where name='gc-ok';") = ""
then
  echo "at least one 'gc' operation must succeed for the test to pass."
  exit 1
fi

# Cleanup any remains
kill $s3_plugin_supervisor_pid
kill $minio_pid

# XXX hacky, but cleanup any bupstash-s3-storage instances that might have been restarted by the supervisor.
sleep 0.5
killall bupstash-s3-storage
wait

trap - EXIT

set +x


echo "test results..."
sqlite3 "$SCRATCH/thrash.summary" 'select * from thrash_results order by name;'
echo "test passed"

