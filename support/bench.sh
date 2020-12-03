hyperfine \
  './bupstash-a put -q -k /tmp/x.key -r /tmp/repox/ /tmp/linux-5.9.8/' \
  './bupstash-b put -q -k /tmp/x.key -r /tmp/repox/ /tmp/linux-5.9.8/' \
  -p 'rm -rf /tmp/repox; bupstash init -r /tmp/repox'

