# Impairment tests

Live impairment tests are intentionally separate from mocks. Against a
temporary/owned deployed Worker, record behavior for latency, jitter, packet
loss, abrupt client close, destination FIN/RST, idle periods, runtime
disconnect/reconnect, parallel connections, and multi-megabyte bidirectional
traffic.

The integration harness must report missing prerequisites as failure and must
never include UUIDs, paths, client addresses, destinations, or traffic in its
saved report.
