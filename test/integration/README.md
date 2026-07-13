# Integration sequence

## Stage 1: local pinned-Xray reference pair

Run the local reference gate before any Worker integration test:

```sh
CF_VLESS_TEST_LOCAL_REFERENCE=1 go test ./internal/xray \
  -run '^TestLocalPinnedXrayVLESSWebSocketReferencePair$' -count=1 -v
```

The test verifies that `third_party/xray-core` is the clean gitlink at
`50231eaff98ccc31b5cbd247a721c16e97fe5ec1` (`v26.7.11`), builds its
unmodified `./main` package, and starts that binary once as a VLESS-over-
WebSocket server and once as a SOCKS-to-VLESS-over-WebSocket client. Through
the client it proves a TCP echo round trip, a 256 KiB HTTP download, and a
128 KiB HTTP upload against test-owned destinations.

All listeners and destinations use IPv4 or IPv6 loopback and ephemeral ports.
The canonical domain case is resolved inside the Xray server by an exact static
`example.com -> 127.0.0.1` mapping; the server uses that internal mapping before
applying an outbound policy that allows only `127.0.0.1/32` and `::1/128` TCP,
then blocks everything else. It never asks public DNS for the test domain.
Generated configs live in a test temporary directory with `0600` modes, use a
synthetic UUID, and disable Xray logging. Reference-pair traffic never leaves
loopback and makes no Cloudflare API, DNS/edge, account, credential, or
deployed-Worker contact. It omits TLS deliberately so this gate isolates
VLESS-over-WebSocket behavior; the live stage owns Cloudflare TLS coverage. A
cold Go module cache may separately cause the build toolchain to download
Xray's declared build dependencies; pre-populate that cache if the command must
run with network access disabled.

Initialize the submodule first if needed:

```sh
git submodule update --init third_party/xray-core
```

### Checked fixture provenance

[`test/fixtures/vless-v0.json`](../fixtures/vless-v0.json) is deterministic,
synthetic, and **source-derived**: `internal/testvectors` independently encodes
the VLESS v0 layout read from the pinned Xray source using sanitized UUIDs,
documentation addresses, and a fixed payload. It was not emitted by an Xray
process and is not a live packet, WebSocket-frame, or network capture. Passing
the Stage-1 behavioral interoperability gate does not change that provenance;
the checked fixture must not be described as Xray-generated or live-captured.

### In-memory reference capture

The same Stage-1 test inserts a transparent loopback TCP/WebSocket observer
between the real pinned client and server. It unmasks separate client streams,
retains one complete IPv4, domain, and IPv6 VLESS request header in memory,
replaces each UUID, port, and destination with its canonical fixture values,
and compares every sanitized header byte-for-byte with the corresponding
independent Go fixture. The raw headers, payloads, credentials, and requested
destinations are never persisted or printed. If the platform cannot bind IPv6
loopback (`EAFNOSUPPORT`, `EPROTONOSUPPORT`, or `EADDRNOTAVAIL`), the gate still
generates, captures, sanitizes, and verifies the pinned client's real IPv6
VLESS header; only the IPv6 echo round trip is reported as skipped. This
capture strengthens the wire-shape gate without changing the checked fixture's
source-derived provenance.

## Stage 2: live Cloudflare integration tests

Local Workerd/socket doubles prove parsing and lifecycle behavior but do not
prove Cloudflare edge `connect()` or client interoperability. The live sequence
is:

1. deploy a Worker and exact Custom Domain owned by the test account;
2. confirm the public certificate and WebSocket Upgrade;
3. test allowed and blocked outbound TCP directly on the edge;
4. run the pinned unmodified Xray client through download, upload, long-lived,
   reconnect, and concurrency probes;
5. repeat with pinned sing-box and Mihomo binaries;
6. run the separate Shadowrocket real-device checklist;
7. capture sanitized CPU/memory/latency/reliability evidence;
8. remove only the temporary named resources.

No local mock result may be copied into a live compatibility column.
