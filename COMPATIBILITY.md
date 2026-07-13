# Compatibility

Compatibility means the client emits VLESS v0 TCP over WebSocket over verified
TLS to the exact Worker hostname and path. It does not mean support for other
VLESS transports, Flow, UDP, REALITY, XTLS, or Mux.

## Recorded baseline

| Client | Version/revision | Configuration syntax | Live Worker E2E |
| --- | --- | --- | --- |
| Xray-core | v26.7.11 / `50231eaff98ccc31b5cbd247a721c16e97fe5ec1` | Passed (`run -test`) | Passed 2026-07-12 |
| sing-box | v1.13.14 / `25a600db24f7680ad9806ce5427bd0ab8afe1114` | Passed (`check`) | Passed 2026-07-12 |
| Mihomo | v1.19.28 / `cbd11db1e13a75d8e680e0fe7742c95be4cba2be` | Passed (`-t`) | Passed 2026-07-12 |
| Shadowrocket | App Store 2.2.90 observed | VLESS URI and QR syntax passed | Real-device import/connection pending |

Syntax validation is not a connection result. The three executable-client live
results above are backed by the sanitized record below; Shadowrocket remains a
separate real-device gate.

The opt-in Stage-1 loopback reference test builds the unmodified pinned Xray
server/client and passes a TCP echo round trip, 256 KiB HTTP download, and
128 KiB HTTP upload. In the same run, a transparent loopback observer removes
the client WebSocket masking, retains one IPv4, domain, and IPv6 VLESS request
header in memory, sanitizes each UUID and destination, and byte-compares all
three shapes with their independent canonical fixtures. That is protocol/reference
evidence only; it does not exercise Cloudflare TLS, a Custom Domain, edge
`connect()`, sing-box, Mihomo, or Shadowrocket and therefore does not change the
live table above.

```sh
CF_VLESS_TEST_LOCAL_REFERENCE=1 go test ./internal/xray \
  -run '^TestLocalPinnedXrayVLESSWebSocketReferencePair$' -count=1 -v
```

## Live acceptance record

In an anonymized 2026-07-12 validation run, each unmodified executable client
in the table passed against an operator-controlled Worker hostname with verified
public DNS and TLS. The fresh matrix contained 36 gates and zero failures:

| Gate | Result for Xray, sing-box, and Mihomo |
| --- | --- |
| Ordinary HTTPS through the tunnel | Passed |
| Download | Passed, 10 MiB |
| Upload | Passed, exact 2 MiB random payload echoed byte-for-byte |
| Download throughput | 33.130 / 34.309 / 36.792 Mbps minimum / median / maximum across clients |
| Upload throughput | 19.692 / 20.068 / 20.287 Mbps minimum / median / maximum across clients |
| Fresh tunnel establishment | Ten samples: 87.7 ms median, 127.2 ms p90, 183.9 ms maximum |
| Active TCP keepalive/echo | Passed, 30 seconds on the same connection |
| Simultaneous connections | Passed, four connections |
| Fresh reconnect after disconnect | Passed, three reconnects |
| Truly idle resume | Passed separately after 45 seconds on the same authenticated WebSocket/TCP session |

An ordinary direct HTTPS request to the public hostname also returned the
Worker's exact generic 404 with successful certificate verification. The
sanitized report retained only versions, gate names, byte counts, durations,
concurrency, reconnect count, time window, and pass/fail; it did not retain a
UUID, path, client address, endpoint, or traffic contents. A separate 75-second
idle attempt was excluded from Worker results because the upstream test service
closed its own idle TCP connection; the 30-second active gate and independent
45-second true-idle resume are the controlled records.

On 2026-07-13 UTC, a separate sing-box v1.13.14 policy gate used the current
deployed Worker and established two explicit TCP connections through the
client's mixed test inbound. A known mainland China address selected
`outbound/direct[direct]` and completed a verified TLS handshake; a known
foreign address selected `outbound/vless[proxy]` and completed a separate
verified TLS handshake through the Worker. Client logs were retained only in
memory and reduced to those two boolean route assertions.

Shadowrocket additionally requires a real-device import from both raw URI and
QR code followed by the checklist in `research/client-compatibility.md`. The
generated raw URI and QR encode the same syntactically valid payload, but that
is not a real-device connection result.

The generated `sing-box.gif` is separately verified by decoding and assembling
every QRS frame, validating the stream checksum and libbox profile envelope,
and comparing its embedded configuration byte-for-byte with `sing-box.json`.
An import with a current official sing-box app is still a device
interoperability gate; it is not included in the executable-client live result
above.

## Version traps

- Current Xray uses flat VLESS outbound fields, `streamSettings.method:
  "websocket"`, and `wsSettings.host`. Its legacy `vnext`, `network: "ws"`, and
  `headers.Host` forms are intentionally not generated.
- Xray warns that WebSocket is deprecated in favor of XHTTP. This repository's
  fixed protocol remains WebSocket; a warning is not permission to change it.
- sing-box uses VLESS `network: "tcp"` to restrict the command and
  `transport.type: "ws"` for the outer transport. The shipped profile uses a
  TUN inbound, the official `geoip-cn` rule set for direct mainland ranges, and
  an explicit `proxy` final route for unmatched public TCP.
- Mihomo uses `network: ws`, `udp: false`, TLS verification, and an empty plain
  VLESS encryption value.
- Shadowrocket publishes no normative VLESS URI parser grammar. The generated
  URI follows Xray's share-link proposal and remains manually unverified.

See `research/client-compatibility.md` and
`docs/client-configurations.md` for the exact schemas.
