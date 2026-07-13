# Client configuration outputs

`cf-vless config` renders five client artifacts (four configuration formats)
from one validated deployment record. The implementation lives in the Go
client-format packages.

## Canonical input

The renderer receives one UUID, server hostname, port 443, TLS server name, WebSocket Host, randomized absolute WebSocket path, and user-selected display name. The deployment hostname, TLS name, and WebSocket Host are normally the same dedicated Cloudflare hostname.

The renderer must not accept protocol choices. Every output is plain VLESS v0 TCP over WebSocket over verified TLS. It must not enable UDP, Mux, early data, VLESS Encryption, Vision, REALITY, XHTTP, gRPC, or any other protocol or transport.

## Field mapping

| Meaning | VLESS URI / Shadowrocket | Xray JSON v26.7.11 | sing-box JSON v1.13.14 | Mihomo YAML v1.19.28 |
| --- | --- | --- | --- | --- |
| UUID | URI user information | `settings.id` | `uuid` | `uuid` |
| server | URI host | `settings.address` | `server` | `server` |
| port | `:443` | `settings.port: 443` | `server_port: 443` | `port: 443` |
| plain VLESS | `encryption=none` | `settings.encryption: "none"` | no encryption field | `encryption: ""` |
| TLS | `security=tls` | `streamSettings.security: "tls"` | `tls.enabled: true` | `tls: true` |
| TLS name | `sni` | `tlsSettings.serverName` | `tls.server_name` | `servername` |
| WebSocket | `type=ws` | `streamSettings.method: "websocket"` | `transport.type: "ws"` | `network: ws` |
| path | encoded `path` query value | `wsSettings.path` | `transport.path` | `ws-opts.path` |
| HTTP Host | encoded `host` query value | `wsSettings.host` | `transport.headers.Host` | `ws-opts.headers.Host` |
| TCP only | no UDP option | local inbound has `udp: false` | VLESS `network: "tcp"` | `udp: false` |
| display name | encoded fragment | not used; fixed local tag `proxy` | not used; fixed local tag `proxy` | quoted proxy and group member name |

The similar-looking `network` fields are not interchangeable: sing-box uses VLESS `network: "tcp"` to restrict destination commands and selects WebSocket under `transport`; Mihomo uses `network: ws` to select the transport; current Xray uses `streamSettings.method: "websocket"`.

## The five artifacts

1. **VLESS URI.** Emit a deterministic Xray-style URI containing UUID, host, port 443, `encryption=none`, `security=tls`, `type=ws`, WebSocket Host/path, SNI, and display-name fragment. Percent-encode UTF-8 component values once using RFC 3986 unreserved characters; spaces are `%20`, not `+`.
2. **QR code.** Encode the exact VLESS URI bytes without a second serialization. Both the text URI and PNG contain the UUID and are secrets.
3. **Xray JSON.** Emit a complete local-client configuration using the pinned core's flat VLESS settings, current `method: "websocket"`, `wsSettings.host`, TLS `serverName`, and a loopback-only SOCKS inbound with UDP disabled. Do not emit legacy `vnext`, legacy `network: "ws"`, `headers.Host`, or `allowInsecure`.
4. **sing-box JSON.** Emit a system-wide TUN profile with verified TLS, a `ws` V2Ray transport, encrypted mainland China DNS, direct and VLESS outbounds, mainland China IP classification, and an explicit foreign-TCP proxy fallback. The integration harness uses the same policy behind an unprivileged loopback mixed inbound.
5. **Mihomo YAML.** Emit a complete local configuration with a loopback mixed port, one quoted VLESS proxy, a selection group, and a final rule. Explicitly disable UDP and certificate skipping. The constrained emitter uses JSON-encoded strings (valid YAML 1.2 scalars) for every user-controlled value and is checked with the native Mihomo parser.

## Validation contract

Before presenting files to the user, validate the canonical values and then run the native syntax check for each executable format:

```sh
xray run -test -format=json -config xray.json
sing-box check -c sing-box.json
mihomo -t -f mihomo.yaml
```

CI installs the exact sing-box v1.13.14 Linux release after verifying its
published SHA-256 digest, so the sing-box native check is required rather than
silently skipped.

The Xray WebSocket deprecation warning is expected at the pinned v26.7.11 baseline because this project's protocol is fixed to WebSocket; `Configuration OK.` and exit status determine syntax success. Pin sing-box and Mihomo versions/checksums in automation.

Also parse the generated URI internally and assert its scheme, authority, exact non-duplicated query-key set, decoded values, fragment, and stable byte-for-byte re-encoding. Syntax checks are gates, not interoperability proof: Xray, sing-box, and Mihomo still require live integration runs.

Shadowrocket has no public executable validator or normative vendor URI grammar. Label its URI and QR output **manual verification pending** until a real App Store build imports both forms, shows every field correctly, and passes the connection checklist in [client compatibility research](../research/client-compatibility.md#required-manual-checklist). Do not claim Shadowrocket support before that record exists.

## sing-box routing policy

The shipped `sing-box.json` uses a TUN inbound with IPv4 and IPv6 addresses,
`auto_route`, `strict_route`, and route-interface auto-detection. Creating the
TUN interface requires administrator privileges in the command-line client;
graphical sing-box clients normally manage this through their platform VPN
permission. A loopback `mixed` inbound alone does not capture ordinary device
traffic.

Routing is evaluated in this order:

| Destination | Outbound |
| --- | --- |
| Private/link-local IP | `direct` |
| Mainland China IPv4 or IPv6 in the official `geoip-cn` rule set | `direct` |
| Foreign UDP or ICMP | rejected; the Worker transport is TCP-only |
| Every other public TCP destination | VLESS `proxy` |

Domain destinations are resolved before the IP rules. Captured and sniffed TUN
DNS is hijacked into verified DNS-over-HTTPS at the mainland China address
`223.5.5.5`, with TLS name `dns.alidns.com`. Linux traffic delivered to a local
resolver before it reaches the TUN cannot be hijacked by a userspace rule. The
remote `geoip-cn` binary rule set is downloaded through the proxy and cached,
avoiding a direct dependency on GitHub reachability from mainland networks.
The VLESS endpoint uses the same China DNS bootstrap plus interface
auto-detection so its connection cannot loop back through its own TUN route.

The opt-in live regression test starts the pinned unmodified client with the
real owner-only deployment record. It connects to one known China IP and one
known foreign IP through the integration mixed inbound, then requires
in-memory route evidence for `direct` and `proxy` respectively:

```sh
CF_VLESS_TEST_LIVE_SING_BOX_POLICY=1 \
CF_VLESS_DEPLOYMENT="$(pwd)/.cf-vless/deployment.json" \
SING_BOX_BIN="$(command -v sing-box)" \
go test ./internal/clientintegration \
  -run '^TestLiveSingBoxChinaDirectForeignProxyPolicy$' -count=1 -v
```

The test never prints the retained sing-box logs or deployment credentials.
It is separate from privileged TUN capture, which must be exercised on the
target operating system or graphical client.

## Output handling

- Never include Cloudflare API tokens, account identifiers, or deployment credentials other than the VLESS UUID.
- Treat JSON, YAML, URI, terminal output containing the URI, and QR images as secrets; do not log their contents.
- Use structured JSON encoders, JSON-quoted YAML scalars, and an explicit URI component encoder. Reject control characters, invalid hostnames, malformed paths, duplicate URI fields, and invalid UTF-8 before rendering.
- Keep certificate verification enabled in every format.
- Prefer restrictive local file permissions when writing artifacts and make overwrites explicit.
- Keep output names and field order deterministic so fixtures and diffs are stable.

Exact source links, version traps, canonical examples, and the Shadowrocket manual procedure are recorded in [client compatibility research](../research/client-compatibility.md).
