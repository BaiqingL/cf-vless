# Client compatibility research

Research date: **2026-07-12 UTC**

Scope: plain VLESS v0 TCP commands over WebSocket over publicly trusted TLS. This document intentionally excludes VLESS Encryption, XTLS Vision, REALITY, XHTTP, gRPC, early data, multiplexing, and UDP.

## Result

The four output formats can represent the required connection without extensions:

- Xray-core v26.7.11: flat VLESS outbound settings, `streamSettings.method: "websocket"`, TLS, and `wsSettings`.
- sing-box v1.13.14: a VLESS outbound with `network: "tcp"`, `transport.type: "ws"`, and outbound TLS.
- Mihomo v1.19.28: a `vless` proxy with `udp: false`, `network: ws`, `tls: true`, and `ws-opts`.
- Shadowrocket: emit the current Xray VLESS share-link proposal as the best verifiable interchange format, but keep support status **manual/unverified** until a real Shadowrocket import and connection run is recorded.

Syntax-only validation was executed locally on the research date with Xray-core v26.7.11, sing-box v1.13.14, and Mihomo v1.19.28. Syntax validation does not prove interoperability or a live connection.

## Version baseline

| Client | Baseline | Upstream revision | Local syntax result |
| --- | ---: | --- | --- |
| Xray-core | v26.7.11 | `50231eaff98ccc31b5cbd247a721c16e97fe5ec1` | `Configuration OK.` |
| sing-box | v1.13.14 | `25a600db24f7680ad9806ce5427bd0ab8afe1114` | exit 0 |
| Mihomo | v1.19.28 | `cbd11db1e13a75d8e680e0fe7742c95be4cba2be` | `configuration file config.yaml test is successful` |
| Shadowrocket | App Store v2.2.90 observed | closed-source App Store application | not executable in this repository; manual test required |

The repository's Xray submodule is the authoritative Xray baseline. The other executable baselines are current stable upstream releases as of the research date. Integration tests should pin versions and checksums rather than download an unqualified `latest` asset.

The 2026-07-12 Darwin arm64 rerun downloaded the exact official release assets
and verified the GitHub-published SHA-256 digests before execution:

- `sing-box-1.13.14-darwin-arm64.tar.gz` — `73e8967b0fc08e17bce4263ca56ebc394822401a16497a1c4e02316c888202ab`;
- `mihomo-darwin-arm64-v1.19.28.gz` — `40cdae2fab4b18df15f40eaa9dc3af70ab3d8be7f77164ae1e5f1af3a2a4fb44`.

Their reported source revisions matched the baseline table, and the executable
conformance test passed for Xray, sing-box, and Mihomo in the same run.

## Canonical deployment values

Every renderer should consume the same validated values:

| Value | Constraint |
| --- | --- |
| UUID | canonical UUID text form; generated locally; secret |
| server | dedicated ASCII hostname managed by Cloudflare, such as `edge.example.com` |
| port | exactly `443` |
| TLS server name | the certificate hostname, normally identical to `server` |
| WebSocket Host | normally identical to `server` for a Worker custom domain |
| WebSocket path | absolute path beginning with `/`; randomized but URL-safe |
| display name | user-selected label; never used for routing or authentication |

TLS certificate verification must remain enabled. None of the outputs may contain Cloudflare API credentials. The UUID in a URI or QR code is a bearer credential and must be handled as a secret.

## Xray-core JSON

### Canonical v26.7.11 shape

```json
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "tag": "socks-in",
      "listen": "127.0.0.1",
      "port": 1080,
      "protocol": "socks",
      "settings": {
        "udp": false
      }
    }
  ],
  "outbounds": [
    {
      "tag": "proxy",
      "protocol": "vless",
      "settings": {
        "address": "edge.example.com",
        "port": 443,
        "id": "27848739-7e62-4138-9fd3-098a63964b6b",
        "encryption": "none"
      },
      "streamSettings": {
        "method": "websocket",
        "security": "tls",
        "tlsSettings": {
          "serverName": "edge.example.com"
        },
        "wsSettings": {
          "path": "/random-path-00000001",
          "host": "edge.example.com"
        }
      }
    }
  ]
}
```

Why this exact shape:

- The pinned source defines flat `settings.address`, `port`, `id`, and `encryption` fields and converts them internally to one VLESS endpoint. `encryption` must be explicitly `"none"` for plain VLESS.
- The v26.7.11 transport key is `streamSettings.method`; `"websocket"` is the canonical current value.
- `wsSettings.host` is the current field for the HTTP `Host` value. Putting `Host` under `wsSettings.headers` still parses but emits a deprecation warning.
- `tlsSettings.serverName` drives SNI and certificate-name verification. Do not emit `allowInsecure`; setting it true was removed in this version, and omitting it keeps normal certificate verification.
- `flow` is omitted. Adding `xtls-rprx-vision` would violate this project's fixed protocol.

Authoritative pinned source:

- [flat and legacy VLESS settings parser](https://github.com/XTLS/Xray-core/blob/50231eaff98ccc31b5cbd247a721c16e97fe5ec1/infra/conf/vless.go#L239-L385)
- [tests proving both VLESS settings shapes parse](https://github.com/XTLS/Xray-core/blob/50231eaff98ccc31b5cbd247a721c16e97fe5ec1/infra/conf/vless_test.go#L17-L87)
- [`method`, legacy `network`, TLS selection, and WebSocket selection](https://github.com/XTLS/Xray-core/blob/50231eaff98ccc31b5cbd247a721c16e97fe5ec1/infra/conf/transport_internet.go#L13-L174)
- [`wsSettings.host`, path, and deprecated `headers.Host`](https://github.com/XTLS/Xray-core/blob/50231eaff98ccc31b5cbd247a721c16e97fe5ec1/infra/conf/transport_method.go#L613-L653)
- [TLS `serverName` and removed `allowInsecure`](https://github.com/XTLS/Xray-core/blob/50231eaff98ccc31b5cbd247a721c16e97fe5ec1/infra/conf/transport_security.go#L296-L359)

### Xray version traps

1. Older examples use `settings.vnext[0].users[0]`. The pinned core still accepts it, but the current docs and source expose the flat form. Emit only the flat form so generated output has one canonical representation.
2. `streamSettings.network: "ws"` remains an accepted compatibility alias at the pin, but v26.7.11 renamed the canonical key to `method`. Do not emit both. Older Xray versions may require `network`, so support for older versions would need a separately versioned renderer and tests.
3. Current Xray prints a deprecation warning for WebSocket and recommends XHTTP. WebSocket still validates and is required by this project's fixed protocol; the warning is expected and must not cause a false test failure. A future removal would require revisiting the pinned version, not silently changing this project's protocol.
4. A literal `Host` entry inside `wsSettings.headers` is deprecated in favor of `wsSettings.host`.
5. `allowInsecure: true` is an error at this pin. It is also unsafe for this deployment and must never be generated.
6. The VLESS URI proposal still describes some fields using the older Xray JSON layout. URI field names are a separate interchange dialect; `type=ws` remains correct even though current Xray JSON uses `method: "websocket"`.

### Executable validation

Build the pinned submodule, then parse without starting listeners:

```sh
mkdir -p ./bin
go -C ./third_party/xray-core build -o ../../bin/xray ./main
./bin/xray run -test -format=json -config ./path/to/xray.json
```

The command is documented by Xray's [command-line reference](https://xtls.github.io/en/document/command.html). Official prebuilt binaries are also published in the [v26.7.11 release](https://github.com/XTLS/Xray-core/releases/tag/v26.7.11). The repository should prefer its locally built pinned binary for reproducibility.

## sing-box JSON

### Canonical v1.13.14 shape

```json
{
  "log": {
    "level": "warn"
  },
  "inbounds": [
    {
      "type": "mixed",
      "tag": "mixed-in",
      "listen": "127.0.0.1",
      "listen_port": 1080
    }
  ],
  "outbounds": [
    {
      "type": "vless",
      "tag": "proxy",
      "server": "edge.example.com",
      "server_port": 443,
      "uuid": "27848739-7e62-4138-9fd3-098a63964b6b",
      "network": "tcp",
      "tls": {
        "enabled": true,
        "server_name": "edge.example.com",
        "insecure": false
      },
      "transport": {
        "type": "ws",
        "path": "/random-path-00000001",
        "headers": {
          "Host": "edge.example.com"
        }
      }
    }
  ],
  "route": {
    "final": "proxy"
  }
}
```

Important distinctions:

- VLESS `network: "tcp"` restricts the proxied network command. It does **not** select the outer transport.
- `transport.type: "ws"` selects the V2Ray WebSocket transport.
- `tls.enabled: true` and `tls.server_name` enable verified TLS. `insecure` must be false.
- Do not set `flow`, `packet_encoding`, `multiplex`, `max_early_data`, or `early_data_header_name` for this project.
- `headers.Host` is an HTTP header map entry in sing-box. This differs from current Xray's independent `wsSettings.host` field.

Authoritative upstream references:

- [VLESS outbound docs](https://sing-box.sagernet.org/configuration/outbound/vless/)
- [WebSocket V2Ray transport docs](https://sing-box.sagernet.org/configuration/shared/v2ray-transport/#websocket)
- [outbound TLS docs](https://sing-box.sagernet.org/configuration/shared/tls/#outbound)
- [v1.13.14 VLESS option fields](https://github.com/SagerNet/sing-box/blob/25a600db24f7680ad9806ce5427bd0ab8afe1114/option/vless.go#L17-L27)
- [v1.13.14 WebSocket option fields](https://github.com/SagerNet/sing-box/blob/25a600db24f7680ad9806ce5427bd0ab8afe1114/option/v2ray_transport.go#L11-L84)
- [v1.13.14 TLS option fields](https://github.com/SagerNet/sing-box/blob/25a600db24f7680ad9806ce5427bd0ab8afe1114/option/tls.go#L97-L125)

### Executable validation

```sh
sing-box check -c ./path/to/sing-box.json
```

The [configuration reference](https://sing-box.sagernet.org/configuration/) documents `sing-box check`. Official v1.13.14 release assets cover common operating systems, and the [package-manager page](https://sing-box.sagernet.org/installation/package-manager/) lists supported installation paths. The exact sample shape above exited 0 with the official darwin-arm64 v1.13.14 binary on the research date.

## Mihomo / Clash Meta YAML

### Canonical v1.19.28 shape

```yaml
mixed-port: 7890
allow-lan: false
mode: rule
log-level: warning

proxies:
  - name: "edge"
    type: vless
    server: "edge.example.com"
    port: 443
    uuid: "27848739-7e62-4138-9fd3-098a63964b6b"
    udp: false
    tls: true
    servername: "edge.example.com"
    skip-cert-verify: false
    network: ws
    encryption: ""
    ws-opts:
      path: "/random-path-00000001"
      headers:
        Host: "edge.example.com"

proxy-groups:
  - name: "PROXY"
    type: select
    proxies:
      - "edge"

rules:
  - "MATCH,PROXY"
```

Why these fields:

- `type: vless`, `server`, `port`, and `uuid` are the VLESS peer.
- `udp: false` prevents this TCP-only endpoint from being advertised for UDP.
- `tls: true`, `servername`, and `skip-cert-verify: false` retain normal certificate verification.
- `network: ws` plus `ws-opts.path` and `ws-opts.headers.Host` select WebSocket and its HTTP routing values.
- Current Mihomo docs show `encryption: ""` for plain VLESS. The v1.19.28 source accepts both an empty value and `none`; emit the documented empty value consistently.
- Omit `flow`, `packet-encoding`, early-data fields, `smux`, REALITY options, and client fingerprint overrides.

Authoritative upstream references:

- [Mihomo VLESS proxy docs](https://wiki.metacubex.one/en/config/proxies/vless/)
- [Mihomo WebSocket transport docs](https://wiki.metacubex.one/en/config/proxies/transport/#ws-opts)
- [Mihomo TLS fields](https://wiki.metacubex.one/en/config/proxies/tls/)
- [v1.19.28 VLESS option tags and WebSocket wiring](https://github.com/MetaCubeX/mihomo/blob/cbd11db1e13a75d8e680e0fe7742c95be4cba2be/adapter/outbound/vless.go#L50-L79)
- [v1.19.28 WebSocket option tags](https://github.com/MetaCubeX/mihomo/blob/cbd11db1e13a75d8e680e0fe7742c95be4cba2be/adapter/outbound/vmess.go#L155-L162)
- [plain VLESS accepts empty or `none`](https://github.com/MetaCubeX/mihomo/blob/cbd11db1e13a75d8e680e0fe7742c95be4cba2be/transport/vless/encryption/factory.go#L10-L16)

### Mihomo version and serialization traps

1. This is a Mihomo/Clash Meta configuration, not a promise of compatibility with legacy Clash cores that do not implement VLESS.
2. `network: ws` is the transport selector here; it does not mean the same thing as sing-box VLESS `network: "tcp"`.
3. Generate YAML with a real serializer. Always quote user-controlled names, hostnames, paths, and UUIDs so YAML keywords, `:`, `#`, and other syntax cannot change the document structure.
4. Do not use `skip-cert-verify: true`.

### Executable validation

```sh
mihomo -t -f ./path/to/mihomo.yaml
```

The `-t` and `-f` flags are present in the official binary's help. Official binaries for common platforms are attached to the [v1.19.28 release](https://github.com/MetaCubeX/mihomo/releases/tag/v1.19.28). The exact sample shape above passed the official darwin-arm64 v1.19.28 binary on the research date.

## VLESS URI and QR code

### Candidate URI

For the example values above, emit:

```text
vless://27848739-7e62-4138-9fd3-098a63964b6b@edge.example.com:443?encryption=none&security=tls&type=ws&host=edge.example.com&path=%2Frandom-path-00000001&sni=edge.example.com#My%20Edge
```

Semantics:

| URI component | Required value |
| --- | --- |
| scheme | `vless` |
| user information | UUID only; no password separator |
| host | Worker custom hostname |
| port | `443` |
| `encryption` | `none` |
| `security` | `tls` |
| `type` | `ws` |
| `host` | WebSocket HTTP `Host` value |
| `path` | encoded WebSocket path |
| `sni` | TLS server name |
| fragment | encoded display name |

The Xray-core [VLESS share-link proposal](https://github.com/XTLS/Xray-core/discussions/716) is the best upstream grammar available. It says field order is insignificant, duplicate fields are forbidden, values use `encodeURIComponent`-style escaping, names and constants are case-sensitive, IPv6 literals use brackets, IDNs use ASCII/Punycode, and WebSocket uses `type=ws`, `path`, and `host`. It is a mutable upstream proposal, not an IETF-registered VLESS URI standard.

### Encoding rules

1. Validate and canonicalize values before encoding. Use a lowercase canonical UUID, an ASCII DNS hostname, decimal port 443, and an absolute WebSocket path.
2. For every query value and the display-name fragment, encode the UTF-8 bytes of every byte other than RFC 3986 unreserved characters (`A-Z a-z 0-9 - . _ ~`) as `%HH`. A path such as `/a?b=c` therefore becomes `%2Fa%3Fb%3Dc` as a query value.
3. Encode each value exactly once. Reject malformed percent escapes in input rather than preserving or double-encoding them.
4. Do not use HTML form encoding for the display name. In particular, a space must become `%20`, not `+`. Some general-purpose query builders use `+` for spaces and therefore do not exactly implement the proposal's `encodeURIComponent` rule.
5. Keep fixed query keys ASCII and unescaped. Emit each key once. Use a deterministic order for reproducible tests even though readers must treat order as insignificant.
6. Convert an internationalized hostname to its validated IDNA A-label before placing it in the authority, `host`, or `sni`. The default deployment should avoid IDNs entirely.
7. Encode the QR payload as the exact UTF-8 bytes of the complete `vless://` URI. Do not wrap it in an HTTP redirect or a `shadowrocket://` URL. The QR code contains the UUID and must not be published or logged.

[RFC 3986](https://www.rfc-editor.org/rfc/rfc3986.html) supplies the generic URI and percent-encoding rules; the Xray proposal supplies the VLESS-specific field meanings.

## Shadowrocket evidence and support boundary

What is verifiable:

- Apple's official [Shadowrocket App Store page](https://apps.apple.com/us/app/shadowrocket/id932747118) showed version 2.2.90 on the research date. Its release history explicitly discusses VLESS, WebSocket, UUID parsing, URL query encoding, and VLESS WebSocket fixes, which is strong evidence that those capabilities exist in the product.
- A detailed but **unofficial** [community Shadowrocket guide](https://github.com/LOWERTOP/Shadowrocket/blob/main/README.md#添加节点) says the app recognizes copied `vless://` links and can scan QR codes. The same guide warns that proxy URL and QR formats lack a single uniform standard and fields can be lost across clients.
- The Xray share-link proposal provides a precise, current candidate URI grammar.

What is not verifiable from public vendor material:

- Shadowrocket does not publish a normative VLESS URI parser grammar or an executable command-line validator.
- Public material does not prove that every query field and percent-encoding edge case above imports correctly in a particular Shadowrocket build.
- A syntactically valid URI does not prove that Shadowrocket can connect to this Worker implementation.

Therefore the product may generate a **candidate Shadowrocket import URI and QR code**, but documentation and CLI output must say **“Shadowrocket manual verification pending”** until the following checklist passes on a real device.

### Required manual checklist

Record a dated, sanitized result containing the Shadowrocket version, iOS/iPadOS version, device class, Worker release/commit, and test hostname (never the UUID).

1. Install or update the App Store build and record its exact version.
2. Import the raw `vless://` URI from the clipboard.
3. Independently scan the generated QR code into a clean/local-node entry.
4. For both imports, inspect that protocol=VLESS, address, port 443, UUID, TLS enabled, certificate verification enabled, SNI, WebSocket transport, path, and Host all match.
5. Confirm REALITY, XTLS/Vision, VLESS Encryption, Mux, early data, and UDP are not enabled.
6. Connect to a controlled deployed Worker and load an HTTPS target through TCP.
7. Exercise a multi-megabyte download, upload, reconnect after disconnect, parallel TCP connections, and a long-lived TCP session.
8. Confirm a deliberately wrong UUID fails without revealing authentication details.
9. Confirm a deliberately wrong path and wrong SNI fail.
10. Save a sanitized pass/fail record. Only after both import paths and the live connection checks pass may the repository claim Shadowrocket support for that tested version.

## Automation and acceptance boundary

| Artifact | Syntax command | What remains after syntax passes |
| --- | --- | --- |
| Xray JSON | `xray run -test -format=json -config FILE` | pinned Xray end-to-end run through the Worker |
| sing-box JSON | `sing-box check -c FILE` | executable end-to-end run through the Worker |
| Mihomo YAML | `mihomo -t -f FILE` | executable end-to-end run through the Worker |
| VLESS URI / QR | internal URI parse-and-round-trip unit tests | real Shadowrocket import plus connection checklist |

URI unit tests should assert scheme, UUID, authority, port, exact query-key set, single occurrence of every key, decoded path/Host/SNI, decoded display name, and byte-for-byte stable re-encoding. They still cannot replace the Shadowrocket manual test.

## Source record

All web sources below were accessed on **2026-07-12**.

- XTLS/Xray-core [v26.7.11 release](https://github.com/XTLS/Xray-core/releases/tag/v26.7.11), released 2026-07-11; repository pin `50231eaff98ccc31b5cbd247a721c16e97fe5ec1`.
- Xray [VLESS outbound documentation](https://xtls.github.io/en/config/outbounds/vless.html), [WebSocket documentation](https://xtls.github.io/config/transports/websocket.html), and [command-line documentation](https://xtls.github.io/en/document/command.html).
- Xray-core [VMessAEAD/VLESS share-link proposal #716](https://github.com/XTLS/Xray-core/discussions/716), opened 2020-12-19 and still edited by maintainers through 2026.
- SagerNet/sing-box [v1.13.14 release](https://github.com/SagerNet/sing-box/releases/tag/v1.13.14), released 2026-06-25; commit `25a600db24f7680ad9806ce5427bd0ab8afe1114`.
- sing-box [VLESS](https://sing-box.sagernet.org/configuration/outbound/vless/), [V2Ray transport](https://sing-box.sagernet.org/configuration/shared/v2ray-transport/), [TLS](https://sing-box.sagernet.org/configuration/shared/tls/), and [installation](https://sing-box.sagernet.org/installation/package-manager/) documentation.
- MetaCubeX/mihomo [v1.19.28 release](https://github.com/MetaCubeX/mihomo/releases/tag/v1.19.28), released 2026-07-08; commit `cbd11db1e13a75d8e680e0fe7742c95be4cba2be`.
- Mihomo [VLESS](https://wiki.metacubex.one/en/config/proxies/vless/), [transport](https://wiki.metacubex.one/en/config/proxies/transport/), and [TLS](https://wiki.metacubex.one/en/config/proxies/tls/) documentation, page content dated 2026-05-14 where shown.
- Apple [Shadowrocket App Store listing](https://apps.apple.com/us/app/shadowrocket/id932747118), version 2.2.90 observed.
- LOWERTOP's [unofficial Shadowrocket guide](https://github.com/LOWERTOP/Shadowrocket/blob/main/README.md), used only as secondary evidence for clipboard/QR workflow and its explicit interoperability warning.
- IETF [RFC 3986, URI Generic Syntax](https://www.rfc-editor.org/rfc/rfc3986.html), January 2005.
