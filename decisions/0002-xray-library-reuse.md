# ADR 0002: Do not import Xray's VLESS parser into the Worker

Status: accepted

Date: 2026-07-12
Upstream assessed: Xray-core [`50231eaff98ccc31b5cbd247a721c16e97fe5ec1`](https://github.com/XTLS/Xray-core/tree/50231eaff98ccc31b5cbd247a721c16e97fe5ec1), tag `v26.7.11`

## Context

The Worker needs only VLESS v0's TCP request header, the two-byte response header, and raw stream relay. The repository requirement asks us to prefer upstream reuse only if the parser is independently reusable, Wasm-compatible, small enough for Workers, and free of Xray's routing/runtime and operating-system dependencies.

The candidate is Xray's exported `github.com/xtls/xray-core/proxy/vless/encoding` package. Its canonical request/response functions are in [`encoding.go`](https://github.com/XTLS/Xray-core/blob/50231eaff98ccc31b5cbd247a721c16e97fe5ec1/proxy/vless/encoding/encoding.go#L29-L173).

## Decision

Do not import that package into production Worker code and do not patch or fork Xray to manufacture a parser-only package.

Implement the fixed, minimal VLESS v0 TCP adapter in native TypeScript under `worker/src/protocol/vless.ts`. Validate it byte-for-byte with deterministic fixtures independently encoded by Go from the pinned Xray source layout, and validate behavior separately with the pinned unmodified Xray binary. Continue using the full upstream repository for the Xray client, reference server, configuration validation, and integration tests. The checked fixtures are source-derived, not emitted by Xray or captured from a live connection.

The fixture file itself remains source-derived rather than a copied capture.
The opt-in reference test separately observes the real pinned client's masked
WebSocket stream for IPv4, domain, and IPv6 requests, retains only bounded VLESS
headers in memory, sanitizes each UUID and destination, and byte-compares each
shape with the corresponding independent fixture.

## Evidence

### The package is not an independent header parser

`encoding.go` imports Xray buffers, errors, networking, protocol, session, signal, proxy, and VLESS packages. Its parser signature exposes Xray-specific `buf.Buffer`, `protocol.RequestHeader`, and `vless.Validator` types. The same compilation unit also contains the Vision `XtlsRead` data path ([imports and functions](https://github.com/XTLS/Xray-core/blob/50231eaff98ccc31b5cbd247a721c16e97fe5ec1/proxy/vless/encoding/encoding.go#L1-L16), [Vision path](https://github.com/XTLS/Xray-core/blob/50231eaff98ccc31b5cbd247a721c16e97fe5ec1/proxy/vless/encoding/encoding.go#L175-L204)).

The package's `addons.go` also combines the header add-on codec with UDP length framing and Vision body wrapping, importing protobuf, `proxy.TrafficState`, session, and `net.Conn` ([source](https://github.com/XTLS/Xray-core/blob/50231eaff98ccc31b5cbd247a721c16e97fe5ec1/proxy/vless/encoding/addons.go#L1-L85)). There is no leaf parser package that accepts plain byte slices and returns a small address/port result.

### Measured dependency graph

Measurements were run from the pinned submodule on macOS arm64 with `go1.26.5`:

```sh
go list -deps ./proxy/vless/encoding | wc -l
# 365 total packages

go list -deps -f '{{if not .Standard}}{{.ImportPath}}{{end}}' \
  ./proxy/vless/encoding | sed '/^$/d' | wc -l
# 154 non-standard packages (Xray internal packages plus external modules)
```

The graph reaches Xray core, dispatcher, routing, geodata, transport/internet, TLS, REALITY, QUIC helpers, gRPC credentials, protobuf, uTLS, compression libraries, and operating-system packages. A short causal path is `vless/encoding -> proxy -> transport/internet/tls -> common/utils`; the direct `proxy` import is visible in [`encoding.go`](https://github.com/XTLS/Xray-core/blob/50231eaff98ccc31b5cbd247a721c16e97fe5ec1/proxy/vless/encoding/encoding.go#L7-L15), and `proxy` imports TLS/REALITY and Xray's dispatcher/runtime ([`proxy.go`](https://github.com/XTLS/Xray-core/blob/50231eaff98ccc31b5cbd247a721c16e97fe5ec1/proxy/proxy.go#L1-L35)).

For scale, a native package archive was 565 KiB, while `go test -c` produced a 20 MiB native test executable. The latter includes the Go test runtime and is an upper bound, not a Worker bundle measurement. More importantly, no deployable Wasm artifact can be built from the unmodified package.

### Wasm build fails before bundling

The standard Go Wasm compilation probe was:

```sh
GOOS=js GOARCH=wasm go build -buildmode=archive \
  -o /tmp/xray-vless-encoding.a ./proxy/vless/encoding
```

It fails against the unmodified pinned tree:

```text
# github.com/xtls/xray-core/common/utils
common/utils/unixsocket.go:29:40: undefined: syscall.RawSockaddrUnix
```

The offending OS-specific code is [`common/utils/unixsocket.go`](https://github.com/XTLS/Xray-core/blob/50231eaff98ccc31b5cbd247a721c16e97fe5ec1/common/utils/unixsocket.go#L1-L34), pulled in transitively despite being unrelated to VLESS header parsing. There is no `js/wasm` build constraint on that file. Fixing this would require an upstream change, a fork/patch, or copied/extracted code, all outside the clean-reuse criterion.

Because compilation fails, there is no Worker Wasm bundle whose compressed size, instantiation cost, or CPU use can pass the deployment gate. The native sizes above must not be misrepresented as a Wasm bundle result.

### Runtime fit is poor even after hypothetical build fixes

Standard Go Wasm would add the Go runtime and JavaScript host glue to a Worker whose hot path otherwise uses native `WebSocket`, `ReadableStream`, and `cloudflare:sockets`. Every stream transition would require adapting/copying data between Worker JavaScript objects, Wasm linear memory, and back. Xray's parser is written for blocking `io.Reader`/`net.Conn`, while the Worker APIs are event-driven streams.

A separate lower-bound parser was compiled with TinyGo 0.41.1. The deliberately
incomplete Wasm artifact was 25,053 bytes raw / 9,550 bytes gzip while omitting
authentication, streaming state, address rendering, policy, host glue, and the
relay. It was already larger when compressed than the complete native Worker at
that checkpoint (28,002 bytes raw / 7,525 bytes gzip). This experiment does not
make direct upstream reuse viable: TinyGo still cannot turn Xray's non-leaf,
OS-coupled package into a standalone parser without changing upstream package
boundaries. A project-owned Go parser would also retain the Wasm frame-copy and
Streams interop overhead without reducing maintained protocol code.

### Canonical behavior remains testable without production linkage

The upstream package tests pass at the pin:

```sh
go test ./proxy/vless/encoding
# ok github.com/xtls/xray-core/proxy/vless/encoding
```

The Xray client writes the header through `EncodeRequestHeader` before copying payload ([outbound path](https://github.com/XTLS/Xray-core/blob/50231eaff98ccc31b5cbd247a721c16e97fe5ec1/proxy/vless/outbound/outbound.go#L321-L369)), and the server reads it through `DecodeRequestHeader` ([inbound path](https://github.com/XTLS/Xray-core/blob/50231eaff98ccc31b5cbd247a721c16e97fe5ec1/proxy/vless/inbound/inbound.go#L286-L313)). Integration tests can therefore use the pinned binary as the oracle without linking the Worker to Xray packages.

## Licensing consequence

Xray-core is MPL 2.0 ([pinned license](https://github.com/XTLS/Xray-core/blob/50231eaff98ccc31b5cbd247a721c16e97fe5ec1/LICENSE)). MPL 2.0 requires distributed covered source and modifications to remain available under MPL, allows a larger work under other terms while preserving those obligations, and requires retaining notices ([sections 3.1-3.4](https://github.com/XTLS/Xray-core/blob/50231eaff98ccc31b5cbd247a721c16e97fe5ec1/LICENSE#L157-L204)).

Keeping the official repository as an unmodified, pinned submodule preserves its license and notices and is appropriate for reference/test use. If Xray code were later compiled into a distributed Worker artifact, release tooling would need to provide the corresponding covered source and license notices. If upstream files were modified, those files would remain MPL-covered.

The selected TypeScript adapter is an independent implementation of the documented byte-level interface; it must not copy Xray function bodies or generated protobuf code. This keeps production code and Xray's covered source in separate files and avoids unnecessary production licensing/bundle obligations.

## Consequences

- Production protocol code is limited to version, UUID, add-on length, command, port, and address parsing plus the two-byte response prefix.
- UDP, Mux, Reverse, Vision, protobuf add-ons, Xray routing, and Xray transports remain out of the Worker bundle.
- Conformance risk is controlled by source-derived deterministic fixtures and
  separate tests using the exact unmodified submodule pin. IPv4, domain, and
  IPv6 TCP header shapes are also verified against bounded, in-memory sanitized
  captures from the real pinned client. IPv6 loopback absence may skip only the
  echo round trip after its real header capture passes.
- Upstream upgrades require rerunning the wire-format tests and this dependency probe before changing the pin.
- Direct upstream reuse can be reconsidered only if Xray publishes a parser-only, plain-byte API whose clean `js/wasm` build and actual Worker bundle/runtime measurements satisfy the repository gates.
