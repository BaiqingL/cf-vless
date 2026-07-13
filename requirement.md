You are a senior Cloudflare Workers, networking, Go, and Xray interoperability engineer.

Build a free, serverless, self-hosted personal TCP tunnel that users deploy into their own Cloudflare accounts and access through their own Cloudflare-managed domains.

Support exactly one protocol:

```
VLESS over WebSocket over Cloudflare-managed TLS
```

Do not implement additional proxy protocols or transports unless they are strictly required to make this protocol work.

The resulting endpoint must produce configurations that can be imported by:

* Shadowrocket
* Mihomo/Clash Meta
* sing-box
* Xray-core

The workspace contains `cf`, Cloudflare’s command-line tool. Use it for Cloudflare authentication, resource inspection, deployment, secrets, logs, and domain configuration whenever it supports the required operation. Use Wrangler only where `cf` lacks the necessary functionality.

## Product objective

A user with:

* a Cloudflare account
* a valid domain managed by Cloudflare
* the `cf` CLI
* no VPS
* no external proxy service

must be able to deploy a private VLESS-over-WebSocket endpoint and import the generated configuration into a compatible client.

The default deployment must:

* run entirely on Cloudflare Workers
* operate on the Workers free tier under reasonable personal usage
* use the user’s own Cloudflare domain
* require authentication
* avoid becoming an open proxy
* support TCP destinations
* work with unmodified clients
* require no project-operated central service
* clearly document Cloudflare’s place in the trust boundary

The final result must be a working repository, not only a research report.

## Fixed protocol decision

Implement:

```
VLESS v0 TCP command
    over WebSocket
    over HTTPS/TLS
    through a Cloudflare Worker
```

Do not implement:

* REALITY
* XTLS Vision
* XHTTP
* gRPC
* VMess
* Trojan
* Shadowsocks
* WireGuard
* Hysteria
* TUIC
* ShadowTLS
* AnyTLS
* arbitrary UDP
* Cloudflare Spectrum
* an external VPS fallback

Cloudflare terminates the public TLS connection before Worker execution, accepts HTTP/WebSocket rather than raw inbound TCP, and exposes outbound TCP through `cloudflare:sockets connect()`. The implementation must be designed around those constraints.

Do not describe the project as REALITY, XTLS, or an end-to-end TLS tunnel.

## Upstream Xray integration

Add the official `XTLS/Xray-core` repository as a pinned Git submodule under:

```
third_party/xray-core
```

Do not fork or patch Xray-core unless an objectively verified upstream bug prevents interoperability.

Use the submodule for:

* running a real Xray client in integration tests
* generating known-good configurations
* inspecting canonical VLESS wire behavior
* producing test vectors
* checking compatibility with newer Xray releases
* validating generated client configurations

Do not attempt to compile the complete Xray-core application into the Worker.

Before importing any Xray package into production Worker code, inspect its dependency graph, Wasm compatibility, binary-size impact, and MPL 2.0 obligations.

Prefer direct reuse only when the imported package:

* exposes the needed VLESS parser independently
* does not depend on Xray’s full routing/runtime stack
* compiles under the selected Worker toolchain
* remains within Workers free-tier bundle and CPU constraints
* does not require raw sockets or operating-system APIs

If the official parser cannot be reused cleanly, implement only the minimal VLESS v0 compatibility adapter required by the Worker.

Do not copy and modify large sections of Xray source.

Document why direct library reuse was or was not feasible in:

```
decisions/0002-xray-library-reuse.md
```

## Language and runtime approach

After inspecting the existing workspace, choose the smallest maintainable implementation compatible with Cloudflare Workers.

Use Go for:

* deployment manager
* configuration generator
* Xray integration-test harness
* test-vector generation
* protocol conformance tests
* security tests
* release tooling

Investigate whether a minimal VLESS parser can be:

1. imported from Xray-core and compiled to Wasm
2. implemented as a small standalone Go package compiled with TinyGo
3. implemented in the Worker’s native TypeScript runtime and tested against the canonical Go test vectors

Select the approach through measurements rather than preference.

Prefer the native Worker implementation if Go/Wasm introduces material:

* startup overhead
* per-frame JavaScript/Wasm copies
* bundle-size growth
* CPU usage
* garbage-collection complexity
* Streams API interop complexity

The goal is not to force Go into the hot path. The goal is to minimize maintained protocol code while retaining Go-based conformance and operational tooling.

If TypeScript is selected for the Worker adapter, keep protocol-specific logic isolated under:

```
worker/src/protocol/vless.ts
```

and ensure it is validated byte-for-byte against Go/Xray-generated fixtures.

## Required repository structure

Use or adapt this structure:

```
cmd/
  cf-vless/
  config-gen/
  integration-test/
  test-vector-gen/

internal/
  cloudflare/
  config/
  xray/
  clientformats/
  security/
  testvectors/

worker/
  src/
    index.ts
    websocket.ts
    tcp.ts
    policy.ts
    auth.ts
    protocol/
      vless.ts
  test/
  wrangler.jsonc
  package.json

third_party/
  xray-core/

test/
  integration/
  conformance/
  security/
  impairment/
  fixtures/

research/
decisions/
learnings/
docs/
```

## Research gate

Before implementation, verify the current official documentation and record:

* Workers inbound protocol support
* outbound TCP `connect()` behavior
* WebSocket behavior
* request and connection limits
* free-tier request and CPU limits
* WebSocket lifetime behavior
* custom-domain behavior
* Workers secrets
* whether TCP sockets may connect to Cloudflare IP ranges
* disallowed ports
* Worker self-connection behavior
* local/private destination restrictions
* deployment support in the installed `cf` CLI
* current VLESS framing in Xray-core
* current WebSocket configuration syntax in Xray, sing-box, and Mihomo
* Shadowrocket URI/config expectations where verifiable

Create:

```
research/cloudflare-capabilities.md
research/vless-wire-format.md
research/client-compatibility.md
research/cf-cli.md
```

Use official documentation and upstream source code as the primary sources.

Do not spend time researching unrelated protocols after confirming the fixed protocol decision.

## Test-driven development

Use test-driven development.

Do not implement a protocol behavior without first creating at least one failing test or interoperability fixture for it.

Proceed in this order:

### Stage 1: Xray reference environment

Build a reproducible local test environment containing:

* a pinned Xray-core binary built from the submodule
* a local reference VLESS-over-WebSocket Xray server
* a local Xray client
* an HTTP test destination
* a TCP echo destination

Verify the reference client/server pair before implementing the Worker.

Capture sanitized VLESS handshake fixtures from the reference environment.

### Stage 2: Protocol unit tests

Create tests for:

* valid UUID authentication
* invalid UUID
* VLESS version
* option length
* TCP command
* unsupported UDP command
* unsupported Mux command
* IPv4 destination
* IPv6 destination
* domain destination
* fragmented first frame
* handshake and payload in the same frame
* handshake split across several frames
* malformed address type
* truncated address
* invalid domain length
* invalid port
* oversized handshake
* response header generation
* constant-time credential comparison

### Stage 3: Worker WebSocket tests

Using Cloudflare’s official Workers test tooling, test:

* HTTP WebSocket upgrade
* rejection of non-WebSocket proxy requests
* correct endpoint path
* invalid path
* missing authentication
* malformed binary frames
* text frames
* fragmented binary messages
* client close
* destination close
* Worker cancellation
* bidirectional backpressure

### Stage 4: outbound TCP tests

Deploy a temporary Worker and verify real outbound TCP through `connect()` against controlled public test endpoints.

Do not infer that it works solely from mocks.

### Stage 5: Xray end-to-end test

Run the pinned, unmodified Xray client against the deployed Worker.

The test must prove:

* DNS resolution through the configured client path
* loading an HTTPS website
* downloading a multi-megabyte file
* uploading data
* SSH or another long-lived TCP connection
* reconnecting after disconnect
* multiple simultaneous TCP connections

The protocol is not considered working until this passes.

### Stage 6: additional clients

Generate configurations for:

* Xray JSON
* sing-box JSON
* Mihomo YAML
* VLESS URI suitable for Shadowrocket import

Validate Xray, sing-box, and Mihomo with executable integration tests where binaries are available.

For Shadowrocket, validate URI syntax against available documentation and provide a manual test checklist because automated execution may not be possible.

Do not claim Shadowrocket support until a real import and connection test is recorded.

## VLESS parsing requirements

Implement only VLESS v0 with the TCP command.

The parser must:

* process streaming input without assuming the handshake arrives in one WebSocket message
* place a strict upper bound on buffered handshake bytes
* compare UUIDs in constant time
* reject unsupported versions
* reject UDP and Mux commands
* support IPv4, IPv6, and domain address types
* preserve application payload bytes following the handshake
* return the correct VLESS response header exactly once
* never include credentials or destinations in errors returned to unauthenticated users

Do not add custom extensions to VLESS.

Do not depend on a secret URL path as the only authentication mechanism. Use UUID authentication as required by VLESS. A randomized path may be an additional routing control.

## WebSocket and stream handling

Implement:

* binary WebSocket frames
* bounded pre-authentication buffering
* full-duplex stream bridging
* backpressure in both directions
* bounded write queues
* clean half-close behavior where Cloudflare supports it
* cancellation propagation
* handshake timeout
* idle timeout
* absolute session timeout where justified
* destination-connect timeout
* deterministic resource cleanup

Do not accumulate the complete proxied stream in memory.

Do not create a Durable Object unless testing demonstrates it is necessary. A single WebSocket request should own its outbound TCP socket and stream state.

Do not use KV, D1, R2, or Durable Objects in the default data path without a demonstrated need.

## SSRF and destination policy

The Worker must never become a general SSRF mechanism into internal networks.

Before connecting, block:

* IPv4 loopback
* IPv6 loopback
* RFC1918 ranges
* link-local ranges
* multicast
* broadcast
* unspecified addresses
* IPv6 unique-local addresses
* IPv4-mapped private IPv6 addresses
* cloud metadata endpoints
* private DNS results
* the Worker’s own domain
* Cloudflare destinations prohibited by `connect()`
* prohibited destination ports

For domain destinations:

* validate domain syntax
* prevent hostname confusion and embedded credentials
* resolve or otherwise validate the effective destination address
* defend against DNS rebinding
* fail closed when the resolved address cannot be safely classified

Investigate what destination validation is actually possible before `connect()` in Workers. Where Cloudflare does not expose adequate DNS resolution information, design a documented safe policy rather than pretending rebinding is solved.

Make port policy configurable, with a conservative default.

## Authentication and secrets

Generate a cryptographically random UUID locally.

Store server credentials using Cloudflare secrets rather than source-controlled configuration.

Support credential rotation with an overlap period containing:

* current UUID
* optional previous UUID
* explicit expiration for the previous UUID

Never log:

* UUIDs
* full client IP addresses
* destination domains
* destination IPs
* traffic contents
* URLs containing credentials

Debug logging must be off by default.

## Domain behavior

Assume the user owns a valid domain managed by Cloudflare.

Use a dedicated hostname such as:

```
edge.example.com
```

Use a randomized WebSocket path.

For ordinary HTTP requests to that hostname:

* return a normal, minimal website or a generic 404 response
* do not reveal that the endpoint is a proxy
* do not reveal supported protocols
* do not return distinguishable authentication diagnostics
* do not proxy arbitrary HTTP requests

Do not impersonate an unrelated third-party website.

## Client configuration output

Generate exactly these formats from one canonical deployment configuration:

### VLESS URI

Include:

* UUID
* hostname
* port 443
* `security=tls`
* `type=ws`
* WebSocket path
* Host header where required
* a user-selected display name

Never put Cloudflare API credentials into client configurations.

### Xray JSON

Generate a VLESS outbound using WebSocket and TLS.

### sing-box JSON

Generate a VLESS outbound using the supported V2Ray WebSocket transport and TLS.

### Mihomo YAML

Generate a `vless` proxy using WebSocket and TLS.

### Shadowrocket

Generate an importable VLESS URI and QR code.

Ensure URI encoding of the path, host, and display name is correct.

## CLI requirements

Build a Go CLI named:

```
cf-vless
```

Support:

```
cf-vless doctor
cf-vless init
cf-vless deploy
cf-vless status
cf-vless test
cf-vless config
cf-vless rotate
cf-vless logs
cf-vless remove
```

### doctor

Check:

* `cf` CLI installation
* Cloudflare authentication
* account access
* domain availability
* required CLI capabilities
* Go
* Node.js package manager
* Xray submodule
* required test tools

### init

Generate:

* UUID
* randomized WebSocket path
* local deployment configuration
* Worker project files

Do not overwrite existing credentials without explicit user action.

### deploy

Use `cf` where possible to:

* create or update the Worker
* configure secrets
* bind the custom hostname
* deploy the script

Fall back to Wrangler only for specific unsupported operations and document why.

### test

Run a real Xray client against the deployed Worker and produce a pass/fail report.

### config

Generate all supported client configuration formats and QR codes.

### rotate

Rotate UUID and path safely.

### remove

Delete the Worker resources created by this project without altering unrelated Cloudflare resources.

## Free-tier verification

Measure rather than assume:

* Worker CPU time during handshake
* CPU time during sustained transfer
* memory behavior
* request count per WebSocket session
* simultaneous outbound connection behavior
* session duration
* bundle size
* WebSocket reliability
* traffic throughput
* connection establishment latency

Document reasonable personal-use limits in:

```
docs/free-tier.md
```

Do not guarantee unlimited bandwidth, unlimited duration, or permanent free operation.

## Required documentation

Produce:

```
README.md
SECURITY.md
PRIVACY.md
THREAT_MODEL.md
COMPATIBILITY.md
LIMITATIONS.md
docs/architecture.md
docs/deployment.md
docs/client-configurations.md
docs/cloudflare-trust-boundary.md
docs/free-tier.md
docs/troubleshooting.md
```

State prominently:

* Cloudflare terminates outer TLS
* Cloudflare is part of the trust boundary
* the project supports TCP, not arbitrary UDP
* the endpoint is VLESS over WebSocket, not REALITY or XTLS
* censorship resistance is not guaranteed
* WebSocket and the user’s domain may be identifiable or blocked
* platform rules and capabilities may change
* users remain responsible for lawful use and Cloudflare policy compliance

## Completion criteria

Do not declare success until:

* a clean Cloudflare account can deploy the endpoint
* a custom Cloudflare domain is bound successfully
* authentication is mandatory
* private and metadata destinations are blocked as far as the platform permits
* an unmodified Xray client passes the end-to-end test
* an unmodified sing-box client passes the end-to-end test
* an unmodified Mihomo client passes the end-to-end test
* the Shadowrocket URI is imported and manually verified, or explicitly marked unverified
* HTTPS browsing works
* uploads and downloads work
* long-lived TCP traffic works
* malformed-input and fuzz tests pass
* the generated configurations contain no Cloudflare credentials
* deployment and removal are reproducible
* free-tier measurements are documented

## Final report

At completion, report:

1. Exact Cloudflare resources created.
2. Exact protocol and transport implemented.
3. Whether Xray source was directly reused and why.
4. Amount of locally maintained protocol-specific code.
5. Xray, sing-box, Mihomo, and Shadowrocket test results.
6. Security-test results.
7. Free-tier measurements.
8. Known censorship and fingerprinting limitations.
9. Cloudflare trust-boundary implications.
10. Exact commands required to deploy, test, generate configs, rotate credentials, and remove the service.

Prefer one small, rigorously tested, universally compatible implementation over multiple incomplete protocol implementations.
