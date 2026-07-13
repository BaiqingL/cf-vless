# ADR 0001: use native TypeScript in the Worker hot path

- Status: accepted
- Date: 2026-07-12
- Scope: VLESS v0 request parsing and WebSocket/TCP stream bridging

## Decision

Keep the production Worker in native TypeScript. Keep the protocol-specific
parser isolated in `worker/src/protocol/vless.ts`, and validate its wire behavior
against independently Go-encoded, pinned-Xray-source-derived fixtures, an
in-memory sanitized capture from the pinned client's real WebSocket traffic,
and the pinned binary's behavioral interoperability tests. Go remains the
language for deployment, configuration, test-vector, integration, and release
tooling.

Do not ship Xray packages or a TinyGo/Wasm parser in the Worker bundle.

## Evidence

Three approaches were tested or inspected.

### Import the Xray parser

The pinned Xray tree is excellent as the reference implementation but not an
independent edge parser. `decisions/0002-xray-library-reuse.md` records the
details: the relevant package graph reaches 365 packages (154 outside the
standard library), a `GOOS=js GOARCH=wasm` build reaches OS-specific
`syscall.RawSockaddrUnix`, and even native test artifacts are coupled to Xray's
protobuf, routing, transport, and operating-system stack. This option does not
produce a Worker-compatible standalone parser.

### Standalone Go parser compiled with TinyGo

The lower-bound experiment in `research/experiments/tinygo-vless` was compiled
with official TinyGo 0.41.1, Go 1.26.5, LLVM 20.1.1, and Binaryen 130:

```sh
tinygo build -target wasm -no-debug -opt=2 \
  -o /tmp/tinygo-vless.wasm ./research/experiments/tinygo-vless
```

Measured artifact:

| Artifact | Raw | gzip |
| --- | ---: | ---: |
| Deliberately incomplete TinyGo parser lower bound | 25,053 B | 9,550 B |
| Complete native Worker dry-run bundle at the same checkpoint | 28,002 B | 7,525 B |

Those are like-for-like experiment-checkpoint values, not the current release
measurement. `docs/free-tier.md` records the later final-tree dry-run bundle and
local startup profile separately.

The TinyGo experiment only validates header offsets. It omits authentication,
streaming parser state, address rendering, destination policy, WebSocket and
Streams APIs, JavaScript/Go memory-transfer glue, and every TCP relay behavior.
Despite that favorable scope, its compressed Wasm artifact is already larger
than the complete native Worker bundle. It also exports an allocator,
scheduler, asyncify hooks, and linear memory in addition to the parser.

Putting Wasm in the frame path would additionally require copying every
fragment into linear memory and copying parsed/payload bytes back to JavaScript,
while the socket and WebSocket APIs remain JavaScript Streams. That adds two
runtimes, a second memory-management model, and more cancellation/error edges
without reducing maintained protocol code.

### Native TypeScript

Wrangler 4.110.0 produced a small bundle, and Cloudflare's Vitest integration
runs the parser in `workerd`, the production runtime. Native typed arrays can be
views over delivered WebSocket data, and the parser hands application payload
directly to the Streams bridge. There is no JS/Wasm boundary in the per-frame
path.

The maintained VLESS wire parser is 201 physical lines at this decision point.
Authentication, policy, and relay code are separate because they are security
and lifecycle concerns rather than VLESS wire-format code.

## Consequences

- The Worker has one runtime and one streaming/cancellation model.
- The deterministic Go-generated fixtures remain an independent source-derived
  oracle. The opt-in loopback reference test additionally observes the pinned,
  unmodified Xray client's masked WebSocket bytes for IPv4, domain, and IPv6
  requests, sanitizes UUID and destination fields in memory, and compares each
  captured header shape with that oracle. If IPv6 loopback is unavailable, the
  real IPv6 header capture must still pass before only its echo round trip is
  skipped.
- The TypeScript parser intentionally supports only version 0, no add-ons, and
  the TCP command. Unsupported UDP, Mux, Flow/add-ons, and other protocols fail
  closed.
- The TinyGo experiment stays tracked as reproducible research but is never
  built or deployed by default.
- Revisit this decision only if Xray exposes a genuinely standalone parser or
  Cloudflare provides a native VLESS primitive; compare measured complete
  bundles and frame-copy cost again before changing runtimes.
