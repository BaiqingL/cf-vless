# Implementation learnings

This directory records facts discovered while implementing and testing the
fixed protocol. Dated primary-source evidence lives in `research/`; durable
architectural choices live in `decisions/`.

Current high-impact findings:

- With the 2026 compatibility date, Workers WebSocket binary messages may
  arrive as `Blob`; a byte relay must normalize Blob/ArrayBuffer/views and still
  enforce a bound before conversion.
- `connect()` rejects Cloudflare addresses, so a raw TCP tunnel cannot reach
  many Cloudflare-hosted destinations. Replacing those bytes with `fetch()`
  would not be a transparent TCP relay.
- The server-side WebSocket API exposes no `bufferedAmount`; bounded application
  queues and chunked/yielded sends are possible, but platform transport
  buffering remains opaque.
- Current Xray canonical JSON differs from many legacy examples: flat VLESS
  fields, `streamSettings.method: "websocket"`, and `wsSettings.host`.
- A parser-only TinyGo Wasm lower bound compressed larger than the complete
  native Worker bundle before adding the necessary Streams/JS interop.
- The `cf` CLI is still a technical preview. It covers most high-level resource
  work, including protected noninteractive Worker-secret input. Generated
  types, startup profiling, and a connected real-time log tail still require
  project-local Wrangler; only the tail is an operational runtime fallback.
- The edge Fetch implementation rejects `redirect: "error"` at runtime. A
  fail-closed DoH request must use `redirect: "manual"` and reject every
  non-2xx response instead; mocks alone did not expose this platform mismatch.
- Custom Domain inventory can be internally consistent while edge traffic falls
  through to its managed `100::` placeholder. A first deployment must publish
  the declarative domain after bind provenance is stored, and success must be
  gated on the public endpoint's exact TLS-verified response rather than on
  control-plane inventory alone.
- Live Custom Domain responses used a 40-hex Domain ID, a UUID certificate-pack
  ID, and a multi-SAN Advanced pack whose Domain `cert_id` was not a child
  certificate ID. Before/after pack-ID provenance was more reliable than API
  schema examples or certificate-ID correlation.
- Generated certificate deletion is asynchronous. The observed first delete
  returned API code `1406` while the exact pack entered `pending_deletion`; the
  safe workflow stopped, retained its checkpoint, and resumed only after the
  pack disappeared.
- The public TCP test service is line-oriented and closes an idle connection
  before 30 seconds. Line-delimited, byte-verified keepalives let the live gate
  measure a 30-second active tunnel session without mistaking endpoint framing
  or idle policy for a tunnel failure.
