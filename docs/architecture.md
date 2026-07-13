# Architecture

## Data path

```text
VLESS client
  |  Cloudflare-managed TLS + HTTP WebSocket Upgrade
  v
Cloudflare edge (outer TLS terminates here)
  |
  v
Worker request/session
  |-- exact Host/path/Upgrade check
  |-- bounded streaming VLESS v0 parser
  |-- constant-time UUID authentication
  |-- port/address/domain policy
  |-- A + AAAA via Cloudflare DNS-over-HTTPS
  |-- classify every answer and pin one validated IP
  v
cloudflare:sockets connect({ validated IP, port })
  |
  v
Public TCP destination
```

If the client speaks HTTPS or SSH through the TCP stream, that inner protocol
continues end to end between the client application and destination. The outer
WSS layer ends at Cloudflare.

## Request lifecycle

1. Ordinary HTTP, wrong-host, wrong-path, and non-upgrade requests receive the
   same minimal `404 Not Found` response. It does not advertise a proxy.
2. A valid path/Upgrade receives a `WebSocketPair`; the server side enables
   half-open handling and rejects every non-binary client frame.
3. One `TunnelSession` owns all request state. There is no module-level mutable
   request state, Durable Object, KV, D1, R2, or shared socket.
4. The streaming parser buffers at most 1 KiB until it has version, UUID,
   zero-add-on marker, TCP command, port, address type, and address. It preserves
   payload bytes already following that header.
5. The session compares the 16 UUID bytes against the credential selected for
   the current or unexpired previous path.
6. Policy validates the destination. Domain requests are resolved once, every
   returned address must be safe, and `connect()` receives the selected IP. The
   domain is not resolved a second time by the socket API.
7. After the socket's `opened` promise succeeds, the Worker sends the VLESS
   response bytes `00 00` exactly once, then writes any coalesced application
   payload.
8. Client messages are serialized into the socket writer. Socket reads are sent
   to WebSocket in bounded chunks. Close/error/timeout in either direction
   cancels and closes the owned resources.

## Backpressure and memory

Inbound messages enter a 1 MiB application queue and are written serially with
`WritableStreamDefaultWriter.write()`, which applies socket-stream backpressure.
The parser does not copy post-header payload into its small handshake buffer.

Cloudflare's server-side `WebSocket.send()` is synchronous and exposes no
`bufferedAmount`. The relay therefore never creates a separate unbounded
outbound queue: it performs one socket read at a time, divides each result into
64 KiB sends, and yields after each send. Cloudflare's internal queue is still a
platform-owned limitation documented in `LIMITATIONS.md`.

## Timeouts and cleanup

Defaults:

| Control | Default |
| --- | ---: |
| Handshake | 10 seconds |
| Destination connect | 10 seconds |
| Idle session | 5 minutes |
| Absolute session | 1 hour |

Both generated Worker configuration schemas pin these bounded values. Handshake
success clears the authentication deadline. Any frame or destination data
refreshes idle time. The session starts the underlying socket close
immediately, then attempts writer close/release, across client close, error,
idle or absolute deadline, connect failure, and malformed input. A destination
EOF instead releases its reader and preserves the client-to-destination
writable half until one of those bounded full-close conditions occurs. Because
the WebSocket is accepted in half-open mode, a peer Close frame is explicitly
answered before cleanup.

## Why no Durable Object or storage

Each client TCP stream maps naturally to one Worker WebSocket invocation and one
outbound socket. Cross-session coordination is neither required nor desirable
for the default personal endpoint. A Durable Object would add cost, lifetime,
state, and an additional failure boundary without improving the byte relay.

## Source boundaries

- `worker/src/protocol/vless.ts`: VLESS wire parser only;
- `worker/src/auth.ts`: credential schema, rotation selection, UUID comparison;
- `worker/src/policy.ts` and `dns.ts`: SSRF policy and pinned resolution;
- `worker/src/tcp.ts`: socket open timeout;
- `worker/src/websocket.ts`: full-duplex lifecycle and queues;
- Go `internal/` packages: deployment/config/client/test tooling, never the hot
  path.
