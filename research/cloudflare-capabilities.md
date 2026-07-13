# Cloudflare Workers capability research

Research snapshot: **2026-07-12 UTC**. This note covers the
Cloudflare portion of the research gate for the fixed transport:

```text
VLESS v0 TCP command -> WebSocket -> Cloudflare-managed HTTPS/TLS -> Worker
```

Status terms used below:

- **Verified** means the behavior is stated in current official Cloudflare
  documentation linked in this file.
- **Observed** means it was established from the installed CLI without changing
  the Cloudflare account.
- **Inference** means it follows from verified behavior but is not stated in
  exactly those words by Cloudflare.
- **Live-test gate** means documentation is absent, ambiguous, or cannot prove
  edge behavior without a deployed Worker.

## Result

**Verified:** The design is possible on Workers only in the specified form.
Workers accept inbound HTTP/HTTPS and WebSockets, do not accept direct inbound
TCP, and provide outbound TCP through `connect()` from `cloudflare:sockets`.
Therefore the public endpoint must be an HTTPS request upgraded to WebSocket;
the Worker then opens one raw outbound TCP socket for the VLESS destination.

This is not a raw TCP listener, REALITY, XTLS, or end-to-end outer TLS. A Custom
Domain gives the endpoint a user-owned hostname and a Cloudflare-managed edge
certificate. Cloudflare terminates that TLS connection and the Worker processes
the WebSocket/VLESS bytes. Cloudflare is consequently inside the trust boundary.

Primary sources:

- [Workers protocols](https://developers.cloudflare.com/workers/reference/protocols/),
  modified 2026-06-09.
- [Workers TCP sockets](https://developers.cloudflare.com/workers/runtime-apis/tcp-sockets/),
  modified 2026-06-19.
- [Workers WebSockets](https://developers.cloudflare.com/workers/runtime-apis/websockets/),
  modified 2026-04-23.

## Inbound protocol and public ports

### Worker protocol surface

**Verified:** Workers support these relevant interfaces:

- inbound HTTP/HTTPS through the `fetch()` handler;
- inbound WebSockets through the WebSocket API;
- outbound HTTP/HTTPS through `fetch()`;
- outbound direct TCP through `connect()`;
- no inbound direct TCP. The TCP documentation also says an HTTP `CONNECT`
  request cannot currently be used to create an inbound TCP connection.

The protocol consequence is strict: VLESS must begin only after a valid
WebSocket upgrade on the configured path. A client cannot connect to a Worker as
though it were an Xray TCP listener.

### Cloudflare proxy ports

**Verified:** Cloudflare's ordinary reverse proxy accepts HTTP/HTTPS on the
following ports:

| Scheme | Supported inbound proxy ports |
| --- | --- |
| HTTP | `80`, `8080`, `8880`, `2052`, `2082`, `2086`, `2095` |
| HTTPS | `443`, `2053`, `2083`, `2087`, `2096`, `8443` |

Source: [Cloudflare network ports](https://developers.cloudflare.com/fundamentals/reference/network-ports/),
modified 2026-04-20.

Use `443` for the generated client configurations. It is the standard WSS port
and avoids client-specific handling of alternate ports. The ingress list above
is unrelated to the ports an outbound TCP socket may target. Ports outside the
ingress list would require a DNS-only origin or Spectrum; neither is part of
this project.

## Outbound TCP with `connect()`

### API behavior

**Verified:** Import `connect` from `cloudflare:sockets` and call it with either
`{ hostname, port }` or a string address. It returns a `Socket` with:

- `readable: ReadableStream`;
- `writable: WritableStream`, accepting `Uint8Array` data or views;
- `opened: Promise<SocketInfo>`;
- `closed: Promise<void>`;
- `close()` to forcibly close both directions;
- `startTls()` when the socket was created with `secureTransport: "starttls"`.

`secureTransport` is `"off"`, `"on"`, or `"starttls"` and defaults to `"off"`.
`allowHalfOpen` defaults to `false`, so EOF on the readable side automatically
closes the writable side.

**Implementation consequence:** The VLESS TCP command needs
`secureTransport: "off"`. The Worker must expose a byte-transparent TCP stream.
If the proxied destination uses TLS (for example, HTTPS on port 443), the VLESS
client sends that inner TLS handshake through the tunnel. Having the Worker add
its own TLS layer would change the requested TCP stream.

Sockets must be created inside a request/event handler, not in global scope,
and cannot be shared between requests. Relay both directions with streams and
backpressure; do not buffer a connection in memory.

### Platform-enforced destination restrictions

**Verified:** The standard Workers TCP socket API rejects:

| Target | Documented result |
| --- | --- |
| Any address in Cloudflare's published IP ranges | Blocked |
| `localhost` | Disallowed-address error |
| Private network IPs | Disallowed-address error |
| The same Worker that opened the socket | `TCP Loop detected` |
| Destination port `25` | `Connections to port 25 are prohibited` |

The docs describe Cloudflare IPs, `localhost`, and private network IPs as
*examples* of disallowed addresses, not an exhaustive address taxonomy. The
project must not turn the platform error into its only authorization or SSRF
control. Reject prohibited/reserved destinations in project policy before
calling `connect()` and fail closed when the destination cannot be validated.

Cloudflare also recommends `fetch()` rather than TCP sockets for code that is
itself making HTTP requests to ports 80 or 443. That is not an outbound-port
ban. A byte-transparent VLESS TCP relay cannot replace the client's arbitrary
HTTP/TLS bytes with a Worker `fetch()` call.

**Verified:** TCP sockets originate from a prefix that is not in Cloudflare's
published [IP ranges](https://www.cloudflare.com/ips/). A destination that only
allowlists those public Cloudflare ranges should not be expected to admit these
connections.

### Connection-count nuance

The TCP API page says each open socket counts toward the open-connection
maximum. The newer, more specific limits page (modified 2026-07-05) and the
[2026-04-09 connection-limit change](https://developers.cloudflare.com/changelog/post/2026-04-09-relaxed-connection-limiting/)
say the limit was relaxed: six connections may be simultaneously in the
initial waiting-for-headers/establishment phase, and established connections no
longer consume one of those six slots.

**Inference based on the current limits page:** A `connect()` attempt counts
while the TCP connection is being established, rather than for the socket's
whole lifetime. A seventh simultaneous attempt is queued. The intended tunnel
uses one attempt and one established socket per WebSocket invocation, so it is
well below either interpretation in normal operation.

Source: [Workers limits, simultaneous open connections](https://developers.cloudflare.com/workers/platform/limits/#simultaneous-open-connections),
modified 2026-07-05.

## WebSocket behavior

### Upgrade and relay

**Verified:** A Worker creates a `WebSocketPair`, keeps the server side, calls
`accept()`, and returns the client side in a response with status `101`. The
server receives `message`, `close`, and `error` events and can send strings,
`ArrayBuffer`, or `ArrayBufferView` values.

Cloudflare WebSockets are available on all Cloudflare plans.

The VLESS endpoint should accept binary messages only. Text messages are not a
second protocol and should be rejected with a protocol-error close.

**Verified:** An inbound WebSocket message is limited to **32 MiB
(33,554,432 bytes)**. A larger message is automatically closed with code `1009`.
This is a per-message delivery limit, not permission to buffer 32 MiB per
connection. The relay should process normal client frames incrementally and
apply a much smaller bounded pre-auth/header buffer.

### Compatibility-date behavior that affects bytes and close handling

**Verified:** For compatibility dates on or after `2026-03-17`, binary messages
default to `Blob` because the `websocket_standard_binary_type` flag is active.
Set `server.binaryType = "arraybuffer"` before `server.accept()` or correctly
handle `Blob`. Setting it explicitly is preferable for a byte protocol and makes
the behavior independent of the compatibility default.

**Verified:** For compatibility dates on or after `2026-04-07`, receiving a
Close frame automatically sends the reciprocal Close frame. `accept({
allowHalfOpen: true })` opts into manual close coordination for proxying. The
relay must deliberately coordinate WebSocket close, TCP EOF, and TCP errors;
tests must cover both directions rather than relying on historical manual-close
behavior.

### Lifetime, idle behavior, and accounting

**Verified:** An incoming HTTP-triggered Worker has no hard wall-clock duration
limit while the client remains connected. Network wait time does not consume CPU
time. This makes a long-lived WebSocket/TCP bridge possible.

**Verified caveats:**

- Cloudflare runtime updates give an in-flight request a 30-second grace period
  and can then terminate it.
- Cloudflare network releases may restart servers and terminate WebSockets.
- Cloudflare closes idle WebSockets, recommends a heartbeat/keepalive, and does
  not publish a numeric default idle timeout on the current WebSocket page.
- The initial HTTP upgrade is subject to WAF/rate-limiting controls. Once the
  connection is established, the WAF does not inspect subsequent frames.

Sources:

- [Workers duration limits](https://developers.cloudflare.com/workers/platform/limits/#duration),
  modified 2026-07-05.
- [Cloudflare network WebSockets](https://developers.cloudflare.com/network/websockets/),
  modified 2026-04-23.

The client configuration and documentation must enable normal client reconnect
behavior and recommend a heartbeat. A single connection can be long lived, but
must never be described as permanent.

**Verified:** Workers billing/counting treats the WebSocket's initial Upgrade as
one Worker request. Messages sent through that established Worker WebSocket do
not each count as Worker requests. Source: [Workers pricing](https://developers.cloudflare.com/workers/platform/pricing/#workers),
modified 2026-07-07.

## Current Free-plan limits relevant to the tunnel

These are the limits published on 2026-07-05/07, not historical Bundled-plan
numbers:

| Limit | Workers Free | Tunnel implication |
| --- | ---: | --- |
| Requests | 100,000/day, reset 00:00 UTC | One initial Upgrade per WebSocket session |
| CPU | 10 ms per HTTP invocation | Parser/auth/frame callbacks must be small; I/O wait is excluded |
| Memory | 128 MB per isolate | Stream; never buffer destinations or many full frames |
| URL | 16 KB | More than sufficient for the fixed WebSocket path |
| Request/response headers | 128 KB each | Reject abnormal Upgrade metadata much earlier |
| Request body on a Free Cloudflare account plan | 100 MB | Not used after WebSocket upgrade |
| External subrequests | 50/invocation | Avoid auxiliary fetches in the hot path |
| Simultaneous connection establishment | 6/invocation | One outbound socket attempt is expected |
| Worker bundle, compressed | 3 MB | Favors a native minimal TypeScript adapter |
| Startup time | 1 second | No expensive global initialization |
| Variables/secrets | 64, 5 KB each | One UUID/auth secret is well within the limit |
| Custom Domains | 100/zone | One exact endpoint hostname is well within the limit |
| WebSocket inbound message | 32 MiB | Use bounded application buffers far below this ceiling |
| Log data | 256 KB/request | Never log payloads, UUIDs, or destination data |

Other relevant current behavior:

- There is no general Worker requests-per-second limit.
- Exceeding 100,000 daily requests returns Worker error 1027. A security endpoint
  must fail closed; it must not bypass the Worker to an origin.
- Cloudflare publishes no numeric Workers transfer quota in the limits table.
  This is not a guarantee of permanent or abuse-tolerant unlimited bandwidth.
- Workers Logs on Free currently includes 200,000 events/day with three-day
  retention. Payload logging is unnecessary and unsafe.

Sources:

- [Workers limits](https://developers.cloudflare.com/workers/platform/limits/),
  modified 2026-07-05.
- [Workers pricing](https://developers.cloudflare.com/workers/platform/pricing/),
  modified 2026-07-07.

**Dated live evidence:** The 2026-07-12 Free-account window recorded aggregate
CPU above 10 ms for some long-lived WebSocket invocations while all 30 outcomes
were the expected `clientDisconnected`, with zero `exceededCpu`, exception, or
error outcomes. Cloudflare documents built-in enforcement flexibility for
infrequent overages, while these analytics cover the complete long-lived
invocation. The exposed data does not prove per-event rollover. Keep every
callback comfortably below 10 ms; the observation does not turn an aggregate
quantile into a larger per-turn allowance or promise future enforcement
behavior.

## Custom Domain and Cloudflare-managed TLS

**Verified:** A Workers Custom Domain is appropriate when the Worker is the
origin. Creating one:

- requires an active zone owned by the account and an existing Worker;
- creates the necessary DNS record automatically;
- issues a certificate for the hostname automatically;
- routes every path on that exact hostname to the Worker;
- does not support a wildcard hostname;
- cannot be created on a hostname with an existing CNAME record or in a zone the
  account does not own.

In `wrangler.jsonc`, the declarative form is:

```jsonc
{
  "routes": [
    {
      "pattern": "vless.example.com",
      "custom_domain": true
    }
  ]
}
```

That is the platform's ordinary Wrangler form, not this repository's deployment
ordering. This project keeps equivalent `wrangler.jsonc` and
`cloudflare.config.ts` schemas because installed `cf 0.2.0` forces the latter's
new-config/Build Output path. Bootstrap copies leave the domain out. After the
fail-closed secret-bearing deployment and persisted direct-bind provenance, the
protected generated copies include the exact domain so later Build Output
deployments preserve public routing.

Source: [Workers Custom Domains](https://developers.cloudflare.com/workers/configuration/routing/custom-domains/),
modified 2026-06-23.

The generated clients should use:

- address/SNI/Host: the exact Custom Domain hostname;
- port: `443`;
- TLS: enabled;
- transport: WebSocket;
- WebSocket path: the configured path. The path is not a substitute for VLESS
  UUID authentication.

**Trust-boundary statement required in user documentation:** The client-to-edge
TLS certificate and TLS session terminate at Cloudflare. The Worker, and thus
Cloudflare's runtime, handles the VLESS header and tunneled bytes. A destination
protocol can add its own inner end-to-end encryption (for example HTTPS), but
this project does not provide end-to-end outer TLS past Cloudflare.

## Worker secrets

**Verified:** A Worker secret is an encrypted binding for text such as the VLESS
UUID/auth token. The value is available to code through `env`, but its value is
hidden in Wrangler and the dashboard after it is defined. Plain `vars` must not
hold authentication material.

Current Wrangler behavior includes:

- `wrangler secret put KEY` creates and immediately deploys a new Worker version;
- `wrangler versions secret put KEY` creates a version without deploying it;
- `wrangler deploy --secrets-file FILE` can upload code and up to 100 secrets in
  one version;
- declaring `secrets.required` makes development/upload/deploy fail clearly when
  a required secret is missing;
- `.dev.vars*` and `.env*` are local-only inputs and must be gitignored.

The installed `cf` CLI also accepts safe per-Worker secret input: it prompts on
a TTY and reads complete protected stdin when `--text` is omitted. The manager
uses the non-TTY protected-stdin branch; the exact division of responsibility is recorded in
[`research/cf-cli.md`](./cf-cli.md).

Source: [Workers secrets](https://developers.cloudflare.com/workers/configuration/secrets/),
modified 2026-07-03.

## Items that documentation cannot close

The following remain explicit deployment/integration gates rather than assumed
facts:

1. **Default WebSocket idle timeout:** Cloudflare documents that idle
   connections are closed but publishes no numeric default. One authenticated
   WebSocket/TCP session resumed after 45 seconds truly idle; that is a lower
   bound, not a platform timeout guarantee.
2. **Long-lived CPU behavior:** One two-minute Free-account window recorded CPU
   and outcomes under the complete client matrix. Longer windows, regions, and
   workload shapes remain unmeasured.
3. **Destination classification edges:** Test IPv4/IPv6 private, loopback,
   link-local, documentation/reserved ranges, DNS names that resolve into those
   ranges, Cloudflare hostnames, self-hostname, and port 25 on the deployed edge.
   Local Miniflare behavior is not proof of production filtering.
4. **Failure propagation:** Test client close, TCP FIN/RST, connect timeout,
   runtime termination, oversized WebSocket message, and reconnect without
   leaking sockets or authentication state.
5. **Free-plan CPU and memory at realistic throughput:** The dated three-client
   matrix supplies one realistic window. It does not establish day-to-day tails
   or future limit behavior.
6. **Specific destination reachability:** A documented generic TCP API cannot
   guarantee that every public host/port is reachable from every Cloudflare
   location. Treat connection errors as normal and bounded.

No item above changes the fixed protocol decision. They determine production
hardening and the strength of the final compatibility/free-tier claim.

## Live follow-up: 2026-07-12

An anonymized, explicitly authorized test deployment added the following
observed evidence without changing the official-documentation claims above:

- the operator-controlled hostname resolved publicly, presented a trusted certificate, and
  returned the Worker's exact generic 404 for an ordinary HTTPS request;
- unmodified Xray v26.7.11, sing-box v1.13.14, and Mihomo v1.19.28 each passed
  all 36 gates with zero failures: HTTPS/DNS, exact random-payload echo for 2
  MiB upload, 10 MiB download, same-connection 30-second active keepalive, four
  concurrent connections, and three reconnects;
- a separate authenticated WebSocket/TCP session resumed after 45 seconds truly
  idle. A 75-second test-service attempt was excluded because its upstream
  closes idle TCP connections;
- clean teardown and fresh recreation converged through the private removal
  checkpoint;
- live Domain IDs and certificate-pack IDs used API shapes broader than the
  original examples, the Domain `cert_id` was an alias rather than a child ID,
  and the generated Advanced pack contained multiple SANs. The manager now
  proves ownership from a pre-bind pack-ID baseline and the exact one new pack;
- Workers edge Fetch rejected `redirect: "error"`. The DoH code therefore uses
  `redirect: "manual"` and rejects every non-`ok` response, preventing redirect
  following while remaining fail closed;
- a deliberately narrow analytics window covered 30 invocations, all
  expected `clientDisconnected`, with zero errors, exceptions, or `exceededCpu`.
  CPU totaled 927.741 ms, memory p50/max was about 1.52/10.48 MiB, and all exact
  resource distributions are recorded in `docs/free-tier.md`. Persistent
  observability remained disabled;
- a follow-up metrics-only matrix measured 33.130/34.309/36.792 Mbps download
  and 19.692/20.068/20.287 Mbps upload (minimum/median/maximum across clients).
  Ten fresh authenticated public tunnel establishments measured 78.9 ms
  minimum, 87.7 ms median, 127.2 ms p90, and 183.9 ms maximum;
- Cloudflare API code `100328` rejected a temporary `limits.cpu_ms = 10` setting
  specifically because configurable CPU limits are unsupported on Free. The
  setting was removed without changing the Worker. `usage_model: standard` was
  treated as an execution-mode label, not evidence of a paid plan.

These results close the planned functional and short-window resource gates for
that deployment. They do not establish a numeric platform idle timeout,
long-duration or multi-region tails, all failure-propagation cases, or
real-device Shadowrocket import.
