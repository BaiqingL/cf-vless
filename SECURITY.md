# Security policy

## Supported versions

Until tagged releases exist, only the latest commit on the default branch is
supported. Security fixes are not backported to older commits or private
deployment snapshots. Operators should update, rerun `make check`, and perform
the documented dry-run before redeploying.

## Reporting a vulnerability

Do not put UUIDs, randomized paths, client configurations, Cloudflare account
details, API tokens, destination history, packet captures, or generated QR codes
in a public issue. Use the forge's private vulnerability-reporting or security-
advisory channel from the repository's **Security** tab. If that channel is not
enabled, contact the repository owner through an established non-public channel
and provide a minimal sanitized reproduction. Repository owners must configure
one of those private channels before inviting public use; do not substitute a
public issue with redacted-but-sensitive operational details.

Assume a disclosed UUID or randomized path is compromised. Do not preserve the
old pair for an overlap. Run `cf-vless rotate --emergency-revoke`, then
`cf-vless config --force` to atomically replace every client artifact, distribute
the new generation, and delete exposed files and QR codes from shared systems.

## Supported security boundary

The project authenticates VLESS v0 TCP sessions and relays them through a
Cloudflare Worker. It is not an anonymity system. Cloudflare terminates outer
TLS and is trusted to operate the edge, Worker runtime, logs, DNS-over-HTTPS,
and outbound socket API correctly.

The endpoint does not protect against:

- a malicious or compelled Cloudflare;
- compromise of the Cloudflare account, operator machine, or client;
- destination/application vulnerabilities;
- traffic analysis, hostname blocking, or WebSocket fingerprinting;
- exposure of plaintext application protocols sent inside the tunnel.

Use end-to-end application encryption such as HTTPS or SSH for sensitive
traffic.

## Authentication and secret handling

- `VLESS_CREDENTIALS` is a Worker secret containing the current UUID/path pair
  and, during rotation, one previous pair with an explicit RFC 3339 expiration.
- UUID comparison uses `crypto.subtle.timingSafeEqual` on fixed-size byte arrays.
- The path is not accepted as the sole credential.
- Local deployment state and generated clients are mode `0600` below ignored
  mode-`0700` directories.
- The manager provides Worker secrets to `cf` through protected non-TTY stdin,
  never command-line arguments, tracked configuration, environment dumps, or
  logs.
- The optional legacy Cloudflare Global API Key is accepted only from a
  size-bounded regular mode-`0600` root `.env`, never sourced, stripped from
  child environments, and usable only after an exact `cf` certificate-pack
  `9109 / 403` denial for bounded list or checkpointed exact-ID deletion.
  Credential-bearing requests never follow redirects, responses are bounded,
  and external errors are credential-redacted. This is a high-value
  account-wide credential. The adapter accepts Cloudflare's documented
  pre-2026 lowercase-hex and current `cfk_`-prefixed formats.
- Rotation refuses to silently discard a still-active previous credential.
- Emergency rotation immediately removes every previous credential; normal
  overlap removal requires `rotate --finalize` after expiration.

## Destination policy

Before `connect()`, the Worker validates the requested port and address. Literal
IP addresses are classified directly. Domains must be lowercase-compatible
ASCII DNS names without embedded credentials or local/internal suffixes. The
Worker resolves A and AAAA records through Cloudflare DNS-over-HTTPS, rejects
the entire answer set if any answer is unsafe, and pins the connection to a
validated address.

The policy blocks IPv4/IPv6 loopback, private space, link-local space,
unspecified addresses, multicast/reserved space, IPv6 unique-local space,
IPv4-mapped private space, known metadata endpoints, documentation/benchmark
ranges, the Worker's hostname, Cloudflare's published/service ranges, port 25,
and every port outside the configured allowlist. Cloudflare applies additional
platform restrictions.

The Cloudflare IP list is time-sensitive. Review it when updating the Worker
compatibility date and run the policy tests before deploying.

## Resource and parser limits

- VLESS handshake buffer: 1 KiB;
- queued client data: 1 MiB per session;
- server-to-client sends: bounded 64 KiB chunks with event-loop yields;
- Cloudflare inbound WebSocket limit: 32 MiB per message;
- handshake, connect, idle, and absolute session timeouts are explicit;
- one WebSocket invocation owns exactly one outbound TCP socket.

Malformed versions, commands, address types, domains, text frames, add-ons,
oversized queues, and unsupported UDP/Mux commands fail closed with generic
public diagnostics.

## Logging

Workers observability, stored logs, invocation logs, and sampling are disabled
by default. Debug logging is off. Source must not log UUIDs, paths, full client
IPs, destination names or addresses, traffic, or credential-bearing URLs.
Structured platform errors must use fixed event codes rather than exception
strings that could contain a destination. Run `test/security/no-secrets.sh`
before release.
