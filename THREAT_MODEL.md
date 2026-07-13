# Threat model

## System and assets

The system is one user-owned Cloudflare Worker Custom Domain. A compatible
client opens WSS, sends a VLESS v0 UUID and TCP destination, and the Worker opens
one outbound TCP socket after authentication and destination validation.

Assets are the UUID/path credential pairs, Cloudflare account authority, local
deployment state, generated client files and QR codes, user traffic, and the
availability/reputation of the user's hostname and Cloudflare account.

## Trust boundaries

1. Client device to Cloudflare edge: protected by Cloudflare-managed TLS;
   Cloudflare terminates it.
2. Cloudflare edge/runtime: trusted to run Worker code, DNS-over-HTTPS, policy,
   and `connect()` as documented.
3. Worker to destination: raw TCP. Security depends on the tunneled application
   protocol; HTTPS/SSH can add end-to-end encryption.
4. Operator workstation to Cloudflare APIs: protected by the installed CLIs'
   authentication and local file permissions. The narrow certificate-pack
   workaround sends a legacy Global API Key directly to Cloudflare over HTTPS
   only after the primary `cf` request receives the exact known denial.

## Adversaries and mitigations

| Threat | Mitigation | Residual risk |
| --- | --- | --- |
| Unauthenticated open-proxy use | Mandatory VLESS UUID, constant-time comparison, generic failures | Stolen client config grants access until rotation |
| UUID/path guessing | Random UUIDv4 plus at least 24 random path bytes; rate/WAF controls remain available | Online traffic analysis and account-level attacks remain possible |
| Pre-auth memory/CPU denial | 1 KiB handshake bound, 1 MiB message queue, strict parser, handshake timeout | Cloudflare request and CPU limits can still be exhausted |
| SSRF into private/metadata networks | Literal classification; DoH answer validation and IP pinning; self/Cloudflare/port blocks; platform enforcement | IP-range lists and platform behavior evolve; live edge tests are required |
| DNS rebinding | Validate every A/AAAA answer and connect to the validated IP, not the domain | Resolver/Cloudflare compromise is inside the trust boundary |
| Protocol smuggling | Only VLESS v0, zero add-ons, TCP command, binary WS; reject UDP/Mux/text/unknown types | VLESS is not designed to hide its traffic shape |
| Queue/memory exhaustion after auth | Serialized writes, bounded queue, chunked sends, idle/session cancellation | Server-side WebSocket exposes no `bufferedAmount`; runtime transport buffering is opaque |
| Secret leakage through tooling | Ignored 0600 state, protected stdin, secret binding, redacted command results, no sensitive logs; optional Global API Key is parsed rather than sourced and stripped from children | Operator shell history/screenshots/backups can still leak artifacts; a leaked Global API Key grants broad account authority |
| Malicious destination | Conservative port allowlist; one socket per session | Port 80/443/22 services can still attack the client application |
| Censorship/fingerprinting | Generic HTTP 404 outside the path; randomized path | Domain, Cloudflare ASN, WSS, timing, and VLESS behavior remain identifiable |
| Cloudflare compromise/compulsion | None within this design | Cloudflare can observe or alter outer-tunnel plaintext; use inner encryption |

## Security invariants

- No request reaches `connect()` before UUID authentication and policy success.
- An unauthenticated response never includes credentials or a destination.
- Exactly one VLESS response header is sent per accepted session.
- No complete proxied stream is accumulated in memory.
- Session close, error, and timeout attempt deterministic writer/socket cleanup.
  Destination EOF releases only the readable half; the writable half remains
  bounded by the idle and absolute session deadlines.
- Default configuration creates no storage binding or shared mutable request
  state.
- Removal targets exact resource names/IDs recorded at initialization.

## Out of scope

Anonymity, cover traffic, domain fronting, bypass guarantees, malware filtering,
content inspection, arbitrary UDP, multi-user accounting, per-user quotas, and
protection of plaintext application protocols are out of scope.
