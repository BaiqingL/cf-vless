# Cloudflare trust boundary

The public connection is:

```text
client -- TLS/WSS --> Cloudflare edge -- Worker APIs --> destination TCP
```

Cloudflare presents and manages the certificate for the user's Custom Domain
and terminates that TLS session before Worker execution. The Worker receives
WebSocket messages containing the VLESS header and application bytes. It asks
Cloudflare DNS-over-HTTPS for destination addresses and asks
`cloudflare:sockets` to establish the outbound TCP stream.

Therefore Cloudflare can technically process:

- the account, Custom Domain, certificate, and source-network metadata;
- the randomized path in the HTTP Upgrade request;
- VLESS UUID and requested destination before the Worker authenticates it;
- timing, sizes, errors, and the tunneled byte stream;
- DNS questions and answers used for policy;
- outbound destination and connection metadata.

Worker source intentionally does not log those values, but source-level logging
discipline cannot remove Cloudflare from the data path or control all platform
records. The deployment disables stored Workers observability, invocation logs,
and sampling by default; Cloudflare can still retain platform, security, and
account records outside Worker source control.

## Inner encryption

When the tunneled application is HTTPS, SSH, or another end-to-end encrypted
protocol, its own encryption remains between the client application and the
destination. Cloudflare still sees outer metadata and encrypted inner bytes.
Plain HTTP through the tunnel is plaintext at Cloudflare and on the outbound TCP
leg.

## Claims this project does not make

- It is not REALITY, XTLS, Vision, domain fronting, or raw inbound TCP.
- The outer TLS connection is not end to end through the destination.
- Cloudflare cannot be excluded from the confidentiality/integrity boundary.
- Use of a personal hostname or WebSocket is not unobservable or unblockable.
- Cloudflare service availability, pricing, policy, and behavior are not
  permanent.

If trusting Cloudflare with this position is unacceptable, this architecture is
the wrong tool; adding a misleading label or another VLESS option cannot change
where TLS terminates.
