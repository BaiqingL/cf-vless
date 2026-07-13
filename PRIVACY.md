# Privacy

This project operates no central service, registry, analytics endpoint, or
control plane. The Go CLI acts directly on the user's Cloudflare account through
the installed Cloudflare tooling and, only for the documented `cf 0.2.0`
certificate authorization gap, a narrow in-process Cloudflare API client. The
default Worker uses no KV, D1, R2, Durable Objects, or project-operated data
store.

That does not mean the tunnel is private from every party.

## Parties that process data

- **Cloudflare** terminates the public TLS session, executes the Worker, resolves
  requested domain destinations through Cloudflare DNS-over-HTTPS, and opens the
  outbound TCP socket. It can process account, hostname, client-network,
  destination, timing, size, and tunneled-byte data subject to its services and
  policies.
- **The destination and intervening network** observe the outbound Worker TCP
  connection and any application data not protected by an inner protocol.
- **The operator and client device** store the UUID, hostname, path, generated
  configurations, and local test results.

Cloudflare is part of the trust boundary. See
`docs/cloudflare-trust-boundary.md`.

## Project logging and storage

The Worker deliberately logs none of the following: UUIDs, randomized paths,
full client IP addresses, destination domains or IPs, traffic contents, or
credential-bearing URLs. The tracked and generated Wrangler configurations
disable Workers observability, stored/invocation logs, and sampling by default.
The optional `cf-vless logs` command opens a real-time tail through the
project-local Wrangler and sanitizes fields before printing; it does not enable
persistent logging. Cloudflare may still generate platform request, security,
and account records outside Worker source control.

Local deployment state is stored under `.cf-vless/`; client outputs default to
`client-configs/`. Both are ignored by Git and should remain owner-readable
only. Removing the Cloudflare resources does not delete local client files;
delete those separately when retiring a credential.

When the optional `cf 0.2.0` certificate authorization workaround is needed,
the repository-root `.env` contains a legacy Cloudflare Global API Key. It is
Git-ignored, must be mode `0600`, is never sourced, and is read only for the
in-process certificate-pack fallback. It is not copied into `.cf-vless`, child
environments, Worker configuration, client artifacts, or logs. The account
email used with it is read transiently from `cf auth whoami` and is not stored
by the project.

The installed `cf`, Wrangler, npm, Go, Git, Xray, sing-box, and Mihomo tools have
their own update, telemetry, and network behavior. Consult their policies and
disable optional telemetry where appropriate.
