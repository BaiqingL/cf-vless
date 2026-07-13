# Limitations

- Cloudflare terminates the outer TLS connection and is part of the trust
  boundary. This is not end-to-end outer TLS.
- Only the VLESS v0 TCP command over WebSocket is implemented. There is no
  arbitrary UDP, DNS packet proxy, Mux, Flow, REALITY, XTLS, XHTTP, gRPC, or
  alternative protocol/transport.
- The default destination allowlist is ports `22`, `80`, and `443`. Operators
  can deliberately generate a different allowlist, but port `25` is always
  blocked and broad ranges weaken the security posture.
- Cloudflare's socket API blocks Cloudflare IP ranges. The project blocks them
  before `connect()` as well. Consequently, destinations served on Cloudflare
  addresses—including many websites—cannot be reached through this raw TCP
  tunnel. There is no `fetch()` substitution because that would not preserve an
  arbitrary client TCP stream.
- Domain policy depends on Cloudflare DNS-over-HTTPS. A name with any unsafe,
  malformed, Cloudflare, or unclassifiable answer fails closed. This can reject
  mixed or unusual but legitimate deployments.
- The Workers server-side WebSocket API has no observable `bufferedAmount`.
  Application queues are bounded and destination data is sent in 64 KiB chunks
  with yields, but Cloudflare's internal transport queue remains opaque.
- WebSockets can be terminated by runtime/network releases, idle policies,
  censorship, or account limits. Clients must reconnect. No duration or
  availability guarantee is made.
- Free-plan limits and platform behavior change. Reasonable personal use is an
  objective, not a promise of unlimited bandwidth, permanent free operation, or
  abuse tolerance. In the dated live window, aggregate per-invocation CPU
  values exceeded 10 ms without any `exceededCpu` outcome. Cloudflare documents
  some enforcement flexibility but not the exact event-accounting mechanism;
  the observation is not permission for expensive callbacks or a guarantee
  about future enforcement.
- A dedicated hostname and Cloudflare account may be identified, rate-limited,
  suspended, or blocked. The generic 404 is not a censorship-resistance system.
- VLESS UUIDs and QR codes are bearer credentials. There is no multi-user
  identity, quota, revocation list, or audit trail in the default data path.
- The current default uses a Cloudflare-hosted DoH resolver for safe address
  classification and does not expose a user-selectable resolver.
- `remove --yes` plans and attempts deletion of the exact marker-owned Worker,
  secret, Custom Domain, and uniquely matched generated Advanced Certificate
  pack. The manager records the pre-bind pack-ID inventory, accepts exactly one
  new hostname-covering Advanced pack after bind, and persists that exact pack
  ID. This is necessary because the live Domain `cert_id` can be an alias and
  the generated pack can be multi-SAN. A pack discovered only during removal is
  never selected. The command fails closed if creation-time proof is
  incomplete, remote IDs changed, or extra domains, secrets, Worker bindings,
  routes, Cron schedules, assets, tags, tails, Logpush, observability,
  workers.dev, or previews are attached. It retains its private checkpoint
  until a read-back proves asynchronous deletion has converged, and retains
  local state/client artifacts. A dated live teardown/resume completed on
  2026-07-12, but future Cloudflare API behavior can still change.
- Shadowrocket cannot be automated in this repository and remains unverified
  until the manual record exists.

Live edge behavior and executable-client E2E status are tracked in
`COMPATIBILITY.md`. The matching CPU, memory, subrequest, wall-time, and traffic
analytics are tracked in `docs/free-tier.md`. They prove one observed
Free-account window, not behavior across every region, day, workload, platform
release, or future plan limit.
