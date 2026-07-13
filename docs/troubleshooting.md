# Troubleshooting

## `doctor` cannot find or authenticate `cf`

Confirm `cf --version` and `cf auth whoami`, then select the intended account
and zone with `cf context`. The installed 0.2.0 CLI is a technical preview; if a
new version changes command schemas, rerun `doctor` and review
`research/cf-cli.md` before deploying.

## A command rejects the installed `cf` version

Deploy, rotate, and remove require exactly `cf 0.2.0`, including dry runs. Do
not bypass the check or assume a newer technical preview is command-compatible.
Install the pinned version, or first update the recorded command research,
adapter, and safety tests for the new schema.

## Client generation or testing reports a pending credential operation

Do not delete `.cf-vless/deployment.pending.json` and do not generate clients
from `.cf-vless/deployment.json`. Rerun the intended `cf-vless rotate` command
to reconcile the remote Worker secret and canonical state. `cf-vless config`,
`cf-vless test`, `config-gen`, and the standalone integration harness remain
blocked until the pending file is safely cleared by rotation.

## `doctor` or `logs` reports a Wrangler authentication error

`cf` and Wrangler keep separate authentication state. Deployment/resource
commands use `cf`; only the connected live-tail fallback uses Wrangler
authentication operationally. `doctor` also requires it because that command
checks readiness for every supported operation:

```sh
npm --prefix worker exec -- wrangler login --cwd worker
```

Do not respond by moving Worker deployment or secret handling to Wrangler.
Authenticate Wrangler independently to the same target account selected in
`cf`.

## `cf.certificate_access` fails with 403

Reauthenticate the current `cf` preview so its OAuth token includes the current
`ssl_certs:write` scope, then rerun doctor:

```sh
cf auth login --force
./bin/cf-vless doctor --zone example.com --hostname edge.example.com
```

If `cf` still reports the exact Cloudflare `9109 / 403` after reauthentication,
put the account's Global API Key in the Git-ignored repository
root `.env` as `CLOUDFLARE_GLOBAL_TOKEN=...`, set mode `0600`, and rerun
`doctor`. Do not source the file or export the key. The manager keeps `cf` as
the primary provider and uses this legacy key only for bounded certificate-pack
inventory and checkpointed exact-ID deletion. Any different failure remains
closed. Global API Keys are account-wide, so remove the file when it is no
longer necessary.

Certificate inventory access is a required deployment gate because Cloudflare
does not remove a Custom Domain's generated Advanced Certificate
automatically. Do not bypass the check or substitute an untracked general API
workflow.

## `remove --yes` reports that verification has not converged

Do not delete `.cf-vless/removal.pending.json`. Cloudflare may accept the
Advanced Certificate deletion before its inventory stops reporting the pack.
Wait briefly and rerun `cf-vless remove --yes`; the command uses the
checkpointed pack ID, revalidates its type and hostname, and repeats the
read-only absence check. The checkpoint is removed only after the Worker,
domain, certificate pack, and secret all read back as absent.

## `deploy` finds a live domain or pack but local provenance is incomplete

Do not edit `.cf-vless/deployment.json` or infer ownership from a hostname
alone. For an interrupted bind whose exact identifiers were obtained through a
separate read-only inventory, use the explicit recovery gates one at a time:

```sh
./bin/cf-vless deploy --recover-domain-id <exact-domain-id>
./bin/cf-vless deploy --recover-certificate-pack-id <exact-pack-id>
```

Recovery cannot be combined with `--dry-run`. The domain recovery requires the
owned Worker marker, required secret, and exactly matching live binding. Pack
recovery requires the already-recovered domain and an exact active Advanced
pack that covers the configured hostname. Any ambiguity fails closed.

## Custom Domain creation fails

- Verify the zone is active and owned by the selected account.
- Use an exact dedicated hostname inside that zone.
- Check for an existing CNAME or another Worker Custom Domain on the hostname.
- Check for a Worker Route whose host pattern covers the dedicated hostname;
  Routes can execute before a Custom Domain and are rejected by this manager.
- Do not delete a conflicting record unless you know it belongs to this
  deployment.
- Certificate issuance can take time; inspect status rather than disabling TLS
  verification in a client.

Never work around a certificate problem with `allowInsecure`,
`skip-cert-verify: true`, or an unrelated Host/SNI.

## Custom Domain is bound but public HTTPS returns 522

Confirm that the protected generated Worker configuration includes the exact
declarative Custom Domain in both the Wrangler and Build Output schemas. The
bootstrap configuration intentionally omits it, but every post-bind deploy must
publish it. On 2026-07-12, a direct bind followed by a generated deployment that
omitted this declaration left the public hostname at 522; publishing the
post-bind domain configuration restored the exact generic 404 with valid TLS.
Do not add an origin DNS record or disable certificate verification as a
workaround.

## A control-plane command returns Cloudflare 521/522

`status`, `logs`, deployment preflights, and removal deliberately inventory the
live Worker before trusting local ownership state. During the 2026-07-12 live
record, the Workers scripts inventory API briefly returned 521/522 while the
public TLS/404 readiness probe and established tunnels remained healthy. Treat
that as a control-plane failure, not proof that the public Custom Domain is
broken. Retry after the API recovers; do not bypass the ownership inventory or
mutate resources from cached IDs. Diagnose a publication problem only when the
independent public readiness probe also fails.

## Workers rejects `fetch()` redirect mode `error`

Cloudflare Workers' edge Fetch implementation does not support
`redirect: "error"`. The DNS-over-HTTPS resolver uses `redirect: "manual"`
instead and requires `response.ok`; exposed 3xx responses therefore fail closed
without being followed. Do not change it to the default follow behavior.

## Upgrade receives 404

The Worker intentionally returns the same generic 404 for ordinary HTTP, wrong
host, wrong path, non-WebSocket requests, invalid local configuration, and
expired previous paths. Compare the generated client against the current local
deployment state without printing the UUID/path into logs. Regenerate client
files after rotation.

## `config` refuses an existing output directory

The generator will not merge credential generations. If the directory contains
only the six files generated by this project and replacement is intentional,
run `cf-vless config --output ./client-configs --force`. It still refuses
unexpected files; move those elsewhere instead of deleting them implicitly.

## WebSocket closes with 1003, 1008, or 1009

- `1003`: the peer sent text/non-binary data;
- `1008`: malformed/unsupported VLESS, failed UUID, policy failure before
  authentication, or handshake timeout;
- `1009`: a message/application queue exceeded the bound.

Public reasons are deliberately generic. Reproduce with sanitized conformance
tests rather than enabling payload logging.

## Destination connection fails

Check the default allowed ports (`22,80,443`), public DNS answers, and whether
the destination uses a private, metadata, reserved, self, or Cloudflare IP.
Cloudflare addresses are blocked by the platform and project, so many
Cloudflare-hosted websites cannot be destinations for this raw TCP API.

Port 25 is prohibited. A different public port requires an explicit policy
change and redeployment; broad allowlists increase SSRF risk.

## Some domain names fail while literal public IP works

The domain path fails closed if any A/AAAA answer is unsafe or unclassifiable.
Mixed public/private answers, Cloudflare anycast addresses, internal suffixes,
malformed DNS responses, or DoH failure are rejected. This is intentional DNS
rebinding defense. Do not bypass it by making the Worker connect to the original
hostname without validated pinning.

## Long-lived sessions disconnect

Cloudflare runtime/network releases, unpublished idle behavior, account limits,
destination FIN/RST, and censorship can end WebSockets. Configure normal client
reconnect/keepalive behavior. The Worker also applies its idle and absolute
session deadlines. It does not promise permanent connections.

The dated live record resumed one authenticated WebSocket/TCP session after 45
seconds with no traffic. Do not treat the separate 75-second test-service result
as a Worker timeout: that upstream closes its own idle TCP connections. Use an
endpoint whose idle behavior you control, or send the active keepalive used by
the 30-second same-connection gate.

## Analytics reports more than 10 ms CPU on a Free account

In the dated Free-account window, aggregate CPU p99/maximum was 289.885 ms but
all 30 outcomes were the expected `clientDisconnected`, with zero
`exceededCpu`, exception, or error outcomes. Cloudflare documents built-in
enforcement flexibility for infrequent overages; it does not expose enough
detail in these analytics to prove per-event rollover. Keep each callback small
and use the outcome field alongside aggregate CPU.

Do not set `limits.cpu_ms` to force 10 ms on Free. Cloudflare rejected that
temporary test with API code `100328` because configurable CPU limits are not
available on the Free plan; the setting was removed without changing the live
Worker. Likewise, analytics `usage_model: standard` is an execution-mode label,
not proof that the account is paid.

## Xray prints a WebSocket deprecation warning

The pinned current Xray accepts the generated configuration but recommends
XHTTP. The warning is expected. The project's fixed protocol is WebSocket; do
not silently switch transports. Treat an actual configuration error separately.

## sing-box or Mihomo rejects a generated file

Record the binary version and run the syntax command from `COMPATIBILITY.md`.
Current formats differ in important ways: sing-box VLESS `network: tcp` is not
Mihomo's `network: ws`, and current Xray uses `streamSettings.method`. Do not
manually combine fields from different clients.

## sing-box runs but shows no traffic

Regenerate the client artifacts. Older generated profiles exposed only a
loopback mixed proxy, so no traffic entered sing-box unless each application or
the operating system explicitly used `127.0.0.1:1080`.

The current `sing-box.json` uses a system-wide TUN inbound. The command-line
client needs permission to create the TUN interface and install routes. Run it
with the appropriate administrator privileges, or import it into a graphical
sing-box client and grant that client's VPN permission. Confirm startup did not
report a TUN/route permission error. The China-direct/foreign-proxy policy only
applies after traffic enters sing-box.

Use the opt-in policy test in `docs/client-configurations.md` to distinguish a
route-policy or tunnel failure from missing system capture. It explicitly
drives the unprivileged mixed inbound and verifies both selected outbound tags.

## Shadowrocket import does not work

Shadowrocket has no public normative URI grammar. Confirm the exact app version,
import from both raw URI and QR, inspect every field, and follow the manual
checklist in `research/client-compatibility.md`. Keep the status unverified until
a real-device import and connection record passes.

## Safe diagnostics

Useful sanitized evidence includes tool/client versions, Worker version ID,
fixed error category, close code, timestamp window, byte counts, and pass/fail
test name. Never include UUIDs, paths, QR codes, full client IPs, destinations,
or captured traffic.
