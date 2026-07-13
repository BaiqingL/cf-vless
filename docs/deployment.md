# Deployment

## What deployment creates

One deployment owns only these Cloudflare resources:

1. one Worker script/service with the configured `worker_name`;
2. versions/deployment state belonging to that Worker;
3. one Worker secret named `VLESS_CREDENTIALS`;
4. one exact Custom Domain hostname bound to that Worker and its
   Cloudflare-managed DNS record;
5. the Advanced Certificate pack Cloudflare generates for that Custom Domain;
6. the Worker's ordinary non-secret variables, including a random
   `DEPLOYMENT_MARKER` ownership value;
7. explicit Workers Logs/observability settings that disable stored logs,
   invocation logs, and sampling by default.

It creates no KV, D1, R2, Durable Object, Queue, Spectrum application, external
server, or project-operated service. Removal uses the exact recorded IDs/names
and ownership marker and must not alter unrelated DNS records or Workers.
Cloudflare does not automatically delete that Advanced Certificate when a
Custom Domain is detached. Immediately before bind, the manager durably records
the complete pack-ID baseline. After bind it accepts exactly one new
`advanced` pack whose host and every child certificate cover the configured
hostname, then persists that pack ID. This deliberately does not depend on the
Domain `cert_id`: live issuance on 2026-07-12 returned an alias there, a
canonical UUID pack ID, and a multi-SAN pack. A deployment is reported complete
only when the exact new pack is `active`. If issuance is asynchronous, rerunning
`deploy` completes or rechecks that partial state without rebinding the Domain.
Removal uses only those creation-time Domain and pack IDs; it never selects a
later same-host pack.

## Prepare Cloudflare

Use an active zone already managed by the same account and choose a dedicated
hostname, for example `edge.example.com`. Remove a conflicting CNAME only after
you establish that it belongs to this intended deployment; the CLI will not
silently delete it.

Authenticate and select the account/zone with `cf`:

```sh
cf auth login --force
cf auth whoami
cf context show
```

The installed `cf` OAuth scope set includes `ssl_certs:write`, but an older
cached login may predate that scope. `doctor` performs a read-only paginated
certificate-pack inventory check. Do not initialize or deploy until it passes;
otherwise Custom Domain removal cannot be reproduced safely.

The verified `cf 0.2.0` OAuth path can also return `9109 / 403` for that
inventory even while `cf auth whoami` reports the SSL scope. First refresh the
login. If the exact denial remains, create an owner-only, Git-ignored root
`.env` containing the legacy Global API Key under the compatibility name:

```dotenv
CLOUDFLARE_GLOBAL_TOKEN=<Global API Key>
```

Set the file to mode `0600`. The manager does not source it. It reads only that
value through a size-bounded regular-file check, obtains the email privately
from the already-valid `cf` identity, and sends `X-Auth-Email`/`X-Auth-Key`
only from its in-process HTTP client. It still tries `cf` first and falls back
only for the exact certificate-pack `9109 / 403`; all other failures remain
failures. The key is stripped from every `cf`, Wrangler, npm, and local client
child environment and never enters argv, diagnostics, state, or generated
configuration. Because a Global API Key is account-wide, use this narrowly
scoped compatibility path only when necessary.

Install sing-box and Mihomo on `PATH`; the versions in
[compatibility](../COMPATIBILITY.md) are verified baselines rather than enforced
minimums. Xray is built from the pinned submodule. The `doctor` command checks
`cf`, auth/account/zone access, Go 1.26+, Node.js `^22.18.0` or `>=24.0.0` with
npm, Git, ripgrep (`rg`), all three clients, the pinned Xray submodule, and the
project-local Wrangler without changing the account.
Before initialization, both `--hostname` and `--zone` are required so domain
availability cannot be silently skipped; initialized state supplies both on
later runs. Wrangler's auth store is separate from `cf`. Only the `logs`
command uses Wrangler authentication operationally, but `doctor` is an
all-command-readiness check and therefore treats Wrangler login and access to
the selected account as required:

```sh
npm --prefix worker exec -- wrangler login --cwd worker
```

Deploy, rotate, status, domain, secret, and removal operations continue to use
the authenticated `cf` session.

## Initialize local state

```sh
go build -o ./bin/cf-vless ./cmd/cf-vless
./bin/cf-vless init \
  --hostname edge.example.com \
  --zone example.com \
  --name "Personal Edge"
```

Initialization generates a UUIDv4 and a path from at least 24 random bytes,
generates a separate non-secret ownership marker, validates the dedicated
hostname/zone relationship and rejects conflicting Custom Domains, exact DNS
records, or Worker Routes covering that hostname, writes the canonical state
to `.cf-vless/deployment.json`, and creates a generated Worker project under
the same ignored owner-only directory. It refuses existing state rather than
overwriting a credential. DNS and route inventories are read again immediately
before a new Custom Domain bind to narrow the deployment race window.

The tracked `worker/wrangler.jsonc` and `worker/cloudflare.config.ts` are tested
equivalent templates. The former drives normal Wrangler tests and explicit
fallbacks. Installed `cf 0.2.0` forces Wrangler's Build Output API/new-config
path, so `cf build` and `cf deploy` consume the latter. Generated deployment
copies of both derive variables from the canonical Go state so hostname, port
policy, timeouts, observability, and secret requirements cannot drift.

The bootstrap copies omit the Custom Domain so the first unprotected upload is
not public. After the protected Worker and secret exist and direct-bind
provenance is persisted, generated copies include the exact declarative Custom
Domain in both schemas. This post-bind publication is required so subsequent
`cf deploy` calls preserve routing through the Build Output path.

## Deploy safely

```sh
./bin/cf-vless deploy --dry-run
./bin/cf-vless deploy
```

The manager uses `cf` first for account/zone/certificate inspection, Worker
build/upload/deploy, status, and Custom Domain configuration. Only the exact
certificate-pack authorization gap described above uses the in-process REST
fallback; it is not a general Cloudflare API or deploy fallback. The installed
`cf` 0.2.0 is an early technical preview; exact capability boundaries and
command schemas are recorded in `research/cf-cli.md`. The explicit dry run
detects whether this is the
unroutable first-upload branch or an owned update and exercises that exact
build/preflight path without changing Cloudflare resources.

Every deploy, rotation, and removal invocation first runs `cf --version` and
requires the exact verified `0.2.0` version. This command-level gate runs before
deploy workspace preparation, before rotation creates a pending credential,
and before removal inventory or deletion, so an unreviewed preview schema
cannot partially execute a transaction. Newer versions are not accepted
implicitly; update the capability research and tests before changing the pin.

Secret values never appear in argv. The manager invokes
`cf workers secrets update` without `--text` and writes the JSON credential set
directly to the child process through protected, non-TTY stdin. Command
diagnostics redact that stream. There is no Wrangler secret or deploy fallback
in the managed bootstrap.

New-Worker bootstrap is fail closed and `cf`-only. The manager first prepares
temporary Wrangler/cf configurations without the required-secret declaration,
dry-runs them, uploads the Worker
with `workers_dev` and preview URLs disabled, writes the secret over protected
stdin, restores the declaration in both schemas, dry-runs and deploys the
protected version, previews and creates the exact Custom Domain binding, and
then verifies the Worker, marker, secret, deployment, and domain. Bootstrap
code without a valid secret returns only the generic 404 and cannot open a TCP
socket.

Every deploy/secret/remove operation reads the remote `DEPLOYMENT_MARKER` and
refuses a same-named Worker with a different marker. The marker is an ownership
guard, not a bearer credential and not a substitute for the UUID.

## Generate and validate clients

```sh
# Replace every probe.example/echo.example value with an approved endpoint.
./bin/cf-vless config --output ./client-configs
./bin/cf-vless test \
  --clients all \
  --https-url https://probe.example/ \
  --download-url https://probe.example/download \
  --upload-url https://probe.example/upload \
  --tcp-echo echo.example:443
```

`config` derives every format from the same current credential and promotes all
six mode-`0600` artifacts as one generation, including the animated
`sing-box.gif` QRS profile. It refuses an existing output
directory unless `--force` is supplied; forced replacement still refuses
unexpected files. `test` defaults to all three unmodified clients and invokes
the same DNS/HTTPS, download, upload, long-lived TCP, concurrency, and reconnect
probes for each. Missing binaries, hostname, controlled endpoints, or live
reachability are failures, not synthetic passes.

The example probe hostnames are placeholders. The upload endpoint must echo
the exact ASCII body as raw bytes or a top-level JSON `data` string; the TCP
service must echo complete newline-framed lines. The full contract is in
[the CLI reference](cli.md#integration-endpoint-contract).

`config`, `test`, the standalone `config-gen`, and the standalone integration
harness take the private state-directory operation lock and refuse to consume
the canonical deployment while its sibling `deployment.pending.json` exists.
Resume `rotate` first; generating or testing the canonical file during that
window could distribute or validate a credential already replaced remotely.

Before relying on the endpoint, record the live gates in `COMPATIBILITY.md` and
`docs/free-tier.md`.

The dated live deployment completed these functional gates, including safe
teardown/recreation and the explicit test-only addition of port `4242`; the
repository default remains `22,80,443`. Exact client results live in
[compatibility](../COMPATIBILITY.md), and resource/performance evidence lives
in [the Free-tier record](free-tier.md). Keep this deployment procedure
tenant-neutral instead of copying dated measurements into it.

## Rotate

```sh
./bin/cf-vless rotate --overlap 24h
./bin/cf-vless config --output ./client-configs --force
```

Rotation atomically generates both a new UUID and path. The former pair moves
to `previous` with an explicit UTC expiration and remains accepted on its old
path during the overlap. The command refuses to discard a previous credential
that is still active. Distribute new client files, wait for the printed overlap
expiry, then remove only the expired previous pair without generating another
credential:

```sh
./bin/cf-vless rotate --finalize
```

If a UUID/path may be exposed, do not preserve it for an overlap. Replace the
current pair and revoke every old pair immediately, then atomically replace the
client artifacts:

```sh
./bin/cf-vless rotate --emergency-revoke
./bin/cf-vless config --output ./client-configs --force
```

Rotation writes a private pending file before changing the remote secret and is
resumable after an interrupted update. Mutating commands use an operation lock
so concurrent deploy/test/config/rotate/remove processes cannot mix credential
generations.

Because client files and QR codes contain bearer credentials, delete superseded
copies from backups/shares where possible.

## Logs and status

```sh
./bin/cf-vless status
./bin/cf-vless logs
```

Stored/log tail output must not contain UUIDs, paths, destinations, client IPs,
or traffic. The Worker emits no application debug logs by default. Platform
metadata may still be present inside the Cloudflare trust boundary.

Persistent Workers observability, invocation logs, and sampling are disabled in
both tracked and generated configurations. `logs` first verifies the ownership
marker, then invokes the project-local Wrangler only because `cf 0.2.0` cannot
attach to the tail WebSocket. It sanitizes JSON fields conservatively before
printing them. This live-tail fallback requires the separate Wrangler login
shown above; deployment authentication remains `cf`-only.

## Remove

```sh
./bin/cf-vless remove --dry-run
./bin/cf-vless remove --yes
```

The dry run verifies and previews the creation-time-recorded domain binding ID,
generated Advanced Certificate pack ID, secret name, and Worker name without
mutation. Automatic removal is refused if full bind-time provenance is absent.
Review that plan before passing `--yes`; Worker deletion may still require
`cf`'s terminal confirmation. A confirmed run executes the complete provider
dry-run again and saves those non-secret IDs to the private
`.cf-vless/removal.pending.json` checkpoint before its first deletion. It then
deletes the exact Custom Domain binding, generated certificate pack,
`VLESS_CREDENTIALS`, and marker-matched Worker in dependency order.

Certificate deletion is previewed with `cf` during dry-run. A confirmed live
delete also tries `cf` first; only an exact `9109 / 403` can activate the
Global-key REST DELETE, and the response must identify the checkpointed pack
ID. Ambiguous transport or provider failures are never replayed through the
fallback.

The manager refuses duplicate/ambiguous certificate or domain IDs, a current
domain or pack that differs from bind-time provenance, additional service
domains, additional or malformed Worker bindings, additional secret bindings,
routes, Cron schedules, assets, tags, tail consumers, Logpush, enabled
observability, workers.dev, preview URLs, and any Worker whose marker differs.
Those attachment inventories are read before any delete command. If a later
step fails after the domain is gone, rerunning `remove --yes` uses only the
checkpointed certificate-pack ID, revalidates its type and hostname, and
resumes. After the delete commands succeed, a read-only pass must prove that
the Worker, domain,
certificate pack, and secret are absent. Pending or merely accepted
asynchronous certificate deletion retains the checkpoint and returns a
retryable failure; the checkpoint is deleted only after that read-back
converges.

An anonymized 2026-07-12 teardown exercised the fail-closed path: the primary `cf`
delete produced provider code `1406`, the private checkpoint was retained, and
a later run resumed rather than rediscovering resources. When the certificate
path encountered the exact authorization denial, the bounded Global-key
fallback deleted only the checkpointed pack. Final read-only inventory proved
the domain, pack, secret, and Worker absent. A fresh test deployment then proved
the same lifecycle again. This record proves one controlled run, not permanent
API compatibility or the state of any current operator account.

Local deployment state/client artifacts are retained for audit unless the user
explicitly deletes them; keeping them also means keeping credentials. Removal
does not promise deletion of Cloudflare account, audit, billing, or security
records outside the exact resource plan.
