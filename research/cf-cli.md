# Installed `cf` CLI versus Wrangler

Research snapshot: **2026-07-12**. All `cf` operations used for this research
were help, authentication-status, schema, package inspection, or `--dry-run`
operations. No Worker, route, domain, DNS record, secret, tail, or other account
resource was created, updated, deployed, or deleted.

That paragraph records the original non-mutating CLI research. The separate
dated live follow-up at the end records later explicitly authorized deployment,
teardown, and client evidence; it does not retroactively redefine the snapshot.

## Bottom line for this repository

The verified executable reported:

```text
cf 0.2.0
Node.js requirement: >= 22
```

`npm view cf` reported `0.2.0` as the current `latest` tag, published
2026-07-10. In an anonymized validation, `cf` authenticated successfully but
returned `403 Unauthorized` for a read-only certificate-pack inventory request.
A legacy-format Global API Key from the test account succeeded for the same
read-only endpoint with `X-Auth-Email`/`X-Auth-Key`; no account/user identifier,
live certificate relationship, or deletion result is retained here.

Cloudflare calls `cf` an **early technical preview** of the future Wrangler CLI,
not a stable replacement for all current Wrangler workflows. The official
[announcement](https://blog.cloudflare.com/cf-cli-local-explorer/) is dated
2026-04-13 and explicitly says the preview will be brought together with the
existing parts of Wrangler over time.

For this project:

1. Use `cf` for authentication, account/zone inspection, the high-level
   build/deploy entry point, Worker inspection, per-Worker secrets, DNS and
   Custom Domain inspection/configuration, status, and removal.
2. Generate equivalent `worker/wrangler.jsonc` and
   `worker/cloudflare.config.ts` files from the canonical Go deployment state.
   Normal Wrangler tooling consumes the former; `cf 0.2.0`'s forced new-config
   Build Output path consumes the latter.
3. Pin Wrangler locally in `worker/package.json`. `cf build`/`cf dev` discover a
   project-installed implementation; the installed `cf` package recognizes
   Wrangler as one such implementation. There is no global `wrangler` binary in
   this workspace at the research snapshot.
4. Use the pinned Wrangler directly only for capabilities `cf 0.2.0` does not
   finish: type generation, startup profiling, a connected real-time log tail,
   convenient bulk/version-scoped secrets, and high-level traffic deployment or
   rollback. The managed deployment path needs none of the secret/deploy
   fallbacks; its only operational Wrangler fallback is live tail attachment.
5. Version-check `cf` before automating it. The manager runs `cf --version` and
   requires exactly `0.2.0` before deploy preparation, rotation pending-state
   creation, or removal planning; a newer preview is not assumed compatible.
6. Keep `cf` primary for certificate-pack list/delete. Only the exact observed
   `9109 / 403` can activate the in-process Global-key fallback; never use that
   account-wide credential for Worker deploy, secrets, domains, or a general
   raw-API path.

## What was observed in `cf 0.2.0`

### Top-level project commands

`cf --help` exposes:

| Command | Observed purpose |
| --- | --- |
| `cf auth` | `login`, `logout`, `whoami` |
| `cf context` | Show/set/clear default account and zone |
| `cf build` | Build a project; accepts `--mode` |
| `cf deploy` | Build/check/upload/deploy; accepts `--mode`, `--prebuilt`, `--tag`, `--message`, `--dry-run` |
| `cf dev` | Discover and spawn the project's installed Cloudflare dev server |
| `cf versions upload` | Build/upload a Worker version without deploying it |
| `cf schema` | Inspect generated API command schemas |
| `cf agent-context` | Emit product command/tool context |
| `cf accounts`, `dns`, `registrar`, `zones` | General account and zone API commands |

`cf dev` is a façade, not a second Worker simulator. Its help states that the
project must have exactly one installed dev-server implementation and that it
spawns that implementation as a subprocess. Arguments after `cf dev` are passed
to the implementation.

Inspection of the installed package's deployment code established that:

- the build layer recognizes `wrangler`, `@cloudflare/vite-plugin`, the Python
  dev server, and the Rust dev server;
- `cf build` invokes the local Wrangler `cf-wrangler` delegate with its
  experimental new-config/Build Output path and therefore requires
  `cloudflare.config.ts` and Node.js 22.18+; a `wrangler.jsonc`-only project
  fails before bundling;
- high-level deploy consumes the resulting Cloudflare Build Output API files;
- it reads the built Worker configuration and forwards configured routes;
- the high-level deploy currently asserts exactly one Worker in the build
  output, which matches this repository's one-Worker design;
- `cf deploy --dry-run` builds and runs checks without upload;
- `cf versions upload --dry-run` does the same for a version upload.

These are **installed-package observations**, not a live account deployment.
With the dual generated configuration in place, the tracked Worker ran both
`cf build` and `cf deploy --dry-run` successfully on 2026-07-12. The latter
reported the expected seven non-secret bindings, disabled public preview
surfaces, and a 31.38 KiB / 8.13 KiB intermediate bundle; it did not upload
anything. The final post-follow-up bundle is recorded separately below and in
`docs/free-tier.md`.

### Generated Cloudflare API commands

`cf schema --list | jq length` returned **2,752** API operations. The short
top-level help does not list every product, but generated Worker commands are
callable. Relevant observed groups are:

```text
cf workers scripts ...
cf workers versions ...
cf workers deployments ...
cf workers secrets ...
cf workers domains ...
cf workers routes ...
cf workers observability telemetry ...
cf workers scripts tail ...
```

Representative dry runs confirmed the intended REST endpoints without changing
the account:

| Command | Endpoint shape printed by `--dry-run` |
| --- | --- |
| `cf workers scripts list --dry-run` | `GET /accounts/<account>/workers/scripts` |
| `cf workers scripts schedules get --worker <worker>` | `GET /accounts/<account>/workers/scripts/<worker>/schedules` |
| `cf workers scripts settings get --worker <worker>` | `GET /accounts/<account>/workers/scripts/<worker>/settings` |
| `cf workers scripts subdomain get --worker <worker>` | `GET /accounts/<account>/workers/scripts/<worker>/subdomain` |
| `cf workers domains list --dry-run` | `GET /accounts/<account>/workers/domains` |
| `cf workers routes list --dry-run` | `GET /zones/<zone>/workers/routes` |
| `cf workers secrets list --dry-run` | `GET /accounts/<account>/workers/scripts/<worker>/secrets` |
| `cf workers scripts tail create --dry-run` | `POST /accounts/<account>/workers/scripts/<worker>/tails` |

Generated API command `--dry-run` prints the request that would be made. It is
not the same as high-level `cf deploy --dry-run`, which builds and checks the
project.

For fail-closed deployment/removal, the manager also validates the target item
from `workers scripts list` (`routes`, `tail_consumers`, `logpush`, and
`has_assets`), requires an empty schedules response, requires disabled
Logpush/observability with no tags or tail consumers in script settings, and
requires both workers.dev and preview subdomain flags to be false. These are
read-only calls; they run before any resource mutation.

## Exact task-by-task split

The Wrangler side of this table reflects current official Wrangler docs and
the current npm release observed on 2026-07-12 (`4.110.0`). The repository
should pin the chosen Wrangler version rather than invoke `@latest` in normal
automation.

| Project task | `cf 0.2.0` | Wrangler | Repository choice |
| --- | --- | --- | --- |
| OAuth login/logout/status | `cf auth login/logout/whoami` | `wrangler login/logout/whoami` | **Use `cf`** |
| Account and zone discovery | First-class `accounts` and `zones` commands | `whoami` exposes account context but Wrangler is not a general zone/DNS CLI | **Use `cf`** |
| DNS inspection/records | `cf dns records ...` | No equivalent general DNS command family | **Use `cf` if manual DNS work is needed**; Custom Domains normally create DNS automatically |
| Build one Worker | `cf build`; requires `cloudflare.config.ts` and delegates to the pinned Wrangler Build Output path | `wrangler deploy --dry-run` can bundle directly from `wrangler.jsonc` | **Use `cf build`**, with equivalent generated configs and pinned Wrangler as the implementation |
| Local development | `cf dev` delegates to exactly one installed dev server | `wrangler dev` implements Worker local/remote development | **Expose `cf dev` as the preferred entry point**; Wrangler remains the implementation |
| Deploy code | `cf deploy`, including `--dry-run`, tags, messages, and prebuilt output | `wrangler deploy` | **Use `cf deploy` exclusively in the deployment manager**; use pinned Wrangler dry runs as a local release check |
| Upload without traffic | High-level `cf versions upload`; raw `cf workers versions create` | `wrangler versions upload` | **Use high-level `cf versions upload`** |
| List/get Worker versions | Raw generated `cf workers versions list/get` | `wrangler versions list/view` | **Use `cf` for read-only inspection** |
| Deploy traffic percentages | Raw `cf workers deployments create` accepts percentage strategy/body | `wrangler versions deploy` is the high-level workflow | **Use Wrangler** for intentional traffic changes; raw API is too low-level for routine release tooling |
| Roll back | Raw deployment API can express an older-version deployment, but no high-level `cf rollback` exists | `wrangler rollback` | **Use Wrangler** |
| List Worker scripts/settings | `cf workers scripts list/get/settings ...` | Several Wrangler inspection commands | **Use `cf`** |
| Upload raw multipart script | `cf workers scripts update` exposes the API but does not provide the normal bundling workflow | Wrangler bundles and uploads | **Do not use raw API upload**; use high-level `cf deploy` |
| Set one Worker secret | `cf workers secrets update NAME --worker WORKER`; prompts on a TTY or reads stdin when `--text` is omitted | `wrangler secret put NAME` | **Use `cf` with protected stdin** |
| List/get/delete a Worker secret | `cf workers secrets list/get/delete` | `wrangler secret list/delete` | **Use `cf`** |
| Bulk or atomic deploy-time secrets | No high-level `cf deploy --secrets-file` or Worker-secret bulk command was observed | `wrangler secret bulk`, `wrangler deploy --secrets-file`, `wrangler versions secret ...` | **Use Wrangler only when this capability is required** |
| Configure a Custom Domain directly | `cf workers domains update/list/get/delete` | Declarative `routes[].custom_domain = true` and deploy | **Use exact `cf` dry-run/update/list calls after the protected Worker deploy** |
| Configure a route directly | `cf workers routes create/list/get/update/delete` | Declarative routes in `wrangler.jsonc` | Not used; this project exposes only the exact Custom Domain |
| Inventory/delete generated certificate pack | `cf ssl certificate-packs list/delete` exists but the current OAuth session receives `9109 / 403` | No general certificate-pack workflow | **Try `cf` first**; use the narrowly scoped in-process legacy Global-key fallback only for that exact denial |
| Stored observability query | `cf workers observability telemetry query` | Dashboard/API-oriented; Wrangler focuses on tail | Available but normally empty because this project disables persistent observability by default |
| Start a tail API session | `cf workers scripts tail create/delete` only creates/deletes the API session | `wrangler tail` creates the session, attaches to its WebSocket, streams, filters, and cleans up | **Use Wrangler for live logs** |
| Generate Worker binding types | No command observed | `wrangler types` / `wrangler types --check` | **Use Wrangler** |
| Profile startup limit | No command observed | `wrangler check startup` and deploy profiling | **Use Wrangler** |
| Initialize a project | No `cf init` observed | Wrangler/C3 project scaffolding exists | Not needed after repository scaffolding |
| General Cloudflare API resources | 2,752 generated operations at this snapshot | Wrangler has curated product families, not the entire API | **Use `cf`** when the exact generated command exists |

Official Wrangler references:

- [Wrangler Workers commands](https://developers.cloudflare.com/workers/wrangler/commands/workers/),
  modified 2026-07-03.
- [Wrangler general commands](https://developers.cloudflare.com/workers/wrangler/commands/general/),
  modified 2026-07-03.
- [Wrangler configuration](https://developers.cloudflare.com/workers/wrangler/configuration/),
  modified 2026-07-09.
- [Real-time logs and `wrangler tail`](https://developers.cloudflare.com/workers/observability/logs/real-time-logs/),
  modified 2026-06-25.

## Safe command forms for this project

The deployment manager should discover IDs rather than requiring users to copy
them from the dashboard:

```sh
cf auth whoami
cf accounts list
cf zones list
cf workers scripts list
cf workers domains list --zone-name "$ZONE"
```

Do not log the raw `cf auth whoami` result because it contains account identity
and token-scope metadata.

### Build and deploy

Run the high-level project commands from the tracked `worker/` directory (or
from the generated owner-only Worker workspace used by the manager):

```sh
cd worker
cf build
cf deploy --dry-run
cf deploy --message "Deploy cf-vless"
```

`cf deploy --dry-run` is mandatory before the first actual upload. The manager
must reject an unsupported `cf` version rather than guessing renamed preview
commands.

### Secret

Use `cf` without `--text` so the VLESS credential set does not enter argv or
shell history:

```sh
cf workers secrets update VLESS_CREDENTIALS \
  --worker "$WORKER" \
  --type secret_text
```

Inspection of the installed `cf` 0.2.0 prompt helper confirmed that omitting
`--text` prompts when attached to a TTY and reads the complete non-TTY stdin
stream otherwise. The deployment manager uses the latter branch: it starts
`cf` without a shell, writes the secret bytes through a protected pipe, never
prints them, and redacts stdin from command diagnostics. Do not pass a
shell-expanded secret through `--text`, put the secret value in either Worker
configuration schema, or create a temporary plaintext secret file. The
bootstrap does not call Wrangler for secrets.

### Custom Domain

The direct command is available and supports both a request preview and the real
API call:

```sh
cf workers domains update \
  --hostname "$HOSTNAME" \
  --service "$WORKER" \
  --environment production \
  --zone-id "$ZONE_ID" \
  --zone-name "$ZONE" \
  --dry-run

cf workers domains update \
  --hostname "$HOSTNAME" \
  --service "$WORKER" \
  --environment production \
  --zone-id "$ZONE_ID" \
  --zone-name "$ZONE"
```

Cloudflare's official [Custom Domain documentation](https://developers.cloudflare.com/workers/configuration/routing/custom-domains/)
says Cloudflare creates the DNS record and certificate automatically. The
project leaves the Custom Domain out of both bootstrap schemas, first completes
the fail-closed Worker/secret deploy, then previews and attaches the exact
hostname with `cf`, and verifies it with `cf workers domains list`. Once domain
and certificate provenance are established, the protected generated schemas
include the exact declarative domain so later `cf` Build Output deployments
preserve public routing. It also lists exact DNS records and zone Worker Routes
again immediately before a new bind; any route pattern covering the dedicated
hostname is a conflict because Routes can execute before a Custom Domain.

Cloudflare's Domain API includes `cert_id`, and the same official documentation
warns that detaching a Custom Domain does not automatically delete its generated
Advanced Certificate. The manager therefore uses:

```sh
cf ssl certificate-packs list --status all --page 1 --per-page 50 --zone "$ZONE_ID"
cf ssl certificate-packs delete "$PACK_ID" --zone "$ZONE_ID" --force --dry-run
cf ssl certificate-packs delete "$PACK_ID" --zone "$ZONE_ID" --force
```

Immediately before a changed live bind, it persists the complete pack-ID
baseline. It then accepts exactly one new `advanced` pack whose pack host list
and every child certificate cover the configured hostname, and persists the
exact pack ID. It does not require the Domain `cert_id` to identify a child.
An asynchronous inventory is resumed without rebinding. Removal requires the
stored Domain and pack IDs rather than inferring a same-host pack, and a
confirmed removal privately checkpoints them before mutation, so a retry never
guesses after the Domain record is gone. It keeps that checkpoint until a
post-delete inventory proves the asynchronous certificate deletion and every
other planned removal have converged.
The certificate-pack endpoints require SSL/Certificates access. The installed
`cf` 0.2.0 login scope set includes `ssl_certs:write`; sessions created with an
older scope set must be refreshed with `cf auth login --force`. The refreshed
session still returned the exact `9109 / 403` at this snapshot. The manager now
tries `cf` first, then permits a bounded in-process REST list or checkpointed
exact-ID delete only after that exact denial and only when a mode-`0600`,
Git-ignored `.env` supplies `CLOUDFLARE_GLOBAL_TOKEN`. It derives the email
transiently from the valid `cf` identity; the key is never sourced, exported,
passed to a child, persisted, or included in a URL/error. Dry-run deletion
remains `cf`-only, and ambiguous failures are never replayed through REST.

The legacy key format passed the anonymized read-only inventory gate.
Cloudflare's current
[Global API Key guidance](https://developers.cloudflare.com/fundamentals/api/get-started/keys/)
documents newer `cfk_`-prefixed scannable keys; this compatibility adapter
accepts both that documented format and pre-2026 lowercase-hex keys.

The underlying [Attach Domain API](https://developers.cloudflare.com/api/resources/workers/subresources/domains/methods/update/)
marks `environment`, `zone_id`, and `zone_name` optional (and `environment` is
deprecated). The generated `cf 0.2.0` handler nevertheless prompts for every
omitted field. Supplying all five flags, as above, avoids surprise prompts in
this preview release; `production` is the API's documented top-level Worker
environment value. This is a `cf 0.2.0` ergonomics issue, not a Custom Domain
platform requirement.

### Logs

`cf 0.2.0` can query stored Workers observability data:

```sh
cf workers observability telemetry query --help
```

This project disables stored observability, invocation logs, and sampling by
default, so that query is not part of the normal diagnostic flow. `cf`'s tail
command only calls the API to create a tail session and prints the
result. It does not attach to the returned WebSocket or continuously render
events. Creating a session without attaching/cleaning it up is not useful.
Use the pinned project Wrangler for an operational tail after its separate
login:

```sh
npm --prefix worker exec -- wrangler login --cwd worker
npm --prefix worker exec -- wrangler tail "$WORKER" --cwd worker
```

The normal operator runs `cf-vless logs`, which first checks the Worker's
ownership marker and sanitizes streamed JSON output. Wrangler authentication is
only used operationally for this connected-tail gap; all deployment/resource
authentication uses `cf`. `cf-vless doctor` still verifies the separate
Wrangler login and selected-account access because it reports readiness for the
complete command surface, including `logs`.

Cloudflare notes that console output from WebSocket event handlers may be held
until the WebSocket closes. Tests and metrics must not depend on immediate
per-frame console output, and production code must never log tunneled payloads,
UUIDs, or credentials.

## Original verification checklist

The non-mutating research snapshot required a later authorized run to separate
local command/configuration evidence from live behavior. Its checklist was:

1. run the pinned Wrangler unit/type/startup checks locally;
2. run `cf build` and `cf deploy --dry-run` from the Worker project;
3. verify the single Worker, disabled workers.dev/previews, and safe staged
   Custom Domain publication;
4. deploy through protected stdin and verify the exact live domain;
5. keep persistent observability disabled and reserve Wrangler for live tail;
6. prove creation-time certificate-pack ownership, checkpointed deletion, and
   final absence on an authorized disposable deployment.

Items 1 and 2 and the local dry-run inspection succeeded during the original
snapshot. The follow-up below records the later live results.

## Live follow-up: 2026-07-12

An explicitly authorized deployment and teardown closed the live CLI/resource
gates without recording account, zone, domain-binding, certificate, deployment,
or credential identifiers:

- the protected Worker and secret were deployed with `cf`, the exact Custom
  Domain was attached, and certificate issuance converged;
- Cloudflare returned a 40-hex Domain ID, a canonical-UUID pack ID, a Domain
  `cert_id` alias that did not equal a child certificate ID, and a multi-SAN
  generated Advanced pack. The implementation was changed to use the pre-bind
  pack-ID baseline plus exactly one new hostname-covering pack;
- a direct bind alone was not sufficient to survive the generated Build Output
  deployment: omitting the domain declaration left the hostname at 522. The
  bootstrap schemas still omit it, while protected post-bind schemas now publish
  it; the public hostname then returned the exact generic 404 with valid TLS;
- clean removal began with `cf` as primary. A certificate deletion attempt
  returned provider code `1406` and left the private removal checkpoint. The
  resumed run reused that exact checkpoint, and the exact authorization denial
  activated the bounded Global-key fallback. Final inventory proved the domain,
  pack, secret, and Worker absent;
- a fresh deployment then recreated the operator-controlled test endpoint and
  proved the marker-owned Worker, required secret, exact domain binding,
  provenance-backed pack, and public generic 404/TLS behavior;
- with all three client binaries on `PATH`, `doctor` passed all 18 checks,
  including its independent authentication and account-access gates;
- unmodified Xray v26.7.11, sing-box v1.13.14, and Mihomo v1.19.28 each passed
  the fresh 36-gate matrix with zero failures: DNS/HTTPS, exact random-payload
  echo for each 2 MiB upload, 10 MiB download, same-connection 30-second active
  keepalive, four concurrent connections, and three reconnects. A separate
  authenticated WebSocket/TCP session resumed after 45 seconds truly idle;
- the tight two-minute Free-account analytics window contained 30 expected
  `clientDisconnected` invocations with zero errors, exceptions, or
  `exceededCpu`; exact CPU, wall, memory, duration, subrequest, and response-byte
  aggregates are in `docs/free-tier.md`. Persistent observability remained
  disabled. A temporary `limits.cpu_ms` check was rejected with API code
  `100328` because configurable CPU limits are unsupported on Free, then removed
  without changing the Worker; `usage_model: standard` was treated as execution
  mode rather than paid-plan evidence. The final bundle measured 31.57 KiB raw /
  8.23 KiB gzip;
- Shadowrocket URI/QR syntax is valid, but real-device import and connection
  remain unverified.

This live record also demonstrated that `cf 0.2.0` remains a technical preview:
the adapter must keep strict schema validation, fail-closed checkpoints, and the
narrow certificate-only fallback rather than generalizing from one successful
run.
