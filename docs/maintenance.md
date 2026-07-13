# Maintenance and dependency updates

This project pins runtime-sensitive dependencies and records live evidence by
date. Upgrade one layer at a time, keep historical measurements unchanged, and
run the complete gate before changing the verified baseline.

## Canonical version sources

| Concern | Source of truth |
| --- | --- |
| Go language floor and lint/Actions tools | `go.mod` tool directives |
| Worker packages and Wrangler | `worker/package.json` and `worker/package-lock.json` |
| Worker compatibility behavior | `internal/workerproject` generators and tracked Worker configs |
| Xray client/reference source | `third_party/xray-core` gitlink and `internal/testvectors` pin |
| Tested executable clients | `COMPATIBILITY.md` |
| Cloudflare CLI surface | dated `research/cf-cli.md` record |
| Live performance/resource evidence | `docs/free-tier.md` |

The minimum supported Go release is the greater of the first-party tool floor
and the version required by the pinned Xray submodule. Node 24 LTS is the
recommended development runtime;
the package engine also permits the documented Node 22.18 floor. npm 11 is
required for the install-script allowlist, and the exact maintenance version is
recorded in `worker/package.json`'s `packageManager` field. The project-local
`.npmrc` makes those runtime engines install-time requirements.

## Worker and npm dependencies

Inspect before changing the lockfile:

```sh
npm --prefix worker outdated
npm --prefix worker audit
```

Upgrade direct packages with exact versions, then validate the install-script
allowlist and lockfile:

```sh
npm --prefix worker install --save-dev --save-exact PACKAGE@VERSION
(cd worker && npm approve-scripts --allow-scripts-pending)
npm --prefix worker ci
npm --prefix worker run check
```

Upgrade `@cloudflare/vitest-pool-workers`, Vitest, Wrangler, TypeScript, and
workerd-compatible transitive packages as one tested set. Do not upgrade the
direct Wrangler pin independently when the current pool pins a different
version. Keep `@types/node` on the newest Node 22 release while Node 22.18 is the
compatibility floor; a newer major would let code depend on APIs unavailable to
that supported runtime. Regenerate types with `npm --prefix worker run types`,
then require `types:check` to pass without rewriting the file.

## Go modules and tools

```sh
go list -m -u all
go get -u ./...
go mod tidy
make lint
go tool govulncheck -test ./...
```

The QR modules have no newer upstream versions. Replacing the archived decoder
is a behavior migration, not a routine version bump: preserve QR round-trip and
owner-only artifact tests if that work is undertaken.

Update a pinned Go tool explicitly:

```sh
go get -tool MODULE/PATH@VERSION
go mod tidy
```

## Xray and executable-client baselines

For Xray:

1. Identify an exact upstream tag and review VLESS/WebSocket changes.
2. Move only the `third_party/xray-core` gitlink to that commit.
3. Update the pin constants and every independent fixture expectation.
4. Run the opt-in loopback Xray reference pair.
5. Run the unmodified Xray live gate before changing `COMPATIBILITY.md`.

For sing-box and Mihomo, record the executable version and checksum used by the
live harness. A version reported by an operator is evidence, not an enforced
minimum, unless the CLI also validates it. Shadowrocket remains unverified
until both URI and QR imports pass the real-device checklist.

## Cloudflare runtime and configuration

When changing the compatibility date, Wrangler, or the Workers runtime:

1. Review current Cloudflare compatibility-date changes, TCP socket behavior,
   WebSocket behavior, limits, and published Cloudflare IP ranges.
2. Update the canonical constants in `internal/workerproject`.
3. Regenerate both `wrangler.jsonc` and `cloudflare.config.ts` from the same
   deployment fixture.
4. Run Worker unit/fuzz tests, both TypeScript checks, and both dry-run builds.
5. Re-run live negative destination/authentication gates before deployment.

The privacy design intentionally disables persistent observability. Do not
enable it merely to make maintenance easier without revisiting the privacy and
resource-ownership documentation.

## Release and rollback

```sh
make release-check
git diff --check
git status --short
```

Tags matching `v*` run the same gate before GitHub creates a release. Install a
tagged version by cloning it recursively:

```sh
git clone --branch vX.Y.Z --recurse-submodules \
  https://github.com/BaiqingL/cf-vless.git
```

Do not advertise GitHub's automatically generated source archives as complete
installations: they omit the pinned Xray submodule. Standalone binary packaging
also requires the matching Worker templates and Xray source, so it must not be
added as a CLI-only archive.

Re-run the executable-client matrix and sanitized Free-tier measurements when
the Worker, compatibility date, client pins, or Cloudflare platform materially
changes. Append a new dated record; do not rewrite an old measurement to match
new dependencies.

Rollback means restoring the previously reviewed source, lockfile, gitlink,
and generated configuration together. Never roll back only the Worker source
while leaving a newer credential schema or resource-ownership plan in place.
