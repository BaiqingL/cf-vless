# Contributing

This repository combines a security-sensitive Cloudflare Worker, a Go
deployment manager, executable-client interoperability tests, and dated
platform research. Keep changes narrow, test driven, and fail closed.

## Set up

Required toolchain:

- Go 1.26 or newer (required by the pinned Xray source);
- Node.js `^22.18.0` or `>=24.0.0` (Node 24 LTS is recommended);
- npm 11, Git, and `rg`;
- `cf 0.2.0` only for Cloudflare deployment operations;
- sing-box and Mihomo for the complete executable-client gate.

Install the pinned local dependencies:

```sh
make deps
```

No setup command should read `.env`, `.cf-vless/`, or `client-configs/`.
Those paths contain private operator state and remain ignored.

## Development loop

```sh
make format
make lint
make test
```

Before handing off a change, run the non-mutating repository gate:

```sh
make check
```

`make release-check` additionally runs both Worker dry-run build paths. It may
use authenticated Cloudflare tooling but does not upload or mutate resources.
Live deployment, rotation, and removal require separate, explicit operator
authorization.

## Code boundaries

- Keep VLESS-specific Worker code isolated in
  [`worker/src/protocol/vless.ts`](worker/src/protocol/vless.ts).
- Treat [`internal/config`](internal/config) as the canonical deployment and
  credential schema.
- Keep `cf` as the primary Cloudflare control-plane adapter; Wrangler is a
  documented fallback only where `cf 0.2.0` lacks the operation.
- Change both Worker configuration serializers through
  [`internal/workerproject`](internal/workerproject). Do not hand-edit only one
  tracked configuration.
- Never copy or patch the Xray gitlink for convenience. Update it through the
  process in [the maintenance guide](docs/maintenance.md).

Protocol behavior, destination policy, credential handling, and resource
ownership changes require a failing test or independent fixture first. Purely
mechanical formatting and dependency lockfile refreshes are the exceptions.

## Security and live testing

Never put a UUID, randomized WebSocket path, client configuration, API key,
account or resource ID, client address, destination history, or traffic body in
test output, a commit, or an issue. Run the secret scan through `make check`.

Live integration endpoints must be operator-controlled or explicitly approved:

- the download endpoint must return at least the configured minimum body;
- the upload endpoint must echo the exact ASCII request body, either raw or as
  a top-level JSON `data` string;
- the TCP endpoint must be line oriented and echo the complete newline-framed
  payload.

The integration harness reads credentials only from the owner-only canonical
deployment file and emits sanitized JSON.

## Pull-request checklist

- [ ] Behavior changes began with a failing test or fixture.
- [ ] `make check` passes without modifying tracked files.
- [ ] `git diff --check` passes.
- [ ] Generated types and both Worker configuration schemas are current.
- [ ] No private state or client artifact is tracked.
- [ ] Documentation distinguishes tested facts from assumptions.
- [ ] Dependency and compatibility changes follow
      [`docs/maintenance.md`](docs/maintenance.md).
- [ ] Live Cloudflare mutations, if any, were explicitly authorized and
      recorded without identifiers or secrets.
