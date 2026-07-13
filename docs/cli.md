# CLI reference

Run `cf-vless <command> --help` for the complete flag list. All commands use
`.cf-vless/deployment.json` unless `--config` is supplied, and all accept a
repository root through `--project-root` where applicable.

| Command | Purpose | Required before initialized |
| --- | --- | --- |
| `doctor` | Verify Cloudflare access, local tools, zone, hostname, and Wrangler fallback readiness | `--zone`, `--hostname` |
| `init` | Create owner-only deployment state and generated Worker workspace | `--zone`, `--hostname`, `--name` |
| `deploy` | Run the exact dry-run branch or publish the managed Worker | Existing state |
| `status` | Verify owned resources, certificate provenance, and public HTTPS | Existing state |
| `test` | Run executable-client live gates | Four approved probe endpoints |
| `config` | Generate five owner-only client artifacts | Existing state |
| `rotate` | Rotate, finalize, or emergency-revoke credentials | Existing state |
| `logs` | Stream sanitized live events through Wrangler | Existing state and Wrangler login |
| `remove` | Plan or delete only marker-owned resources | Existing state |

Exit status `0` means success, `1` means an operational or verification
failure, and `2` means invalid usage. Help exits `0`.

## Typical lifecycle

```sh
./bin/cf-vless doctor --zone example.com --hostname edge.example.com
./bin/cf-vless init \
  --zone example.com \
  --hostname edge.example.com \
  --name "Personal Edge"
./bin/cf-vless deploy --dry-run
./bin/cf-vless deploy
./bin/cf-vless status
./bin/cf-vless config --output ./client-configs
```

`deploy --recover-domain-id` and `--recover-certificate-pack-id` are exceptional
resume controls for an interrupted first bind. Use only immutable IDs returned
by that exact interrupted operation; ordinary deploys must not guess them.

## Integration endpoint contract

The four endpoint flags are required and are operator-controlled placeholders,
not project-operated services:

```sh
./bin/cf-vless test \
  --clients all \
  --https-url https://probe.example/ \
  --download-url https://probe.example/download \
  --upload-url https://probe.example/upload \
  --tcp-echo echo.example:443
```

- `--https-url` must be a trusted HTTPS hostname and exercises DNS, TLS, and
  browsing through the client.
- `--download-url` must return at least 2 MiB by default.
- `--upload-url` must echo the exact ASCII POST body, either as the raw response
  or a top-level JSON `data` string. The default upload is 2 MiB.
- `--tcp-echo` must be a public, line-oriented TCP service that echoes the full
  newline-framed payload.

The 30-second long-lived gate sends periodic line frames over one connection;
it is not a truly idle test. Missing binaries, rejected configurations, partial
uploads, mismatched echoes, and cleanup failures are hard failures.

## Credential operations

```sh
./bin/cf-vless rotate --overlap 24h
./bin/cf-vless config --output ./client-configs --force
# After the overlap expires:
./bin/cf-vless rotate --finalize
# For a disclosure, revoke immediately instead:
./bin/cf-vless rotate --emergency-revoke
```

`--finalize` and `--emergency-revoke` are mutually exclusive. A pending marker
is a recovery checkpoint; do not delete it manually.

## Logs and removal

```sh
./bin/cf-vless logs
./bin/cf-vless logs --status error
./bin/cf-vless remove --dry-run
./bin/cf-vless remove --yes
```

`logs` emits only the sanitizer's fixed operational fields. `remove --yes`
uses stored creation-time provenance and stops if attachments or identities no
longer match.
