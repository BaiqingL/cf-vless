# Client integration test

This command runs the same live DNS/HTTPS, download, upload, long-lived TCP,
concurrency, and reconnect gates through unmodified client binaries. It does
not deploy or modify Cloudflare resources.

The default `-clients all` mode requires all three clients:

- Xray is built from the pinned `third_party/xray-core` gitlink.
- `sing-box` is resolved from `PATH` or `-sing-box-binary`.
- `mihomo` is resolved from `PATH` or `-mihomo-binary`.

Use a comma-separated explicit subset when intentionally testing fewer
clients, for example `-clients xray` or `-clients sing-box,mihomo`. A selected
client that is missing or rejects its generated configuration is a failed
gate; it is never silently skipped.

Credentials are accepted only through the canonical deployment file. The
file must pass `config.Load`, including its regular-file and mode `0600`
checks. UUIDs and WebSocket paths are never accepted as flags or environment
variables. The harness holds the private state-directory operation lock for
the complete run and refuses a sibling `deployment.pending.json`; resume the
credential rotation before testing so a stale or remotely revoked canonical
credential is never exercised.

Example:

```sh
# Replace every probe.example/echo.example value with an approved endpoint.
go run ./cmd/integration-test \
  -deployment .cf-vless/deployment.json \
  -clients all \
  -https-url https://probe.example/ \
  -download-url https://probe.example/download \
  -upload-url https://probe.example/upload \
  -tcp-echo echo.example:443
```

The download must meet the configured minimum size. The upload service must
echo the exact ASCII `POST` body, either raw or as a top-level JSON `data`
string. The TCP service must be line oriented: the harness appends `\n` and
verifies the complete framed echo. The example hostnames are placeholders, not
project-operated services. Results are sanitized JSON with one object per
selected client; client subprocess output is discarded.
