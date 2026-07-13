# Workers Free-tier posture

Snapshot date: 2026-07-12. Limits change; verify the linked research before a
new release.

## Published limits relevant here

| Item | Workers Free | Design consequence |
| --- | ---: | --- |
| Requests | 100,000/day | One initial Upgrade per session; frames are not individual Worker requests |
| CPU | 10 ms/invocation | Keep parser/auth/callback work small; network wait is excluded |
| Memory | 128 MB/isolate | Stream; 1 KiB pre-auth and 1 MiB app queue bounds |
| Compressed Worker | 3 MB | Native Worker is far below the ceiling |
| External subrequests | 50/request | Two DoH queries plus one TCP connect are within the limit |
| Simultaneous connection establishment | 6/request | One outbound socket per session |
| WebSocket message | 32 MiB | Application closes above its much smaller queue bound |
| Custom Domains | 100/zone | One exact hostname |

See `research/cloudflare-capabilities.md` for dated official source links and
the nuance that established sockets no longer consume all six establishment
slots under current limits.

## Reproducible local measurements

| Measurement | Result | Evidence scope |
| --- | ---: | --- |
| Wrangler 4.110.0 and `cf 0.2.0` dry-run bundle | 31.57 KiB raw / 8.23 KiB gzip on 2026-07-12 | Both current config paths produced the same bundle after the final DoH and domain-publication changes |
| Local startup profile | 1 sample / 2,626 microseconds on 2026-07-12 | Local Wrangler profiler only; not Cloudflare edge CPU |
| TinyGo parser-only lower bound | 25,053 B raw / 9,550 B gzip | Deliberately incomplete alternative, not deployed |
| Workerd test suite | See current `npm test` count | Correctness/malformed-input behavior, not edge CPU |

The current release process must refresh bundle numbers with:

```sh
make release-check
npm --prefix worker exec -- wrangler check startup --cwd worker \
  --outfile /tmp/cf-vless-worker-startup.cpuprofile
```

`wrangler check startup` writes a CPU profile by default; `*.cpuprofile` is
ignored and must not be committed. The explicit `/tmp` output above keeps the
artifact outside the repository. Wrangler 4.110.0 does not accept the old
`deploy --experimental-startup-profile` form. The bundle and startup
measurements above are local results, not deployed Worker size/CPU records.

## Anonymized Free-account benchmark

A test account's Free status was established without changing the deployed Worker.
A temporary configuration that set `limits.cpu_ms = 10` was rejected with
Cloudflare API code `100328` specifically because configurable CPU limits are
unsupported on the Free plan. The temporary setting was removed and the Worker
was unchanged. Analytics field `usage_model: standard` names the execution
model; it is not evidence of a paid account.

The fresh client matrix and its surrounding analytics window were deliberately
short. Persistent Workers observability, invocation logs, and sampling remained
disabled; the anonymized record used aggregate platform analytics and retained
no UUID, randomized path, client address, endpoint, or traffic content.

### Functional matrix

| Measurement | Result | Evidence scope |
| --- | ---: | --- |
| Public Custom Domain | Valid TLS and exact generic 404 | Public DNS/TLS/routing to the fail-closed Worker response |
| Readiness | `doctor` 18/18 passed | Included corrected same-account Wrangler authentication/access and all client binaries on `PATH` |
| Executable clients | Xray v26.7.11, sing-box v1.13.14, and Mihomo v1.19.28 | 36 gates, zero failed |
| DNS and HTTPS | Passed for every client | Unmodified binaries and generated configurations |
| Download | 10 MiB per client | End-to-end tunnel transfer |
| Upload | Exact 2 MiB random payload echoed per client | Stricter byte-for-byte proof, not only a byte count |
| Transfer throughput | Download 33.130 / 34.309 / 36.792 Mbps; upload 19.692 / 20.068 / 20.287 Mbps | Minimum / median / maximum across a follow-up three-client matrix; decimal Mbps |
| DNS/HTTPS gate latency | 408 / 422 / 451 ms | Minimum / median / maximum across Xray, sing-box, and Mihomo |
| Tunnel establishment latency | 78.9 ms minimum, 87.7 ms median, 104.9 ms mean, 127.2 ms p90, 183.9 ms maximum | Ten fresh public WSS + VLESS authentication + safe DNS + outbound TCP establishments |
| Active keepalive | 30 seconds per client on the same connection | Active long-lived TCP echo |
| Concurrency | Four simultaneous connections per client | Established behavior, not a six-attempt-limit test |
| Reconnect | Three fresh connections per client | Recovery after deliberate disconnect |
| True idle resume | Same authenticated WebSocket/TCP session resumed after 45 seconds | Separate from the 36-gate matrix |

A 75-second attempt against a different test service is not counted as a Worker
failure: that service closes its own idle upstream TCP connection. The
same-connection active gate exists to distinguish upstream idleness from Worker
relay behavior, and the separate 45-second test is the controlled true-idle
record.

The follow-up metrics-only client matrix completed in 103.735 seconds. Its
four-connection gate took 90 / 121 / 133 ms and its three-reconnect gate took
269 / 274 / 451 ms (minimum / median / maximum across clients). Those gates
include echo validation and are not substituted for the ten-sample direct
establishment distribution above.

### Aggregate analytics

| Metric | Total | Average | p50 | p99 / maximum |
| --- | ---: | ---: | ---: | ---: |
| Invocations | 30 | — | — | — |
| CPU time | 927.741 ms | 30.925 ms | 4.656 ms | 289.885 ms |
| Wall time | 301.210 s | 10.040 s | 76.718 ms | 34.922 s |
| Memory | — | — | ~1.52 MiB | ~10.48 MiB |
| Duration | 34.1572 GB-s | 1.1386 GB-s | 0.00959 GB-s | 3.75 GB-s |
| Subrequests | 90 | exactly 3/invocation | — | — |
| Response bytes | 36.29 MiB | — | — | 10.04 MiB |
| Request-duration metric | 0 | 0 | 0 | 0 |

All 30 invocations ended with the expected `clientDisconnected` outcome. The
window recorded zero errors, exceptions, `exceededCpu`, or other CPU-limit
outcomes. The three subrequests per invocation are the intended two
DNS-over-HTTPS queries and one outbound TCP connection. The separate
request-duration metric was zero throughout; it is not the wall-time field.

The aggregate CPU average and maximum exceed the published 10 ms Free limit,
while none of the 30 invocations ended as `exceededCpu`. Cloudflare documents
built-in enforcement flexibility for infrequent overages, and analytics report
the complete long-lived invocation, but the platform does not expose enough
detail here to assign the result to per-event rollover or another mechanism.
This observation does not justify expensive callbacks; each parser/auth/frame
turn must remain small.

A clean teardown and fresh recreation also converged in the test environment,
including the required secret, exact Custom Domain, provenance-backed Advanced
Certificate pack, disabled persistent observability, and a generic 404 for
non-tunnel HTTPS.

## Remaining measurement scope

This record closes the planned functional and short-window resource gates for
one anonymized Free account, one deployed version, and one test window. It does not prove
regional or day-to-day tails, long-duration availability, an unpublished
default idle cutoff beyond the observed 45 seconds, heavier concurrency, or
future Cloudflare behavior. Repeat the same sanitized method when the Worker,
clients, limits, or platform materially change.

## No unlimited-use promise

Cloudflare currently does not publish a simple tunnel bandwidth quota in the
Workers limits table, but that is not a guarantee of unlimited traffic,
duration, abuse tolerance, or permanent free operation. Daily requests, CPU,
memory, platform protections, acceptable-use rules, network releases, and
future product changes still apply.
