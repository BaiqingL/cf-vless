# Third-party notices

`cf-vless` depends on or verifies against the following notable third-party
projects. Their licenses remain in force independently of this repository's
Apache License 2.0.

## Included in the Go CLI

- [`github.com/skip2/go-qrcode`](https://github.com/skip2/go-qrcode) — MIT
  License; used to generate client QR codes. Copyright (c) 2014 Tom Harwood.

## Test-only Go dependency

- [`github.com/liyue201/goqr`](https://github.com/liyue201/goqr) — GNU Lesser
  General Public License v3.0; used only by tests to decode generated QR codes
  and not linked into the distributed CLI.

## Pinned upstream source

- [`XTLS/Xray-core`](https://github.com/XTLS/Xray-core) — Mozilla Public
  License 2.0. It is retained as an unmodified Git submodule and used as the
  executable reference implementation. Its complete license and notices are in
  `third_party/xray-core` after recursive checkout.

The complete machine-resolved Go and npm dependency sets are recorded in
`go.sum` and `worker/package-lock.json`. Review those manifests and the
corresponding upstream license files before redistributing a modified bundle.
