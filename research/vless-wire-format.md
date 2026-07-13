# VLESS v0 TCP wire format

Status: research gate complete for the fixed `VLESS v0 TCP over WebSocket` subset

Upstream snapshot: Xray-core [`50231eaff98ccc31b5cbd247a721c16e97fe5ec1`](https://github.com/XTLS/Xray-core/tree/50231eaff98ccc31b5cbd247a721c16e97fe5ec1), tagged `v26.7.11`
Reviewed: 2026-07-12

## Scope and source of truth

This note describes the bytes consumed and emitted by the current Xray-core VLESS implementation for the repository's fixed subset:

- protocol version `0`;
- command `TCP`;
- empty VLESS flow/add-ons;
- a byte stream carried by WebSocket over Cloudflare-managed TLS.

The canonical implementation is Xray's [`proxy/vless/encoding/encoding.go`](https://github.com/XTLS/Xray-core/blob/50231eaff98ccc31b5cbd247a721c16e97fe5ec1/proxy/vless/encoding/encoding.go#L18-L173). Command and address constants come from [`common/protocol/headers.go`](https://github.com/XTLS/Xray-core/blob/50231eaff98ccc31b5cbd247a721c16e97fe5ec1/common/protocol/headers.go#L11-L29) and [`common/protocol/payload.go`](https://github.com/XTLS/Xray-core/blob/50231eaff98ccc31b5cbd247a721c16e97fe5ec1/common/protocol/payload.go#L10-L16).

## Transport model

VLESS sees an ordered byte stream, not WebSocket message boundaries. Xray wraps WebSocket as a `net.Conn`: reads continue with the next WebSocket message after the current message reaches EOF, while writes use binary messages ([`connection.go`](https://github.com/XTLS/Xray-core/blob/50231eaff98ccc31b5cbd247a721c16e97fe5ec1/transport/internet/websocket/connection.go#L44-L79)). Therefore:

- the request header may be split across multiple WebSocket messages;
- the first TCP payload bytes may follow the header in the same message;
- a Worker parser must buffer only until one complete header is available, preserve all remaining bytes as TCP payload, and never require one-message-per-field framing.

Xray has an optional WebSocket early-data mode (`ed`) that base64url-encodes initial stream bytes into `Sec-WebSocket-Protocol` ([client](https://github.com/XTLS/Xray-core/blob/50231eaff98ccc31b5cbd247a721c16e97fe5ec1/transport/internet/websocket/dialer.go#L142-L165), [server](https://github.com/XTLS/Xray-core/blob/50231eaff98ccc31b5cbd247a721c16e97fe5ec1/transport/internet/websocket/hub.go#L53-L75)). It is a WebSocket transport optimization, not part of the VLESS header. This project should generate `ed = 0`/omit it and does not need that extension for baseline interoperability.

## Client request

All integers are unsigned. Multi-byte integers are network byte order (big endian); Xray's address parser reads the port before the address and uses a big-endian 16-bit port ([`address.go`](https://github.com/XTLS/Xray-core/blob/50231eaff98ccc31b5cbd247a721c16e97fe5ec1/common/protocol/address.go#L83-L110), [`readPort`](https://github.com/XTLS/Xray-core/blob/50231eaff98ccc31b5cbd247a721c16e97fe5ec1/common/protocol/address.go#L144-L153)).

| Offset | Size | Field | Fixed-subset value |
| ---: | ---: | --- | --- |
| `0` | 1 | Version | `0x00` |
| `1` | 16 | User ID | UUID bytes in displayed byte order |
| `17` | 1 | Add-on length `A` | `0x00` |
| `18` | `A` | Protobuf-encoded `Addons` | absent |
| `18 + A` | 1 | Command | `0x01` (`TCP`) |
| `19 + A` | 2 | Destination port | big-endian `uint16` |
| `21 + A` | 1 | Address type | `0x01`, `0x02`, or `0x03` |
| `22 + A` | variable | Address | encoding below |
| next byte | remainder | TCP payload | opaque byte stream; no VLESS length prefix |

Xray writes these fields in exactly this order in [`EncodeRequestHeader`](https://github.com/XTLS/Xray-core/blob/50231eaff98ccc31b5cbd247a721c16e97fe5ec1/proxy/vless/encoding/encoding.go#L29-L60) and reads them incrementally with `ReadFull` in [`DecodeRequestHeader`](https://github.com/XTLS/Xray-core/blob/50231eaff98ccc31b5cbd247a721c16e97fe5ec1/proxy/vless/encoding/encoding.go#L63-L132).

### Address encoding

| Type | Value bytes | Header size when `A = 0` |
| --- | --- | ---: |
| IPv4 (`0x01`) | 4 bytes, network order | 26 bytes |
| Domain (`0x02`) | 1-byte length `L`, then `L` bytes | `23 + L` bytes |
| IPv6 (`0x03`) | 16 bytes, network order | 38 bytes |

The current address reader is in [`common/protocol/address.go`](https://github.com/XTLS/Xray-core/blob/50231eaff98ccc31b5cbd247a721c16e97fe5ec1/common/protocol/address.go#L174-L225). Domain bytes are treated as a string and validated by Xray against ASCII letters, digits, `-`, `.`, and `_` ([validation](https://github.com/XTLS/Xray-core/blob/50231eaff98ccc31b5cbd247a721c16e97fe5ec1/common/protocol/address.go#L155-L165)). A minimal parser should explicitly reject a zero-length domain rather than reproduce Xray's unsafe `domain[0]` access.

### Add-ons

The general v0 format is a one-byte length followed by that many bytes of protobuf `Addons`. With no flow, Xray emits a single zero length byte. It protobuf-encodes only the Vision flow in its encoder ([`addons.go`](https://github.com/XTLS/Xray-core/blob/50231eaff98ccc31b5cbd247a721c16e97fe5ec1/proxy/vless/encoding/addons.go#L17-L63)).

This repository explicitly excludes Vision, so the accepted request subset is `A = 0`. Nonzero add-ons should be rejected; accepting them would enlarge the protocol and require protobuf and flow validation without improving compatibility with the generated configuration.

### Worked request header

For the non-secret test UUID `00112233-4455-6677-8899-aabbccddeeff`, destination `example.com:443`, empty flow, and TCP command:

```text
00                                      version
00112233445566778899aabbccddeeff        UUID
00                                      add-on length
01                                      TCP command
01bb                                    port 443
02 0b 6578616d706c652e636f6d            domain, length 11, "example.com"
```

Concatenated header:

```text
0000112233445566778899aabbccddeeff000101bb020b6578616d706c652e636f6d
```

Application data begins immediately after the last `6d` and may already be present in the same WebSocket message.

## Server response

The response header contains only the request version and response add-ons. Xray uses the same add-on encoder and requires the response version to equal the request version ([encode/decode](https://github.com/XTLS/Xray-core/blob/50231eaff98ccc31b5cbd247a721c16e97fe5ec1/proxy/vless/encoding/encoding.go#L134-L173)).

| Offset | Size | Field | Fixed-subset value |
| ---: | ---: | --- | --- |
| `0` | 1 | Version | `0x00` |
| `1` | 1 | Add-on length `R` | `0x00` |
| `2` | `R` | Response add-ons | absent |
| next byte | remainder | TCP response payload | opaque byte stream |

Thus every successful connection in this subset begins its downstream byte stream with:

```text
0000
```

There is no VLESS success/error status or payload length. The client reads the two-byte header before exposing destination bytes ([outbound response path](https://github.com/XTLS/Xray-core/blob/50231eaff98ccc31b5cbd247a721c16e97fe5ec1/proxy/vless/outbound/outbound.go#L381-L407)). Connection failure is signaled by closing the WebSocket rather than inventing a VLESS error frame.

## Authentication behavior

The request carries the raw 16 UUID bytes; there is no nonce, timestamp, or separate MAC in the v0 header. Confidentiality and on-path integrity for this deployment come from Cloudflare-managed TLS and WebSocket transport. The server must avoid logging the UUID/header bytes.

At this snapshot, Xray's validator deliberately zeroes UUID bytes 6 and 7 for its lookup and exposes the client-sent values as `vlessRoute` ([validator](https://github.com/XTLS/Xray-core/blob/50231eaff98ccc31b5cbd247a721c16e97fe5ec1/proxy/vless/validator.go#L21-L68), [inbound use](https://github.com/XTLS/Xray-core/blob/50231eaff98ccc31b5cbd247a721c16e97fe5ec1/proxy/vless/inbound/inbound.go#L527-L539)). This is an Xray routing extension, not an extra wire field. The project's generated clients send the configured UUID exactly, so constant-time comparison of all 16 bytes remains interoperable for the supported product while retaining the full configured credential. The project should not generate or promise `vlessRoute` behavior.

## Minimal parser contract

The Worker adapter can remain small and deterministic if it:

1. accumulates bytes across WebSocket messages until the header is complete;
2. requires version `0`, add-on length `0`, and command `TCP (0x01)`;
3. accepts only address types IPv4, domain, and IPv6 with strict length/bounds checks;
4. compares the complete 16-byte configured UUID in constant time before dialing;
5. preserves every byte after the header as the first outbound TCP payload;
6. sends `00 00` before the first destination response bytes;
7. treats all later WebSocket bytes as raw TCP stream bytes, with no VLESS chunking;
8. rejects UDP, Mux, Reverse, Vision, nonzero add-ons, malformed domains, truncated headers, and unsupported versions without attempting a destination connection.

This is the complete protocol surface required by the fixed product decision. Direct reuse of Xray's Go parser is assessed separately in [`decisions/0002-xray-library-reuse.md`](../decisions/0002-xray-library-reuse.md).
