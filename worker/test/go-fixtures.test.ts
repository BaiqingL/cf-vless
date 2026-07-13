import { describe, expect, it } from "vitest";
import fixtures from "../../test/fixtures/vless-v0.json";
import { buildVlessResponseHeader, VlessHandshakeParser } from "../src/protocol/vless";

function hexBytes(value: string): Uint8Array {
  if (!/^(?:[0-9a-f]{2})*$/i.test(value)) throw new Error("fixture hex is invalid");
  const result = new Uint8Array(value.length / 2);
  for (let index = 0; index < result.length; index += 1) {
    result[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return result;
}

describe("Go/Xray-derived conformance fixtures", () => {
  it("is pinned to the repository Xray revision and response bytes", () => {
    expect(fixtures.upstream_commit).toBe("50231eaff98ccc31b5cbd247a721c16e97fe5ec1");
    expect(fixtures.upstream_tag).toBe("v26.7.11");
    expect(buildVlessResponseHeader()).toEqual(hexBytes(fixtures.response_header_hex));
  });

  for (const fixture of fixtures.cases) {
    for (const fragmentation of fixture.fragmentations) {
      it(`parses ${fixture.name} with ${fragmentation.name} fragmentation byte-for-byte`, () => {
        const wire = hexBytes(fixture.wire_hex);
        const parser = new VlessHandshakeParser();
        let offset = 0;
        let parsed;
        const subsequentPayload: Uint8Array[] = [];
        for (const chunkSize of fragmentation.chunk_sizes) {
          const chunk = wire.subarray(offset, offset + chunkSize);
          if (parsed === undefined) {
            parsed = parser.push(chunk);
          } else {
            subsequentPayload.push(chunk.slice());
          }
          offset += chunkSize;
        }
        expect(offset).toBe(wire.length);
        expect(parsed).toBeDefined();
        expect(parsed?.request.destination).toEqual({
          type: fixture.address_type,
          host: fixture.host,
          port: fixture.port
        });
        const combinedPayload = new Uint8Array(
          (parsed?.initialPayload.length ?? 0) + subsequentPayload.reduce((total, chunk) => total + chunk.length, 0)
        );
        let payloadOffset = 0;
        if (parsed !== undefined) {
          combinedPayload.set(parsed.initialPayload, payloadOffset);
          payloadOffset += parsed.initialPayload.length;
        }
        for (const chunk of subsequentPayload) {
          combinedPayload.set(chunk, payloadOffset);
          payloadOffset += chunk.length;
        }
        expect(combinedPayload).toEqual(hexBytes(fixture.initial_payload_hex));
      });
    }
  }
});
