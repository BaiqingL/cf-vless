import { describe, expect, it } from "vitest";
import { authenticateUser, parseCredentialSet, selectCredentialForPath, uuidStringToBytes } from "../src/auth";
import { VALID_UUID, VALID_UUID_BYTES } from "./fixtures";

describe("VLESS credentials", () => {
  it("parses canonical UUID bytes", () => {
    expect(uuidStringToBytes(VALID_UUID)).toEqual(VALID_UUID_BYTES);
  });

  it("rejects malformed secret configuration", () => {
    expect(() => parseCredentialSet("{}")).toThrow("credential configuration is invalid");
    expect(() => parseCredentialSet("not-json")).toThrow("credential configuration is invalid");
  });

  it("authenticates the current UUID", () => {
    expect(authenticateUser(VALID_UUID_BYTES, uuidStringToBytes(VALID_UUID))).toBe(true);
  });

  it("rejects an invalid UUID", () => {
    const invalid = VALID_UUID_BYTES.slice();
    invalid[15] = invalid[15]! ^ 1;
    expect(authenticateUser(invalid, uuidStringToBytes(VALID_UUID))).toBe(false);
  });

  it("accepts an unexpired previous path and rejects it after expiry", () => {
    const credentials = parseCredentialSet(
      JSON.stringify({
        current: { uuid: VALID_UUID, path: "/current-path-0001" },
        previous: {
          uuid: "ffffffff-ffff-4fff-8fff-ffffffffffff",
          path: "/previous-path-0001",
          expiresAt: "2030-01-01T00:00:00Z"
        }
      })
    );
    expect(selectCredentialForPath(credentials, "/previous-path-0001", new Date("2029-01-01"))).toBeDefined();
    expect(selectCredentialForPath(credentials, "/previous-path-0001", new Date("2031-01-01"))).toBeUndefined();
  });
});
