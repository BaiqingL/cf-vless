import { describe, expect, it } from "vitest";
import {
  DestinationPolicyError,
  assertAllowedIPAddress,
  parseAllowedPorts,
  resolveAndValidateDestination,
  validateDomainName
} from "../src/policy";

describe("destination policy", () => {
  it.each([
    "0.0.0.0",
    "10.0.0.1",
    "100.64.0.1",
    "127.0.0.1",
    "168.63.129.16",
    "169.254.169.254",
    "172.16.0.1",
    "192.168.1.1",
    "224.0.0.1",
    "255.255.255.255",
    "::",
    "::1",
    "2001::1",
    "2001:db8::1",
    "2002::1",
    "3fff::1",
    "fc00::1",
    "fe80::1",
    "ff02::1",
    "::ffff:127.0.0.1",
    "::ffff:10.0.0.1"
  ])("blocks non-public address %s", (address) => {
    expect(() => assertAllowedIPAddress(address)).toThrow(DestinationPolicyError);
  });

  it.each(["8.8.8.8", "9.9.9.9", "2001:4860:4860::8888"])("allows public address %s", (address) => {
    expect(() => assertAllowedIPAddress(address)).not.toThrow();
  });

  it.each(["1.1.1.1", "104.16.0.1", "2606:4700::1111"])("blocks Cloudflare address %s", (address) => {
    expect(() => assertAllowedIPAddress(address)).toThrow(DestinationPolicyError);
  });

  it.each(["localhost", "a.localhost", "metadata.google.internal", "user@example.com", "a..example", "-bad.example"])(
    "rejects unsafe domain %s",
    (domain) => expect(() => validateDomainName(domain, "edge.example.com")).toThrow(DestinationPolicyError)
  );

  it("rejects the Worker hostname case-insensitively", () => {
    expect(() => validateDomainName("EDGE.EXAMPLE.COM", "edge.example.com")).toThrow(DestinationPolicyError);
  });

  it("parses an explicit conservative port set", () => {
    const ports = parseAllowedPorts("22,80,443,8000-8002");
    expect(ports.has(22)).toBe(true);
    expect(ports.has(8001)).toBe(true);
    expect(ports.has(25)).toBe(false);
  });

  it("pins a domain to a validated resolver result", async () => {
    const result = await resolveAndValidateDestination(
      { type: "domain", host: "example.com", port: 443 },
      { expectedHost: "edge.example.com", allowedPorts: new Set([443]) },
      async () => ["93.184.216.34"]
    );
    expect(result).toEqual({ hostname: "93.184.216.34", port: 443, originalHostname: "example.com" });
  });

  it("fails closed if any resolver result is private", async () => {
    await expect(
      resolveAndValidateDestination(
        { type: "domain", host: "example.com", port: 443 },
        { expectedHost: "edge.example.com", allowedPorts: new Set([443]) },
        async () => ["93.184.216.34", "10.0.0.1"]
      )
    ).rejects.toThrow(DestinationPolicyError);
  });
});
