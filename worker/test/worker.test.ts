import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

describe("Worker HTTP and WebSocket boundary", () => {
  it("serves an innocuous HTTP response without proxy disclosure", async () => {
    const response = await SELF.fetch("https://edge.example.com/");
    expect(response.status).toBe(404);
    expect(await response.text()).not.toMatch(/vless|proxy|tunnel/i);
  });

  it("rejects non-WebSocket requests to the endpoint", async () => {
    const response = await SELF.fetch("https://edge.example.com/unit-test-path-0001");
    expect(response.status).toBe(404);
  });

  it("rejects an invalid path without identifying the endpoint", async () => {
    const response = await SELF.fetch("https://edge.example.com/wrong", {
      headers: { Upgrade: "websocket" }
    });
    expect(response.status).toBe(404);
  });

  it.each([
    ["plaintext HTTP", "http://edge.example.com/unit-test-path-0001"],
    ["an explicit non-443 port", "https://edge.example.com:8443/unit-test-path-0001"]
  ])("rejects %s WebSocket upgrades with the generic response", async (_description, url) => {
    const response = await SELF.fetch(url, { headers: { Upgrade: "websocket" } });
    expect(response.status).toBe(404);
    expect(await response.text()).toBe("Not Found\n");
    expect(response.headers.get("Cache-Control")).toBe("no-store");
  });

  it("upgrades the configured WebSocket path", async () => {
    const response = await SELF.fetch("https://edge.example.com/unit-test-path-0001", {
      headers: { Upgrade: "websocket" }
    });
    expect(response.status).toBe(101);
    expect(response.webSocket).not.toBeNull();
    response.webSocket?.accept();
    response.webSocket?.close(1000, "done");
  });

  it("closes on text frames", async () => {
    const response = await SELF.fetch("https://edge.example.com/unit-test-path-0001", {
      headers: { Upgrade: "websocket" }
    });
    const socket = response.webSocket!;
    socket.accept();
    const closed = new Promise<CloseEvent>((resolve) => socket.addEventListener("close", resolve, { once: true }));
    socket.send("not binary");
    expect((await closed).code).toBe(1003);
  });
});
