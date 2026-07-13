import { parseCredentialSet, selectCredentialForPath } from "./auth";
import { TunnelSession, type SessionOptions } from "./websocket";

const NOT_FOUND_HEADERS = {
  "Cache-Control": "no-store",
  "Content-Type": "text/plain; charset=utf-8",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY"
};

function notFound(): Response {
  return new Response("Not Found\n", { status: 404, headers: NOT_FOUND_HEADERS });
}

function parseMilliseconds(value: string, minimum: number, maximum: number): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new Error("runtime configuration is invalid");
  }
  return parsed;
}

function sessionOptions(env: Env): SessionOptions {
  return {
    expectedHost: env.EXPECTED_HOST,
    allowedPorts: env.ALLOWED_PORTS,
    handshakeTimeoutMs: parseMilliseconds(env.HANDSHAKE_TIMEOUT_MS, 100, 60_000),
    connectTimeoutMs: parseMilliseconds(env.CONNECT_TIMEOUT_MS, 100, 60_000),
    idleTimeoutMs: parseMilliseconds(env.IDLE_TIMEOUT_MS, 1_000, 86_400_000),
    sessionTimeoutMs: parseMilliseconds(env.SESSION_TIMEOUT_MS, 1_000, 86_400_000)
  };
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (
      request.method !== "GET" ||
      url.protocol !== "https:" ||
      (url.port !== "" && url.port !== "443") ||
      url.hostname.toLowerCase() !== env.EXPECTED_HOST.toLowerCase()
    )
      return notFound();
    if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") return notFound();

    try {
      const credentials = parseCredentialSet(env.VLESS_CREDENTIALS);
      const credential = selectCredentialForPath(credentials, url.pathname);
      if (credential === undefined) return notFound();

      const pair = new WebSocketPair();
      const client = pair[0];
      const server = pair[1];
      const session = new TunnelSession(server, credential, sessionOptions(env));
      session.start();
      return new Response(null, { status: 101, webSocket: client });
    } catch {
      return notFound();
    }
  }
} satisfies ExportedHandler<Env>;
