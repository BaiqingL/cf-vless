import { bindings, defineWorker } from "wrangler/experimental-config";

export default defineWorker({
  name: "cf-vless",
  compatibilityDate: "2026-07-12",
  compatibilityFlags: ["nodejs_compat"],
  entrypoint: "./src/index.ts",
  workersDev: false,
  previewUrls: false,
  observability: {
    enabled: false,
    headSamplingRate: 0,
    logs: { enabled: false, headSamplingRate: 0, invocationLogs: false, persist: false },
    traces: { enabled: false, headSamplingRate: 0, persist: false }
  },
  env: {
    EXPECTED_HOST: bindings.text("edge.example.com"),
    DEPLOYMENT_MARKER: bindings.text("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
    ALLOWED_PORTS: bindings.text("22,80,443"),
    HANDSHAKE_TIMEOUT_MS: bindings.text("10000"),
    CONNECT_TIMEOUT_MS: bindings.text("10000"),
    IDLE_TIMEOUT_MS: bindings.text("300000"),
    SESSION_TIMEOUT_MS: bindings.text("3600000"),
    VLESS_CREDENTIALS: bindings.secret(),
  }
});
