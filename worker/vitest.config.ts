import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

const TEST_CREDENTIALS = JSON.stringify({
  current: {
    uuid: "00112233-4455-6677-8899-aabbccddeeff",
    path: "/unit-test-path-0001"
  }
});
process.env.VLESS_CREDENTIALS = TEST_CREDENTIALS;

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.jsonc" },
      miniflare: {
        bindings: {
          EXPECTED_HOST: "edge.example.com",
          ALLOWED_PORTS: "22,80,443",
          HANDSHAKE_TIMEOUT_MS: "250",
          CONNECT_TIMEOUT_MS: "250",
          IDLE_TIMEOUT_MS: "1000",
          SESSION_TIMEOUT_MS: "5000",
          VLESS_CREDENTIALS: TEST_CREDENTIALS
        }
      }
    })
  ]
});
