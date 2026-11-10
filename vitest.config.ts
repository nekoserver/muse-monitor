import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";

// The Durable Object imports Workers-only modules (cloudflare:workers, the
// Go WASM runtime and the .wasm module). Tests swap them for small stubs;
// the Tailscale node itself is replaced per test through globalThis.newIPN.
const stub = (name: string) => fileURLToPath(new URL(`./test/stubs/${name}`, import.meta.url));

export default defineConfig({
  resolve: {
    alias: [
      { find: "cloudflare:workers", replacement: stub("cloudflare-workers.ts") },
      { find: "@ai-ecoverse/wasm-tailscale/main.wasm", replacement: stub("main-wasm.ts") },
      { find: "@ai-ecoverse/wasm-tailscale/wasm_exec.js", replacement: stub("wasm-exec.ts") },
    ],
  },
  test: { include: ["test/**/*.test.ts"] },
});
