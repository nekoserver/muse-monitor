import { createHmac } from "node:crypto";
import { execFileSync } from "node:child_process";
import { afterEach, describe, expect, it, vi } from "vitest";
import worker from "../src/index";

// The set the DO accepts (src/do.ts SECTIONS); anything else is a 404 there.
const DO_SECTIONS = ["status", "diag", "jobs", "pkgs", "vm", "procs", "ports", "git", "recent", "pending", "execlog", "sdkhealth", "sdkprofiles", "sdksessions", "sdkts"];

// What can break: a route opens without a key, the bearer and HMAC keys get mixed up,
// an old or replayed signature is accepted, a signature for one section unlocks another,
// a request lands on the wrong DO URL, or the dashboard script stops parsing (blank page).

const WORKER_API_KEY = "worker-key-0123456789";
const MONITOR_HMAC_SECRET = "hmac-secret-abcdef";

function makeEnv() {
  const calls: string[] = [];
  const ids: string[] = [];
  const env = {
    WORKER_API_KEY,
    TS_API_KEY: "ts-key",
    MONITOR_HMAC_SECRET,
    MONITOR_GATEWAY: {
      idFromName: (name: string) => { ids.push(name); return name; },
      get: () => ({ fetch: async (url: string) => { calls.push(url); return Response.json({ from: "do", url }); } }),
    },
  };
  return { env: env as never, calls, ids };
}

const call = (path: string, headers: Record<string, string> = {}, method = "GET") =>
  new Request(`https://muse-monitor.example${path}`, { method, headers });

const sign = (section: string, ts = Math.floor(Date.now() / 1000), secret = MONITOR_HMAC_SECRET) => ({
  "X-Muse-Timestamp": String(ts),
  "X-Muse-Signature": createHmac("sha256", secret).update(`${ts}.${section}`).digest("hex"),
});

afterEach(() => { vi.useRealTimers(); });

describe("open routes", () => {
  it("GET /health answers without the DO", async () => {
    const { env, calls } = makeEnv();
    const res = await worker.fetch(call("/health"), env);
    expect(await res.json()).toEqual({ status: "ok", worker: "muse-monitor" });
    expect(calls).toEqual([]);
  });

  it("GET / returns the dashboard as HTML", async () => {
    const { env } = makeEnv();
    const res = await worker.fetch(call("/"), env);
    expect(res.headers.get("Content-Type")).toBe("text/html; charset=utf-8");
    expect(await res.text()).toContain("<title>muse-monitor</title>");
  });

  it("unknown paths and non-GET methods return 404", async () => {
    const { env, calls } = makeEnv();
    for (const req of [call("/nope"), call("/api/status", { Authorization: `Bearer ${WORKER_API_KEY}` }, "POST")]) {
      expect((await worker.fetch(req, env)).status).toBe(404);
    }
    expect(calls).toEqual([]);
  });
});

describe("bearer routes", () => {
  it("forward to the single named DO at the matching URL", async () => {
    const { env, calls, ids } = makeEnv();
    const auth = { Authorization: `Bearer ${WORKER_API_KEY}` };
    expect((await worker.fetch(call("/api/status", auth), env)).status).toBe(200);
    expect((await worker.fetch(call("/api/monitor/jobs", auth), env)).status).toBe(200);
    expect(calls).toEqual(["http://do/status", "http://do/monitor/jobs"]);
    expect(new Set(ids)).toEqual(new Set(["monitor-gateway"]));
  });

  it.each([
    ["no header", {}],
    ["wrong key", { Authorization: "Bearer worker-key-0123456788" }],
    ["shorter key", { Authorization: "Bearer worker" }],
    ["no Bearer prefix", { Authorization: WORKER_API_KEY }],
    ["HMAC secret instead of the bearer key", { Authorization: `Bearer ${MONITOR_HMAC_SECRET}` }],
  ])("rejects %s with 401 and never reaches the DO", async (_label, headers) => {
    const { env, calls } = makeEnv();
    for (const path of ["/api/status", "/api/monitor/status"]) {
      const res = await worker.fetch(call(path, headers as Record<string, string>), env);
      expect(res.status).toBe(401);
      expect(await res.json()).toEqual({ error: "unauthorized" });
    }
    expect(calls).toEqual([]);
  });

  it("rejects every request when WORKER_API_KEY is not set", async () => {
    const { env, calls } = makeEnv();
    (env as { WORKER_API_KEY: string }).WORKER_API_KEY = "";
    expect((await worker.fetch(call("/api/status", { Authorization: "Bearer " }), env)).status).toBe(401);
    expect(calls).toEqual([]);
  });
});

describe("HMAC routes", () => {
  it("accept a fresh signature for the same section", async () => {
    const { env, calls } = makeEnv();
    expect((await worker.fetch(call("/api/hmac/status", sign("status")), env)).status).toBe(200);
    expect((await worker.fetch(call("/api/hmac/monitor/diag", sign("diag")), env)).status).toBe(200);
    const upper = sign("git");
    upper["X-Muse-Signature"] = upper["X-Muse-Signature"].toUpperCase();
    expect((await worker.fetch(call("/api/hmac/monitor/git", upper), env)).status).toBe(200);
    expect(calls).toEqual(["http://do/status", "http://do/monitor/diag", "http://do/monitor/git"]);
  });

  it("accepts up to 300 s of clock skew in both directions and nothing beyond", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-11-10T00:00:00Z"));
    const now = Math.floor(Date.now() / 1000);
    const { env } = makeEnv();
    const status = async (ts: number) => (await worker.fetch(call("/api/hmac/status", sign("status", ts)), env)).status;
    expect(await status(now - 300)).toBe(200);
    expect(await status(now + 300)).toBe(200);
    expect(await status(now - 301)).toBe(401);
    expect(await status(now + 301)).toBe(401);
  });

  it.each([
    ["a signature for another section", () => sign("status"), "/api/hmac/monitor/execlog"],
    ["the wrong secret", () => sign("status", undefined, "other-secret"), "/api/hmac/status"],
    ["the bearer key as the secret", () => sign("status", undefined, WORKER_API_KEY), "/api/hmac/status"],
    ["a non-hex signature", () => ({ ...sign("status"), "X-Muse-Signature": "z".repeat(64) }), "/api/hmac/status"],
    ["a truncated signature", () => { const h = sign("status"); return { ...h, "X-Muse-Signature": h["X-Muse-Signature"].slice(0, 63) }; }, "/api/hmac/status"],
    ["a non-numeric timestamp", () => ({ ...sign("status"), "X-Muse-Timestamp": "soon" }), "/api/hmac/status"],
    ["no headers", () => ({}), "/api/hmac/status"],
    ["the bearer header only", () => ({ Authorization: `Bearer ${WORKER_API_KEY}` }), "/api/hmac/status"],
  ])("reject %s with 401", async (_label, headers, path) => {
    const { env, calls } = makeEnv();
    const res = await worker.fetch(call(path, headers() as Record<string, string>), env);
    expect(res.status).toBe(401);
    expect(calls).toEqual([]);
  });

  it("rejects every signature when MONITOR_HMAC_SECRET is not set", async () => {
    const { env, calls } = makeEnv();
    (env as { MONITOR_HMAC_SECRET: string }).MONITOR_HMAC_SECRET = "";
    expect((await worker.fetch(call("/api/hmac/status", sign("status", undefined, "")), env)).status).toBe(401);
    expect(calls).toEqual([]);
  });
});

describe("dashboard script", () => {
  it("parses as JavaScript once the template literal has been rendered", async () => {
    const { env } = makeEnv();
    const html = await (await worker.fetch(call("/"), env)).text();
    const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((m) => m[1]);
    expect(scripts.length).toBeGreaterThan(0);
    for (const source of scripts) {
      expect(() => execFileSync(process.execPath, ["--check"], { input: source, stdio: "pipe" })).not.toThrow();
    }
  });

  it("lists every section the DO serves, each in exactly one tab", async () => {
    const { env } = makeEnv();
    const html = await (await worker.fetch(call("/"), env)).text();
    const sections = (JSON.parse(/const SECTIONS = (.*);/.exec(html)![1]) as [string, string][]).map(([n]) => n).sort();
    expect(sections).toEqual([...DO_SECTIONS].sort());
    const catsSource = /const CATS = (\[[\s\S]*?\]);\n/.exec(html)![1];
    const tabbed = (JSON.parse(catsSource.replace(/,\s*\]$/, "]")) as [string, string[]][]).flatMap(([, n]) => n).sort();
    expect(tabbed).toEqual(sections);
  });
});
