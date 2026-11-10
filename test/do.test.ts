import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MonitorGateway } from "../src/do";
import type { IPNCallbacks, IPNConfig } from "../src/wasm-ipn";

// What can break between the DO and the receiver on muse-vm:
//  - the node never reaches Running (no auth key, approval pending, panic) and the caller
//    gets a misleading error, or a later request uses the node as if it were up;
//  - several requests at once (the dashboard's "全て取得" sends 15) start several nodes;
//  - muse-vm is missing from the netmap, or its IP changed after re-registering;
//  - the receiver answers too much, or the TS_API_KEY is not sent / leaks into /status;
//  - the node's state is not persisted, so every restart needs a fresh login.

type Req = { url: string; method?: string; headers?: [string, string][] };
type Handler = (req: Req) => Promise<{ status: number; body?: string; chunks?: Uint8Array[] }>;

const NETMAP = (peers: [string, string][]) =>
  JSON.stringify({
    self: { name: "muse-monitor.taile4e096.ts.net.", addresses: ["100.99.0.5"] },
    peers: peers.map(([name, ip]) => ({ name: `${name}.taile4e096.ts.net.`, addresses: [ip, "fd7a::1"] })),
  });

class FakeNode {
  callbacks: IPNCallbacks | null = null;
  config: IPNConfig;
  login = vi.fn();
  requests: Req[] = [];
  handler: Handler = async (req) =>
    new URL(req.url).pathname === "/health" ? { status: 200, body: "ok" } : { status: 200, body: '{"output":"jobs ok"}' };
  statusJson = JSON.stringify({ backendState: "Running", self: { name: "muse-monitor" } });
  constructor(config: IPNConfig) { this.config = config; }
  run(cb: IPNCallbacks) { this.callbacks = cb; }
  status() { return this.statusJson; }
  async fetch(req: Req) {
    this.requests.push(req);
    const r = await this.handler(req);
    const queue = r.chunks ? [...r.chunks] : [new TextEncoder().encode(r.body ?? "")];
    return {
      status: r.status, statusText: String(r.status), url: req.url, headers: {},
      read: async () => queue.shift() ?? null,
      cancel: vi.fn(),
    };
  }
  /** Simulates the control plane: state changes and netmap arrive asynchronously. */
  up(peers: [string, string][] = [["muse-vm", "100.86.29.77"]]) {
    this.callbacks!.notifyNetMap(NETMAP(peers));
    this.callbacks!.notifyState("Running");
  }
}

let nodes: FakeNode[];
let goRuns: number;
let onLogin: (node: FakeNode) => void;
let newIpnResult: ((config: IPNConfig) => unknown) | null;

beforeEach(() => {
  nodes = [];
  goRuns = 0;
  newIpnResult = null;
  onLogin = (node) => queueMicrotask(() => node.up());
  (globalThis as Record<string, unknown>).Go = class { importObject = {}; run() { goRuns++; return new Promise(() => {}); } };
  vi.spyOn(WebAssembly, "instantiate").mockResolvedValue({} as WebAssembly.Instance);
  (globalThis as Record<string, unknown>).newIPN = (config: IPNConfig) => {
    if (newIpnResult) return newIpnResult(config);
    const node = new FakeNode(config);
    node.login.mockImplementation(() => onLogin(node));
    nodes.push(node);
    return node;
  };
});
afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks(); });

function makeCtx(initial: Record<string, unknown> = {}) {
  const stored = new Map<string, unknown>(Object.entries(initial));
  const waits: Promise<unknown>[] = [];
  const ctx = {
    storage: {
      get: async (k: string) => stored.get(k),
      put: async (k: string, v: unknown) => { stored.set(k, structuredClone(v)); },
    },
    waitUntil: (p: Promise<unknown>) => { waits.push(p); },
  };
  return { ctx: ctx as unknown as DurableObjectState, stored, waits };
}
const ENV = { TS_API_KEY: "ts-api-key-secret", TS_AUTHKEY: "tskey-auth-secret" };
const gateway = (env: Record<string, string> = ENV, ctx = makeCtx().ctx) => new MonitorGateway(ctx, env as never);
const get = (gw: MonitorGateway, path: string) => gw.fetch(new Request(`http://do${path}`));

describe("GET /monitor/<section>", () => {
  it("joins with the auth key, finds muse-vm, and relays the receiver's answer with the TS_API_KEY", async () => {
    const gw = gateway();
    const res = await get(gw, "/monitor/jobs");
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("application/json");
    expect(await res.json()).toEqual({ output: "jobs ok" });
    const [node] = nodes;
    expect(node.config).toMatchObject({ authKey: "tskey-auth-secret", hostname: "muse-monitor", ephemeral: false });
    expect(node.login).toHaveBeenCalledWith("tskey-auth-secret");
    expect(node.requests.map((r) => r.url)).toEqual(["http://100.86.29.77:8090/health", "http://100.86.29.77:8090/monitor/jobs"]);
    expect(node.requests[1]).toMatchObject({ method: "GET", headers: [["Authorization", "Bearer ts-api-key-secret"]] });
  });

  it("passes the receiver's own status through (e.g. 401 from a wrong TS_API_KEY)", async () => {
    const gw = gateway();
    await get(gw, "/monitor/status");
    nodes[0].handler = async () => ({ status: 401, body: '{"error":"unauthorized"}' });
    const res = await get(gw, "/monitor/status");
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "unauthorized" });
  });

  it("returns 404 for a section outside the list without starting the node", async () => {
    const gw = gateway();
    for (const path of ["/monitor/exec", "/monitor/", "/monitor/JOBS", "/monitor/jobs/x", "/other"]) {
      expect((await get(gw, path)).status).toBe(404);
    }
    expect(nodes).toHaveLength(0);
  });

  it("starts exactly one node when many sections are requested at once", async () => {
    const gw = gateway();
    const sections = ["status", "diag", "jobs", "pkgs", "vm", "procs", "ports", "git", "recent", "pending", "execlog", "sdkhealth", "sdkprofiles", "sdksessions", "sdkts"];
    const results = await Promise.all(sections.map((s) => get(gw, `/monitor/${s}`)));
    expect(results.map((r) => r.status)).toEqual(sections.map(() => 200));
    expect(nodes).toHaveLength(1);
    expect(goRuns).toBe(1);
  });

  it("follows muse-vm to muse-vm-1 when the cached IP stops answering", async () => {
    const gw = gateway();
    onLogin = (node) => queueMicrotask(() => node.up([["muse-vm", "100.0.0.1"], ["muse-vm-1", "100.0.0.2"]]));
    expect((await get(gw, "/monitor/jobs")).status).toBe(200);
    const node = nodes[0];
    node.handler = async (req) => {
      if (req.url.startsWith("http://100.0.0.1:")) throw new Error("dial tcp 100.0.0.1:8090: timeout");
      return { status: 200, body: '{"output":"moved"}' };
    };
    const res = await get(gw, "/monitor/jobs");
    expect(await res.json()).toEqual({ output: "moved" });
    expect((await (await get(gw, "/status")).json()).receiver.resolvedIp).toBe("100.0.0.2");
  });

  it("returns receiver_not_found when muse-vm is not in the netmap", async () => {
    onLogin = (node) => queueMicrotask(() => node.up([["ipad", "100.74.35.120"]]));
    const res = await get(gateway(), "/monitor/jobs");
    expect(res.status).toBe(502);
    expect(await res.json()).toMatchObject({ error: "receiver_not_found" });
  });

  it("returns delivery_unknown when the GET fails on every candidate after a healthy probe", async () => {
    const gw = gateway();
    await get(gw, "/monitor/jobs");
    nodes[0].handler = async (req) => {
      if (new URL(req.url).pathname === "/health") return { status: 200 };
      throw new Error("connection reset");
    };
    const res = await get(gw, "/monitor/jobs");
    expect(res.status).toBe(502);
    expect(await res.json()).toMatchObject({ error: "delivery_unknown", message: expect.stringContaining("connection reset") });
  });

  it("stops reading past 8 MiB and cancels the response", async () => {
    const gw = gateway();
    await get(gw, "/monitor/jobs");
    const mib = new Uint8Array(1024 * 1024);
    nodes[0].handler = async (req) =>
      new URL(req.url).pathname === "/health" ? { status: 200 } : { status: 200, chunks: Array.from({ length: 9 }, () => mib) };
    const res = await get(gw, "/monitor/procs");
    expect(res.status).toBe(502);
    expect(await res.json()).toMatchObject({ error: "response_too_large" });
  });

  it("joins a multi-chunk answer without corrupting multi-byte characters", async () => {
    const gw = gateway();
    await get(gw, "/monitor/jobs");
    const bytes = new TextEncoder().encode('{"output":"ジョブキュー"}');
    nodes[0].handler = async (req) =>
      new URL(req.url).pathname === "/health" ? { status: 200 } : { status: 200, chunks: [bytes.slice(0, 15), bytes.slice(15)] };
    expect(await (await get(gw, "/monitor/jobs")).json()).toEqual({ output: "ジョブキュー" });
  });
});

describe("node start failures", () => {
  it("reports the login URL when the node waits for interactive approval (no TS_AUTHKEY)", async () => {
    vi.useFakeTimers();
    onLogin = (node) => queueMicrotask(() => {
      node.callbacks!.notifyState("NeedsLogin");
      node.callbacks!.notifyBrowseToURL("https://login.tailscale.com/a/abc123");
    });
    const gw = gateway({ TS_API_KEY: "k" });
    const pending = get(gw, "/monitor/jobs");
    await vi.advanceTimersByTimeAsync(60_000);
    const res = await pending;
    expect(res.status).toBe(502);
    expect(await res.json()).toMatchObject({ error: "tailnet_unavailable", message: expect.stringContaining("https://login.tailscale.com/a/abc123") });
    expect(nodes[0].config).not.toHaveProperty("authKey");
    const status = await (await get(gw, "/status")).json();
    expect(status).toMatchObject({ loginUrl: "https://login.tailscale.com/a/abc123", authKeyConfigured: false });
  });

  it("keeps answering tailnet_unavailable while the node is not Running, and works once it is", async () => {
    vi.useFakeTimers();
    onLogin = () => {};
    const gw = gateway();
    const first = get(gw, "/monitor/jobs");
    await vi.advanceTimersByTimeAsync(60_000);
    expect(await (await first).json()).toMatchObject({ error: "tailnet_unavailable", message: expect.stringContaining("did not reach Running") });

    // Second request: the node exists but is still not Running. It must not be used as if it were up.
    const second = get(gw, "/monitor/jobs");
    await vi.advanceTimersByTimeAsync(60_000);
    expect(await (await second).json()).toMatchObject({ error: "tailnet_unavailable" });
    expect(nodes[0].requests).toEqual([]);

    // The approval arrives late: the same node becomes Running and requests go through.
    const third = get(gw, "/monitor/jobs");
    await vi.advanceTimersByTimeAsync(1);
    nodes[0].up();
    expect((await third).status).toBe(200);
    expect(nodes).toHaveLength(1);
  });

  it("does not leave the node unusable after a recovered panic", async () => {
    vi.useFakeTimers();
    onLogin = (node) => queueMicrotask(() => node.callbacks!.notifyPanicRecover("runtime error: index out of range"));
    const gw = gateway();
    const first = await get(gw, "/monitor/jobs");
    expect(await first.json()).toMatchObject({ error: "tailnet_unavailable", message: expect.stringContaining("index out of range") });

    const second = get(gw, "/monitor/jobs");
    await vi.advanceTimersByTimeAsync(1);
    nodes[0].up();
    expect((await second).status).toBe(200);
    expect(nodes).toHaveLength(1);
  });

  it("reports newIPN errors and tries again on the next request", async () => {
    newIpnResult = () => new Error("bad config");
    const gw = gateway();
    expect(await (await get(gw, "/monitor/jobs")).json()).toMatchObject({ error: "tailnet_unavailable", message: expect.stringContaining("newIPN failed: bad config") });
    newIpnResult = null;
    expect((await get(gw, "/monitor/jobs")).status).toBe(200);
  });
});

describe("GET /status", () => {
  it("before any request: not-started, without starting the node", async () => {
    const gw = gateway();
    expect(await (await get(gw, "/status")).json()).toEqual({
      node: "not-started", lastStatus: "not-started", lastError: null, loginUrl: null, authKeyConfigured: true,
    });
    expect(nodes).toHaveLength(0);
  });

  it("after start: state, receiver candidates and the node's status, with no secret in the body", async () => {
    const gw = gateway();
    await get(gw, "/monitor/jobs");
    const res = await get(gw, "/status");
    const text = await res.text();
    expect(JSON.parse(text)).toMatchObject({
      node: "Running",
      receiver: { baseName: "muse-vm", resolvedIp: "100.86.29.77", candidates: [{ name: "muse-vm", ip: "100.86.29.77" }] },
      tailscale: { backendState: "Running" },
    });
    expect(text).not.toContain("ts-api-key-secret");
    expect(text).not.toContain("tskey-auth-secret");
  });

  it("wraps a non-JSON status string instead of failing", async () => {
    const gw = gateway();
    await get(gw, "/monitor/jobs");
    nodes[0].statusJson = "not json";
    expect((await (await get(gw, "/status")).json()).tailscale).toEqual({ raw: "not json" });
  });
});

describe("node state persistence", () => {
  it("flushes setState to DO storage and hands it back to the next instance", async () => {
    const store = makeCtx();
    const gw = gateway(ENV, store.ctx);
    await get(gw, "/monitor/jobs");
    nodes[0].config.stateStorage.setState("_current-profile", "profile-1");
    await Promise.all(store.waits);
    expect(store.stored.get("ts-state")).toEqual({ "_current-profile": "profile-1" });

    const next = gateway(ENV, makeCtx({ "ts-state": store.stored.get("ts-state") }).ctx);
    await get(next, "/monitor/jobs");
    expect(nodes[1].config.stateStorage.getState("_current-profile")).toBe("profile-1");
    expect(nodes[1].config.stateStorage.getState("missing")).toBe("");
  });

  it("records a failed flush in lastError", async () => {
    const store = makeCtx();
    (store.ctx.storage as { put: unknown }).put = async () => { throw new Error("storage full"); };
    const gw = gateway(ENV, store.ctx);
    await get(gw, "/monitor/jobs");
    nodes[0].config.stateStorage.setState("k", "v");
    await Promise.all(store.waits);
    expect((await (await get(gw, "/status")).json()).lastError).toContain("storage full");
  });
});
