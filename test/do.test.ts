import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MonitorGateway, RECEIVER_RETRIES, RECEIVER_RETRY_DELAY_MS } from "../src/do";
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
let onLogin: (node: FakeNode, authKey?: string) => void;
let onStart: (node: FakeNode) => void;
let newIpnResult: ((config: IPNConfig) => unknown) | null;

beforeEach(() => {
  nodes = [];
  goRuns = 0;
  newIpnResult = null;
  onLogin = (node) => queueMicrotask(() => node.up());
  onStart = () => {};
  (globalThis as Record<string, unknown>).Go = class { importObject = {}; run() { goRuns++; return new Promise(() => {}); } };
  vi.spyOn(WebAssembly, "instantiate").mockResolvedValue({} as WebAssembly.Instance);
  (globalThis as Record<string, unknown>).newIPN = (config: IPNConfig) => {
    if (newIpnResult) return newIpnResult(config);
    const node = new FakeNode(config);
    node.login.mockImplementation((authKey?: string) => onLogin(node, authKey));
    const run = node.run.bind(node);
    node.run = (callbacks) => { run(callbacks); onStart(node); };
    nodes.push(node);
    return node;
  };
});
afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks(); });

class FakeSocket {
  sent: string[] = [];
  closed = false;
  send(data: string) { this.sent.push(data); }
  close() { this.closed = true; }
}
class FakeWebSocketPair {
  0 = new FakeSocket();
  1 = new FakeSocket();
}

function makeCtx(initial: Record<string, unknown> = {}) {
  const stored = new Map<string, unknown>(Object.entries(initial));
  const waits: Promise<unknown>[] = [];
  const sockets: FakeSocket[] = [];
  let alarmAt: number | null = null;
  const ctx = {
    storage: {
      get: async (k: string) => stored.get(k),
      put: async (k: string, v: unknown) => { stored.set(k, structuredClone(v)); },
      delete: async (k: string) => { stored.delete(k); },
      setAlarm: async (t: number) => { alarmAt = t; },
      getAlarm: async () => alarmAt,
    },
    waitUntil: (p: Promise<unknown>) => { waits.push(p); },
    acceptWebSocket: (ws: FakeSocket) => { sockets.push(ws); },
    getWebSockets: () => sockets,
  };
  return { ctx: ctx as unknown as DurableObjectState, stored, waits, sockets, alarmAt: () => alarmAt };
}
const ENV = { TS_AUTHKEY: "tskey-auth-secret", TS_API_KEY: "receiver-key-secret" };
const gateway = (env: Record<string, string> = ENV, ctx = makeCtx().ctx) => new MonitorGateway(ctx, env as never);
const get = (gw: MonitorGateway, path: string) => gw.fetch(new Request(`http://do${path}`));

describe("GET /monitor/<section>", () => {
  it("joins with TS_AUTHKEY, finds muse-vm, and sends TS_API_KEY to the receiver (roles separated)", async () => {
    const gw = gateway();
    const res = await get(gw, "/monitor/jobs");
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("application/json");
    expect(await res.json()).toEqual({ output: "jobs ok" });
    const [node] = nodes;
    expect(node.config).toMatchObject({ authKey: "tskey-auth-secret", hostname: "muse-monitor", ephemeral: false });
    expect(node.login).toHaveBeenCalledWith("tskey-auth-secret");
    expect(node.requests.map((r) => r.url)).toEqual(["http://100.86.29.77:8090/health", "http://100.86.29.77:8090/monitor/jobs"]);
    expect(node.requests[1]).toMatchObject({ method: "GET", headers: [["Authorization", "Bearer receiver-key-secret"]] });
  });

  it("passes the receiver's other statuses and bodies through unchanged", async () => {
    const gw = gateway();
    await get(gw, "/monitor/status");
    nodes[0].handler = async (req) =>
      new URL(req.url).pathname === "/health" ? { status: 200 } : { status: 504, body: '{"error":"timeout"}' };
    const res = await get(gw, "/monitor/status");
    expect(res.status).toBe(504);
    expect(await res.json()).toEqual({ error: "timeout" });
  });

  it("explains a 401 from the receiver instead of relaying a bare unauthorized", async () => {
    const gw = gateway();
    await get(gw, "/monitor/status");
    nodes[0].handler = async (req) =>
      new URL(req.url).pathname === "/health" ? { status: 200 } : { status: 401, body: '{"error":"unauthorized"}' };
    const res = await get(gw, "/monitor/status");
    expect(res.status).toBe(401);
    const body = await res.json();
    expect(body).toMatchObject({ error: "receiver_unauthorized", keySource: "TS_API_KEY", receiver: { error: "unauthorized" } });
    expect(body.message).toContain("TS_API_KEY");
    expect(JSON.stringify(body)).not.toContain("tskey-auth-secret");
    expect(JSON.stringify(body)).not.toContain("receiver-key-secret");
  });

  it("explains a 503 from the receiver as a missing key on the receiver side", async () => {
    const gw = gateway();
    await get(gw, "/monitor/status");
    nodes[0].handler = async (req) =>
      new URL(req.url).pathname === "/health" ? { status: 200 } : { status: 503, body: "no key" };
    const res = await get(gw, "/monitor/status");
    expect(res.status).toBe(503);
    expect(await res.json()).toMatchObject({ error: "receiver_key_not_configured", receiver: "no key" });
  });

  it("TS_AUTHKEY alone does not open the receiver: without TS_API_KEY the answer is receiver_key_missing and the node is not started", async () => {
    const res = await get(gateway({ TS_AUTHKEY: "tskey-other" }), "/monitor/jobs");
    expect(res.status).toBe(500);
    expect(await res.json()).toMatchObject({ error: "receiver_key_missing" });
    expect(nodes).toHaveLength(0);
  });

  it("with TS_AUTHKEY unset, TS_API_KEY is never used to join (fallback removed): no key is passed to the node or to login", async () => {
    const gw = gateway({ TS_API_KEY: "tskey-auth-secret" });
    const res = await get(gw, "/monitor/jobs");
    expect(res.status).toBe(200);
    expect(nodes[0].config.authKey).toBeUndefined();
    expect(nodes[0].login).not.toHaveBeenCalledWith("tskey-auth-secret");
    expect(await (await get(gw, "/status")).json()).toMatchObject({ authKeyConfigured: false, authKeySource: null });
    expect(await (await get(gw, "/public-status")).json()).toMatchObject({ authKeySource: null, receiverKeySource: "TS_API_KEY" });
  });

  it("does not send a request with an empty or undefined Bearer when neither key is set", async () => {
    const res = await get(gateway({}), "/monitor/jobs");
    expect(res.status).toBe(500);
    expect(await res.json()).toMatchObject({ error: "receiver_key_missing" });
    expect(nodes).toHaveLength(0);
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
    const sections = ["status", "diag", "jobs", "pkgs", "vm", "procs", "ports", "git", "recent", "pending", "execlog", "sdkhealth", "sdkprofiles", "sdksessions", "sdkts", "hooks"];
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
    const body = await res.json();
    expect(body).toMatchObject({ error: "receiver_not_found", candidates: 0, probes: [] });
    expect(body.message).toContain("netmap");
  });

  it("says the receiver is not listening when muse-vm refuses :8090, with the probe results and no IP", async () => {
    onLogin = (node) => {
      node.handler = async () => { throw new Error("connect tcp 100.86.29.77:8090: connection was refused"); };
      queueMicrotask(() => node.up());
    };
    vi.useFakeTimers();
    const pending = get(gateway(), "/monitor/jobs");
    await vi.advanceTimersByTimeAsync(RECEIVER_RETRY_DELAY_MS * RECEIVER_RETRIES + 1000);
    const res = await pending;
    expect(res.status).toBe(502);
    const text = await res.text();
    const body = JSON.parse(text);
    expect(body).toMatchObject({
      error: "receiver_not_found",
      candidates: 1,
      probes: [{ name: "muse-vm", result: expect.stringContaining("connection was refused") }],
    });
    expect(body.message).toContain("muse-receiver");
    expect(body.message).toContain("receiver-check.sh");
    expect(text).not.toContain("100.86.29.77");
    // 1回目 + 再試行の分だけ /health を叩いた
    expect(nodes[0].requests.filter((r) => r.url.endsWith("/health"))).toHaveLength(1 + RECEIVER_RETRIES);
  });

  it("waits and probes again while the receiver is restarting, and answers once it is back", async () => {
    // 受信側は systemd の Restart=always で数秒後に戻る。その間に来た要求を receiver_not_found にしない
    let refusals = 2;
    onLogin = (node) => {
      node.handler = async (req) => {
        if (new URL(req.url).pathname === "/health" && refusals > 0) { refusals--; throw new Error("connection was refused"); }
        return new URL(req.url).pathname === "/health" ? { status: 200 } : { status: 200, body: '{"output":"back"}' };
      };
      queueMicrotask(() => node.up());
    };
    vi.useFakeTimers();
    const pending = get(gateway(), "/monitor/jobs");
    await vi.advanceTimersByTimeAsync(RECEIVER_RETRY_DELAY_MS * RECEIVER_RETRIES + 1000);
    const res = await pending;
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ output: "back" });
    expect(nodes[0].requests.filter((r) => r.url.endsWith("/health"))).toHaveLength(3);
  });

  it("does not wait when muse-vm is not in the netmap at all", async () => {
    onLogin = (node) => queueMicrotask(() => node.up([["ipad", "100.74.35.120"]]));
    vi.useFakeTimers();
    const pending = get(gateway(), "/monitor/jobs");
    await vi.advanceTimersByTimeAsync(100);
    const res = await pending;
    expect(res.status).toBe(502);
    expect(nodes[0].requests).toEqual([]);
  });

  it("keeps the retries short: at most a few seconds in total", () => {
    expect(RECEIVER_RETRIES).toBeGreaterThanOrEqual(2);
    expect(RECEIVER_RETRY_DELAY_MS * RECEIVER_RETRIES).toBeLessThanOrEqual(8000);
  });

  it("says /health answered wrongly when muse-vm answers :8090 with a non-200", async () => {
    onLogin = (node) => {
      node.handler = async () => ({ status: 404 });
      queueMicrotask(() => node.up());
    };
    vi.useFakeTimers();
    const pending = get(gateway(), "/monitor/jobs");
    await vi.advanceTimersByTimeAsync(RECEIVER_RETRY_DELAY_MS * RECEIVER_RETRIES + 1000);
    const body = await (await pending).json();
    expect(body).toMatchObject({ error: "receiver_not_found", probes: [{ name: "muse-vm", result: "HTTP 404" }] });
    expect(body.message).toContain("/health");
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
  it("says the auth key was not accepted, and from which secret, when the node still asks for login", async () => {
    vi.useFakeTimers();
    onLogin = (node) => queueMicrotask(() => {
      node.callbacks!.notifyState("NeedsLogin");
      node.callbacks!.notifyBrowseToURL("https://login.tailscale.com/a/abc123");
    });
    const gw = gateway({ TS_AUTHKEY: "expired-key", TS_API_KEY: "receiver-key-secret" });
    const pending = get(gw, "/monitor/jobs");
    await vi.advanceTimersByTimeAsync(60_000);
    const res = await pending;
    expect(res.status).toBe(502);
    const body = await res.json();
    expect(body).toMatchObject({ error: "tailnet_unavailable" });
    expect(body.message).toContain("the auth key from TS_AUTHKEY was not accepted");
    expect(body.message).toContain("https://login.tailscale.com/a/abc123");
    expect(body.message).not.toContain("expired-key");
    expect(nodes[0].login).toHaveBeenCalledWith("expired-key");
    // REQ-SEC-055: once the attempt has closed, its URL is no longer shown.
    // The /status read drives a fresh attempt (REQ-SEC-053/054); the URL it
    // offers is the one shown while that attempt is open.
    const status = await (await get(gw, "/status")).json();
    expect(status).toMatchObject({ loginUrl: null, authKeyConfigured: true, authKeySource: "TS_AUTHKEY" });
    await vi.advanceTimersByTimeAsync(1);
    expect(nodes[0].login).toHaveBeenCalledTimes(2);
    const status2 = await (await get(gw, "/status")).json();
    expect(status2).toMatchObject({ loginUrl: "https://login.tailscale.com/a/abc123" });
  });

  it("uses TS_AUTHKEY as the auth key instead of asking for interactive login", async () => {
    const gw = gateway({ TS_AUTHKEY: "tskey-auth-shared", TS_API_KEY: "receiver-key" });
    const res = await get(gw, "/monitor/jobs");
    expect(res.status).toBe(200);
    expect(nodes[0].config).toMatchObject({ authKey: "tskey-auth-shared" });
    expect(nodes[0].login).toHaveBeenCalledWith("tskey-auth-shared");
    expect(nodes[0].requests[1].headers).toEqual([["Authorization", "Bearer receiver-key"]]);
    expect(await (await get(gw, "/status")).json()).toMatchObject({ authKeyConfigured: true, authKeySource: "TS_AUTHKEY", loginUrl: null });
  });

  it("reports authKeyConfigured from TS_AUTHKEY only: TS_API_KEY alone does not count as a join key", async () => {
    expect(await (await get(gateway({ TS_AUTHKEY: "k" }), "/status")).json()).toMatchObject({ authKeyConfigured: true, authKeySource: "TS_AUTHKEY" });
    expect(await (await get(gateway({ TS_API_KEY: "k" }), "/status")).json()).toMatchObject({ authKeyConfigured: false, authKeySource: null });
    expect(await (await get(gateway({ TS_AUTHKEY: "k", TS_API_KEY: "r" }), "/status")).json()).toMatchObject({ authKeyConfigured: true, authKeySource: "TS_AUTHKEY" });
    expect(await (await get(gateway({ TS_API_KEY: "" }), "/status")).json()).toMatchObject({ authKeyConfigured: false, authKeySource: null });
    expect(await (await get(gateway({}), "/status")).json()).toMatchObject({ authKeyConfigured: false, authKeySource: null });
  });

  it("keeps answering tailnet_unavailable while the node is not Running, and works once it is", async () => {
    vi.useFakeTimers();
    onLogin = () => {};
    const gw = gateway();
    const first = get(gw, "/monitor/jobs");
    await vi.advanceTimersByTimeAsync(60_000);
    expect(await (await first).json()).toMatchObject({ error: "tailnet_unavailable", message: expect.stringContaining("auth key from: TS_AUTHKEY") });

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

describe("GET /public-status (for /health, no secrets)", () => {
  it("starts the node in the background, so the state can be checked without a key", async () => {
    const gw = gateway({ TS_AUTHKEY: "join-key", TS_API_KEY: "k" });
    const first = await (await get(gw, "/public-status")).json();
    expect(first).toMatchObject({ authKeySource: "TS_AUTHKEY", receiverKeySource: "TS_API_KEY", loginPending: false });
    await new Promise((r) => setTimeout(r, 0));
    expect(nodes).toHaveLength(1);
    expect(await (await get(gw, "/public-status")).json()).toMatchObject({ node: "Running", receiverCandidates: 1 });
    expect(nodes).toHaveLength(1);
  });

  it("after start: Running, the node's own IP (REQ-SEC-043), and whether muse-vm was found — never the receiver's IP, login URL or key values", async () => {
    const gw = gateway();
    await get(gw, "/monitor/jobs");
    const text = await (await get(gw, "/public-status")).text();
    const { bootLog, ...rest } = JSON.parse(text) as Record<string, unknown>;
    expect(rest).toEqual({
      node: "Running", ip: "100.99.0.5", authKeySource: "TS_AUTHKEY", receiverKeySource: "TS_API_KEY", loginPending: false, receiverCandidates: 1, receiverResolved: true,
      receiverPort: 8090, receiverProbes: [{ name: "muse-vm", result: "ok" }], lastError: null,
    });
    // REQ-SEC-045: the recent boot attempts ride along (last 5).
    expect(bootLog).toHaveLength(1);
    expect((bootLog as Array<Record<string, unknown>>)[0]).toMatchObject({ kind: "start", origin: "fresh", login: "immediate", outcome: "running" });
    for (const secret of ["100.86.29.77", "tskey-auth-secret", "receiver-key-secret", "login.tailscale.com"]) expect(text).not.toContain(secret);
  });

  it("ip is null while the node has not joined (no self node in the netmap yet)", async () => {
    const gw = gateway({ TS_AUTHKEY: "join-key", TS_API_KEY: "k" });
    const first = await (await get(gw, "/public-status")).json();
    expect(first).toMatchObject({ node: "not-started", ip: null });
  });

  it("when Running but the receiver is not resolved yet, probes it in the background and shows why it failed", async () => {
    const gw = gateway();
    await get(gw, "/public-status");
    await new Promise((r) => setTimeout(r, 0));
    nodes[0].handler = async () => { throw new Error("dial tcp 100.86.29.77:8090: connection refused"); };
    await get(gw, "/public-status");
    await new Promise((r) => setTimeout(r, 10));
    const text = await (await get(gw, "/public-status")).text();
    expect(JSON.parse(text)).toMatchObject({ node: "Running", receiverCandidates: 1, receiverResolved: false, receiverProbes: [{ name: "muse-vm", result: "error: dial tcp x.x.x.x:8090: connection refused" }] });
    expect(text).not.toContain("100.86.29.77");
  });

  it("says a login is pending without showing the URL", async () => {
    vi.useFakeTimers();
    onLogin = (node) => queueMicrotask(() => { node.callbacks!.notifyState("NeedsLogin"); node.callbacks!.notifyBrowseToURL("https://login.tailscale.com/a/xyz"); });
    const gw = gateway({ TS_API_KEY: "expired" });
    const pending = get(gw, "/monitor/jobs");
    await vi.advanceTimersByTimeAsync(60_000);
    await pending;
    const text = await (await get(gw, "/public-status")).text();
    expect(JSON.parse(text)).toMatchObject({ node: "NeedsLogin", loginPending: true, receiverCandidates: 0 });
    expect(text).not.toContain("login.tailscale.com");
  });

  it("shows the failure reason as a sanitized summary: no URLs, IPs or key values (REQ-SEC-031)", async () => {
    onLogin = (node) => queueMicrotask(() => node.callbacks!.notifyPanicRecover("Tailscale could not start: Get https://login.tailscale.com/a/xyz via 100.86.29.77 with tskey-auth-secret / receiver-key-secret"));
    const gw = gateway();
    await get(gw, "/monitor/jobs");
    const body = await (await get(gw, "/public-status")).json();
    expect(body.lastError).toContain("Tailscale could not start");
    for (const secret of ["login.tailscale.com", "100.86.29.77", "tskey-auth-secret", "receiver-key-secret"]) expect(body.lastError).not.toContain(secret);
  });

  it("caps the public failure summary at 120 characters (REQ-SEC-031)", async () => {
    onLogin = (node) => queueMicrotask(() => node.callbacks!.notifyPanicRecover("x".repeat(300)));
    const gw = gateway();
    await get(gw, "/monitor/jobs");
    const body = await (await get(gw, "/public-status")).json();
    expect(body.lastError.length).toBeLessThanOrEqual(121);
  });
});

describe("GET /status", () => {
  it("before any request: not-started, and the read drives a background start (REQ-SEC-053)", async () => {
    const gw = gateway();
    expect(await (await get(gw, "/status")).json()).toMatchObject({
      node: "not-started", lastStatus: "not-started", lastError: null, loginUrl: null, authKeyConfigured: true, authKeySource: "TS_AUTHKEY",
    });
    await new Promise((r) => setTimeout(r, 0));
    expect(nodes).toHaveLength(1);
    expect(await (await get(gw, "/status")).json()).toMatchObject({ node: "Running" });
    expect(nodes).toHaveLength(1);
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
    expect(text).not.toContain("receiver-key-secret");
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

    const next = gateway(ENV, makeCtx({ "ts-state": store.stored.get("ts-state"), "ts-state-epoch": 1 }).ctx);
    onStart = (node) => queueMicrotask(() => node.up());
    await get(next, "/monitor/jobs");
    expect(nodes[1].config.stateStorage.getState("_current-profile")).toBe("profile-1");
    expect(nodes[1].config.stateStorage.getState("missing")).toBe("");
  });

  it("with persisted state, resumes from the state: no auth key is passed and login is not called", async () => {
    const gw = gateway(ENV, makeCtx({ "ts-state": { "_current-profile": "profile-1" }, "ts-state-epoch": 1 }).ctx);
    onStart = (node) => queueMicrotask(() => node.up());
    const res = await get(gw, "/monitor/jobs");
    expect(res.status).toBe(200);
    expect(nodes[0].config.authKey).toBeUndefined();
    expect(nodes[0].login).not.toHaveBeenCalled();
  });

  it("with persisted state that asks for login (NeedsLogin), uses the key for exactly one deferred login", async () => {
    const gw = gateway(ENV, makeCtx({ "ts-state": { "_current-profile": "profile-1" }, "ts-state-epoch": 1 }).ctx);
    onStart = (node) => queueMicrotask(() => node.callbacks!.notifyState("NeedsLogin"));
    const res = await get(gw, "/monitor/jobs");
    expect(res.status).toBe(200);
    expect(nodes[0].login).toHaveBeenCalledTimes(1);
    expect(nodes[0].login).toHaveBeenCalledWith("tskey-auth-secret");
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

describe("DO recovery (SPEC REQ-SEC-026/027/028)", () => {
  const SEEDED = { "ts-state": { "_current-profile": "profile-1", "profile-1": "{}", "_machinekey": "mk" }, "ts-state-epoch": 1 };

  it("discards a persisted state whose node never leaves NoState, and rejoins with the auth key", async () => {
    vi.useFakeTimers();
    const store = makeCtx(SEEDED);
    const gw = gateway(ENV, store.ctx);
    let starts = 0;
    onStart = (node) => { starts++; if (starts === 1) queueMicrotask(() => node.callbacks!.notifyState("NoState")); };
    const pending = get(gw, "/monitor/jobs");
    await vi.advanceTimersByTimeAsync(60_000);
    const res = await pending;
    expect(res.status).toBe(200);
    expect(nodes).toHaveLength(2);
    // The fresh node is a first join again: the key is passed and login is called with it.
    expect(nodes[1].config.authKey).toBe("tskey-auth-secret");
    expect(nodes[1].login).toHaveBeenCalledWith("tskey-auth-secret");
    // The discard is recorded, without any secret value.
    const status = await (await get(gw, "/status")).json();
    expect(status.lastError).toContain("discarded the persisted node state");
    expect(status.lastError).not.toContain("tskey-auth-secret");
  });

  it("recovers at most once: a fresh node that also wedges is an error, not another discard", async () => {
    vi.useFakeTimers();
    const store = makeCtx(SEEDED);
    const gw = gateway(ENV, store.ctx);
    onStart = (node) => queueMicrotask(() => node.callbacks!.notifyState("NoState"));
    onLogin = () => {};
    const pending = get(gw, "/monitor/jobs");
    await vi.advanceTimersByTimeAsync(60_000);
    await vi.advanceTimersByTimeAsync(60_000);
    const res = await pending;
    expect(res.status).toBe(502);
    expect(await res.json()).toMatchObject({ error: "tailnet_unavailable" });
    expect(nodes).toHaveLength(2);
  });

  it("does not discard state when the node asks for login instead (browse URL present)", async () => {
    vi.useFakeTimers();
    const store = makeCtx(SEEDED);
    const gw = gateway(ENV, store.ctx);
    onStart = (node) => queueMicrotask(() => node.callbacks!.notifyState("NeedsLogin"));
    onLogin = (node) => queueMicrotask(() => node.callbacks!.notifyBrowseToURL("https://login.tailscale.com/a/abc123"));
    const pending = get(gw, "/monitor/jobs");
    await vi.advanceTimersByTimeAsync(60_000);
    const res = await pending;
    expect(res.status).toBe(502);
    const body = await res.json();
    expect(body.message).toContain("the auth key from TS_AUTHKEY was not accepted");
    expect(nodes).toHaveLength(1);
    expect(store.stored.get("ts-state")).toEqual(SEEDED["ts-state"]);
  });
});

describe("state integrity at load (SPEC REQ-SEC-033)", () => {
  const BAD_STATES: Array<[string, unknown]> = [
    ["the stored value is not an object", "garbage"],
    ["the stored value is an array", ["_machinekey", "mk"]],
    ["a value is not a string", { "_machinekey": 42 }],
  ];

  for (const [name, bad] of BAD_STATES) {
    it(`discards the state before starting the node when ${name}, and joins fresh`, async () => {
      const store = makeCtx({ "ts-state": bad, "ts-state-epoch": 1 });
      const gw = gateway(ENV, store.ctx);
      const res = await get(gw, "/monitor/jobs");
      expect(res.status).toBe(200);
      expect(nodes).toHaveLength(1);
      // A first join, not a resume: the key is passed and login is called.
      expect(nodes[0].config.authKey).toBe("tskey-auth-secret");
      expect(nodes[0].login).toHaveBeenCalledWith("tskey-auth-secret");
      const status = await (await get(gw, "/status")).json();
      expect(status.lastError).toContain("discarded the persisted node state at load");
    });
  }

  it("keeps a structurally intact state and resumes from it", async () => {
    const store = makeCtx({ "ts-state": { "_current-profile": "profile-1", "profile-1": "{}", "_machinekey": "mk" }, "ts-state-epoch": 1 });
    const gw = gateway(ENV, store.ctx);
    onStart = (node) => queueMicrotask(() => node.up());
    const res = await get(gw, "/monitor/jobs");
    expect(res.status).toBe(200);
    expect(nodes[0].config.authKey).toBeUndefined();
    expect(nodes[0].login).not.toHaveBeenCalled();
  });
});

describe("one-time state reset at load (revision 17 recovery)", () => {
  const INTACT = { "_current-profile": "profile-1", "profile-1": "{}", "_machinekey": "mk" };

  it("discards a state stored before the reset epoch, joins fresh, and records the epoch", async () => {
    const store = makeCtx({ "ts-state": INTACT });
    const gw = gateway(ENV, store.ctx);
    const res = await get(gw, "/monitor/jobs");
    expect(res.status).toBe(200);
    expect(nodes).toHaveLength(1);
    expect(nodes[0].config.authKey).toBe("tskey-auth-secret");
    expect(nodes[0].login).toHaveBeenCalledWith("tskey-auth-secret");
    expect(store.stored.get("ts-state-epoch")).toBe(1);
    const status = await (await get(gw, "/status")).json();
    expect(status.lastError).toContain("one-time reset");
  });

  it("keeps a state stored at the reset epoch and resumes from it", async () => {
    const store = makeCtx({ "ts-state": INTACT, "ts-state-epoch": 1 });
    const gw = gateway(ENV, store.ctx);
    onStart = (node) => queueMicrotask(() => node.up());
    const res = await get(gw, "/monitor/jobs");
    expect(res.status).toBe(200);
    expect(nodes[0].config.authKey).toBeUndefined();
    expect(nodes[0].login).not.toHaveBeenCalled();
  });
});

describe("live WebSocket (REQ-SEC-037)", () => {
  const RealResponse = globalThis.Response;
  class WsResponse extends RealResponse {
    webSocket?: unknown;
    constructor(body?: BodyInit | null, init?: ResponseInit & { webSocket?: unknown }) {
      super(body, init?.status === 101 ? { ...init, status: 200 } : init);
      if (init?.status === 101) {
        Object.defineProperty(this, "status", { value: 101 });
        this.webSocket = init.webSocket;
      }
    }
  }
  beforeEach(() => {
    (globalThis as Record<string, unknown>).WebSocketPair = FakeWebSocketPair;
    (globalThis as Record<string, unknown>).Response = WsResponse;
  });
  afterEach(() => {
    (globalThis as Record<string, unknown>).Response = RealResponse;
    delete (globalThis as Record<string, unknown>).WebSocketPair;
  });
  const liveReq = () => new Request("http://do/live", { headers: { Upgrade: "websocket" } });

  it("rejects a non-upgrade request with 426", async () => {
    const gw = gateway(ENV, makeCtx({ "ts-state-epoch": 1 }).ctx);
    const res = await gw.fetch(new Request("http://do/live"));
    expect(res.status).toBe(426);
  });

  it("accepts the socket, returns 101 and arms the alarm", async () => {
    const store = makeCtx({ "ts-state-epoch": 1 });
    const gw = gateway(ENV, store.ctx);
    const res = await gw.fetch(liveReq());
    expect(res.status).toBe(101);
    expect(store.sockets).toHaveLength(1);
    expect(store.alarmAt()).not.toBeNull();
  });

  it("on alarm, broadcasts every section to the connected sockets and re-arms", async () => {
    const store = makeCtx({ "ts-state-epoch": 1 });
    const gw = gateway(ENV, store.ctx);
    await get(gw, "/monitor/jobs"); // bring the node up
    await gw.fetch(liveReq());
    const sock = store.sockets[0];
    // The connect itself kicks a sweep; wait for it to finish before measuring the alarm sweep.
    await vi.waitFor(() => expect(sock.sent.length).toBe(16));
    sock.sent.length = 0;
    const before = store.alarmAt();
    await gw.alarm();
    const frames = sock.sent.map((s) => JSON.parse(s) as { type: string; section?: string; status?: number });
    expect(frames).toHaveLength(16);
    expect(frames.every((f) => f.type === "section" && f.status === 200)).toBe(true);
    expect(new Set(frames.map((f) => f.section))).toEqual(new Set(["status", "diag", "jobs", "pkgs", "vm", "procs", "ports", "git", "recent", "pending", "execlog", "sdkhealth", "sdkprofiles", "sdksessions", "sdkts", "hooks"]));
    expect(store.alarmAt()).not.toBeNull();
    expect(store.alarmAt()).not.toBe(before);
  });

  it("on alarm with no sockets connected, does not re-arm and does not start the node", async () => {
    const store = makeCtx({ "ts-state-epoch": 1 });
    const gw = gateway(ENV, store.ctx);
    await gw.alarm();
    expect(store.alarmAt()).toBeNull();
    expect(nodes).toHaveLength(0);
  });

  it("while the node is not Running, broadcasts a node frame instead of sections", async () => {
    const store = makeCtx({ "ts-state-epoch": 1 });
    const gw = gateway(ENV, store.ctx);
    await gw.fetch(liveReq());
    const sock = store.sockets[0];
    const frames = sock.sent.map((s) => JSON.parse(s) as { type: string; node?: string });
    expect(frames.length).toBeGreaterThan(0);
    expect(frames[0]).toMatchObject({ type: "node", node: "not-started" });
    expect(frames.every((f) => f.type === "node")).toBe(true);
  });
});

describe("POST /hmac-claim (HMAC replay prevention, SPEC REQ-SEC-011/012)", () => {
  const claim = (gw: MonitorGateway, sig: string, ts: number) =>
    gw.fetch(new Request("http://do/hmac-claim", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ sig, ts }) }));
  const SIG_A = "a".repeat(64);
  const SIG_B = "b".repeat(64);

  it("accepts a signature once and refuses the same signature again", async () => {
    const gw = gateway();
    expect(await (await claim(gw, SIG_A, 1_000)).json()).toEqual({ ok: true });
    expect(await (await claim(gw, SIG_A, 1_000)).json()).toEqual({ ok: false });
    expect(await (await claim(gw, SIG_B, 1_000)).json()).toEqual({ ok: true });
  });

  it("keeps the claims across instances through DO storage", async () => {
    const store = makeCtx();
    expect(await (await claim(gateway(ENV, store.ctx), SIG_A, 1_000)).json()).toEqual({ ok: true });
    await Promise.all(store.waits);
    expect(await (await claim(gateway(ENV, store.ctx), SIG_A, 1_001)).json()).toEqual({ ok: false });
  });

  it("prunes claims older than twice the HMAC window (600 s), so an old signature can be claimed again", async () => {
    const gw = gateway();
    expect(await (await claim(gw, SIG_A, 1_000)).json()).toEqual({ ok: true });
    // A claim at ts=1601 prunes entries older than 1001; SIG_A (ts 1000) is gone afterwards.
    expect(await (await claim(gw, SIG_B, 1_601)).json()).toEqual({ ok: true });
    expect(await (await claim(gw, SIG_A, 1_601)).json()).toEqual({ ok: true });
  });

  it("rejects malformed claims with 400", async () => {
    const gw = gateway();
    for (const body of [{ sig: "xyz", ts: 1_000 }, { sig: SIG_A, ts: "soon" }, { sig: SIG_A }, {}]) {
      const res = await gw.fetch(new Request("http://do/hmac-claim", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }));
      expect(res.status).toBe(400);
    }
    expect((await gw.fetch(new Request("http://do/hmac-claim"))).status).toBe(404);
  });
});

describe("boot log (SPEC REQ-SEC-044/045)", () => {
  const flush = () => new Promise((r) => setTimeout(r, 0));
  type Rec = Record<string, unknown>;
  const storedLog = (store: ReturnType<typeof makeCtx>) => store.stored.get("ts-boot-log") as Rec[];

  it("records a fresh start: origin, immediate login, transitions and the running outcome, persisted to storage", async () => {
    const store = makeCtx();
    const gw = gateway(ENV, store.ctx);
    await get(gw, "/monitor/jobs");
    await flush();
    const log = storedLog(store);
    expect(log).toHaveLength(1);
    expect(log[0]).toMatchObject({ kind: "start", origin: "fresh", login: "immediate", outcome: "running", browseUrlOffered: false });
    expect((log[0].transitions as Array<{ state: string }>).map((t) => t.state)).toContain("Running");
    expect(typeof log[0].startedAt).toBe("string");
  });

  it("records a resumed start with a deferred login", async () => {
    const store = makeCtx({ "ts-state": { "_current-profile": "profile-1" }, "ts-state-epoch": 1 });
    const gw = gateway(ENV, store.ctx);
    onStart = (node) => queueMicrotask(() => { node.callbacks!.notifyState("NeedsLogin"); node.up(); });
    await get(gw, "/monitor/jobs");
    await flush();
    expect(storedLog(store).at(-1)).toMatchObject({ kind: "start", origin: "persisted", login: "deferred", outcome: "running" });
  });

  it("records a NeedsLogin stall as a timeout with no browse URL offered (the shape of the current live stall)", async () => {
    vi.useFakeTimers();
    const store = makeCtx();
    const gw = gateway(ENV, store.ctx);
    onLogin = (node) => queueMicrotask(() => node.callbacks!.notifyState("NeedsLogin"));
    const pending = get(gw, "/monitor/jobs");
    await vi.advanceTimersByTimeAsync(60_000);
    await pending;
    const last = storedLog(store).at(-1)!;
    expect(last).toMatchObject({ kind: "start", outcome: "timeout", browseUrlOffered: false });
    expect((last.transitions as Array<{ state: string }>).map((t) => t.state)).toEqual(["NeedsLogin"]);
  });

  it("closes an unfinished record as interrupted on the next load", async () => {
    const open = { kind: "start", startedAt: "2026-11-18T00:00:00.000Z", origin: "fresh", login: "immediate", transitions: [{ state: "NeedsLogin", atMs: 1200 }], browseUrlOffered: false, outcome: null, detail: null };
    const store = makeCtx({ "ts-boot-log": [open], "ts-state-epoch": 1 });
    const gw = gateway(ENV, store.ctx);
    await get(gw, "/monitor/jobs");
    await flush();
    const log = storedLog(store);
    expect(log[0].outcome).toBe("interrupted");
    expect(log.at(-1)).toMatchObject({ kind: "start", outcome: "running" });
  });

  it("records the recovery discard as its own entry with the reason", async () => {
    vi.useFakeTimers();
    const store = makeCtx({ "ts-state": { "_current-profile": "profile-1", "profile-1": "{}", "_machinekey": "mk" }, "ts-state-epoch": 1 });
    const gw = gateway(ENV, store.ctx);
    let starts = 0;
    onStart = (node) => { starts++; if (starts === 1) queueMicrotask(() => node.callbacks!.notifyState("NoState")); };
    const pending = get(gw, "/monitor/jobs");
    await vi.advanceTimersByTimeAsync(60_000);
    await pending;
    expect(storedLog(store).some((e) => e.kind === "state_discarded" && e.reason === "recovery")).toBe(true);
  });

  it("a failing boot-log write never blocks the node start", async () => {
    const store = makeCtx();
    const storage = store.ctx.storage as unknown as { put: (k: string, v: unknown) => Promise<void> };
    const realPut = storage.put.bind(store.ctx.storage);
    storage.put = async (k: string, v: unknown) => { if (k === "ts-boot-log") throw new Error("storage full"); return realPut(k, v); };
    const gw = gateway(ENV, store.ctx);
    const res = await get(gw, "/monitor/jobs");
    expect(res.status).toBe(200);
  });

  it("caps the log at 50 entries, dropping the oldest", async () => {
    const seeded = Array.from({ length: 50 }, (_, i) => ({ kind: "start", startedAt: `2026-11-01T00:00:${String(i).padStart(2, "0")}.000Z`, origin: "fresh", login: "immediate", transitions: [], browseUrlOffered: false, outcome: "timeout", detail: null }));
    const store = makeCtx({ "ts-boot-log": seeded, "ts-state-epoch": 1 });
    const gw = gateway(ENV, store.ctx);
    await get(gw, "/monitor/jobs");
    await flush();
    const log = storedLog(store);
    expect(log.length).toBeLessThanOrEqual(50);
    expect(log.at(-1)).toMatchObject({ outcome: "running" });
  });

  it("never writes key values or login URLs into the log", async () => {
    onLogin = (node) => queueMicrotask(() => node.callbacks!.notifyPanicRecover("start failed via https://login.tailscale.com/a/xyz with tskey-auth-secret"));
    const store = makeCtx();
    const gw = gateway(ENV, store.ctx);
    await get(gw, "/monitor/jobs");
    await flush();
    const text = JSON.stringify(store.stored.get("ts-boot-log"));
    for (const secret of ["tskey-auth-secret", "receiver-key-secret", "login.tailscale.com"]) expect(text).not.toContain(secret);
    expect(storedLog(store).at(-1)).toMatchObject({ kind: "start", outcome: "error" });
  });

  it("exposes the last 5 entries on /public-status and the last 20 on /status", async () => {
    const seeded = Array.from({ length: 25 }, (_, i) => ({ kind: "start", startedAt: `2026-11-01T00:${String(i).padStart(2, "0")}:00.000Z`, origin: "fresh", login: "immediate", transitions: [], browseUrlOffered: false, outcome: "timeout", detail: null }));
    const pubGw = gateway(ENV, makeCtx({ "ts-boot-log": seeded, "ts-state-epoch": 1 }).ctx);
    const pub = await (await get(pubGw, "/public-status")).json();
    expect(pub.bootLog).toHaveLength(5);

    const stGw = gateway(ENV, makeCtx({ "ts-boot-log": seeded, "ts-state-epoch": 1 }).ctx);
    const st = await (await get(stGw, "/status")).json();
    expect(st.bootLog).toHaveLength(20);
    expect(st.bootLog[0].startedAt).toBe(seeded[5].startedAt);
  });
});

describe("node check on /status and /node-check (SPEC v20, REQ-SEC-053..056)", () => {
  const FIRST_URL = "https://login.tailscale.com/a/first";
  /** A node whose login is never approved: NeedsLogin with a browse URL, then the attempt times out. */
  async function wedged() {
    vi.useFakeTimers();
    onLogin = (node) => queueMicrotask(() => {
      node.callbacks!.notifyState("NeedsLogin");
      node.callbacks!.notifyBrowseToURL(FIRST_URL);
    });
    const gw = gateway();
    const pending = get(gw, "/monitor/jobs");
    await vi.advanceTimersByTimeAsync(60_000);
    expect((await pending).status).toBe(502);
    expect(nodes[0].login).toHaveBeenCalledTimes(1);
    return gw;
  }
  const startRecords = async (gw: MonitorGateway) =>
    ((await (await get(gw, "/status")).json()).bootLog as Array<Record<string, unknown>>).filter((r) => r.kind === "start");

  it("re-drives on /status after a timed-out attempt: login is called again on the same node and a new record opens", async () => {
    const gw = await wedged();
    const st = await (await get(gw, "/status")).json();
    expect(st.loginUrl).toBeNull();
    await vi.advanceTimersByTimeAsync(1);
    expect(nodes).toHaveLength(1);
    expect(nodes[0].login).toHaveBeenCalledTimes(2);
    expect(nodes[0].login).toHaveBeenLastCalledWith("tskey-auth-secret");
    const records = await startRecords(gw);
    expect(records).toHaveLength(2);
    expect(records[0]).toMatchObject({ origin: "fresh", login: "immediate", outcome: "timeout" });
    expect(records[1]).toMatchObject({ origin: "persisted", login: "deferred", outcome: null });
  });

  it("does not stack while an attempt is open: repeated /status reads add neither a login call nor a record", async () => {
    const gw = await wedged();
    await get(gw, "/status");
    await vi.advanceTimersByTimeAsync(1);
    await get(gw, "/status");
    await get(gw, "/status");
    await vi.advanceTimersByTimeAsync(1);
    expect(nodes[0].login).toHaveBeenCalledTimes(2);
    expect(await startRecords(gw)).toHaveLength(2);
  });

  it("keeps driving on later reads: when the re-drive also times out, the next /status opens another attempt", async () => {
    const gw = await wedged();
    await get(gw, "/status");
    await vi.advanceTimersByTimeAsync(60_000);
    await get(gw, "/status");
    await vi.advanceTimersByTimeAsync(1);
    expect(nodes[0].login).toHaveBeenCalledTimes(3);
    const records = await startRecords(gw);
    expect(records).toHaveLength(3);
    expect(records[1]).toMatchObject({ outcome: "timeout" });
    expect(records[2]).toMatchObject({ outcome: null });
  });

  it("shows the URL only while its attempt is open, and does not adopt a URL offered with no attempt open (REQ-SEC-055)", async () => {
    vi.useFakeTimers();
    onLogin = (node) => queueMicrotask(() => {
      node.callbacks!.notifyState("NeedsLogin");
      node.callbacks!.notifyBrowseToURL(FIRST_URL);
    });
    const gw = gateway();
    const pending = get(gw, "/monitor/jobs");
    await vi.advanceTimersByTimeAsync(1);
    // The first attempt is open and has offered its URL: it is shown.
    expect((await (await get(gw, "/status")).json()).loginUrl).toBe(FIRST_URL);
    await vi.advanceTimersByTimeAsync(60_000);
    await pending;
    // A URL arriving after the attempt closed must not be adopted.
    onLogin = () => {};
    nodes[0].callbacks!.notifyBrowseToURL("https://login.tailscale.com/a/late");
    const st = await (await get(gw, "/status")).json();
    expect(st.loginUrl).toBeNull();
    await vi.advanceTimersByTimeAsync(1);
    expect((await (await get(gw, "/status")).json()).loginUrl).toBeNull();
  });

  // 2026-11-18 本番: TS_AUTHKEY を付けた login() は NeedsLogin のまま URL を出さず、毎回60秒で時間切れになった
  // (/health の bootLog で browseUrlOffered: false が続いた)。鍵が受け付けられないと、鍵付きの再駆動では
  // 何度押してもログインのリンクが出ない。鍵を付けた前の試行が URL も Running も無く閉じたなら、
  // 再確認では鍵を付けずに login() を呼び、対話のログイン URL を出させる。
  describe("when the auth key is not accepted (NeedsLogin, no URL)", () => {
    const KEYLESS_URL = "https://login.tailscale.com/a/keyless";
    async function keyRejected() {
      vi.useFakeTimers();
      onLogin = (node, authKey) => queueMicrotask(() => {
        node.callbacks!.notifyState("NeedsLogin");
        if (!authKey) node.callbacks!.notifyBrowseToURL(KEYLESS_URL);
      });
      const gw = gateway();
      const pending = get(gw, "/monitor/jobs");
      await vi.advanceTimersByTimeAsync(60_000);
      expect((await pending).status).toBe(502);
      return gw;
    }

    it("POST /node-check re-drives WITHOUT the key, so a login URL is offered and shown", async () => {
      const gw = await keyRejected();
      expect(nodes[0].login).toHaveBeenLastCalledWith("tskey-auth-secret");
      const res = await gw.fetch(new Request("http://do/node-check", { method: "POST" }));
      expect(res.status).toBe(200);
      await vi.advanceTimersByTimeAsync(1);
      expect(nodes[0].login).toHaveBeenCalledTimes(2);
      expect(nodes[0].login.mock.calls[1][0]).toBeUndefined();
      const st = await (await get(gw, "/status")).json();
      expect(st.loginUrl).toBe(KEYLESS_URL);
      const records = (st.bootLog as Array<Record<string, unknown>>).filter((r) => r.kind === "start");
      expect(records.at(-1)).toMatchObject({ origin: "persisted", browseUrlOffered: true, outcome: null });
    });

    it("keeps using the key while the previous attempt did offer a URL (the key path is not dropped needlessly)", async () => {
      const gw = await wedgedWithUrl();
      await gw.fetch(new Request("http://do/node-check", { method: "POST" }));
      await vi.advanceTimersByTimeAsync(1);
      expect(nodes[0].login).toHaveBeenLastCalledWith("tskey-auth-secret");
    });
  });

  async function wedgedWithUrl() { return wedged(); }

  it("POST /node-check drives the check before answering, and returns the current state", async () => {
    const gw = await wedged();
    const res = await gw.fetch(new Request("http://do/node-check", { method: "POST" }));
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.node).toBe("NeedsLogin");
    expect(nodes[0].login).toHaveBeenCalledTimes(2);
    const records = (body.bootLog as Array<Record<string, unknown>>).filter((r) => r.kind === "start");
    expect(records).toHaveLength(2);
    expect(records[1]).toMatchObject({ origin: "persisted", login: "deferred", outcome: null });
  });

  it("drives nothing while the node is Running", async () => {
    const gw = gateway();
    await get(gw, "/monitor/jobs");
    expect(nodes[0].login).toHaveBeenCalledTimes(1);
    await get(gw, "/status");
    const res = await gw.fetch(new Request("http://do/node-check", { method: "POST" }));
    expect(res.status).toBe(200);
    await new Promise((r) => setTimeout(r, 0));
    expect(nodes[0].login).toHaveBeenCalledTimes(1);
    expect(await startRecords(gw)).toHaveLength(1);
  });
});
