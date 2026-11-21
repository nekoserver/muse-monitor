import { createHmac } from "node:crypto";
import { execFileSync } from "node:child_process";
import { runInNewContext } from "node:vm";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import worker from "../src/index";

// The set the DO accepts (src/do.ts SECTIONS); anything else is a 404 there.
const DO_SECTIONS = ["status", "diag", "jobs", "pkgs", "vm", "procs", "ports", "git", "recent", "pending", "execlog", "sdkhealth", "sdkprofiles", "sdksessions", "sdkts", "hooks"];

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
    TS_AUTHKEY: "tskey-auth-other",
    TS_API_KEY: "ts-key",
    MONITOR_HMAC_SECRET,
    MONITOR_GATEWAY: {
      idFromName: (name: string) => { ids.push(name); return name; },
      get: () => ({ fetch: async (url: string) => { calls.push(url); if (url.includes("hmac-claim")) return Response.json({ ok: true }); return Response.json({ from: "do", url }); } }),
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

afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks(); });

describe("open routes", () => {
  it("GET /health needs no key and shows the code revision, the deployed version and the node's public state", async () => {
    const { env, calls } = makeEnv();
    const publicState = { node: "Running", authKeySource: "TS_AUTHKEY", receiverKeySource: "TS_API_KEY", loginPending: false, receiverCandidates: 1, receiverResolved: true };
    (env as Record<string, unknown>).MONITOR_GATEWAY = {
      idFromName: (name: string) => name,
      get: () => ({ fetch: async (url: string) => { calls.push(url); return Response.json(publicState); } }),
    };
    (env as Record<string, unknown>).CF_VERSION_METADATA = { id: "ver-123", tag: "", timestamp: "2026-11-11T06:50:00Z" };
    const res = await worker.fetch(call("/health"), env);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      status: "ok", worker: "muse-monitor", revision: 36,
      version: { id: "ver-123", tag: "", timestamp: "2026-11-11T06:50:00Z" },
      node: publicState,
    });
    expect(calls).toEqual(["http://do/public-status"]);
  });

  it("GET /health still answers 200 when the DO fails or version metadata is missing", async () => {
    const { env } = makeEnv();
    (env as Record<string, unknown>).MONITOR_GATEWAY = { idFromName: (n: string) => n, get: () => ({ fetch: async () => { throw new Error("do down"); } }) };
    const res = await worker.fetch(call("/health"), env);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body).toMatchObject({ status: "ok", worker: "muse-monitor", revision: 36, version: null, node: { error: expect.stringContaining("do down") } });
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

describe("login cookie: keeps the authenticated state for 7 days, never the key", () => {
  const auth = { Authorization: `Bearer ${WORKER_API_KEY}` };
  const cookieOf = (res: Response) => (res.headers.get("Set-Cookie") ?? "").split(";")[0];

  it("a request with the key to /api/status sets an HttpOnly, Secure, SameSite=Strict cookie for 7 days that does not contain the key", async () => {
    const { env } = makeEnv();
    const res = await worker.fetch(call("/api/status", auth), env);
    expect(res.status).toBe(200);
    const setCookie = res.headers.get("Set-Cookie") ?? "";
    expect(setCookie).toMatch(/^mm_auth=\d+\.[0-9a-f]{64}; /);
    for (const attr of ["Path=/", "Max-Age=604800", "HttpOnly", "Secure", "SameSite=Strict"]) expect(setCookie).toContain(attr);
    expect(setCookie).not.toContain(WORKER_API_KEY);
    expect(await res.json()).toEqual({ from: "do", url: "http://do/status" });
  });

  it("the cookie alone opens /api/status and /api/monitor/*, without issuing a new cookie (7 days from login, not extended)", async () => {
    const { env, calls } = makeEnv();
    const cookie = cookieOf(await worker.fetch(call("/api/status", auth), env));
    for (const path of ["/api/status", "/api/monitor/jobs"]) {
      const res = await worker.fetch(call(path, { Cookie: `other=1; ${cookie}` }), env);
      expect(res.status, path).toBe(200);
      expect(res.headers.get("Set-Cookie"), path).toBeNull();
    }
    expect(calls).toEqual(["http://do/status", "http://do/status", "http://do/monitor/jobs"]);
  });

  it("withholds a result when its browser cookie expires during a direct data request", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-11-11T00:00:00Z"));
    const { env } = makeEnv();
    const cookie = cookieOf(await worker.fetch(call("/api/status", auth), env));
    (env as { MONITOR_GATEWAY: { get: () => unknown } }).MONITOR_GATEWAY.get = () => ({
      fetch: async () => {
        vi.setSystemTime(new Date("2026-11-18T00:00:00Z"));
        return Response.json({ output: "protected data" });
      },
    });
    const response = await worker.fetch(call("/api/monitor/jobs", { Cookie: cookie }), env);
    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({ error: "unauthorized" });
  });

  it("stops working after 7 days", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-11-11T00:00:00Z"));
    const { env } = makeEnv();
    const cookie = cookieOf(await worker.fetch(call("/api/status", auth), env));
    vi.setSystemTime(new Date("2026-11-17T23:59:00Z"));
    expect((await worker.fetch(call("/api/status", { Cookie: cookie }), env)).status).toBe(200);
    vi.setSystemTime(new Date("2026-11-18T00:00:01Z"));
    expect((await worker.fetch(call("/api/status", { Cookie: cookie }), env)).status).toBe(401);
  });

  it("rejects a tampered cookie, a stretched expiry, and a cookie made under another WORKER_API_KEY", async () => {
    const { env, calls } = makeEnv();
    const cookie = cookieOf(await worker.fetch(call("/api/status", auth), env));
    const [name, value] = cookie.split("=");
    const [exp, sig] = value.split(".");
    const bad = [
      `${name}=${exp}.${sig.slice(0, -1)}${sig.endsWith("0") ? "1" : "0"}`,
      `${name}=${Number(exp) + 86400 * 365}.${sig}`,
      `${name}=garbage`,
      `${name}=`,
    ];
    const other = makeEnv();
    (other.env as { WORKER_API_KEY: string }).WORKER_API_KEY = "another-worker-key-0000";
    calls.length = 0;
    for (const c of bad) expect((await worker.fetch(call("/api/monitor/jobs", { Cookie: c }), env)).status, c).toBe(401);
    expect((await worker.fetch(call("/api/monitor/jobs", { Cookie: cookie }), other.env)).status).toBe(401);
    expect(calls).toEqual([]);
  });

  it("a wrong key sets no cookie", async () => {
    const { env } = makeEnv();
    const res = await worker.fetch(call("/api/status", { Authorization: "Bearer nope" }), env);
    expect(res.status).toBe(401);
    expect(res.headers.get("Set-Cookie")).toBeNull();
  });

  it("POST /api/logout clears the cookie", async () => {
    const { env } = makeEnv();
    const res = await worker.fetch(call("/api/logout", {}, "POST"), env);
    expect(res.status).toBe(200);
    const setCookie = res.headers.get("Set-Cookie") ?? "";
    expect(setCookie).toMatch(/^mm_auth=; /);
    expect(setCookie).toContain("Max-Age=0");
  });

  it("the dashboard sends no Authorization header when the key box is empty (the cookie is used), and has a logout button; the key is never stored in the browser", async () => {
    const { env } = makeEnv();
    const html = await (await worker.fetch(call("/"), env)).text();
    expect(html).toContain('id="authbtn"');
    expect(html).toContain("/api/logout");
    expect(html).toMatch(/function headers\(\) \{[^}]*key\(\) \?/);
    expect(html).not.toMatch(/localStorage|sessionStorage/);
  });
});

describe("dashboard layout", () => {
  it("defaults to the side panel, saves only a supported layout and follows the current section", async () => {
    const { env } = makeEnv();
    const html = await (await worker.fetch(call("/"), env)).text();
    const script = html.match(/<script>([\s\S]*?)<\/script>/)![1]
      .split("\n  render();\n  loadLoginState();")[0];
    const tops = [10, 600];
    const link = (name: string) => ({
      dataset: { section: name }, setAttribute: vi.fn(), removeAttribute: vi.fn(),
    });
    const links = [link("status"), link("jobs")];
    const writes: string[] = [];
    function page(cookie: string) {
      return runInNewContext(script + "\n({ getView: () => view, setView, updatePanelSection })", {
        setInterval: () => {},
        window: { addEventListener: () => {}, innerHeight: 400, scrollY: 0 },
        document: {
          get cookie() { return cookie; },
          set cookie(value: string) { writes.push(value); },
          addEventListener: () => {},
          documentElement: { scrollHeight: 1200 },
          getElementById: () => ({}),
          querySelectorAll: (selector: string) => {
            if (selector === "#view .side a[data-section]") return links;
            if (selector === "#view .main > .card") return tops.map((top, i) => ({
              id: i === 0 ? "sec-status" : "sec-jobs", getBoundingClientRect: () => ({ top }),
            }));
            return [];
          },
          createElement: () => ({ innerHTML: "" }),
        },
      });
    }
    const active = page("unrelated=1");
    expect(active.getView()).toBe("panel");
    expect(writes.at(-1)).toMatch(/^mm_view=panel;.*SameSite=Strict/);
    active.updatePanelSection();
    expect(links[0].setAttribute).toHaveBeenCalledWith("aria-current", "location");
    tops.splice(0, 2, -550, 12);
    active.updatePanelSection();
    expect(links[0].removeAttribute).toHaveBeenCalledWith("aria-current");
    expect(links[1].setAttribute).toHaveBeenCalledWith("aria-current", "location");
    active.setView("tree");
    expect(writes.at(-1)).toMatch(/^mm_view=tree;/);
    expect(page(writes.at(-1)!.split(";")[0]).getView()).toBe("tree");
    active.setView("invalid");
    expect(active.getView()).toBe("tree");
    expect(page("mm_view=invalid").getView()).toBe("panel");
  });
});

it("colors OK, only zero FAIL counts and exact installed-version matches", async () => {
  const { env } = makeEnv();
  const html = await (await worker.fetch(call("/"), env)).text();
  const script = html.match(/<script>([\s\S]*?)<\/script>/)![1]
    .split("\n  render();\n  loadLoginState();")[0];
  const { formatOutput } = runInNewContext(script + "\n({ formatOutput })", {
    setInterval: () => {}, window: {},
    document: {
      createElement: () => ({
        set textContent(text: string) { this.innerHTML = text.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;"); },
        innerHTML: "",
      }),
    },
  });
  const diag = formatOutput("diag", "OK test / FAIL 0 / FAIL 1\n<script>");
  expect(diag).toContain('<span class="is-ok">OK</span>');
  expect(diag).toContain('FAIL <span class="is-ok">0</span>');
  expect(diag).toContain("FAIL 1");
  expect(diag).toContain("&lt;script&gt;");
  const packages = formatOutput("pkgs", "curl\t1.2\t1.2\nruby\t3.1\t3.2\nlocal\t1.2\t未確認");
  expect(packages).toContain('curl\t<span class="is-ok">1.2</span>\t1.2');
  expect(packages).toContain("ruby\t3.1\t3.2");
  expect(packages).toContain("local\t1.2\t未確認");
  expect(formatOutput("pkgs", "== Nix profile ==\ncurl-1.2")).toContain("最新版候補: 未確認");
});

describe("HMAC routes", () => {
  it("accept a fresh signature for the same section", async () => {
    const { env, calls } = makeEnv();
    expect((await worker.fetch(call("/api/hmac/status", sign("status")), env)).status).toBe(200);
    expect((await worker.fetch(call("/api/hmac/monitor/diag", sign("diag")), env)).status).toBe(200);
    const upper = sign("git");
    upper["X-Muse-Signature"] = upper["X-Muse-Signature"].toUpperCase();
    expect((await worker.fetch(call("/api/hmac/monitor/git", upper), env)).status).toBe(200);
    expect(calls).toEqual(["http://do/hmac-claim", "http://do/status", "http://do/hmac-claim", "http://do/monitor/diag", "http://do/hmac-claim", "http://do/monitor/git"]);
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

  it("accepts a signature only once: a replay is 401 {error: replay} and is not forwarded again (REQ-SEC-011)", async () => {
    const { env, calls } = makeEnv();
    const seen = new Set<string>();
    (env as Record<string, unknown>).MONITOR_GATEWAY = {
      idFromName: (name: string) => name,
      get: () => ({ fetch: async (url: string, init?: { body?: string }) => {
        calls.push(url);
        if (url.includes("hmac-claim")) {
          const { sig } = JSON.parse(init?.body ?? "{}") as { sig: string };
          if (seen.has(sig)) return Response.json({ ok: false });
          seen.add(sig);
          return Response.json({ ok: true });
        }
        return Response.json({ from: "do", url });
      } }),
    };
    const headers = sign("status");
    expect((await worker.fetch(call("/api/hmac/status", headers), env)).status).toBe(200);
    const second = await worker.fetch(call("/api/hmac/status", headers), env);
    expect(second.status).toBe(401);
    expect(await second.json()).toEqual({ error: "replay" });
    expect(calls.filter((u) => u === "http://do/status")).toHaveLength(1);
    // A different section with its own fresh signature still works.
    expect((await worker.fetch(call("/api/hmac/monitor/diag", sign("diag")), env)).status).toBe(200);
  });

  it("fails closed with 503 when the replay claim cannot be checked (REQ-SEC-013)", async () => {
    const { env, calls } = makeEnv();
    (env as Record<string, unknown>).MONITOR_GATEWAY = {
      idFromName: (name: string) => name,
      get: () => ({ fetch: async (url: string) => { calls.push(url); if (url.includes("hmac-claim")) throw new Error("do down"); return Response.json({ from: "do", url }); } }),
    };
    const res = await worker.fetch(call("/api/hmac/status", sign("status")), env);
    expect(res.status).toBe(503);
    expect(await res.json()).toEqual({ error: "replay_check_unavailable" });
    expect(calls).toEqual(["http://do/hmac-claim"]);
  });
});

describe("GET /api/live (WebSocket, REQ-SEC-037)", () => {
  it("rejects an unauthenticated upgrade with 401 and does not forward", async () => {
    const { env, calls } = makeEnv();
    const res = await worker.fetch(call("/api/live", { Upgrade: "websocket" }), env);
    expect(res.status).toBe(401);
    expect(calls).toEqual([]);
  });

  it("uses the signed cookie deadline instead of a caller-supplied live deadline", async () => {
    const { env } = makeEnv();
    const fixture = env as { MONITOR_GATEWAY: { get: () => unknown } };
    const login = await worker.fetch(call("/api/status", { Authorization: `Bearer ${WORKER_API_KEY}` }), env);
    const cookie = login.headers.get("Set-Cookie")!.split(";")[0];
    const deadline = cookie.split("=")[1].split(".")[0];
    const forward = vi.fn(async (_url: string, _request: Request) => Response.json({}));
    fixture.MONITOR_GATEWAY.get = () => ({ fetch: forward });
    const response = await worker.fetch(call("/api/live", {
      Cookie: cookie, Upgrade: "websocket", Origin: "https://muse-monitor.example", "X-Muse-Live-Expires": "999999999999",
    }), env);
    expect(response.status).toBe(200);
    expect(forward.mock.calls[0][1].headers.get("X-Muse-Live-Expires")).toBe(deadline);
  });

  it("rejects an upgrade from another origin even with a valid browser cookie", async () => {
    const { env, calls } = makeEnv();
    const login = await worker.fetch(call("/api/status", { Authorization: `Bearer ${WORKER_API_KEY}` }), env);
    const cookie = login.headers.get("Set-Cookie")!.split(";")[0];
    const response = await worker.fetch(call("/api/live", {
      Cookie: cookie, Upgrade: "websocket", Origin: "https://other.example",
    }), env);
    expect(response.status).toBe(401);
    expect(calls).toEqual(["http://do/status"]);
  });

  it("rejects an authenticated request without the Upgrade header with 426", async () => {
    const { env, calls } = makeEnv();
    const res = await worker.fetch(call("/api/live", { Authorization: `Bearer ${WORKER_API_KEY}` }), env);
    expect(res.status).toBe(426);
    expect(calls).toEqual([]);
  });

  it("forwards an authenticated upgrade to the DO", async () => {
    const { env, calls } = makeEnv();
    const res = await worker.fetch(call("/api/live", { Authorization: `Bearer ${WORKER_API_KEY}`, Upgrade: "websocket" }), env);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ from: "do", url: "http://do/live" });
    expect(calls).toEqual(["http://do/live"]);
  });
});

describe("structured audit log (REQ-SEC-014/015)", () => {
  let lines: string[];
  beforeEach(() => {
    lines = [];
    vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => { lines.push(args.map(String).join(" ")); });
  });
  const audits = () => lines.map((l) => JSON.parse(l) as Record<string, unknown>);

  it("logs one JSON line per bearer decision, accepted and rejected", async () => {
    const { env } = makeEnv();
    await worker.fetch(call("/api/status", { Authorization: `Bearer ${WORKER_API_KEY}` }), env);
    await worker.fetch(call("/api/monitor/jobs", { Authorization: "Bearer wrong" }), env);
    expect(audits()).toEqual([
      expect.objectContaining({ type: "audit", route: "/api/status", auth: "bearer", result: "accepted" }),
      expect.objectContaining({ type: "audit", route: "/api/monitor/jobs", auth: "none", result: "rejected" }),
    ]);
    for (const entry of audits()) expect(typeof entry.ts).toBe("string");
  });

  it("logs cookie authentication as auth=cookie", async () => {
    const { env } = makeEnv();
    const login = await worker.fetch(call("/api/status", { Authorization: `Bearer ${WORKER_API_KEY}` }), env);
    const cookie = (login.headers.get("Set-Cookie") ?? "").split(";")[0];
    lines.length = 0;
    await worker.fetch(call("/api/monitor/jobs", { Cookie: cookie }), env);
    expect(audits()).toEqual([expect.objectContaining({ type: "audit", route: "/api/monitor/jobs", auth: "cookie", result: "accepted" })]);
  });

  it("logs HMAC decisions with the section, and a replay as result=replay", async () => {
    const { env } = makeEnv();
    const seen = new Set<string>();
    (env as Record<string, unknown>).MONITOR_GATEWAY = {
      idFromName: (name: string) => name,
      get: () => ({ fetch: async (url: string, init?: { body?: string }) => {
        if (url.includes("hmac-claim")) {
          const { sig } = JSON.parse(init?.body ?? "{}") as { sig: string };
          if (seen.has(sig)) return Response.json({ ok: false });
          seen.add(sig);
          return Response.json({ ok: true });
        }
        return Response.json({ from: "do", url });
      } }),
    };
    const headers = sign("diag");
    await worker.fetch(call("/api/hmac/monitor/diag", headers), env);
    await worker.fetch(call("/api/hmac/monitor/diag", headers), env);
    await worker.fetch(call("/api/hmac/status", { "X-Muse-Timestamp": "1", "X-Muse-Signature": "0".repeat(64) }), env);
    expect(audits()).toEqual([
      expect.objectContaining({ type: "audit", route: "/api/hmac/monitor/diag", auth: "hmac", result: "accepted", section: "diag" }),
      expect.objectContaining({ type: "audit", route: "/api/hmac/monitor/diag", auth: "hmac", result: "replay", section: "diag" }),
      expect.objectContaining({ type: "audit", route: "/api/hmac/status", auth: "hmac", result: "rejected", section: "status" }),
    ]);
  });

  it("never logs a key value, a cookie value, or a signature", async () => {
    const { env } = makeEnv();
    const headers = sign("status");
    await worker.fetch(call("/api/status", { Authorization: `Bearer ${WORKER_API_KEY}` }), env);
    await worker.fetch(call("/api/hmac/status", headers), env);
    await worker.fetch(call("/api/status", { Authorization: "Bearer wrong" }), env);
    const all = lines.join("\n");
    expect(all).not.toContain(WORKER_API_KEY);
    expect(all).not.toContain(MONITOR_HMAC_SECRET);
    expect(all).not.toContain(headers["X-Muse-Signature"]);
    expect(all).not.toContain("mm_auth=");
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

  it("shows the node's login state in colored text (REQ-SEC-034): a dedicated element, both labels, and a keyless /health read", async () => {
    const { env } = makeEnv();
    const html = await (await worker.fetch(call("/"), env)).text();
    expect(html).toContain('id="loginstat"');
    expect(html).toContain("ログイン中");
    expect(html).toContain("未ログイン");
    // The two states are told apart by color as well as by the words.
    expect(html).toMatch(/\.login-ok\s*\{[^}]*color:\s*#[0-9a-fA-F]+/);
    expect(html).toMatch(/\.login-ng\s*\{[^}]*color:\s*#[0-9a-fA-F]+/);
    expect(html).not.toMatch(/\.login-ok\s*\{[^}]*color:\s*(#[0-9a-fA-F]+)[^}]*\}[\s\S]*?\.login-ng\s*\{[^}]*color:\s*\1/);
    // The state comes from /health, which needs no key: the label is visible
    // whether or not the viewer is logged in.
    expect(html).toContain("fetch('/health')");
    expect(html).toContain("loadLoginState()");
  });

  it("the key button reflects the actual login state (REQ-SEC-038): starts as キー登録， probes the cookie on load, and switches both ways", async () => {
    const { env } = makeEnv();
    const html = await (await worker.fetch(call("/"), env)).text();
    // The button's initial label is the register action, not logout.
    expect(html).toMatch(/<button type="button" id="authbtn" onclick="authAction\(\)">キー登録<\/button>/);
    // On load the page probes the login state with the cookie only (no key sent).
    expect(html).toContain("probeLogin()");
    expect(html).toMatch(/async function probeLogin\(\) \{\s*try \{\s*const r = await fetch\('\/api\/status'\);/);
    // One state setter drives both labels.
    expect(html).toContain("function setLoggedIn(");
    expect(html).toContain("v ? 'ログアウト' : 'キー登録'");
    // A 401 from a data fetch (expired cookie) flips the button back to キー登録.
    expect(html).toMatch(/r\.status === 401\) setLoggedIn\(false\)/);
    // Registering with a key goes through /api/status, whose 200 sets the cookie.
    expect(html).toContain("async function authAction()");
  });

  it("shows the two stages separately (REQ-SEC-039): the browser's own key-auth state has its own line, updated by the same setter", async () => {
    const { env } = makeEnv();
    const html = await (await worker.fetch(call("/"), env)).text();
    expect(html).toContain('id="authstat"');
    expect(html).toContain("このブラウザのキー認証:");
    expect(html).toContain("認証済み");
    expect(html).toContain("未認証");
    expect(html).toMatch(/getElementById\('authstat'\)/);
  });

  it("greys out the whole area below the key box as one section while logged out (REQ-SEC-040)", async () => {
    const { env } = makeEnv();
    const html = await (await worker.fetch(call("/"), env)).text();
    // The area below the key box is wrapped in one container, locked at first paint.
    expect(html).toContain('<div id="gated" class="off" inert>');
    const gatedAt = html.indexOf('id="gated"');
    expect(gatedAt).toBeGreaterThan(-1);
    expect(html.indexOf('onclick="loadAll()"')).toBeGreaterThan(gatedAt);
    expect(html.indexOf('id="view"')).toBeGreaterThan(gatedAt);
    expect(html.indexOf('id="nodestat"')).toBeGreaterThan(gatedAt);
    // The grey-out applies to the section as a whole, not per button.
    expect(html).toMatch(/#gated\.off\s*\{[^}]*opacity:\s*\.45[^}]*pointer-events:\s*none/);
    // REQ-SEC-041: the grey-out also drops saturation, so text and button
    // colours inside the section do not keep standing out.
    expect(html).toMatch(/#gated\.off\s*\{[^}]*filter:\s*grayscale\(1\)/);
    expect(html).not.toContain("applyAuthToButtons");
    // One function toggles the section from the login state, driven by the setter.
    expect(html).toContain("function applyAuthGate()");
    expect(html).toMatch(/function setLoggedIn\(v\) \{[\s\S]*?applyAuthGate\(\)/);
  });

  it("unlocks data only after both logins and keeps a valid session on a receiver error", async () => {
    const { env } = makeEnv();
    const html = await (await worker.fetch(call("/"), env)).text();
    const script = html.match(/<script>([\s\S]*?)<\/script>/)![1]
      .split("\n  render();\n  loadLoginState();")[0];
    const gated = { inert: true, classList: { toggle: vi.fn() } };
    const auth = { className: "", textContent: "" };
    const elements: Record<string, object> = { gated, authstat: auth };
    let browserStatus = 401;
    let node = "NeedsLogin";
    let dataStatus = 200;
    let pendingData: Promise<Response> | undefined;
    const fetch = vi.fn(async (path: string) => {
      if (path === "/health") return Response.json({ node: { node } });
      if (path === "/api/status") return Response.json({}, { status: browserStatus });
      if (pendingData) return pendingData;
      return Response.json({ error: dataStatus === 502 ? "receiver_unauthorized" : "unauthorized" }, { status: dataStatus });
    });
    const page = runInNewContext(script + "\n({ loadLoginState, probeLogin, load, data })", {
      fetch, setInterval: () => {}, window: {},
      document: {
        getElementById: (id: string) => elements[id] ??= { value: "" },
        querySelectorAll: () => [],
        createElement: () => ({ innerHTML: "" }),
      },
    });

    await page.load("status");
    expect(fetch).not.toHaveBeenCalledWith("/api/monitor/status", expect.anything());
    node = "Running";
    await page.loadLoginState();
    expect(gated.inert).toBe(true);
    node = "NeedsLogin";
    await page.loadLoginState();
    browserStatus = 200;
    await page.probeLogin();
    expect(gated.inert).toBe(true);

    node = "Running";
    await page.loadLoginState();
    expect(gated.inert).toBe(false);
    const sectionCalls = () => fetch.mock.calls.filter(([path]) => path.startsWith("/api/monitor/"));
    expect(sectionCalls().map(([path]) => path).sort()).toEqual(DO_SECTIONS.map(name => "/api/monitor/" + name).sort());
    await page.loadLoginState();
    expect(sectionCalls()).toHaveLength(DO_SECTIONS.length);
    dataStatus = 502;
    await page.load("status");
    expect(gated.inert).toBe(false);
    expect(auth.className).toBe("login-ok");

    let resolveData!: (response: Response) => void;
    pendingData = new Promise(resolve => { resolveData = resolve; });
    const late = page.load("status");
    node = "NeedsLogin";
    await page.loadLoginState();
    resolveData(Response.json({ output: "stale result" }));
    await late;
    pendingData = undefined;
    expect(gated.inert).toBe(true);
    expect(page.data).toEqual({});
    expect(auth.className).toBe("login-ok");

    node = "Running";
    await page.loadLoginState();
    expect(gated.inert).toBe(false);
    dataStatus = 401;
    await page.load("status");
    expect(gated.inert).toBe(true);
    expect(auth.className).toBe("login-ng");
  });

  it("offers the Tailscale login link from the authenticated status while the node waits for login (REQ-SEC-042)", async () => {
    const { env } = makeEnv();
    const html = await (await worker.fetch(call("/"), env)).text();
    // A dedicated link element sits next to the node login-state line, hidden at first paint.
    expect(html).toContain('<a id="loginlink"');
    expect(html).toMatch(/<a id="loginlink"[^>]*style="display:none"/);
    expect(html.indexOf('id="loginlink"')).toBeGreaterThan(html.indexOf('id="loginstat"'));
    // The authenticated status fetch drives it: a loginUrl in /api/status shows
    // the link, anything else (Running, no URL, 401) hides it.
    expect(html).toMatch(/function loadStatus\(\) \{[\s\S]*?j\.loginUrl/);
    expect(html).toMatch(/getElementById\('loginlink'\)/);
    // The keyless /health read must not be the source of the URL.
    expect(html).not.toMatch(/function loadLoginState\(\) \{[\s\S]*?loginUrl/);
  });

  it("shows the node's own IP next to the login state from the keyless /health (REQ-SEC-043)", async () => {
    const { env } = makeEnv();
    const html = await (await worker.fetch(call("/"), env)).text();
    // loadLoginState reads the node ip out of /health and prints it with the state.
    expect(html).toMatch(/function loadLoginState\(\) \{[\s\S]*?\.ip/);
    expect(html).toContain("IP: ");
  });

  it("shows the recent boot attempts next to the login state (REQ-SEC-045)", async () => {
    const { env } = makeEnv();
    const html = await (await worker.fetch(call("/"), env)).text();
    // A dedicated element sits with the login-state line, filled from the
    // bootLog that /health carries (keyless, same source as the IP).
    expect(html).toContain('id="bootlog"');
    expect(html).toContain("直近の起動");
    expect(html).toMatch(/function loadLoginState\(\) \{[\s\S]*?bootLog/);
  });
});

describe("POST /api/node-check (REQ-SEC-056)", () => {
  it("rejects unauthenticated calls with 401 and never reaches the DO", async () => {
    const { env, calls } = makeEnv();
    for (const headers of [{}, { Authorization: "Bearer wrong" }, { Authorization: `Bearer ${MONITOR_HMAC_SECRET}` }]) {
      const res = await worker.fetch(call("/api/node-check", headers, "POST"), env);
      expect(res.status).toBe(401);
      expect(await res.json()).toEqual({ error: "unauthorized" });
    }
    expect(calls).toEqual([]);
  });

  it("forwards an authenticated call to the DO's /node-check", async () => {
    const { env, calls } = makeEnv();
    const res = await worker.fetch(call("/api/node-check", { Authorization: `Bearer ${WORKER_API_KEY}` }, "POST"), env);
    expect(res.status).toBe(200);
    expect(calls).toEqual(["http://do/node-check"]);
  });

  it("is POST-only: a GET is not the check route", async () => {
    const { env, calls } = makeEnv();
    const res = await worker.fetch(call("/api/node-check", { Authorization: `Bearer ${WORKER_API_KEY}` }), env);
    expect(res.status).toBe(404);
    expect(calls).toEqual([]);
  });

  it("refreshes authenticated node status so delayed approval links appear", async () => {
    const { env } = makeEnv();
    const html = await (await worker.fetch(call("/"), env)).text();
    expect(html).toMatch(/setInterval\(\(\) => \{ if \(loggedIn\) loadStatus\(\); \}, 5000\)/);
  });

  it("the dashboard has a manual node-check button that calls /api/node-check", async () => {
    const { env } = makeEnv();
    const html = await (await worker.fetch(call("/"), env)).text();
    expect(html).toContain('id="nodecheck"');
    expect(html).toContain("ノード再確認");
    expect(html).toMatch(/function nodeCheck\(\) \{[\s\S]*?fetch\('\/api\/node-check', \{ method: 'POST'/);
  });
});
