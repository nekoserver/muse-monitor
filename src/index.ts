/**
 * muse-monitor — minimal standalone Worker for the Muse system monitor.
 *
 * Serves a read-only dashboard of the muse-vm host (the lib/muse monitor
 * assets) and proxies section data through the MonitorGateway Durable
 * Object's Tailscale WASM node to the shared receiver on muse-vm (:8090,
 * GET /monitor/<section>).
 *
 * Deliberately NOT here: any execution path. Submitting a request is the
 * dashboard/ask.cgi flow on the host, approval is host-side only
 * (see lib/muse/SPEC.md). This Worker only looks.
 *
 * Auth (keys are separate and never mixed):
 *   - callers present WORKER_API_KEY (Bearer) to /api/*
 *   - the DO presents RECEIVER_API_KEY to the receiver
 *   - the WASM node logs in with TS_AUTHKEY
 */

interface Env {
  MONITOR_GATEWAY: DurableObjectNamespace;
  WORKER_API_KEY: string;
  RECEIVER_API_KEY: string;
  RECEIVER_URL: string;
  TS_AUTHKEY: string;
  MONITOR_HMAC_SECRET: string;
}

export { MonitorGateway } from "./do";

const HMAC_WINDOW_S = 300;

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/**
 * HMAC check for the main Worker (machine-to-machine).
 * The caller sends:
 *   X-Muse-Timestamp: unix seconds
 *   X-Muse-Signature: hex HMAC-SHA256(MONITOR_HMAC_SECRET, "<ts>.<section>")
 * Accepted within ±300 s. The secret is shared with the main Worker and
 * set by the operator on both sides; it never appears in the repo.
 */
async function hmacMatches(
  request: Request,
  secret: string,
  section: string,
): Promise<boolean> {
  if (!secret) return false;
  const ts = request.headers.get("X-Muse-Timestamp");
  const sig = request.headers.get("X-Muse-Signature");
  if (!ts || !sig) return false;
  if (!/^[0-9a-fA-F]{64}$/.test(sig)) return false;
  const tsNum = Number(ts);
  if (!Number.isFinite(tsNum)) return false;
  if (Math.abs(Date.now() / 1000 - tsNum) > HMAC_WINDOW_S) return false;
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const mac = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(`${ts}.${section}`),
  );
  const expected = [...new Uint8Array(mac)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return timingSafeEqual(expected, sig.toLowerCase());
}

function bearerMatches(header: string | null, expected: string): boolean {
  if (!header || !expected) return false;
  if (!header.startsWith("Bearer ")) return false;
  const got = header.slice("Bearer ".length);
  if (got.length !== expected.length) return false;
  let diff = 0;
  for (let i = 0; i < got.length; i++) diff |= got.charCodeAt(i) ^ expected.charCodeAt(i);
  return diff === 0;
}

const SECTIONS: Array<[string, string]> = [
  ["status", "状態（tailscaled / Bridge）"],
  ["diag", "診断サマリ（全33項目）"],
  ["sdkhealth", "SDK ヘルス"],
  ["jobs", "ジョブキュー"],
  ["pending", "承認待ち"],
  ["execlog", "実行監査ログ"],
  ["pkgs", "パッケージ版数"],
  ["vm", "VM 情報"],
  ["procs", "プロセス上位"],
  ["ports", "待ち受けポート"],
  ["git", "git 状態"],
  ["recent", "直近の完了ジョブ"],
];

const DASHBOARD = `<!DOCTYPE html>
<html lang="ja"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>muse-monitor</title>
<style>
  body { font-family: sans-serif; margin: 1em; background: #111; color: #ddd; }
  section { border: 1px solid #2a4d2a; border-radius: 6px; padding: .4em 1em 1em; margin: 1em 0; }
  h1 { font-size: 1.2em; } h2 { font-size: 1.05em; }
  pre { background: #1b1b1b; border: 1px solid #333; border-radius: 6px;
        padding: .6em 1em; overflow-x: auto; white-space: pre-wrap; }
  .meta { color: #999; font-size: .85em; }
  button { margin-left: .5em; }
</style></head><body>
<h1>muse-monitor <span class="meta">読み取り専用モニタ（muse-vm）</span></h1>
<p class="meta">実行系はここにはありません。依頼の受付はホスト側ダッシュボード、
承認はホストのシェルでのみ行えます。</p>
<p><label>API キー: <input type="password" id="key" size="32"></label>
<button type="button" onclick="loadAll()">全て取得</button></p>
<div id="sections"></div>
<script>
  const SECTIONS = ${JSON.stringify(SECTIONS)};
  const root = document.getElementById('sections');
  for (const [name, title] of SECTIONS) {
    const s = document.createElement('section');
    s.innerHTML = '<h2>' + title + ' <button type="button" data-s="' + name + '">再取得</button></h2><pre id="b-' + name + '">（未取得）</pre>';
    root.appendChild(s);
  }
  root.addEventListener('click', (e) => {
    const b = e.target.closest('button[data-s]');
    if (b) load(b.dataset.s);
  });
  function key() { return document.getElementById('key').value.trim(); }
  async function load(name) {
    const el = document.getElementById('b-' + name);
    el.textContent = '取得中…';
    try {
      const r = await fetch('/api/monitor/' + name, { headers: { Authorization: 'Bearer ' + key() } });
      const j = await r.json();
      el.textContent = j.output !== undefined ? j.output : JSON.stringify(j, null, 2);
    } catch (err) { el.textContent = '取得失敗: ' + err; }
  }
  function loadAll() { for (const [name] of SECTIONS) load(name); }
</script>
</body></html>`;

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/health" && request.method === "GET") {
      return Response.json({ status: "ok", worker: "muse-monitor" });
    }

    if (url.pathname === "/" && request.method === "GET") {
      return new Response(DASHBOARD, {
        headers: { "Content-Type": "text/html; charset=utf-8" },
      });
    }

    if (url.pathname === "/api/status" && request.method === "GET") {
      if (!bearerMatches(request.headers.get("Authorization"), env.WORKER_API_KEY)) {
        return Response.json({ error: "unauthorized" }, { status: 401 });
      }
      const id = env.MONITOR_GATEWAY.idFromName("monitor-gateway");
      const stub = env.MONITOR_GATEWAY.get(id);
      return stub.fetch("http://do/status");
    }

    if (url.pathname.startsWith("/api/hmac/monitor/") && request.method === "GET") {
      const section = url.pathname.slice("/api/hmac/monitor/".length);
      if (!(await hmacMatches(request, env.MONITOR_HMAC_SECRET, section))) {
        return Response.json({ error: "unauthorized" }, { status: 401 });
      }
      const id = env.MONITOR_GATEWAY.idFromName("monitor-gateway");
      const stub = env.MONITOR_GATEWAY.get(id);
      return stub.fetch(`http://do/monitor/${section}`);
    }

    if (url.pathname.startsWith("/api/monitor/") && request.method === "GET") {
      if (!bearerMatches(request.headers.get("Authorization"), env.WORKER_API_KEY)) {
        return Response.json({ error: "unauthorized" }, { status: 401 });
      }
      const section = url.pathname.slice("/api/monitor/".length);
      const id = env.MONITOR_GATEWAY.idFromName("monitor-gateway");
      const stub = env.MONITOR_GATEWAY.get(id);
      return stub.fetch(`http://do/monitor/${section}`);
    }

    return Response.json({ error: "not found" }, { status: 404 });
  },
};
