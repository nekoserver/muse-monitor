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
 *   - the DO presents TS_API_KEY to the receiver
 *   - the WASM node joins with TS_AUTHKEY if set, otherwise by
 *     interactive login (approve the loginUrl from /api/status)
 */

interface Env {
  MONITOR_GATEWAY: DurableObjectNamespace;
  WORKER_API_KEY: string;
  TS_API_KEY: string;
  TS_AUTHKEY?: string;
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
  ["sdkprofiles", "SDK プロファイル"],
  ["sdksessions", "SDK セッション"],
  ["sdkts", "SDK ヘルス（TypeScript）"],
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
  section.card { border: 1px solid #2a4d2a; border-radius: 6px; padding: .4em 1em 1em; margin: 1em 0; }
  h1 { font-size: 1.2em; } h2 { font-size: 1.05em; }
  pre { background: #1b1b1b; border: 1px solid #333; border-radius: 6px;
        padding: .6em 1em; overflow-x: auto; white-space: pre-wrap; }
  .meta { color: #999; font-size: .85em; }
  button { margin-left: .5em; cursor: pointer; }
  .viewbtn.active, .tab.active { background: #2a4d2a; color: #fff; }
  .tabs { margin: 1em 0 0; border-bottom: 1px solid #2a4d2a; padding-bottom: .4em; }
  .layout { display: flex; gap: 1em; align-items: flex-start; }
  .side { position: sticky; top: 1em; min-width: 11em; border: 1px solid #333;
          border-radius: 6px; padding: .6em .8em; max-height: calc(100vh - 3em); overflow-y: auto; }
  .side h3 { margin: .6em 0 .2em; font-size: .9em; color: #9c9; }
  .side a { display: block; color: #ddd; text-decoration: none; padding: .15em 0; }
  .side a:hover { text-decoration: underline; }
  .tree { min-width: 12em; border: 1px solid #333; border-radius: 6px; padding: .6em .8em; }
  .tree button { display: block; margin: .2em 0 .2em 1em; background: none; border: none; color: #ddd; }
  .tree button.sel { color: #9c9; font-weight: bold; }
  .tree summary { cursor: pointer; color: #9c9; }
  .main { flex: 1; min-width: 0; }
</style></head><body>
<h1>muse-monitor <span class="meta">読み取り専用モニタ（muse-vm）</span></h1>
<p class="meta">実行系はここにはありません。依頼の受付はホスト側ダッシュボード、
承認はホストのシェルでのみ行えます。</p>
<p><label>API キー: <input type="password" id="key" size="32"></label>
<button type="button" onclick="loadAll()">全て取得</button>
<span style="margin-left:1em">表示:
<button type="button" class="viewbtn" data-v="tabs" onclick="setView('tabs')">タブ</button>
<button type="button" class="viewbtn" data-v="tree" onclick="setView('tree')">ツリー</button>
<button type="button" class="viewbtn" data-v="panel" onclick="setView('panel')">サイドパネル</button>
</span></p>
<pre id="nodestat">ノード状態: （未取得）</pre>
<div id="view"></div>
<script>
  const SECTIONS = ${JSON.stringify(SECTIONS)};
  const CATS = [
    ["概要", ["status", "diag"]],
    ["SDK", ["sdkhealth", "sdkts", "sdkprofiles", "sdksessions"]],
    ["ジョブ", ["jobs", "pending", "execlog", "recent"]],
    ["システム", ["vm", "procs", "ports", "pkgs", "git"]],
  ];
  const TITLE = Object.fromEntries(SECTIONS);
  const data = {};   // name -> text
  let view = "tabs", activeTab = CATS[0][0], treeSel = "status";
  function key() { return document.getElementById('key').value.trim(); }
  async function load(name) {
    data[name] = "取得中…"; render();
    try {
      const r = await fetch('/api/monitor/' + name, { headers: { Authorization: 'Bearer ' + key() } });
      const j = await r.json();
      data[name] = j.output !== undefined ? j.output : JSON.stringify(j, null, 2);
    } catch (err) { data[name] = '取得失敗: ' + err; }
    render();
  }
  async function loadStatus() {
    const el = document.getElementById('nodestat');
    try {
      const r = await fetch('/api/status', { headers: { Authorization: 'Bearer ' + key() } });
      const j = await r.json();
      const rcv = j.receiver || {};
      el.textContent = 'ノード状態: ' + (j.node ?? JSON.stringify(j)) +
        ' / 受信側: ' + (rcv.baseName ?? '-') + ' -> ' + (rcv.resolvedIp ?? '未解決') +
        ' / 候補: ' + ((rcv.candidates || []).map(c => c.name + '(' + c.ip + ')').join(', ') || 'なし');
    } catch (err) { el.textContent = 'ノード状態: 取得失敗 ' + err; }
  }
  function loadAll() { loadStatus(); for (const [name] of SECTIONS) load(name); }
  function esc(t) { const d = document.createElement('div'); d.textContent = t; return d.innerHTML; }
  function card(name) {
    return '<section class="card" id="sec-' + name + '"><h2>' + esc(TITLE[name]) +
      ' <button type="button" onclick="load(\\'' + name + '\\')">再取得</button></h2><pre>' +
      esc(data[name] ?? '（未取得）') + '</pre></section>';
  }
  function render() {
    for (const b of document.querySelectorAll('.viewbtn'))
      b.classList.toggle('active', b.dataset.v === view);
    const root = document.getElementById('view');
    if (view === 'tabs') {
      let h = '<div class="tabs">' + CATS.map(([c]) =>
        '<button type="button" class="tab' + (c === activeTab ? ' active' : '') +
        '" onclick="activeTab=\\'' + c + '\\';render()">' + esc(c) + '</button>').join('') + '</div>';
      const [, names] = CATS.find(([c]) => c === activeTab);
      root.innerHTML = h + names.map(card).join('');
    } else if (view === 'tree') {
      let tree = '';
      for (const [c, names] of CATS) {
        tree += '<details open><summary>' + esc(c) + '</summary>' + names.map(n =>
          '<button type="button" class="' + (n === treeSel ? 'sel' : '') +
          '" onclick="treeSel=\\'' + n + '\\';render()">' + esc(TITLE[n]) + '</button>').join('') + '</details>';
      }
      root.innerHTML = '<div class="layout"><div class="tree">' + tree +
        '</div><div class="main">' + card(treeSel) + '</div></div>';
    } else {
      let side = '';
      for (const [c, names] of CATS) {
        side += '<h3>' + esc(c) + '</h3>' + names.map(n =>
          '<a href="#sec-' + n + '">' + esc(TITLE[n]) + '</a>').join('');
      }
      root.innerHTML = '<div class="layout"><div class="side">' + side +
        '</div><div class="main">' + SECTIONS.map(([n]) => card(n)).join('') + '</div></div>';
    }
  }
  function setView(v) { view = v; render(); }
  render();
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

    if (url.pathname === "/api/hmac/status" && request.method === "GET") {
      if (!(await hmacMatches(request, env.MONITOR_HMAC_SECRET, "status"))) {
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
