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
 * Auth (keys are separate and never mixed — see docs/KEY_LEDGER.md):
 *   - callers present WORKER_API_KEY (Bearer) to /api/*; a Bearer request to
 *     /api/status also sets a login cookie (7 days, holds no key) that opens
 *     /api/* by itself (src/auth-cookie.ts)
 *   - TS_AUTHKEY (Tailscale-issued) only joins the tailnet; TS_API_KEY
 *     (operator-chosen) is only the Bearer the DO presents to the receiver.
 *     While TS_AUTHKEY is unset the join falls back to TS_API_KEY and says
 *     so (authKeySource); interactive login only when neither is set
 *   - the main Worker signs /api/hmac/* with MONITOR_HMAC_SECRET; a
 *     signature is accepted only once (replay is refused), and every auth
 *     decision on /api/* and /api/hmac/* emits one structured audit line
 */

interface Env {
  MONITOR_GATEWAY: DurableObjectNamespace;
  WORKER_API_KEY: string;
  /** TS_AUTHKEY: Tailscale-issued auth key; the DO joins the tailnet with it, and sends it nowhere else. */
  TS_AUTHKEY?: string;
  /** TS_API_KEY: operator-chosen receiver key; the DO presents it to the receiver as the Bearer, and uses it nowhere else. */
  TS_API_KEY?: string;
  MONITOR_HMAC_SECRET: string;
  /** wrangler.toml の [version_metadata]。デプロイした版のIDと時刻。 */
  CF_VERSION_METADATA?: { id: string; tag: string; timestamp: string };
}

/**
 * コードの版の目印(/health で返す)。どの修正が本番に入っているかを、鍵なしで見分けるため。
 * 2: netmapの読み違いの修正・鍵のフォールバック(nekoserver/muse-monitor#7)。3: /health にノードの公開状態を出す。
 * 9: 鍵の役割分離(TS_AUTHKEY=参加専用、TS_API_KEY=receiver専用)、HMACリプレイ防止、構造化監査ログ(SPEC.muse-monitor.security.hardening)。
 * 10: 永続化された状態がある場合は login を呼ばず状態から復帰する(参加は一度だけ。鍵の変更で参加済みノードを壊さない)。
 * 動きが変わる修正を入れたら上げる。
 */
const MONITOR_REVISION = 22;

export { MonitorGateway } from "./do";
import { authCookieValid, clearAuthCookie, makeAuthCookie } from "./auth-cookie";

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

function nowS(): number { return Math.floor(Date.now() / 1000); }

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
  ["hooks", "Hooks 状態"],
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
  #loginstat, #authstat { font-size: 1.05em; }
  .login-ok { color: #7ee787; font-weight: bold; }
  .login-ng { color: #ff7b72; font-weight: bold; }
  button { margin-left: .5em; cursor: pointer; }
  #gated.off { opacity: .45; pointer-events: none; filter: grayscale(1); }
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
<p id="loginstat" class="login-ng">ノードのログイン状態: 未ログイン（未取得）</p>
<p id="authstat" class="login-ng">このブラウザのキー認証: 未認証</p>
<p class="meta">実行系はここにはありません。依頼の受付はホスト側ダッシュボード、
承認はホストのシェルでのみ行えます。</p>
<p><label>API キー: <input type="password" id="key" size="32" autocomplete="off"></label>
<button type="button" id="authbtn" onclick="authAction()">キー登録</button>
<span class="meta" id="authmsg"></span>
<span class="meta">キーで認証が通ると、このブラウザで7日間ログインしたままになります(キーは保存しません)</span></p>
<div id="gated" class="off" inert>
<p><button type="button" onclick="loadAll()">全て取得</button>
<span style="margin-left:1em">表示:
<button type="button" class="viewbtn" data-v="tabs" onclick="setView('tabs')">タブ</button>
<button type="button" class="viewbtn" data-v="tree" onclick="setView('tree')">ツリー</button>
<button type="button" class="viewbtn" data-v="panel" onclick="setView('panel')">サイドパネル</button>
</span></p>
<pre id="nodestat">ノード状態: （未取得）</pre>
<div id="view"></div>
</div>
<script>
  const SECTIONS = ${JSON.stringify(SECTIONS)};
  const CATS = [
    ["概要", ["status", "diag"]],
    ["SDK", ["sdkhealth", "sdkts", "sdkprofiles", "sdksessions"]],
    ["ジョブ", ["jobs", "pending", "execlog", "recent"]],
    ["システム", ["vm", "procs", "ports", "pkgs", "git", "hooks"]],
  ];
  const TITLE = Object.fromEntries(SECTIONS);
  const data = {};   // name -> text
  let view = "tabs", activeTab = CATS[0][0], treeSel = "status";
  function key() { return document.getElementById('key').value.trim(); }
  function headers() { return key() ? { Authorization: 'Bearer ' + key() } : {}; }
  let loggedIn = false;
  function setLoggedIn(v) {
    loggedIn = v;
    document.getElementById('authbtn').textContent = v ? 'ログアウト' : 'キー登録';
    const a = document.getElementById('authstat');
    a.className = v ? 'login-ok' : 'login-ng';
    a.textContent = 'このブラウザのキー認証: ' + (v ? '認証済み' : '未認証');
    applyAuthGate();
  }
  // 未認証の間は、キー入力窓より下のセクション全体をグレーアウトして操作できなくする(REQ-SEC-040)。
  function applyAuthGate() {
    const g = document.getElementById('gated');
    g.classList.toggle('off', !loggedIn);
    g.inert = !loggedIn;
  }
  // Cookie だけで認証が通るかを見る(キーは送らない)。通ればログイン中である。
  async function probeLogin() {
    try {
      const r = await fetch('/api/status');
      setLoggedIn(r.status === 200);
    } catch { setLoggedIn(false); }
  }
  async function authAction() {
    const msg = document.getElementById('authmsg');
    if (loggedIn) {
      await fetch('/api/logout', { method: 'POST' });
      document.getElementById('key').value = '';
      setLoggedIn(false);
      msg.textContent = '';
      document.getElementById('nodestat').textContent = 'ノード状態: （ログアウトしました）';
      return;
    }
    if (!key()) { msg.textContent = 'キーを入力してください'; return; }
    try {
      const r = await fetch('/api/status', { headers: headers() });
      if (r.status === 200) {
        setLoggedIn(true);
        msg.textContent = '';
        document.getElementById('key').value = '';
        loadAll();
      } else {
        msg.textContent = 'キーが違います';
      }
    } catch (err) { msg.textContent = '登録失敗: ' + err; }
  }
  async function load(name) {
    data[name] = "取得中…"; render();
    try {
      const r = await fetch('/api/monitor/' + name, { headers: headers() });
      if (r.status === 401) setLoggedIn(false);
      const j = await r.json();
      data[name] = j.output !== undefined ? j.output : JSON.stringify(j, null, 2);
    } catch (err) { data[name] = '取得失敗: ' + err; }
    render();
  }
  async function loadStatus() {
    const el = document.getElementById('nodestat');
    try {
      const r = await fetch('/api/status', { headers: headers() });
      if (r.status === 401) setLoggedIn(false);
      if (r.status === 200 && key()) { setLoggedIn(true); document.getElementById('key').value = ''; }
      const j = await r.json();
      const rcv = j.receiver || {};
      el.textContent = 'ノード状態: ' + (j.node ?? JSON.stringify(j)) +
        ' / 受信側: ' + (rcv.baseName ?? '-') + ' -> ' + (rcv.resolvedIp ?? '未解決') +
        ' / 候補: ' + ((rcv.candidates || []).map(c => c.name + '(' + c.ip + ')').join(', ') || 'なし');
    } catch (err) { el.textContent = 'ノード状態: 取得失敗 ' + err; }
  }
  async function loadLoginState() {
    // ノードのログイン状態は鍵なしの /health から取る(REQ-SEC-034)。
    // 見る側がログインしていなくても、ノードがログイン中かどうかが色と文字で分かる。
    const el = document.getElementById('loginstat');
    try {
      const r = await fetch('/health');
      const j = await r.json();
      const state = j.node && j.node.node;
      if (state === 'Running') {
        el.className = 'login-ok';
        el.textContent = 'ノードのログイン状態: ログイン中';
      } else {
        el.className = 'login-ng';
        el.textContent = 'ノードのログイン状態: 未ログイン（状態: ' + (state ?? '不明') + '）';
      }
    } catch (err) {
      el.className = 'login-ng';
      el.textContent = 'ノードのログイン状態: 未ログイン（取得失敗）';
    }
  }
  function loadAll() { loadLoginState(); loadStatus(); for (const [name] of SECTIONS) load(name); }
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
  loadLoginState();
  probeLogin();
  loadStatus();  // 7日間の Cookie が残っていれば、キーを入れずに状態が出る
</script>
</body></html>`;

type AuditAuth = "bearer" | "cookie" | "hmac" | "none";
type AuditResult = "accepted" | "rejected" | "replay" | "unavailable";

/**
 * One structured audit line per auth decision (SPEC REQ-SEC-014/015).
 * Never carries a key value, a cookie value, or a signature — only the
 * route, the auth kind, the outcome, and (for HMAC) the section name.
 */
function audit(route: string, auth: AuditAuth, result: AuditResult, section?: string): void {
  console.log(JSON.stringify({
    type: "audit",
    ts: new Date().toISOString(),
    route,
    auth,
    result,
    ...(section ? { section } : {}),
  }));
}

/**
 * Claim an accepted HMAC signature in the Durable Object, so the same
 * signature cannot be replayed inside its validity window
 * (SPEC REQ-SEC-011/013). "unavailable" fails closed.
 */
async function claimSignature(env: Env, sig: string, ts: number): Promise<"claimed" | "replay" | "unavailable"> {
  try {
    const stub = env.MONITOR_GATEWAY.get(env.MONITOR_GATEWAY.idFromName("monitor-gateway"));
    const res = await stub.fetch("http://do/hmac-claim", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ sig, ts }),
    });
    if (res.status !== 200) return "unavailable";
    const body = (await res.json()) as { ok?: unknown };
    if (body.ok === true) return "claimed";
    if (body.ok === false) return "replay";
    return "unavailable";
  } catch {
    return "unavailable";
  }
}

/**
 * HMAC gate for /api/hmac/*: signature check, then the one-time claim.
 * Returns null when the request may proceed, else the refusal response.
 */
async function hmacGate(request: Request, env: Env, section: string, route: string): Promise<Response | null> {
  if (!(await hmacMatches(request, env.MONITOR_HMAC_SECRET, section))) {
    audit(route, "hmac", "rejected", section);
    return Response.json({ error: "unauthorized" }, { status: 401 });
  }
  const sig = (request.headers.get("X-Muse-Signature") ?? "").toLowerCase();
  const ts = Number(request.headers.get("X-Muse-Timestamp"));
  const claim = await claimSignature(env, sig, ts);
  if (claim === "replay") {
    audit(route, "hmac", "replay", section);
    return Response.json({ error: "replay" }, { status: 401 });
  }
  if (claim === "unavailable") {
    audit(route, "hmac", "unavailable", section);
    return Response.json({ error: "replay_check_unavailable" }, { status: 503 });
  }
  audit(route, "hmac", "accepted", section);
  return null;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/health" && request.method === "GET") {
      // 鍵なしで、どの版が動いていてノードがどういう状態かを確かめられるようにする(秘密は含めない)。
      let node: unknown;
      try {
        const stub = env.MONITOR_GATEWAY.get(env.MONITOR_GATEWAY.idFromName("monitor-gateway"));
        node = await (await stub.fetch("http://do/public-status")).json();
      } catch (err) {
        node = { error: `node status unavailable: ${String(err).slice(0, 200)}` };
      }
      const meta = env.CF_VERSION_METADATA;
      return Response.json({
        status: "ok",
        worker: "muse-monitor",
        revision: MONITOR_REVISION,
        version: meta ? { id: meta.id, tag: meta.tag, timestamp: meta.timestamp } : null,
        node,
      });
    }

    if (url.pathname === "/" && request.method === "GET") {
      return new Response(DASHBOARD, {
        headers: { "Content-Type": "text/html; charset=utf-8" },
      });
    }

    if (url.pathname === "/api/logout" && request.method === "POST") {
      return Response.json({ ok: true }, { headers: { "Set-Cookie": clearAuthCookie() } });
    }

    if (url.pathname === "/api/status" && request.method === "GET") {
      const byKey = bearerMatches(request.headers.get("Authorization"), env.WORKER_API_KEY);
      if (!byKey && !(await authCookieValid(request.headers.get("Cookie"), env.WORKER_API_KEY, nowS()))) {
        audit("/api/status", "none", "rejected");
        return Response.json({ error: "unauthorized" }, { status: 401 });
      }
      audit("/api/status", byKey ? "bearer" : "cookie", "accepted");
      const id = env.MONITOR_GATEWAY.idFromName("monitor-gateway");
      const stub = env.MONITOR_GATEWAY.get(id);
      const res = await stub.fetch("http://do/status");
      if (!byKey) return res;
      // ログイン: 7日間の認証状態を Cookie に保つ(Cookie を使った要求では延ばさない)
      const out = new Response(res.body, res);
      out.headers.append("Set-Cookie", await makeAuthCookie(env.WORKER_API_KEY, nowS()));
      return out;
    }

    if (url.pathname === "/api/hmac/status" && request.method === "GET") {
      const gate = await hmacGate(request, env, "status", url.pathname);
      if (gate) return gate;
      const id = env.MONITOR_GATEWAY.idFromName("monitor-gateway");
      const stub = env.MONITOR_GATEWAY.get(id);
      return stub.fetch("http://do/status");
    }

    if (url.pathname.startsWith("/api/hmac/monitor/") && request.method === "GET") {
      const section = url.pathname.slice("/api/hmac/monitor/".length);
      const gate = await hmacGate(request, env, section, url.pathname);
      if (gate) return gate;
      const id = env.MONITOR_GATEWAY.idFromName("monitor-gateway");
      const stub = env.MONITOR_GATEWAY.get(id);
      return stub.fetch(`http://do/monitor/${section}`);
    }

    if (url.pathname.startsWith("/api/monitor/") && request.method === "GET") {
      const byKey = bearerMatches(request.headers.get("Authorization"), env.WORKER_API_KEY);
      if (!byKey && !(await authCookieValid(request.headers.get("Cookie"), env.WORKER_API_KEY, nowS()))) {
        audit(url.pathname, "none", "rejected");
        return Response.json({ error: "unauthorized" }, { status: 401 });
      }
      audit(url.pathname, byKey ? "bearer" : "cookie", "accepted");
      const section = url.pathname.slice("/api/monitor/".length);
      const id = env.MONITOR_GATEWAY.idFromName("monitor-gateway");
      const stub = env.MONITOR_GATEWAY.get(id);
      return stub.fetch(`http://do/monitor/${section}`);
    }

    if (url.pathname === "/api/live" && request.method === "GET") {
      // ライブ表示ページ用 WebSocket (REQ-SEC-037)。認証は upgrade の前に済ませる。
      const byKey = bearerMatches(request.headers.get("Authorization"), env.WORKER_API_KEY);
      if (!byKey && !(await authCookieValid(request.headers.get("Cookie"), env.WORKER_API_KEY, nowS()))) {
        audit("/api/live", "none", "rejected");
        return Response.json({ error: "unauthorized" }, { status: 401 });
      }
      if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
        audit("/api/live", byKey ? "bearer" : "cookie", "rejected");
        return Response.json({ error: "websocket upgrade required" }, { status: 426 });
      }
      audit("/api/live", byKey ? "bearer" : "cookie", "accepted");
      const id = env.MONITOR_GATEWAY.idFromName("monitor-gateway");
      const stub = env.MONITOR_GATEWAY.get(id);
      return stub.fetch("http://do/live", request);
    }

    return Response.json({ error: "not found" }, { status: 404 });
  },
};
