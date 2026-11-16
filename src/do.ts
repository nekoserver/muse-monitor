/**
 * MonitorGateway — one Durable Object holding one Tailscale WASM node.
 *
 * Read-only monitor transport: the node GETs /monitor/<section> from the
 * shared receiver on muse-vm (the muse-code-wasm receiver on :8090) over
 * the tailnet. There is no write path here at all.
 *
 * State persistence follows the muse-code-wasm CodeGateway pattern:
 * the package's stateStorage interface is synchronous while DO storage
 * is async, so state lives in an in-memory Map (source of truth while
 * alive) and is flushed to DO storage asynchronously after every
 * setState. A DO eviction before a flush can lose the latest state; on
 * the next start the node re-logs in with the auth key and re-registers
 * (ephemeral: false keeps the node identity in the persisted profile).
 */

import { DurableObject } from "cloudflare:workers";
import wasmModule from "@ai-ecoverse/wasm-tailscale/main.wasm";
// Go's wasm_exec.js defines globalThis.Go (browser path in a Worker).
// eslint-disable-next-line @typescript-eslint/no-unused-vars
import "@ai-ecoverse/wasm-tailscale/wasm_exec.js";
import type {
  IPN,
  IPNCallbacks,
  IPNConfig,
} from "./wasm-ipn";
import {
  parsePeers,
  candidatesFor,
  PeerResolver,
  type PeerCandidate,
} from "./ts-discover";

interface Env {
  // TS_AUTHKEY: the Tailscale-issued auth key, used only to join the tailnet.
  // Optional: without it the node cannot join unattended and falls back to
  // interactive login — the operator opens the login URL (exposed in
  // /api/status) and approves the node once. With it, joining is unattended
  // but the key expires (90 days max) and a lost DO state then needs a new key.
  TS_AUTHKEY?: string;
  // TS_API_KEY: the operator-chosen receiver key, used only as the Bearer
  // presented to the receiver. It is never a Tailscale key.
  TS_API_KEY?: string;
}

// The receiver is the shared muse-code-wasm receiver on the host node.
// Only the node's base name is fixed here: its tailnet IP changes when
// the node re-registers, and its name may gain a numeric suffix
// (muse-vm-1, muse-vm-2, ...). The concrete peer is therefore resolved
// at runtime from this node's own netmap, and confirmed by probing the
// receiver's /health (see resolveReceiver below).
// This node's own tailnet hostname. Not the Worker name: the Worker
// name lives only in wrangler.toml's `name` and code cannot read it.
// The two strings match by choice, not by mechanism.
const NODE_HOSTNAME = "muse-monitor";
const RECEIVER_NAME = "muse-vm";
const RECEIVER_PORT = 8090;

const STATE_KEY = "ts-state";
const STATE_EPOCH_KEY = "ts-state-epoch";
/**
 * One-time state reset epoch (revision 17). The state left behind by the
 * failed revision-16 rejoins resumes into a silent NeedsLogin loop and
 * offers no interactive login URL, so it can neither be used nor
 * approved. When the stored epoch differs, loadState discards the state
 * once so the next start is a clean first join. Bump this only as a
 * deliberate recovery action; the marker lives in the same storage, so
 * each value fires exactly once.
 */
const STATE_EPOCH = 1;

/**
 * Structural integrity of the persisted node state (REQ-SEC-033): a plain
 * object of string values. Anything else is the kind of torn write the
 * asynchronous flush can leave behind, and must not be handed to the node.
 * The check is deliberately limited to what is verifiable here — the
 * client's internal key layout is not assumed; state that is structurally
 * sound but semantically broken is the recovery's job (REQ-SEC-026).
 */
function stateIsIntact(stored: unknown): boolean {
  if (typeof stored !== "object" || stored === null || Array.isArray(stored)) return false;
  for (const v of Object.values(stored)) if (typeof v !== "string") return false;
  return true;
}
const CLAIMS_KEY = "hmac-claims";
/** How long an accepted HMAC signature is remembered: twice the ±300 s window. */
const CLAIMS_TTL_S = 600;
const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;
const SECTIONS = new Set([
  "status", "diag", "jobs", "pkgs", "vm", "procs",
  "ports", "git", "recent", "pending", "execlog", "sdkhealth",
  "sdkprofiles", "sdksessions", "sdkts", "hooks",
]);
/** Live page sweep interval while at least one WebSocket client is connected (REQ-SEC-037). */
const LIVE_INTERVAL_MS = 10_000;

/** How many extra probes, and how far apart, before answering receiver_not_found. */
export const RECEIVER_RETRIES = 2;
export const RECEIVER_RETRY_DELAY_MS = 2500;

export class MonitorGateway extends DurableObject<Env> {
  private ipn: IPN | null = null;
  /** Single flight for creating the node: concurrent requests share one start. */
  private starting: Promise<IPN> | null = null;
  /** Requests waiting for the node to reach Running (resolved/rejected by the callbacks). */
  private waiters = new Set<{ resolve(): void; reject(err: Error): void }>();
  /** A panic reported while nobody was waiting; the next wait reports it. */
  private pendingPanic: string | null = null;
  private state = new Map<string, string>();
  private stateLoaded = false;
  /** Whether the current node was started from persisted state, and whether the one state-discarding recovery has been used. */
  private startedWithState = false;
  private recoveryDone = false;
  /** Bumped whenever a node is created or discarded, so a stale node's callbacks cannot touch the current node's tracking. */
  private nodeGeneration = 0;
  /** Accepted HMAC signatures (sig -> unix ts), for replay prevention. */
  private claims: Map<string, number> | null = null;
  private flushPending: Promise<void> | null = null;
  private lastStatus = "not-started";
  private lastError: string | null = null;
  private browseUrl: string | null = null;
  private peers: PeerCandidate[] = [];
  private probing = false;
  private resolver = new PeerResolver(RECEIVER_NAME, RECEIVER_PORT);

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
  }

  /**
   * Join key, role-separated (SPEC.muse-monitor.security.hardening):
   * TS_AUTHKEY (Tailscale-issued) is the join key and nothing else.
   * TS_API_KEY is only ever the receiver Bearer (see receiverKey) and is
   * never used to join — the migration fallback that did so was removed
   * once the deployed node reported TS_AUTHKEY (REQ-SEC-005).
   */
  private authKey(): { value: string; source: "TS_AUTHKEY" } | null {
    if (this.env.TS_AUTHKEY) return { value: this.env.TS_AUTHKEY, source: "TS_AUTHKEY" };
    return null;
  }

  /** Which secret the join key comes from (never the value). */
  private authKeySource(): "TS_AUTHKEY" | null {
    return this.authKey()?.source ?? null;
  }

  private receiverKey(): { value: string; source: "TS_API_KEY" } | null {
    return this.env.TS_API_KEY ? { value: this.env.TS_API_KEY, source: "TS_API_KEY" } : null;
  }

  private async loadState(): Promise<void> {
    if (this.stateLoaded) return;
    const epoch = await this.ctx.storage.get<number>(STATE_EPOCH_KEY);
    if (epoch !== STATE_EPOCH) {
      const existing = await this.ctx.storage.get<Record<string, string>>(STATE_KEY);
      try {
        await this.ctx.storage.delete(STATE_KEY);
        await this.ctx.storage.put(STATE_EPOCH_KEY, STATE_EPOCH);
        if (existing !== undefined) {
          this.lastError = "discarded the persisted node state at load: one-time reset (revision 17)";
        }
      } catch {
        // The reset bookkeeping must never block the node start; if the
        // epoch was not recorded, the reset simply runs again next load.
      }
      this.stateLoaded = true;
      return;
    }
    const stored = await this.ctx.storage.get<Record<string, string>>(STATE_KEY);
    if (stored !== undefined && !stateIsIntact(stored)) {
      // REQ-SEC-033: never start the node on a state that fails the
      // integrity check. Discard it here, before any start, and join fresh
      // — a broken state must surface as a rejoin, not as a wedged node.
      this.lastError = "discarded the persisted node state at load: it failed the integrity check";
      await this.ctx.storage.delete(STATE_KEY);
    } else if (stored) {
      for (const [k, v] of Object.entries(stored)) this.state.set(k, v);
    }
    this.stateLoaded = true;
  }

  private flushState(): void {
    const snapshot = Object.fromEntries(this.state);
    this.flushPending = this.ctx.storage
      .put(STATE_KEY, snapshot)
      .catch((err: unknown) => {
        this.lastError = `state flush failed: ${String(err)}`;
      });
    this.ctx.waitUntil(this.flushPending);
  }

  /**
   * Return the node once it is Running. The node is created once and then
   * kept (its identity lives in the persisted state); every call waits for
   * Running on its own, up to 60 s, so a node that is still waiting for
   * login approval, or that reported a panic, is never used as if it were
   * up, and a later approval makes the same node usable again.
   *
   * Recovery (SPEC REQ-SEC-026/027/028): if the node was started from
   * persisted state and never gets anywhere — the start failed, or it sits
   * in NoState with no login on offer — the state is assumed broken: it is
   * discarded once and the node rejoins from scratch with the auth key.
   */
  private async ensureNode(): Promise<IPN> {
    const ipn = await this.startOnce();
    if (this.lastStatus === "Running") return ipn;
    try {
      await this.waitForRunning();
      return ipn;
    } catch (err) {
      if (!this.recoveryEligible(err)) throw err;
      await this.discardStateForRecovery(err);
      const fresh = await this.startOnce();
      if (this.lastStatus !== "Running") await this.waitForRunning();
      return fresh;
    }
  }

  private async startOnce(): Promise<IPN> {
    if (!this.ipn) {
      this.starting ??= this.startNode().finally(() => {
        this.starting = null;
      });
      await this.starting;
    }
    return this.ipn!;
  }

  private recoveryEligible(err: unknown): boolean {
    if (this.recoveryDone || !this.startedWithState || this.browseUrl) return false;
    return this.lastStatus === "NoState" || String(err).includes("could not start");
  }

  private async discardStateForRecovery(err: unknown): Promise<void> {
    this.recoveryDone = true;
    this.nodeGeneration++; // the wedged node's callbacks must not touch the fresh node's tracking
    this.lastError = `discarded the persisted node state and rejoined with the auth key (recovery; cause: ${String(err).slice(0, 160)})`;
    this.ipn = null;
    this.peers = [];
    this.browseUrl = null;
    this.pendingPanic = null;
    this.lastStatus = "not-started";
    this.state.clear();
    await this.ctx.storage.delete(STATE_KEY);
  }

  private waitForRunning(): Promise<void> {
    if (this.pendingPanic !== null) {
      const error = this.pendingPanic;
      this.pendingPanic = null;
      return Promise.reject(new Error(error));
    }
    return new Promise<void>((resolve, reject) => {
      const waiter = {
        resolve: () => {
          clearTimeout(timer);
          this.waiters.delete(waiter);
          resolve();
        },
        reject: (err: Error) => {
          clearTimeout(timer);
          this.waiters.delete(waiter);
          reject(err);
        },
      };
      const timer = setTimeout(
        () =>
          waiter.reject(
            new Error(
              this.browseUrl
                ? this.authKeySource()
                  ? `the auth key from ${this.authKeySource()} was not accepted (expired, revoked or not an auth key?); the node is waiting for interactive login approval instead: ${this.browseUrl}`
                  : `tailscale node is waiting for interactive login approval: ${this.browseUrl}`
                : `tailscale node did not reach Running in 60s (state: ${this.lastStatus}, auth key from: ${this.authKeySource() ?? "none"})`,
            ),
          ),
        60_000,
      );
      this.waiters.add(waiter);
    });
  }

  private async startNode(): Promise<IPN> {
    await this.loadState();
    // The join happens once. With persisted state the node resumes from it:
    // no auth key is passed and login is not called, so changing (or
    // breaking) a key secret can never wedge a node that already joined.
    // Only a node whose state asks for login (NeedsLogin: state missing
    // pieces, node key expired) gets one deferred login with the key.
    const hasState = this.state.size > 0;
    this.startedWithState = hasState;
    const gen = ++this.nodeGeneration;

    const go = new Go();
    const instance = await WebAssembly.instantiate(wasmModule, go.importObject);
    void go.run(instance);
    const auth = hasState ? null : this.authKey();
    const created = newIPN({
      ...(auth ? { authKey: auth.value } : {}),
      hostname: NODE_HOSTNAME,
      ephemeral: false,
      logUpload: false,
      stateStorage: {
        getState: (id: string) => this.state.get(id) ?? "",
        setState: (id: string, value: string) => {
          this.state.set(id, value);
          this.flushState();
        },
      },
    });
    if (created instanceof Error) {
      throw new Error(`newIPN failed: ${created.message}`);
    }
    const ipn = created;

    let deferredLoginDone = false;
    const callbacks: IPNCallbacks = {
      notifyState: (state: string) => {
        if (gen !== this.nodeGeneration) return;
        this.lastStatus = state;
        if (state === "NeedsLogin" && hasState && !deferredLoginDone) {
          deferredLoginDone = true;
          ipn.login(this.authKey()?.value);
        }
        if (state !== "Running") return;
        this.pendingPanic = null;
        for (const w of [...this.waiters]) w.resolve();
      },
      notifyNetMap: (netMap: string) => {
        if (gen !== this.nodeGeneration) return;
        this.peers = parsePeers(netMap);
      },
      notifyBrowseToURL: (url: string) => {
        if (gen !== this.nodeGeneration) return;
        this.browseUrl = url;
      },
      notifyPanicRecover: (error: string) => {
        if (gen !== this.nodeGeneration) return;
        this.lastError = error;
        if (this.waiters.size === 0) this.pendingPanic = error;
        for (const w of [...this.waiters]) w.reject(new Error(error));
      },
    };
    ipn.run(callbacks);
    this.ipn = ipn;
    if (!hasState) ipn.login(auth?.value);
    return ipn;
  }

  /** Durable Object entrypoint: /status, /monitor/<section>, /hmac-claim. */
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/status") return this.status();
    if (url.pathname === "/public-status") return this.publicStatus();
    if (url.pathname === "/live") return this.live(request);
    if (url.pathname === "/hmac-claim") {
      if (request.method !== "POST") return Response.json({ error: "not found" }, { status: 404 });
      return this.hmacClaim(request);
    }
    if (url.pathname.startsWith("/monitor/")) {
      const section = url.pathname.slice("/monitor/".length);
      if (!SECTIONS.has(section)) {
        return Response.json({ error: "unknown monitor section" }, { status: 404 });
      }
      return this.monitor(section);
    }
    return Response.json({ error: "not found" }, { status: 404 });
  }

  /**
   * Resolve, and while muse-vm is in the netmap but its receiver does not
   * answer, wait and probe again a few times: the receiver restarts within
   * seconds (systemd Restart=always), so a request that lands in that window
   * should not end in receiver_not_found.
   */
  private async resolveReceiverPatiently(ipn: IPN, force: boolean): Promise<string | null> {
    let ip = await this.resolveReceiver(ipn, force);
    for (let i = 0; !ip && i < RECEIVER_RETRIES && candidatesFor(this.peers, RECEIVER_NAME).length > 0; i++) {
      await new Promise((resolve) => setTimeout(resolve, RECEIVER_RETRY_DELAY_MS));
      ip = await this.resolveReceiver(ipn, true);
    }
    return ip;
  }

  /** Resolve (or re-resolve) the receiver's current tailnet IP. */
  private async resolveReceiver(ipn: IPN, force: boolean): Promise<string | null> {
    return this.resolver.resolve((req) => ipn.fetch(req), this.peers, force);
  }

  /** GET one monitor section from the receiver through the tailnet. */
  async monitor(section: string): Promise<Response> {
    const key = this.receiverKey();
    if (!key) {
      return Response.json(
        {
          error: "receiver_key_missing",
          message: "TS_API_KEY is not set; set it with wrangler secret put TS_API_KEY (the same value as the receiver's TS_API_KEY)",
        },
        { status: 500 },
      );
    }
    let ipn: IPN;
    try {
      ipn = await this.ensureNode();
    } catch (err) {
      return Response.json(
        { error: "tailnet_unavailable", message: String(err) },
        { status: 502 },
      );
    }
    let ip = await this.resolveReceiverPatiently(ipn, false);
    if (!ip) {
      return Response.json(
        this.receiverNotFound(),
        { status: 502 },
      );
    }
    let resp;
    try {
      resp = await this.fetchSection(ipn, ip, section, key.value);
    } catch {
      // Transport failed against the cached peer: re-resolve once.
      this.resolver.invalidate();
      ip = await this.resolveReceiverPatiently(ipn, true);
      if (!ip) {
        return Response.json(
          this.receiverNotFound(),
          { status: 502 },
        );
      }
      try {
        resp = await this.fetchSection(ipn, ip, section, key.value);
      } catch (err) {
        return Response.json(
          { error: "delivery_unknown", message: `tailnet GET failed: ${String(err)}` },
          { status: 502 },
        );
      }
    }
    const chunks: Uint8Array[] = [];
    let total = 0;
    try {
      for (;;) {
        const chunk = await resp.read();
        if (chunk === null) break;
        total += chunk.length;
        if (total > MAX_RESPONSE_BYTES) {
          resp.cancel();
          return Response.json(
            { error: "response_too_large", message: "receiver response exceeded 8 MiB" },
            { status: 502 },
          );
        }
        chunks.push(chunk);
      }
    } catch (err) {
      return Response.json(
        { error: "delivery_unknown", message: `reading receiver response failed: ${String(err)}` },
        { status: 502 },
      );
    }
    const merged = new Uint8Array(total);
    let offset = 0;
    for (const c of chunks) {
      merged.set(c, offset);
      offset += c.length;
    }
    const text = new TextDecoder().decode(merged);
    if (resp.status === 401 || resp.status === 503) {
      let receiver: unknown = text;
      try {
        receiver = JSON.parse(text);
      } catch {
        // keep the raw text
      }
      return Response.json(
        resp.status === 401
          ? {
              error: "receiver_unauthorized",
              message: `the receiver on ${RECEIVER_NAME} rejected the Bearer from ${key.source}; it must equal the receiver's TS_API_KEY`,
              keySource: key.source,
              receiver,
            }
          : {
              error: "receiver_key_not_configured",
              message: `the receiver on ${RECEIVER_NAME} has no key configured; start it with TS_API_KEY set to the same value as ${key.source}`,
              keySource: key.source,
              receiver,
            },
        { status: resp.status },
      );
    }
    return new Response(text, {
      status: resp.status,
      headers: { "Content-Type": "application/json" },
    });
  }

  /**
   * Why no receiver was found, from the last probes (IPs are already masked):
   * not in the netmap, refused (nothing listens on the tailnet address), or
   * /health answered with something other than 200.
   */
  private receiverNotFound() {
    const candidates = candidatesFor(this.peers, RECEIVER_NAME).length;
    const probes = this.resolver.lastProbes;
    let message: string;
    if (candidates === 0) {
      message = `no peer named ${RECEIVER_NAME}(-*) in the netmap; is ${RECEIVER_NAME} online in the tailnet?`;
    } else if (probes.some((p) => /refused/i.test(p.result))) {
      message = `${RECEIVER_NAME} refused :${RECEIVER_PORT}; the receiver (lib/muse/samples/receiver.py) is not listening on its tailnet address (still refused after retrying for a few seconds). Start it on ${RECEIVER_NAME} with systemctl --user start muse-receiver (it listens on 0.0.0.0:${RECEIVER_PORT}; lib/muse/SPEC.scripts.md 4.0) and check with sh lib/muse/samples/receiver-check.sh`;
    } else if (probes.some((p) => p.result.startsWith("HTTP "))) {
      message = `${RECEIVER_NAME}:${RECEIVER_PORT} answered /health with something other than 200; check that the receiver on that port is receiver.py`;
    } else {
      message = `${RECEIVER_NAME}:${RECEIVER_PORT} did not answer /health (see probes)`;
    }
    return { error: "receiver_not_found", message, candidates, probes };
  }

  /** One GET against the receiver on a resolved peer IP. */
  private async fetchSection(ipn: IPN, ip: string, section: string, bearer: string) {
    return ipn.fetch({
      url: `http://${ip}:${RECEIVER_PORT}/monitor/${section}`,
      method: "GET",
      headers: [["Authorization", `Bearer ${bearer}`]],
    });
  }

  private async loadClaims(): Promise<Map<string, number>> {
    if (this.claims) return this.claims;
    const stored = await this.ctx.storage.get<Record<string, number>>(CLAIMS_KEY);
    this.claims = new Map(Object.entries(stored ?? {}));
    return this.claims;
  }

  /**
   * Record one accepted HMAC signature (SPEC REQ-SEC-011/012): the same
   * signature is claimable only once. The check-and-set after the load is
   * synchronous, so concurrent claims cannot both win. Claims older than
   * CLAIMS_TTL_S (relative to the incoming timestamp) are pruned.
   */
  private async hmacClaim(request: Request): Promise<Response> {
    let body: { sig?: unknown; ts?: unknown };
    try {
      body = (await request.json()) as { sig?: unknown; ts?: unknown };
    } catch {
      return Response.json({ error: "bad request" }, { status: 400 });
    }
    const { sig, ts } = body;
    if (typeof sig !== "string" || !/^[0-9a-f]{64}$/.test(sig) || typeof ts !== "number" || !Number.isFinite(ts)) {
      return Response.json({ error: "bad request" }, { status: 400 });
    }
    const claims = await this.loadClaims();
    for (const [s, t] of claims) if (t < ts - CLAIMS_TTL_S) claims.delete(s);
    if (claims.has(sig)) return Response.json({ ok: false });
    claims.set(sig, ts);
    const flushed = this.ctx.storage
      .put(CLAIMS_KEY, Object.fromEntries(claims))
      .catch((err: unknown) => {
        this.lastError = `claim flush failed: ${String(err)}`;
      });
    this.ctx.waitUntil(flushed);
    return Response.json({ ok: true });
  }

  /**
   * Live page WebSocket (REQ-SEC-037). The Worker has already authenticated
   * the upgrade (Bearer or login cookie); here we only accept the socket.
   * Hibernation (acceptWebSocket + alarm) keeps the connection and the sweep
   * alive across DO eviction.
   */
  private live(request: Request): Response {
    if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
      return Response.json({ error: "websocket upgrade required" }, { status: 426 });
    }
    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    this.ctx.acceptWebSocket(server);
    void this.sweepLive();
    void this.ctx.storage.setAlarm(Date.now() + LIVE_INTERVAL_MS);
    return new Response(null, { status: 101, webSocket: client });
  }

  /** Periodic sweep while clients are connected; stops when none remain. */
  async alarm(): Promise<void> {
    if (this.ctx.getWebSockets().length === 0) return;
    await this.sweepLive();
    await this.ctx.storage.setAlarm(Date.now() + LIVE_INTERVAL_MS);
  }

  private async sweepLive(): Promise<void> {
    const sockets = this.ctx.getWebSockets();
    if (sockets.length === 0) return;
    const send = (frame: unknown) => {
      const text = JSON.stringify(frame);
      for (const ws of sockets) {
        try { ws.send(text); } catch { /* a closing socket must not stop the sweep */ }
      }
    };
    if (this.lastStatus !== "Running") {
      send({ type: "node", node: this.lastStatus, loginPending: Boolean(this.browseUrl), at: Date.now() });
      // Keep the node starting in the background, as /health does.
      if (!this.ipn) this.ctx.waitUntil(this.ensureNode().catch((err) => { this.lastError = `node start failed: ${String(err).slice(0, 200)}`; }));
      return;
    }
    for (const section of SECTIONS) {
      let frame: Record<string, unknown>;
      try {
        const res = await this.monitor(section);
        const body: unknown = await res.json().catch(() => null);
        frame = { type: "section", section, status: res.status, body, at: Date.now() };
      } catch (err) {
        frame = { type: "section", section, status: 502, body: { error: "tailnet_unavailable", message: String(err) }, at: Date.now() };
      }
      send(frame);
    }
  }

  webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): void {
    // Clients only listen; the text "refresh" asks for an immediate sweep.
    void ws;
    if (typeof message === "string" && message === "refresh") void this.sweepLive();
  }

  webSocketClose(ws: WebSocket, code: number, reason: string): void {
    try { ws.close(code, reason); } catch { /* already closed */ }
  }

  webSocketError(ws: WebSocket): void {
    try { ws.close(1011, "error"); } catch { /* already closed */ }
  }

  /** Node status for diagnostics (no secrets). */
  /**
   * /health 用(鍵なしで見える)。秘密を含まない: ログインURL・IPアドレス・鍵の値は出さない。
   * ログインURLが漏れると、他人がこのノードを自分のtailnetに取り込める恐れがあるため。
   */
  async publicStatus(): Promise<Response> {
    // 鍵なしでも状態を確かめられるよう、ノードが無ければ起動を始める(待たない。起動は1回にまとめられる)。
    if (!this.ipn) this.ctx.waitUntil(this.ensureNode().catch((err) => { this.lastError = `node start failed: ${String(err).slice(0, 200)}`; }));
    // ノードは動いているのに受信側が決まっていなければ、到達確認を裏で走らせる(結果は receiverProbes に出る)。
    else if (this.lastStatus === "Running" && !this.resolver.cachedIp && !this.probing) {
      const ipn = this.ipn;
      this.probing = true;
      this.ctx.waitUntil(this.resolveReceiver(ipn, true).catch(() => null).finally(() => { this.probing = false; }));
    }
    return Response.json({
      node: this.ipn ? this.lastStatus : "not-started",
      authKeySource: this.authKeySource(),
      receiverKeySource: this.receiverKey()?.source ?? null,
      loginPending: this.lastStatus !== "Running" && Boolean(this.browseUrl),
      receiverCandidates: candidatesFor(this.peers, RECEIVER_NAME).length,
      receiverResolved: Boolean(this.resolver.cachedIp),
      receiverPort: this.resolver.probePort,
      receiverProbes: this.resolver.lastProbes,
      lastError: this.publicErrorSummary(),
    });
  }

  /**
   * The failure reason in public form (REQ-SEC-031): /health must show WHY
   * the node is down without needing a key, so the summary strips URLs, IP
   * addresses and any occurrence of the configured key values, and is
   * length-capped.
   */
  private publicErrorSummary(): string | null {
    if (!this.lastError) return null;
    let s = this.lastError;
    for (const secret of [this.authKey()?.value, this.receiverKey()?.value]) {
      if (secret) s = s.split(secret).join("[redacted]");
    }
    s = s.replace(/https?:\/\/\S+/g, "[url]").replace(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g, "[ip]").replace(/\s+/g, " ").trim();
    return s.length > 120 ? `${s.slice(0, 120)}…` : s;
  }

  async status(): Promise<Response> {
    if (!this.ipn) {
      return Response.json({
        node: "not-started",
        lastStatus: this.lastStatus,
        lastError: this.lastError,
        loginUrl: this.browseUrl,
        authKeyConfigured: Boolean(this.authKey()),
        authKeySource: this.authKeySource(),
      });
    }
    const raw = this.ipn.status();
    let parsed: unknown = raw;
    if (typeof raw === "string") {
      try {
        parsed = JSON.parse(raw);
      } catch {
        parsed = { raw };
      }
    }
    return Response.json({
      node: this.lastStatus,
      lastError: this.lastError,
      loginUrl: this.browseUrl,
      authKeyConfigured: Boolean(this.authKey()),
        authKeySource: this.authKeySource(),
      receiver: {
        baseName: RECEIVER_NAME,
        resolvedIp: this.resolver.cachedIp,
        candidates: candidatesFor(this.peers, RECEIVER_NAME),
      },
      tailscale: parsed,
    });
  }
}

