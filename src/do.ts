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
  // Optional: without it the node falls back to interactive login —
  // the operator opens the login URL (exposed in /api/status) and
  // approves the node once. With it, joining is unattended but the
  // key expires (90 days max) and a lost DO state then needs a new key.
  TS_AUTHKEY?: string;
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
const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;
const SECTIONS = new Set([
  "status", "diag", "jobs", "pkgs", "vm", "procs",
  "ports", "git", "recent", "pending", "execlog", "sdkhealth",
  "sdkprofiles", "sdksessions", "sdkts",
]);

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
   * The Tailscale auth key: TS_AUTHKEY, or TS_API_KEY when TS_AUTHKEY is
   * not set (the operator keeps one key for both). Only when neither is set
   * does the node fall back to interactive login.
   */
  private authKey(): string | undefined {
    return this.env.TS_AUTHKEY || this.env.TS_API_KEY || undefined;
  }

  /** Which secret the node's auth key comes from (never the value). */
  private authKeySource(): "TS_AUTHKEY" | "TS_API_KEY" | null {
    if (this.env.TS_AUTHKEY) return "TS_AUTHKEY";
    if (this.env.TS_API_KEY) return "TS_API_KEY";
    return null;
  }

  private async loadState(): Promise<void> {
    if (this.stateLoaded) return;
    const stored = await this.ctx.storage.get<Record<string, string>>(STATE_KEY);
    if (stored) {
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
   */
  private async ensureNode(): Promise<IPN> {
    if (!this.ipn) {
      this.starting ??= this.startNode().finally(() => {
        this.starting = null;
      });
      await this.starting;
    }
    const ipn = this.ipn!;
    if (this.lastStatus !== "Running") await this.waitForRunning();
    return ipn;
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

    const go = new Go();
    const instance = await WebAssembly.instantiate(wasmModule, go.importObject);
    void go.run(instance);
    const created = newIPN({
      ...(this.authKey() ? { authKey: this.authKey() } : {}),
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

    const callbacks: IPNCallbacks = {
      notifyState: (state: string) => {
        this.lastStatus = state;
        if (state !== "Running") return;
        this.pendingPanic = null;
        for (const w of [...this.waiters]) w.resolve();
      },
      notifyNetMap: (netMap: string) => {
        this.peers = parsePeers(netMap);
      },
      notifyBrowseToURL: (url: string) => {
        this.browseUrl = url;
      },
      notifyPanicRecover: (error: string) => {
        this.lastError = error;
        if (this.waiters.size === 0) this.pendingPanic = error;
        for (const w of [...this.waiters]) w.reject(new Error(error));
      },
    };
    ipn.run(callbacks);
    this.ipn = ipn;
    ipn.login(this.authKey());
    return ipn;
  }

  /** Durable Object entrypoint: /status and /monitor/<section>. */
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/status") return this.status();
    if (url.pathname === "/public-status") return this.publicStatus();
    if (url.pathname.startsWith("/monitor/")) {
      const section = url.pathname.slice("/monitor/".length);
      if (!SECTIONS.has(section)) {
        return Response.json({ error: "unknown monitor section" }, { status: 404 });
      }
      return this.monitor(section);
    }
    return Response.json({ error: "not found" }, { status: 404 });
  }

  /** Resolve (or re-resolve) the receiver's current tailnet IP. */
  private async resolveReceiver(ipn: IPN, force: boolean): Promise<string | null> {
    return this.resolver.resolve((req) => ipn.fetch(req), this.peers, force);
  }

  /** GET one monitor section from the receiver through the tailnet. */
  async monitor(section: string): Promise<Response> {
    let ipn: IPN;
    try {
      ipn = await this.ensureNode();
    } catch (err) {
      return Response.json(
        { error: "tailnet_unavailable", message: String(err) },
        { status: 502 },
      );
    }
    let ip = await this.resolveReceiver(ipn, false);
    if (!ip) {
      return Response.json(
        { error: "receiver_not_found", message: `no reachable peer named ${RECEIVER_NAME}(-*)` },
        { status: 502 },
      );
    }
    let resp;
    try {
      resp = await this.fetchSection(ipn, ip, section);
    } catch {
      // Transport failed against the cached peer: re-resolve once.
      this.resolver.invalidate();
      ip = await this.resolveReceiver(ipn, true);
      if (!ip) {
        return Response.json(
          { error: "receiver_not_found", message: `no reachable peer named ${RECEIVER_NAME}(-*)` },
          { status: 502 },
        );
      }
      try {
        resp = await this.fetchSection(ipn, ip, section);
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
    return new Response(text, {
      status: resp.status,
      headers: { "Content-Type": "application/json" },
    });
  }

  /** One GET against the receiver on a resolved peer IP. */
  private async fetchSection(ipn: IPN, ip: string, section: string) {
    return ipn.fetch({
      url: `http://${ip}:${RECEIVER_PORT}/monitor/${section}`,
      method: "GET",
    });
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
      loginPending: this.lastStatus !== "Running" && Boolean(this.browseUrl),
      receiverCandidates: candidatesFor(this.peers, RECEIVER_NAME).length,
      receiverResolved: Boolean(this.resolver.cachedIp),
      receiverPort: this.resolver.probePort,
      receiverProbes: this.resolver.lastProbes,
    });
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

