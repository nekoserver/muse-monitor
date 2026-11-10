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

interface Env {
  TS_AUTHKEY: string;
  TS_API_KEY: string;
}

// The receiver is the shared muse-code-wasm receiver on the host node.
// Only the node's base name is fixed here: its tailnet IP changes when
// the node re-registers, and its name may gain a numeric suffix
// (muse-vm-1, muse-vm-2, ...). The concrete peer is therefore resolved
// at runtime from this node's own netmap, and confirmed by probing the
// receiver's /health (see resolveReceiver below).
const RECEIVER_NAME = "muse-vm";
const RECEIVER_PORT = 8090;
const PROBE_TIMEOUT_MS = 5000;

interface PeerCandidate {
  name: string;
  ip: string;
}

const STATE_KEY = "ts-state";
const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;
const SECTIONS = new Set([
  "status", "diag", "jobs", "pkgs", "vm", "procs",
  "ports", "git", "recent", "pending", "execlog", "sdkhealth",
]);

export class MonitorGateway extends DurableObject<Env> {
  private ipn: IPN | null = null;
  private ready: Promise<void> | null = null;
  private readyResolve: (() => void) | null = null;
  private readyReject: ((err: Error) => void) | null = null;
  private state = new Map<string, string>();
  private stateLoaded = false;
  private flushPending: Promise<void> | null = null;
  private lastStatus = "not-started";
  private lastError: string | null = null;
  private peers: PeerCandidate[] = [];
  private resolvedIp: string | null = null;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.ready = new Promise<void>((resolve, reject) => {
      this.readyResolve = resolve;
      this.readyReject = reject;
    });
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

  private async ensureNode(): Promise<IPN> {
    if (this.ipn) return this.ipn;
    await this.loadState();
    if (!this.env.TS_AUTHKEY) {
      throw new Error("TS_AUTHKEY secret is not set");
    }

    const go = new Go();
    const instance = await WebAssembly.instantiate(wasmModule, go.importObject);
    void go.run(instance);
    const created = newIPN({
      authKey: this.env.TS_AUTHKEY,
      hostname: "muse-monitor",
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
    this.ipn = ipn;

    const callbacks: IPNCallbacks = {
      notifyState: (state: string) => {
        this.lastStatus = state;
        if (state === "Running") this.readyResolve?.();
      },
      notifyNetMap: (netMap: string) => {
        this.peers = parsePeers(netMap);
      },
      notifyBrowseToURL: () => undefined,
      notifyPanicRecover: (error: string) => {
        this.lastError = error;
        this.readyReject?.(new Error(error));
      },
    };
    ipn.run(callbacks);
    ipn.login(this.env.TS_AUTHKEY);

    const timeout = new Promise<void>((_, reject) =>
      setTimeout(() => reject(new Error("tailscale node did not reach Running in 60s")), 60_000),
    );
    await Promise.race([this.ready, timeout]);
    return ipn;
  }

  /** Durable Object entrypoint: /status and /monitor/<section>. */
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/status") return this.status();
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
   * Resolve the receiver's current tailnet IP: candidates are netmap
   * peers named RECEIVER_NAME or RECEIVER_NAME-<n>; each is probed via
   * the receiver's unauthenticated /health. The first that answers is
   * cached; the cache is dropped whenever a request fails in transport.
   */
  private async resolveReceiver(ipn: IPN, force: boolean): Promise<string | null> {
    if (this.resolvedIp && !force) return this.resolvedIp;
    const base = new RegExp(`^${RECEIVER_NAME}(-\\d+)?$`);
    const candidates = this.peers.filter((p) => base.test(p.name));
    // Exact name first, then suffixed names in ascending order.
    candidates.sort((a, b) => a.name.localeCompare(b.name));
    for (const c of candidates) {
      if (await this.probe(ipn, c.ip)) {
        this.resolvedIp = c.ip;
        return c.ip;
      }
    }
    this.resolvedIp = null;
    return null;
  }

  /** Probe one candidate's receiver /health (no auth needed). */
  private async probe(ipn: IPN, ip: string): Promise<boolean> {
    try {
      const attempt = (async () => {
        const resp = await ipn.fetch({
          url: `http://${ip}:${RECEIVER_PORT}/health`,
          method: "GET",
          headers: [],
        });
        resp.cancel();
        return resp.status === 200;
      })();
      const timeout = new Promise<boolean>((resolve) =>
        setTimeout(() => resolve(false), PROBE_TIMEOUT_MS),
      );
      return await Promise.race([attempt, timeout]);
    } catch {
      return false;
    }
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
      headers: [["Authorization", `Bearer ${this.env.TS_API_KEY}`]],
    });
  }

  /** Node status for diagnostics (no secrets). */
  async status(): Promise<Response> {
    if (!this.ipn) {
      return Response.json({
        node: "not-started",
        lastStatus: this.lastStatus,
        lastError: this.lastError,
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
      receiver: {
        baseName: RECEIVER_NAME,
        resolvedIp: this.resolvedIp,
        candidates: this.peers.filter((p) =>
          new RegExp(`^${RECEIVER_NAME}(-\\d+)?$`).test(p.name),
        ),
      },
      tailscale: parsed,
    });
  }
}

/**
 * Extract peer candidates (first DNS label + first IPv4) from the
 * netmap JSON delivered by notifyNetMap. The exact field layout of the
 * WASM build's serialization is not typed, so the plausible spellings
 * are all tried and unknown shapes simply yield no candidates.
 */
function parsePeers(netMapJson: string): PeerCandidate[] {
  let root: unknown;
  try {
    root = JSON.parse(netMapJson);
  } catch {
    return [];
  }
  const out: PeerCandidate[] = [];
  const seen = new Set<string>();
  const visit = (value: unknown, depth: number): void => {
    if (depth > 6 || value === null || typeof value !== "object") return;
    if (Array.isArray(value)) {
      for (const item of value) visit(item, depth + 1);
      return;
    }
    const rec = value as Record<string, unknown>;
    const name = rec["Name"] ?? rec["name"];
    const ips = rec["TailscaleIPs"] ?? rec["tailscaleIPs"] ?? rec["Addresses"];
    if (typeof name === "string" && Array.isArray(ips)) {
      const label = name.split(".")[0].replace(/\.$/, "");
      const ip = ips.find(
        (a): a is string => typeof a === "string" && a.includes("."),
      );
      if (label && ip && !seen.has(label)) {
        seen.add(label);
        out.push({ name: label, ip });
      }
    }
    for (const v of Object.values(rec)) visit(v, depth + 1);
  };
  visit(root, 0);
  return out;
}
