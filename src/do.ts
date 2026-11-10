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
  TS_HOST_URL: string;
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
      notifyNetMap: () => undefined,
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
    const url = `${this.env.TS_HOST_URL.replace(/\/$/, "")}/monitor/${section}`;
    let resp;
    try {
      resp = await ipn.fetch({
        url,
        method: "GET",
        headers: [["Authorization", `Bearer ${this.env.TS_API_KEY}`]],
      });
    } catch (err) {
      return Response.json(
        { error: "delivery_unknown", message: `tailnet GET failed: ${String(err)}` },
        { status: 502 },
      );
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
      tailscale: parsed,
    });
  }
}
