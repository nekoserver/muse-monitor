/**
 * ts-discover — shared tailnet peer discovery for WASM Workers.
 *
 * Rule (see ~/AGENTS.md, "tailnet peer addressing rule"): never hardcode
 * a peer's tailnet IP or full hostname. Hold only the base name, take
 * candidates from this node's own netmap (base name and base-N numeric
 * suffixes), probe reachability to decide the actual peer, cache the
 * winner, and re-resolve when transport fails. IPs change when a node
 * re-registers, and Tailscale may suffix duplicate names.
 *
 * Reuse by copying this file into the other Worker projects
 * (muse-code-wasm). It depends only on a minimal fetch-like function
 * with the ipn.fetch shape, so it stays transport-agnostic.
 */

export interface PeerCandidate {
  /** First DNS label, e.g. "muse-vm" or "muse-vm-1". */
  name: string;
  /** Current tailnet IPv4 of the peer. */
  ip: string;
}

export type ProbeFetch = (request: {
  url: string;
  method?: string;
  headers?: [string, string][];
}) => Promise<{ status: number; cancel(): void }>;

/**
 * Extract peer candidates (first DNS label + first IPv4) from the
 * netmap JSON delivered by the WASM node's notifyNetMap callback. The
 * exact field layout of the serialization is not typed, so plausible
 * spellings are all tried and unknown shapes yield no candidates.
 */
export function parsePeers(netMapJson: string): PeerCandidate[] {
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
    // The WASM node (tsconnect jsNetMapNode) serializes "addresses"; the
    // other spellings come from the Go/LocalAPI status shapes.
    const ips =
      rec["addresses"] ?? rec["Addresses"] ?? rec["TailscaleIPs"] ?? rec["tailscaleIPs"];
    if (typeof name === "string" && Array.isArray(ips)) {
      const label = name.split(".")[0].replace(/\.$/, "");
      const ip = ips
        .filter((a): a is string => typeof a === "string")
        .map((a) => a.split("/")[0])
        .find((a) => a.includes("."));
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

/** Candidates for a base name: exact name first, then -1, -2, ... */
export function candidatesFor(
  peers: PeerCandidate[],
  baseName: string,
): PeerCandidate[] {
  const base = new RegExp(`^${baseName}(-\\d+)?$`);
  return peers
    .filter((p) => base.test(p.name))
    .sort((a, b) => a.name.localeCompare(b.name, undefined, { numeric: true }));
}

/**
 * Stateful resolver: probes candidates via an unauthenticated health
 * path and caches the first reachable peer IP.
 */
export class PeerResolver {
  private resolvedIp: string | null = null;

  constructor(
    private readonly baseName: string,
    private readonly port: number,
    private readonly healthPath = "/health",
    private readonly probeTimeoutMs = 5000,
  ) {}

  get cachedIp(): string | null {
    return this.resolvedIp;
  }

  /** Drop the cache (call when transport against the cached IP fails). */
  invalidate(): void {
    this.resolvedIp = null;
  }

  async resolve(
    probeFetch: ProbeFetch,
    peers: PeerCandidate[],
    force = false,
  ): Promise<string | null> {
    if (this.resolvedIp && !force) return this.resolvedIp;
    for (const c of candidatesFor(peers, this.baseName)) {
      if (await this.probe(probeFetch, c.ip)) {
        this.resolvedIp = c.ip;
        return c.ip;
      }
    }
    this.resolvedIp = null;
    return null;
  }

  private async probe(probeFetch: ProbeFetch, ip: string): Promise<boolean> {
    try {
      const attempt = (async () => {
        const resp = await probeFetch({
          url: `http://${ip}:${this.port}${this.healthPath}`,
          method: "GET",
          headers: [],
        });
        resp.cancel();
        return resp.status === 200;
      })();
      const timeout = new Promise<boolean>((resolve) =>
        setTimeout(() => resolve(false), this.probeTimeoutMs),
      );
      return await Promise.race([attempt, timeout]);
    } catch {
      return false;
    }
  }
}
