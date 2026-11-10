import { afterEach, describe, expect, it, vi } from "vitest";
import { candidatesFor, parsePeers, PeerResolver, type ProbeFetch } from "../src/ts-discover";

// What can break: the netmap shape differs from what parsePeers expects, a
// look-alike name (muse-vm2, muse-vmx) is taken for the receiver, a dead
// candidate is cached, or a hung probe blocks resolution forever.

describe("parsePeers", () => {
  it("reads the WASM netmap shape (name + addresses) and takes the first IPv4", () => {
    const netmap = JSON.stringify({
      peers: [
        { name: "muse-vm.taile4e096.ts.net.", addresses: ["fd7a:115c:a1e0::1", "100.86.29.77"] },
        { name: "ipad.taile4e096.ts.net.", addresses: ["100.74.35.120"] },
      ],
    });
    expect(parsePeers(netmap)).toEqual([
      { name: "muse-vm", ip: "100.86.29.77" },
      { name: "ipad", ip: "100.74.35.120" },
    ]);
  });

  it("also reads the Go-style spelling (Name + TailscaleIPs) nested deeper", () => {
    const netmap = JSON.stringify({ Peers: { list: [{ Name: "muse-vm-1.x.ts.net", TailscaleIPs: ["100.1.2.3"] }] } });
    expect(parsePeers(netmap)).toEqual([{ name: "muse-vm-1", ip: "100.1.2.3" }]);
  });

  it("keeps the first entry when a name repeats and skips peers without IPv4", () => {
    const netmap = JSON.stringify({
      peers: [
        { name: "muse-vm.a.", addresses: ["100.0.0.1"] },
        { name: "muse-vm.b.", addresses: ["100.0.0.2"] },
        { name: "v6only.a.", addresses: ["fd7a::9"] },
      ],
    });
    expect(parsePeers(netmap)).toEqual([{ name: "muse-vm", ip: "100.0.0.1" }]);
  });

  it.each(["", "not json", "null", "42", JSON.stringify({ peers: "x" })])("returns no candidates for %j", (input) => {
    expect(parsePeers(input)).toEqual([]);
  });
});

describe("candidatesFor", () => {
  const peers = [
    { name: "muse-vm-10", ip: "100.0.0.10" },
    { name: "muse-vm2", ip: "100.0.0.99" },
    { name: "muse-vm-2", ip: "100.0.0.2" },
    { name: "muse-vmx", ip: "100.0.0.98" },
    { name: "muse-vm", ip: "100.0.0.1" },
    { name: "x-muse-vm", ip: "100.0.0.97" },
  ];

  it("takes the exact name first, then -N in numeric order, and nothing that only looks similar", () => {
    expect(candidatesFor(peers, "muse-vm").map((p) => p.name)).toEqual(["muse-vm", "muse-vm-2", "muse-vm-10"]);
  });
});

describe("PeerResolver", () => {
  afterEach(() => { vi.useRealTimers(); });

  const peers = [
    { name: "muse-vm", ip: "100.0.0.1" },
    { name: "muse-vm-1", ip: "100.0.0.2" },
  ];
  const probeBy = (healthy: Set<string>) => {
    const calls: string[] = [];
    const cancel = vi.fn();
    const fetch: ProbeFetch = async ({ url }) => {
      calls.push(url);
      return { status: healthy.has(new URL(url).hostname) ? 200 : 503, cancel };
    };
    return { fetch, calls, cancel };
  };

  it("probes /health on the given port and caches the first healthy candidate", async () => {
    const resolver = new PeerResolver("muse-vm", 8090);
    const probe = probeBy(new Set(["100.0.0.2"]));
    expect(await resolver.resolve(probe.fetch, peers)).toBe("100.0.0.2");
    expect(probe.calls).toEqual(["http://100.0.0.1:8090/health", "http://100.0.0.2:8090/health"]);
    expect(probe.cancel).toHaveBeenCalledTimes(2);
    expect(resolver.cachedIp).toBe("100.0.0.2");
    // cached: no new probes
    expect(await resolver.resolve(probe.fetch, peers)).toBe("100.0.0.2");
    expect(probe.calls).toHaveLength(2);
  });

  it("re-probes on force and after invalidate, and clears the cache when nothing answers", async () => {
    const resolver = new PeerResolver("muse-vm", 8090);
    await resolver.resolve(probeBy(new Set(["100.0.0.1"])).fetch, peers);
    expect(await resolver.resolve(probeBy(new Set()).fetch, peers, true)).toBeNull();
    expect(resolver.cachedIp).toBeNull();
    await resolver.resolve(probeBy(new Set(["100.0.0.1"])).fetch, peers);
    resolver.invalidate();
    expect(resolver.cachedIp).toBeNull();
  });

  it("treats a probe that throws as unreachable and moves on", async () => {
    const resolver = new PeerResolver("muse-vm", 8090);
    const fetch: ProbeFetch = async ({ url }) => {
      if (url.includes("100.0.0.1")) throw new Error("dial failed");
      return { status: 200, cancel() {} };
    };
    expect(await resolver.resolve(fetch, peers)).toBe("100.0.0.2");
  });

  it("gives up on a probe that never answers after the timeout", async () => {
    vi.useFakeTimers();
    const resolver = new PeerResolver("muse-vm", 8090, "/health", 5000);
    const fetch: ProbeFetch = async ({ url }) => (url.includes("100.0.0.1") ? new Promise(() => {}) : { status: 200, cancel() {} });
    const pending = resolver.resolve(fetch, peers);
    await vi.advanceTimersByTimeAsync(5000);
    expect(await pending).toBe("100.0.0.2");
  });

  it("returns null when the netmap has no candidate", async () => {
    const resolver = new PeerResolver("muse-vm", 8090);
    const probe = probeBy(new Set(["100.0.0.1"]));
    expect(await resolver.resolve(probe.fetch, [{ name: "ipad", ip: "100.0.0.1" }])).toBeNull();
    expect(probe.calls).toEqual([]);
  });
});

describe("parsePeers with the netmap shape the bundled WASM emits", () => {
  // json tags in @ai-ecoverse/wasm-tailscale's main.wasm: self, peers, name, addresses.
  // Before the fix this shape yielded no peers, so every request ended in receiver_not_found.
  it("finds muse-vm among peers and also lists self, with CIDR suffixes removed", () => {
    const netmap = JSON.stringify({
      nodeKey: "nodekey:x", machineKey: "mkey:x",
      self: { name: "muse-monitor.taile4e096.ts.net.", addresses: ["100.99.0.5/32", "fd7a::5/128"] },
      peers: [{ name: "muse-vm.taile4e096.ts.net.", addresses: ["100.86.29.77/32"], online: true }],
    });
    const peers = parsePeers(netmap);
    expect(peers).toContainEqual({ name: "muse-vm", ip: "100.86.29.77" });
    expect(candidatesFor(peers, "muse-vm")).toEqual([{ name: "muse-vm", ip: "100.86.29.77" }]);
  });
});
