import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

// SPEC.muse-monitor.security.hardening REQ-SEC-007/008/016/017:
// the key ledger (docs/KEY_LEDGER.md) must name exactly the secrets the code
// reads — no secret without a ledger row, no ledger row without a secret —
// and the same names must appear in wrangler.toml's comments.

const read = (rel: string) => readFileSync(new URL(rel, import.meta.url), "utf8");

const NON_SECRET_BINDINGS = new Set(["MONITOR_GATEWAY", "CF_VERSION_METADATA"]);

function envSecrets(src: string): string[] {
  const names = new Set<string>();
  for (const block of src.matchAll(/interface Env \{([\s\S]*?)\n\}/g)) {
    for (const line of block[1].split("\n")) {
      const m = /^\s*([A-Z][A-Z0-9_]*)\??:/.exec(line);
      if (m && !NON_SECRET_BINDINGS.has(m[1])) names.add(m[1]);
    }
  }
  return [...names].sort();
}

function ledgerRows(md: string): Map<string, string> {
  const rows = new Map<string, string>();
  for (const line of md.split("\n")) {
    const m = /^\| `([A-Z][A-Z0-9_]*)` \|/.exec(line);
    // The main table comes first; later tables (rotation record) repeat the
    // names with fewer columns and must not replace the main row.
    if (m && !rows.has(m[1])) rows.set(m[1], line);
  }
  return rows;
}

describe("key ledger (docs/KEY_LEDGER.md)", () => {
  const ledger = read("../docs/KEY_LEDGER.md");
  const rows = ledgerRows(ledger);
  const codeSecrets = [...new Set([...envSecrets(read("../src/index.ts")), ...envSecrets(read("../src/do.ts"))])].sort();

  it("names exactly the secrets the code reads", () => {
    expect(codeSecrets.length).toBeGreaterThan(0);
    expect([...rows.keys()].sort()).toEqual(codeSecrets);
  });

  it("every row records issuer, purpose, consumer, location, rotation and status", () => {
    expect(ledger).toContain("発行者");
    expect(ledger).toContain("用途");
    expect(ledger).toContain("消費側");
    expect(ledger).toContain("設定場所");
    expect(ledger).toContain("ローテーション");
    expect(ledger).toContain("状態");
    for (const [name, row] of rows) {
      // | name | issuer | purpose | consumer | location | rotation | status |
      expect(row.split("|").length, name).toBeGreaterThanOrEqual(9);
    }
  });

  it("the same names appear in wrangler.toml's secret comments", () => {
    const toml = read("../wrangler.toml");
    const commented = new Set([...toml.matchAll(/^#\s+([A-Z][A-Z0-9_]*)\s+-/gm)].map((m) => m[1]));
    expect([...commented].sort()).toEqual(codeSecrets);
  });

  it("records the rotation procedure and the alert split (REQ-SEC-016/017)", () => {
    expect(ledger).toContain("ローテーション記録");
    expect(ledger).toContain("receiver-watch");
    expect(ledger).toContain("WORKER_API_KEY");
    // Rotating WORKER_API_KEY invalidates the login cookies: the ledger must say so.
    const workerRow = rows.get("WORKER_API_KEY") ?? "";
    expect(workerRow).toContain("Cookie");
  });

  it("contains no secret value: the receiver key is referred to by name and place only", () => {
    expect(ledger).not.toMatch(/tskey-auth-[A-Za-z0-9]/);
    expect(ledger).not.toMatch(/[0-9a-f]{8} {0,2}指紋/);
  });

  it("has an expiry record for TS_AUTHKEY (REQ-SEC-032)", () => {
    expect(ledger).toContain("期限の記録");
    expect(ledger).toMatch(/TS_AUTHKEY[^|]*\|[^|]*期限|TS_AUTHKEY[^\n]*期限日/);
  });
});
