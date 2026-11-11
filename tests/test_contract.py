#!/usr/bin/env python3
"""Contract tests for muse-monitor <-> receiver.

Written after the 2026-11-11 all-errors incident: the unit tests and the
unauthenticated live checks all passed while the real path
(Worker -> WASM node -> tailnet -> receiver) was never exercised.
These tests guard the seams that CAN be checked from here:

  1. The section lists agree in all three places they are defined
     (Worker dashboard, Durable Object allowlist, receiver).
  2. The secret names the Worker code reads are exactly the names the
     README / wrangler.toml tell the operator to set, and the
     receiver's auth env name is the documented counterpart.
  3. Live local contract: the receiver, started under its documented
     env name, answers every Worker section with the right key,
     rejects a wrong key, and 404s an unknown section.
  3b. Pairing contract against the production receiver code (the lib
     sample): a request built exactly as the DO builds it succeeds
     only when the Worker's TS_API_KEY value equals the receiver's;
     a missing secret must never reach the receiver as the literal
     token "undefined" (the DO guards instead).
  4. Deployed Worker, outside the auth gate only: /health is 200 and
     the gated routes reject unauthenticated calls. (The authenticated
     path cannot be tested from here; it needs the operator's key.)

Run: python3 tests/test_contract.py
"""
import json
import os
import re
import secrets
import subprocess
import sys
import time
import urllib.request
import urllib.error

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RECEIVER = os.path.expanduser("~/workspace/muse-code-wasm/receiver/receiver.py")
DEPLOYED = "https://muse-monitor.nekoflare.workers.dev"

results = []


def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(("PASS" if ok else "FAIL"), name, detail if not ok else "")


def read(p):
    with open(p) as f:
        return f.read()


# --- 1. section lists agree -------------------------------------------------
idx = read(os.path.join(ROOT, "src/index.ts"))
do = read(os.path.join(ROOT, "src/do.ts"))
rcv = read(RECEIVER)

dash_sections = set(re.findall(r'\["([a-z]+)", "', idx))
do_sections = set(re.findall(r'"([a-z]+)",?\n?\s*\]\);', do)[0:0])  # placeholder
m = re.search(r"const SECTIONS = new Set\(\[(.*?)\]\);", do, re.S)
do_sections = set(re.findall(r'"([a-z]+)"', m.group(1))) if m else set()
m = re.search(r"MONITOR_SECTIONS\s*=\s*\{(.*?)\n\}", rcv, re.S)
rcv_sections = set(re.findall(r'"([a-z]+)":', m.group(1))) if m else set()
check("sections: dashboard == DO allowlist", dash_sections == do_sections,
      f"dash={sorted(dash_sections)} do={sorted(do_sections)}")
check("sections: DO allowlist == receiver", do_sections == rcv_sections,
      f"do={sorted(do_sections)} rcv={sorted(rcv_sections)}")

# --- 2. secret names: code vs docs ------------------------------------------
code_names = set(re.findall(r"env\.([A-Z][A-Z_]+)", idx + do))
code_names.discard("MONITOR_GATEWAY")  # a binding, not a secret
docs = read(os.path.join(ROOT, "README.md")) + read(os.path.join(ROOT, "wrangler.toml"))
doc_put = set(re.findall(r"secret put ([A-Z][A-Z_]+)", docs))
check("secrets: every name the code reads is documented for `secret put`",
      code_names <= doc_put, f"code={sorted(code_names)} put={sorted(doc_put)}")
check("secrets: no documented `secret put` name is unread by the code",
      doc_put <= code_names, f"put={sorted(doc_put)} code={sorted(code_names)}")
rcv_env = set(re.findall(r'os\.environ\[?"?([A-Z][A-Z_]+)"?\]?', rcv)) | \
          set(re.findall(r'os\.environ\.get\("([A-Z][A-Z_]+)"', rcv)) | \
          set(re.findall(r'getenv\("([A-Z][A-Z_]+)"', rcv))
check("receiver: auth env name is the documented TS_API_KEY",
      "TS_API_KEY" in rcv_env, f"rcv_env={sorted(rcv_env)}")
check("guard: DO refuses to call the receiver when TS_API_KEY is unset",
      "receiver_key_not_configured" in do and "if (!this.env.TS_API_KEY)" in do)

# --- 3. live local contract ---------------------------------------------------
key = secrets.token_urlsafe(24)
env = dict(os.environ, TS_API_KEY=key, MUSE_CODE_WASM_PORT="18090")
proc = subprocess.Popen(
    [sys.executable, RECEIVER], env=env,
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    base = "http://127.0.0.1:18090"
    for _ in range(50):
        try:
            urllib.request.urlopen(base + "/health", timeout=2)
            break
        except Exception:
            time.sleep(0.2)

    def call(path, k=None):
        req = urllib.request.Request(base + path)
        if k:
            req.add_header("Authorization", "Bearer " + k)
        try:
            with urllib.request.urlopen(req, timeout=70) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, {}

    bad = [s for s in sorted(do_sections) if call(f"/monitor/{s}", key)[0] != 200]
    check("live: every section returns 200 with the key", not bad, f"bad={bad}")
    st, _ = call("/monitor/status", "wrong-key")
    check("live: wrong key is 401", st == 401, f"got {st}")
    st, _ = call("/monitor/no-such-section", key)
    check("live: unknown section is 404", st == 404, f"got {st}")
finally:
    proc.terminate()

# --- 3b. pairing contract against the production receiver (lib sample) -------
SAMPLE = os.path.expanduser("~/workspace/lib-muse/muse/samples/receiver.py")
pair_key = secrets.token_urlsafe(24)
env = dict(os.environ, TS_API_KEY=pair_key)
proc = subprocess.Popen(
    [sys.executable, SAMPLE, "--host", "127.0.0.1", "--port", "18091"],
    env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    base = "http://127.0.0.1:18091"

    def scall(path, k=None):
        req = urllib.request.Request(base + path)
        if k is not None:
            req.add_header("Authorization", "Bearer " + k)
        try:
            with urllib.request.urlopen(req, timeout=70) as r:
                return r.status
        except urllib.error.HTTPError as e:
            return e.code
        except Exception:
            return -1

    for _ in range(50):
        if scall("/monitor/status") == 401:
            break
        time.sleep(0.2)
    # Requests below are built exactly as the DO builds them:
    # Authorization: Bearer <the Worker's TS_API_KEY value>.
    check("pairing: equal TS_API_KEY value returns 200",
          scall("/monitor/status", pair_key) == 200)
    check("pairing: different value is 401",
          scall("/monitor/status", pair_key + "x") == 401)
    check("pairing: literal 'undefined' token is 401",
          scall("/monitor/status", "undefined") == 401)
    check("pairing: no Authorization header is 401",
          scall("/monitor/status") == 401)
finally:
    proc.terminate()

# --- 4. deployed Worker, outside the gate ------------------------------------
def dcall(path, headers=None):
    h = {"User-Agent": "Mozilla/5.0 (contract-test)"}
    h.update(headers or {})
    req = urllib.request.Request(DEPLOYED + path, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return -1

check("deployed: /health is 200", dcall("/health") == 200)
check("deployed: /api/monitor/status without key is 401",
      dcall("/api/monitor/status") == 401)
check("deployed: /api/hmac/monitor/status without signature is 401",
      dcall("/api/hmac/monitor/status") == 401)

failed = [n for n, ok, _ in results if not ok]
print(f"\n{len(results) - len(failed)}/{len(results)} passed")
sys.exit(1 if failed else 0)
