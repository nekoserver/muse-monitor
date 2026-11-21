#!/usr/bin/env python3
"""Gate tests for the lib monitor receiver (~/lib/muse/samples/receiver.py).

Covers SPEC.muse-monitor.security.hardening REQ-SEC-001/002/004/020/060/062 (v21) and 063/064/065 (v22):
  - /monitor/* and /queue require Authorization: Bearer <TS_API_KEY>
  - no key configured on the receiver -> 503 receiver_key_not_configured (one name, REQ-SEC-062)
  - wrong or missing Bearer -> 401
  - /health stays open and carries keyFingerprint (SHA-256 of the key, first 8 hex
    chars; null while no key is configured), and a 401 body carries
    expectedKeyFingerprint / presentedKeyFingerprint (REQ-SEC-060). Key values
    themselves never appear in any response body
  - the key is loaded from the receiver env file (~/.config/muse-receiver.env)
  - rotation (v22): while TS_API_KEY_PREVIOUS + TS_API_KEY_PREVIOUS_UNTIL are in
    the env file and the deadline has not passed, the previous key is accepted;
    after the deadline it is rejected and identified by its fingerprint. The
    receiver re-reads the env file when it changes (no restart), and /health
    reports previousKeyFingerprint / previousKeyUntil during an overlap

Run: python3 test/receiver_gate_test.py
The receiver under test defaults to ~/lib/muse/samples/receiver.py and can
be overridden with the RECEIVER_PY environment variable.
"""
import hashlib
import importlib.util
import socket
import subprocess
import time
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
from http.server import ThreadingHTTPServer
import urllib.error
import urllib.request

RECEIVER_PY = os.environ.get(
    "RECEIVER_PY", str(Path.home() / "lib" / "muse" / "samples" / "receiver.py"))

spec = importlib.util.spec_from_file_location("lib_receiver", RECEIVER_PY)
receiver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(receiver)

KEY = "test-receiver-key"


def fp(value):
    """SPEC v21 REQ-SEC-060: first 8 hex chars of the value's SHA-256."""
    return hashlib.sha256(value.encode()).hexdigest()[:8]


def call(port, path, key=None):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", method="GET")
    if key is not None:
        req.add_header("Authorization", f"Bearer {key}")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def serve(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


def main():
    results = []

    def check(name, ok):
        results.append((name, ok))
        print(f"{'PASS' if ok else 'FAIL'}: {name}")

    with tempfile.TemporaryDirectory() as td:
        scripts = Path(td)
        (scripts / "echo.sh").write_text("#!/bin/sh\necho hello-from-echo\n")
        (scripts / "echo.sh").chmod(0o755)
        sections = {"echo": "echo.sh"}

        # No key configured: gated paths are 503, /health stays open.
        server, port = serve(receiver.make_handler(None, scripts_dir=scripts, sections=sections))
        try:
            s, b = call(port, "/monitor/echo")
            check("no key configured: /monitor/echo -> 503 receiver_key_not_configured",
                  s == 503 and b.get("error") == "receiver_key_not_configured")
            s, b = call(port, "/queue")
            check("no key configured: /queue -> 503", s == 503)
            s, b = call(port, "/health")
            check("no key configured: /health -> 200", s == 200 and b.get("status") == "ok")
            check("no key configured: /health keyFingerprint is present and null",
                  "keyFingerprint" in b and b.get("keyFingerprint") is None)
        finally:
            server.shutdown()

        # Key configured: Bearer required and compared.
        server, port = serve(receiver.make_handler(KEY, scripts_dir=scripts, sections=sections))
        try:
            s, b = call(port, "/monitor/echo")
            check("key set, no header: /monitor/echo -> 401", s == 401)
            check("401 without a Bearer: expected fingerprint is the receiver key's, presented is null",
                  b.get("expectedKeyFingerprint") == fp(KEY) and b.get("presentedKeyFingerprint") is None)
            check("401 body never contains the key value", KEY not in json.dumps(b))
            s, b = call(port, "/monitor/echo", key="wrong")
            check("key set, wrong key: /monitor/echo -> 401", s == 401)
            check("401 with a wrong key: presented fingerprint is the wrong key's",
                  b.get("expectedKeyFingerprint") == fp(KEY) and b.get("presentedKeyFingerprint") == fp("wrong"))
            s, b = call(port, "/monitor/echo", key=KEY)
            check("key set, correct key: /monitor/echo -> 200 with the section output",
                  s == 200 and b.get("section") == "echo" and "hello-from-echo" in b.get("output", ""))
            s, _ = call(port, "/queue", key=KEY)
            check("key set, correct key: /queue -> 200", s == 200)
            s, _ = call(port, "/queue")
            check("key set, no header: /queue -> 401", s == 401)
            s, b = call(port, "/health")
            check("key set: /health -> 200 without a header", s == 200 and b.get("status") == "ok")
            check("key set: /health keyFingerprint is the key's fingerprint, never the value",
                  b.get("keyFingerprint") == fp(KEY) and KEY not in json.dumps(b))
            s, _ = call(port, "/monitor/unknown", key=KEY)
            check("key set, correct key: unknown section -> 404", s == 404)
        finally:
            server.shutdown()

        # Key loading from the receiver env file.
        env_file = scripts / "muse-receiver.env"
        env_file.write_text("OTHER=1\nTS_API_KEY=loaded-key-1\n")
        check("load_key reads TS_API_KEY from the env file", receiver.load_key(env_file) == "loaded-key-1")
        env_file.write_text("TS_API_KEY=first\nTS_API_KEY=last\n")
        check("load_key takes the last TS_API_KEY line", receiver.load_key(env_file) == "last")
        env_file.write_text("OTHER=1\n")
        check("load_key without the line -> None", receiver.load_key(env_file) is None)
        check("load_key with a missing file -> None", receiver.load_key(scripts / "nope.env") is None)

        # Rotation, exercised against the receiver's real CLI entry point
        # (SPEC v22 REQ-SEC-063/064/065, AC-SEC-038). Phase A rewrites the env
        # file under a running process (the file is the live truth: no restart).
        # Phases B-D start fresh processes so expiry and no-deadline behavior are
        # judged on startup-loaded state, independent of the re-read.
        def wait_status(port, path, key, want, tries=40):
            last = None
            for _ in range(tries):
                try:
                    last = call(port, path, key=key)
                except Exception:
                    last = None
                if last is not None and last[0] == want:
                    return last
                time.sleep(0.05)
            return last

        def start_receiver(env_text):
            env_file = scripts / "rotation.env"
            env_file.write_text(env_text)
            sock = socket.socket()
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
            sock.close()
            proc = subprocess.Popen(
                [sys.executable, RECEIVER_PY, "--host", "127.0.0.1", "--port", str(port),
                 "--key-env-file", str(env_file)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return proc, port, env_file

        # Phase A: rotate under a running receiver.
        proc, rot_port, rot_env = start_receiver("TS_API_KEY=old-key\n")
        try:
            s, _ = wait_status(rot_port, "/queue", "old-key", 200)
            check("rotation: the starting key is accepted", s == 200)
            until = int(time.time()) + 3600
            rot_env.write_text(
                f"TS_API_KEY=new-key\nTS_API_KEY_PREVIOUS=old-key\nTS_API_KEY_PREVIOUS_UNTIL={until}\n")
            s, _ = wait_status(rot_port, "/queue", "new-key", 200)
            check("rotation: the new key is accepted without a restart (file re-read)", s == 200)
            s, _ = call(rot_port, "/queue", key="old-key")
            _, hb = call(rot_port, "/health")
            # Conjoin the health fingerprint: on a receiver that never re-read
            # the file, old-key is still its ONLY key and a bare 200 would be a
            # false pass. Overlap acceptance only counts once current == new.
            check("rotation: the previous key is accepted during the overlap",
                  s == 200 and hb.get("keyFingerprint") == fp("new-key"))
            s, b = call(rot_port, "/health")
            check("rotation: /health shows the current and previous fingerprints and the deadline",
                  b.get("keyFingerprint") == fp("new-key")
                  and b.get("previousKeyFingerprint") == fp("old-key")
                  and b.get("previousKeyUntil") == until)
        finally:
            proc.terminate()

        # Phase B: the overlap deadline has already passed at startup.
        proc, rot_port, _ = start_receiver(
            f"TS_API_KEY=new-key\nTS_API_KEY_PREVIOUS=old-key\nTS_API_KEY_PREVIOUS_UNTIL={int(time.time()) - 10}\n")
        try:
            s, b = wait_status(rot_port, "/queue", "old-key", 401)
            check("rotation: the previous key is rejected after the deadline, identified by its fingerprint",
                  s == 401 and b.get("presentedKeyFingerprint") == fp("old-key"))
            s, _ = call(rot_port, "/queue", key="new-key")
            check("rotation: the current key works after the deadline", s == 200)
        finally:
            proc.terminate()

        # Phase C: a previous key with no deadline is never accepted.
        proc, rot_port, _ = start_receiver("TS_API_KEY=new-key\nTS_API_KEY_PREVIOUS=old-key\n")
        try:
            s, _ = wait_status(rot_port, "/queue", "old-key", 401)
            check("rotation: a previous key without a deadline is never accepted", s == 401)
        finally:
            proc.terminate()

        # Phase D: no overlap configured: /health carries the fields as null.
        proc, rot_port, _ = start_receiver("TS_API_KEY=new-key\n")
        try:
            s, b = wait_status(rot_port, "/health", None, 200)
            check("rotation: /health reports null previous fields when no overlap is configured",
                  "previousKeyFingerprint" in b and b.get("previousKeyFingerprint") is None
                  and "previousKeyUntil" in b and b.get("previousKeyUntil") is None)
        finally:
            proc.terminate()

    failed = [name for name, ok in results if not ok]
    print(f"{len(results) - len(failed)}/{len(results)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
