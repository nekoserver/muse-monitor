#!/usr/bin/env python3
"""Gate tests for the lib monitor receiver (~/lib/muse/samples/receiver.py).

Covers SPEC.muse-monitor.security.hardening REQ-SEC-001/002/004/020:
  - /monitor/* and /queue require Authorization: Bearer <TS_API_KEY>
  - no key configured on the receiver -> 503 receiver_key_missing
  - wrong or missing Bearer -> 401
  - /health stays open
  - the key is loaded from the receiver env file (~/.config/muse-receiver.env)

Run: python3 test/receiver_gate_test.py
The receiver under test defaults to ~/lib/muse/samples/receiver.py and can
be overridden with the RECEIVER_PY environment variable.
"""
import importlib.util
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
            check("no key configured: /monitor/echo -> 503 receiver_key_missing",
                  s == 503 and b.get("error") == "receiver_key_missing")
            s, b = call(port, "/queue")
            check("no key configured: /queue -> 503", s == 503)
            s, b = call(port, "/health")
            check("no key configured: /health -> 200", s == 200 and b.get("status") == "ok")
        finally:
            server.shutdown()

        # Key configured: Bearer required and compared.
        server, port = serve(receiver.make_handler(KEY, scripts_dir=scripts, sections=sections))
        try:
            s, _ = call(port, "/monitor/echo")
            check("key set, no header: /monitor/echo -> 401", s == 401)
            s, _ = call(port, "/monitor/echo", key="wrong")
            check("key set, wrong key: /monitor/echo -> 401", s == 401)
            s, b = call(port, "/monitor/echo", key=KEY)
            check("key set, correct key: /monitor/echo -> 200 with the section output",
                  s == 200 and b.get("section") == "echo" and "hello-from-echo" in b.get("output", ""))
            s, _ = call(port, "/queue", key=KEY)
            check("key set, correct key: /queue -> 200", s == 200)
            s, _ = call(port, "/queue")
            check("key set, no header: /queue -> 401", s == 401)
            s, b = call(port, "/health")
            check("key set: /health -> 200 without a header", s == 200 and b.get("status") == "ok")
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

    failed = [name for name, ok in results if not ok]
    print(f"{len(results) - len(failed)}/{len(results)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
