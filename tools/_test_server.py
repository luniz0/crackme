#!/usr/bin/env python3
"""Stdlib-only local test harness for the C++ client.

Serves the SAME binary protocol as server/app/main.py by calling the very same
challenge_logic handlers, but without FastAPI/uvicorn (handy on machines where
those aren't installed). Behavior matches main.py exactly: base64 in/out, and a
constant {"ok": false, "error": "invalid proof"} on any failure.

    python tools/_test_server.py            # listens on 127.0.0.1:31337
"""
from __future__ import annotations

import base64
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "server"))

from app import challenge_logic as L   # noqa: E402
from app import config                 # noqa: E402

GENERIC = json.dumps({"ok": False, "error": "invalid proof"}).encode()
ROUTES = {
    "/api/v1/hello": L.handle_hello,
    "/api/v1/exchange": L.handle_exchange,
    "/api/v1/finalize": L.handle_finalize,
}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # quiet
        pass

    def _send(self, code: int, body: bytes, ctype="text/plain"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            self._send(200, json.dumps(
                {"status": "ok", "service": "rankgate-insane", "version": 6}).encode(),
                "application/json")
        elif self.path == "/api/v1/public-key":
            self._send(200, json.dumps(
                {"alg": "ed25519", "public_key": config.SERVER_SIGN_PK.hex()}).encode(),
                "application/json")
        else:
            self._send(404, b"not found")

    def do_POST(self):
        handler = ROUTES.get(self.path)
        if handler is None:
            self._send(404, b"not found")
            return
        n = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(n).strip()
        try:
            raw = base64.b64decode(body, validate=False)
            out = handler(raw)
            self._send(200, base64.b64encode(out))
        except Exception as exc:  # noqa: BLE001
            sys.stderr.write(f"rejected: {exc!r}\n")
            self._send(200, GENERIC, "application/json")


def main():
    port = config.LISTEN_PORT
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"[test-server] listening on http://127.0.0.1:{port}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
