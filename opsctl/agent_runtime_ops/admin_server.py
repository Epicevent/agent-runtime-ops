from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    server_version = "AgentRuntimeOpsAdmin/0.1"

    def _send_json(self, data: dict, status: int = 200) -> None:
        body = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/api/health":
            self._send_json({"status": "ok", "service": "agent-runtime-ops-admin"})
            return
        if self.path == "/":
            body = (
                "<!doctype html><meta charset='utf-8'>"
                "<title>Agent Runtime Ops</title>"
                "<h1>Agent Runtime Ops</h1>"
                "<p>Initial admin console skeleton. Use /api/health for a machine-readable check.</p>"
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self._send_json({"error": "not_found"}, status=404)

    def log_message(self, fmt: str, *args: object) -> None:
        return


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18088)
    args = parser.parse_args(argv)
    if args.host not in {"127.0.0.1", "localhost"}:
        raise SystemExit("admin console must bind to loopback in the initial release")
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"admin_console=http://{args.host}:{args.port}")
    server.serve_forever()
    return 0

