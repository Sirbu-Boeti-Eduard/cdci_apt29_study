"""Blue Team app: the inline sensor's findings and the enforced response actions."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from lab_client import call_lab, fetch_capture


PORT = 8080
FRONTEND_DIR = Path(__file__).resolve().parents[1] / "frontend"
ASSETS = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/favicon.svg": ("favicon.svg", "image/svg+xml"),
    "/styles.css": ("styles.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
}
ACTIONS = ("block-dns", "unblock-dns", "isolate", "restore-tap")


class BlueHandler(BaseHTTPRequestHandler):
    def send_bytes(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, status: int, value: dict[str, object]) -> None:
        self.send_bytes(status, json.dumps(value).encode("utf-8"), "application/json")

    def same_origin(self) -> bool:
        origin = urlsplit(self.headers.get("Origin", ""))
        host = self.headers.get("Host", "")
        return (
            origin.scheme == "http"
            and origin.hostname in {"localhost", "127.0.0.1", "::1"}
            and origin.netloc.lower() == host.lower()
            and origin.username is None
            and origin.password is None
        )

    def do_GET(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if path in ASSETS:
            filename, content_type = ASSETS[path]
            self.send_bytes(200, (FRONTEND_DIR / filename).read_bytes(), content_type)
        elif path == "/health":
            self.send_json(200, {"ready": True})
        elif path == "/api/state":
            try:
                self.send_json(200, call_lab("/api/blue-state"))
            except RuntimeError as exc:
                self.send_json(503, {"error": str(exc)})
        elif path == "/capture.pcap":
            try:
                self.send_bytes(200, fetch_capture(), "application/vnd.tcpdump.pcap")
            except RuntimeError as exc:
                self.send_json(404, {"error": str(exc)})
        else:
            self.send_json(404, {"error": "Not found."})

    def do_POST(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if not self.same_origin():
            self.send_json(403, {"error": "State changes must come from this app's local origin."})
            return
        if self.headers.get_content_type() != "application/json":
            self.send_json(415, {"error": "Send a JSON request body."})
            return
        try:
            length = int(self.headers.get("Content-Length", "-1"))
            if length < 0 or length > 4096:
                raise ValueError("invalid body length")
            body = json.loads(self.rfile.read(length))
            if not isinstance(body, dict):
                raise ValueError("JSON body must be an object")
            if path != "/api/respond":
                self.send_json(404, {"error": "Not found."})
                return
            action = str(body.get("action", ""))
            if action not in ACTIONS:
                raise ValueError("Unknown response action.")
            self.send_json(200, call_lab("/api/response", "POST", {"action": action}))
        except (ValueError, json.JSONDecodeError, RuntimeError) as exc:
            self.send_json(400, {"error": str(exc)})

    def log_message(self, _format: str, *_args: object) -> None:
        return


def main() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", PORT), BlueHandler)
    print("Task 5 Blue Team app ready on port 8080", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
