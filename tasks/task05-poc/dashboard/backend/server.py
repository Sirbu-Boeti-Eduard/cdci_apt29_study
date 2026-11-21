"""Minimal presenter dashboard: reset the lab and list running services."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import ProxyHandler, build_opener

from lab_client import call_lab, call_pipeline


PORT = 8080
FRONTEND_DIR = Path(__file__).resolve().parents[1] / "frontend"
ASSETS = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/favicon.svg": ("favicon.svg", "image/svg+xml"),
    "/styles.css": ("styles.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
}
SERVICES = (
    ("pipeline", "http://pipeline:8080/health"),
    ("lab", "http://lab:8080/health"),
    ("client", "http://client:8080/health"),
    ("attacker", "http://attacker:8080/health"),
    ("dashboard", "http://127.0.0.1:8080/health"),
    ("gateway", "http://gateway:8083/health"),
)
DIRECT_HTTP = build_opener(ProxyHandler({}))


def _running(url: str) -> bool:
    try:
        with DIRECT_HTTP.open(url, timeout=0.7) as response:
            return 200 <= response.status < 400
    except (HTTPError, URLError, TimeoutError, OSError):
        return False


def running_services() -> dict[str, object]:
    containers = [
        {"name": name, "status": "running"}
        for name, url in SERVICES
        if _running(url)
    ]
    return {"containers": containers}


class DashboardHandler(BaseHTTPRequestHandler):
    def send_bytes(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, status: int, value: dict[str, object]) -> None:
        self.send_bytes(status, json.dumps(value).encode("utf-8"), "application/json")

    def read_json(self) -> dict[str, object]:
        length = int(self.headers.get("Content-Length", "-1"))
        if length < 0 or length > 4096:
            raise ValueError("request body is too large")
        value = json.loads(self.rfile.read(length))
        if not isinstance(value, dict):
            raise ValueError("JSON body must be an object")
        return value

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
            self.send_json(200, running_services())
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
            self.read_json()
            if path != "/api/reset":
                self.send_json(404, {"error": "Not found."})
                return
            pipeline = call_pipeline("/api/reset", "POST", {}, presenter=True)
            lab = call_lab("/api/reset", "POST", {})
            message = f"{pipeline.get('message', 'Release channel reset.')} {lab.get('message', 'Lab reset.')}"
            self.send_json(200, {"message": message})
        except (ValueError, json.JSONDecodeError, OSError, RuntimeError) as exc:
            self.send_json(400, {"error": str(exc)})

    def log_message(self, _format: str, *_args: object) -> None:
        return


def main() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", PORT), DashboardHandler)
    print("Task 5 presentation dashboard ready on port 8080", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
