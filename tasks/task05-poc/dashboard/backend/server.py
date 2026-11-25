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
    ("blue", "http://blue:8080/health"),
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


CHAIN = (
    ("build", "Build"),
    ("delivery", "Delivery"),
    ("install", "Installation"),
    ("c2", "C2"),
    ("tasking", "Tasking"),
    ("detection", "Detection"),
    ("response", "Response"),
)


def _safe(call, path: str) -> dict[str, object]:
    try:
        return call(path)
    except RuntimeError:
        return {}


def killchain() -> dict[str, object]:
    """Summarise the run as seven phases from the apps' own state."""
    pipeline = _safe(call_pipeline, "/api/state")
    client = _safe(call_lab, "/api/client-state")
    attacker = _safe(call_lab, "/api/attacker-state")
    blue = _safe(call_lab, "/api/blue-state")

    releases = (pipeline.get("catalog") or {}).get("releases") or []
    components = client.get("components") or []
    beacons = attacker.get("beacons") or []
    results = attacker.get("results") or []
    alerts = blue.get("alerts") or []
    resolver = blue.get("resolver") or {}
    isolation = (blue.get("sensor") or {}).get("isolation") or {}

    done = {
        "build": any(isinstance(item, dict) and item.get("version") == "v3" for item in releases),
        "delivery": client.get("version") == "v3",
        "install": any(isinstance(item, dict) and item.get("status") == "running" for item in components),
        "c2": bool(beacons),
        "tasking": bool(results),
        "detection": any(
            isinstance(item, dict)
            and not (item.get("rule") == "T5-C2-001" and item.get("dport") == 8000)
            for item in alerts
        ),
        "response": bool(resolver.get("blocked")) or bool(isolation.get("active")),
    }

    phases: list[dict[str, object]] = []
    current = False
    for phase_id, label in CHAIN:
        if done[phase_id]:
            state = "done"
        elif not current:
            state = "active"
            current = True
        else:
            state = "pending"
        phases.append({"id": phase_id, "label": label, "state": state})
    return {"phases": phases, "done": sum(done.values()), "total": len(CHAIN)}


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
            state = running_services()
            state["killchain"] = killchain()
            self.send_json(200, state)
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
            notes: list[str] = []
            failures: list[str] = []
            try:
                pipeline = call_pipeline("/api/reset", "POST", {}, presenter=True)
                notes.append(str(pipeline.get("message", "Release channel reset.")))
            except RuntimeError as exc:
                failures.append(f"Release channel reset failed: {exc}")
            try:
                lab = call_lab("/api/reset", "POST", {})
                notes.append(str(lab.get("message", "Lab reset.")))
            except RuntimeError as exc:
                failures.append(f"Lab reset failed: {exc}")
            if failures:
                self.send_json(400, {"error": " ".join(failures + notes)})
                return
            self.send_json(200, {"message": " ".join(notes)})
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
