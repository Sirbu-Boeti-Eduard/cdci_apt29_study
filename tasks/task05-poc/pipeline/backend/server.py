"""Backend routes for the supplier-side build and release web app."""

from __future__ import annotations

import base64
import binascii
import copy
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from release_builder import (
    initialize_channel,
    load_or_initialize_channel,
    publish_artifact,
    read_artifact,
    read_catalog,
    sign_artifact,
    upload_artifact,
)

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
from build_release import build as build_from_source, log_lines as build_log_lines  # noqa: E402


PORT = 8080
RELEASE_DIR = Path(os.environ.get("RELEASE_DIR", "/data/releases"))
FRONTEND_DIR = Path(__file__).resolve().parents[1] / "frontend"
ASSETS = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/favicon.svg": ("favicon.svg", "image/svg+xml"),
    "/styles.css": ("styles.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
}
pipeline_lock = threading.RLock()


def _timestamped(line: str) -> str:
    return f"{time.strftime('%H:%M:%S')} INFO  {line}"


def log(message: str, level: str = "INFO") -> None:
    build_log.append(f"{time.strftime('%H:%M:%S')} {level:<5} {message}")
    del build_log[:-200]


build_log = [_timestamped(line) for line in load_or_initialize_channel(RELEASE_DIR)]

PIPELINE_STAGES = (
    ("checkout", "Source checkout"),
    ("build", "Build component"),
    ("manifest", "Generate manifest"),
    ("package", "Package artifact"),
    ("sign", "Sign artifact"),
    ("publish", "Publish catalog"),
)
pipeline_status_lock = threading.RLock()


def _new_pipeline() -> dict[str, object]:
    return {
        "state": "idle",
        "started_at": None,
        "finished_at": None,
        "rollout": "mandatory",
        "message": "",
        "stages": [
            {
                "id": stage_id,
                "name": name,
                "status": "pending",
                "started_at": None,
                "finished_at": None,
                "detail": "",
            }
            for stage_id, name in PIPELINE_STAGES
        ],
    }


pipeline_status = _new_pipeline()


def _clock() -> str:
    return time.strftime("%H:%M:%S")


def _start_stage(stage_id: str) -> None:
    with pipeline_status_lock:
        for stage in pipeline_status["stages"]:
            if stage["id"] == stage_id:
                stage["status"] = "running"
                stage["started_at"] = _clock()


def _finish_stage(stage_id: str, detail: str, log_detail: bool = True) -> None:
    with pipeline_status_lock:
        stages = pipeline_status["stages"]
        for index, stage in enumerate(stages):
            if stage["id"] != stage_id:
                continue
            stage["status"] = "done"
            stage["finished_at"] = _clock()
            stage["detail"] = detail
            if index + 1 < len(stages):
                following = stages[index + 1]
                following["status"] = "running"
                following["started_at"] = _clock()
            break
    if log_detail:
        log(detail)


def _progress(stage_id: str, detail: str) -> None:
    _finish_stage(stage_id, detail)


def run_pipeline(rollout: str) -> None:
    with pipeline_status_lock:
        pipeline_status.clear()
        pipeline_status.update(_new_pipeline())
        pipeline_status.update({
            "state": "running",
            "started_at": _clock(),
            "rollout": rollout,
            "message": "Release pipeline running.",
        })
    log("Release pipeline started")
    _start_stage("checkout")
    try:
        build_from_source(RELEASE_DIR, progress=_progress, stage_delay=0.45)
        with pipeline_lock:
            sign_artifact(RELEASE_DIR)
        _finish_stage("sign", "RSA/SHA-256 signature written")
        time.sleep(0.35)
        with pipeline_lock:
            entry, publish_log = publish_artifact(RELEASE_DIR, rollout)
            for line in publish_log:
                log(line)
        _finish_stage("publish", f"Published {entry['artifact']} to stable ({rollout})", log_detail=False)
        with pipeline_status_lock:
            pipeline_status.update({
                "state": "done",
                "finished_at": _clock(),
                "message": f"Published {entry['artifact']} to the stable channel.",
            })
    except Exception as exc:
        with pipeline_status_lock:
            pipeline_status.update({
                "state": "error",
                "finished_at": _clock(),
                "message": str(exc),
            })
            for stage in pipeline_status["stages"]:
                if stage["status"] == "running":
                    stage["status"] = "error"
                    stage["finished_at"] = _clock()
                    stage["detail"] = str(exc)
        log(f"Release pipeline failed: {exc}", "ERROR")


class PipelineHandler(BaseHTTPRequestHandler):
    def send_bytes(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, status: int, value: dict[str, object]) -> None:
        self.send_bytes(status, json.dumps(value).encode("utf-8"), "application/json")

    def read_json(self, limit: int = 16 * 1024) -> dict[str, object]:
        length = int(self.headers.get("Content-Length", "-1"))
        if length < 0 or length > limit:
            raise ValueError("request body is too large")
        value = json.loads(self.rfile.read(length))
        if not isinstance(value, dict):
            raise ValueError("JSON body must be an object")
        return value

    def same_origin(self) -> bool:
        from urllib.parse import urlsplit as parse_url

        origin = parse_url(self.headers.get("Origin", ""))
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
            with pipeline_lock:
                current_log = list(build_log)
                artifact = read_artifact(RELEASE_DIR)
                catalog = read_catalog(RELEASE_DIR)
            with pipeline_status_lock:
                pipeline = copy.deepcopy(pipeline_status)
            self.send_json(200, {
                "build_log": current_log,
                "artifact": artifact,
                "catalog": catalog,
                "pipeline": pipeline,
            })
        else:
            self.send_json(404, {"error": "Not found."})

    def do_POST(self) -> None:  # noqa: N802
        global build_log
        path = urlsplit(self.path).path
        if not self.same_origin() and self.headers.get("X-Presenter-Request") != "true":
            self.send_json(403, {"error": "State changes must come from this app's local origin."})
            return
        if self.headers.get_content_type() != "application/json":
            self.send_json(415, {"error": "Send a JSON request body."})
            return
        try:
            body = self.read_json(512 * 1024 if path == "/api/upload-artifact" else 16 * 1024)
            if path == "/api/upload-artifact":
                filename = body.get("filename")
                encoded = body.get("content_base64")
                if not isinstance(filename, str) or not isinstance(encoded, str):
                    raise ValueError("Choose a ZIP build artifact to upload.")
                try:
                    content = base64.b64decode(encoded, validate=True)
                except (binascii.Error, ValueError) as exc:
                    raise ValueError("Uploaded artifact is not valid base64.") from exc
                with pipeline_lock:
                    _artifact, log_lines = upload_artifact(RELEASE_DIR, filename, content)
                    for line in log_lines:
                        log(line)
                message = "Artifact uploaded. Review the manifest, then sign it."
            elif path == "/api/pipeline":
                rollout = str(body.get("rollout", "mandatory"))
                if rollout not in {"available", "mandatory"}:
                    raise ValueError("Choose available or mandatory rollout.")
                with pipeline_status_lock:
                    if pipeline_status["state"] == "running":
                        raise ValueError("A release pipeline is already running.")
                if any(
                    isinstance(entry, dict) and entry.get("version") == "v3"
                    for entry in read_catalog(RELEASE_DIR)["releases"]
                ):
                    raise ValueError("V3 is already published. Reset the demo before running the pipeline again.")
                threading.Thread(target=run_pipeline, args=(rollout,), daemon=True).start()
                message = "Release pipeline started."
            elif path == "/api/build":
                with pipeline_lock:
                    record = build_from_source(RELEASE_DIR)
                    for line in build_log_lines(record):
                        log(line)
                message = (
                    f"Built {record['artifact']['name']}; manifest pinned "
                    f"{record['artifact']['component_sha256'][:16]}."
                )
            elif path == "/api/sign-artifact":
                with pipeline_lock:
                    _artifact, log_lines = sign_artifact(RELEASE_DIR)
                    for line in log_lines:
                        log(line)
                message = "Artifact signed with the release key."
            elif path == "/api/publish-artifact":
                rollout = str(body.get("rollout", "mandatory"))
                with pipeline_lock:
                    entry, log_lines = publish_artifact(RELEASE_DIR, rollout)
                    for line in log_lines:
                        log(line)
                message = f"Published {entry['artifact']} to the stable channel with {rollout} rollout."
            elif path == "/api/reset":
                with pipeline_status_lock:
                    if pipeline_status["state"] == "running":
                        raise ValueError("A release pipeline is running; wait for it to finish before resetting.")
                    pipeline_status.clear()
                    pipeline_status.update(_new_pipeline())
                with pipeline_lock:
                    build_log = [_timestamped(line) for line in initialize_channel(RELEASE_DIR)]
                message = "Release channel reset to V1/V2."
            else:
                self.send_json(404, {"error": "Not found."})
                return
            self.send_json(200, {"message": message})
        except (ValueError, json.JSONDecodeError, OSError, RuntimeError, KeyError, binascii.Error) as exc:
            self.send_json(400, {"error": str(exc)})

    def log_message(self, _format: str, *_args: object) -> None:
        return


def main() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", PORT), PipelineHandler)
    print("Orion CI/CD web app ready on port 8080", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
