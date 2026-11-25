#!/usr/bin/env python3
"""Prove the dependency-confusion build path without Docker.

Run from the repository:

    python3 pipeline/build/test_build_swap.py

It creates a throwaway release channel with a throwaway RSA key and a tiny
local package index.  Publishing ``orion-compat 2.0.0`` there means the build
resolves the public package over its internal ``1.4.2``, runs the package's
install hook, and packages the injected component.  Passing means:

  * the source tree is clean before the build,
  * the public package's hook changed the workspace,
  * the manifest and the signature agree with the artifact,
  * a trusted rebuild (internal package only) disagrees with the artifact.
"""

from __future__ import annotations

import io
import json
import subprocess
import sys
import tempfile
import threading
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "backend"))

import build_release  # noqa: E402
import release_builder  # noqa: E402

HOOK = (
    "from pathlib import Path\n\n"
    "def install(workspace):\n"
    "    source = Path(__file__).resolve().parent / 'orion_support.py'\n"
    "    target = Path(workspace) / 'orion_support.py'\n"
    "    target.write_bytes(source.read_bytes())\n"
)


def _package_zip() -> bytes:
    payload = (HERE.parents[1] / "registry" / "payload" / "orion_support.py").read_bytes()
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as package:
        package.writestr("install.py", HOOK)
        package.writestr("orion_support.py", payload)
        package.writestr("orion_compat/__init__.py", '"""orion-compat 2.0.0."""\n')
    return buffer.getvalue()


def _serve(archive: bytes) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/api/packages/orion-compat":
                body = json.dumps({"name": "orion-compat", "versions": [{"version": "2.0.0"}]}).encode()
                content_type = "application/json"
            elif self.path == "/api/packages/orion-compat/2.0.0/archive":
                body = archive
                content_type = "application/zip"
            else:
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *_args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def main() -> int:
    problems: list[str] = []
    with tempfile.TemporaryDirectory(prefix="orion-swap-test-") as temporary:
        root = Path(temporary)
        key = root / "signing-private.pem"
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(key)],
            check=True,
            capture_output=True,
        )
        release_builder.PRIVATE_KEY = key
        release_dir = root / "releases"
        release_builder.initialize_channel(release_dir)

        server = _serve(_package_zip())
        try:
            build_release.PUBLIC_INDEX_URL = f"http://127.0.0.1:{server.server_address[1]}"
            stages: list[str] = []
            record = build_release.build(
                release_dir,
                inject=True,
                progress=lambda stage, _detail: stages.append(stage),
            )
            release_builder.sign_artifact(release_dir)
            artifact = release_builder.read_artifact(release_dir)
            trusted = build_release.build(release_dir, inject=False, stage=False)
        finally:
            server.shutdown()
            server.server_close()

        if stages != ["checkout", "build", "manifest", "package"]:
            problems.append(f"unexpected pipeline stages: {stages}")

        source = record["source"]["orion_support.py"]
        workspace = record["workspace_after"]["orion_support.py"]
        packaged = record["artifact"]["component_sha256"]
        manifest_digest = record["manifest"]["components"][0]["sha256"]
        trusted_component = trusted["artifact"]["component_sha256"]

        persisted = build_release.read_record(release_dir)
        if persisted is None:
            problems.append("build record was not persisted for the current artifact")
        elif persisted.get("artifact", {}).get("component_sha256") != packaged:
            problems.append("persisted build record does not match the artifact")

        if "public index" not in str(record.get("build_detail", "")):
            problems.append(f"build did not resolve from the public index: {record.get('build_detail')}")
        if record.get("changed") != ["orion_support.py"]:
            problems.append(f"build did not report the workspace change: {record.get('changed')}")
        if source == workspace:
            problems.append("workspace component hash matches source; no injection happened")
        if packaged != workspace:
            problems.append("packaged component hash does not match the workspace")
        if packaged != manifest_digest:
            problems.append("manifest does not pin the packaged component")
        if trusted_component != source:
            problems.append("trusted rebuild does not reproduce the source component")
        if trusted_component == packaged:
            problems.append("trusted rebuild matches the artifact; detection would not work")
        if not artifact or artifact.get("signed") is not True:
            problems.append("staged artifact was not signed")

        if artifact:
            archive = release_dir / "staging" / str(artifact["artifact"])
            with zipfile.ZipFile(archive) as package:
                names = package.namelist()
                if set(names) != {"manifest.json", "orion_support.py"}:
                    problems.append(f"unexpected package entries: {names}")
                embedded = json.loads(package.read("manifest.json"))
                if embedded["components"][0]["sha256"] != packaged:
                    problems.append("embedded manifest digest does not match the build record")

        width = 62
        print("dependency-confusion self-test")
        print("-" * width)
        print(f"{'build detail':<34} {str(record.get('build_detail'))[:60]}")
        print(f"{'source orion_support.py':<34} {source[:24]}")
        print(f"{'workspace after install hook':<34} {workspace[:24]}")
        print(f"{'artifact component':<34} {packaged[:24]}")
        print(f"{'manifest pins':<34} {manifest_digest[:24]}")
        print(f"{'trusted rebuild (internal)':<34} {trusted_component[:24]}")
        print(f"{'files changed during build':<34} {', '.join(record.get('changed') or []) or 'none'}")
        print(f"{'artifact signed':<34} {artifact.get('signed') if artifact else False}")
        print("-" * width)
        if problems:
            for problem in problems:
                print(f"FAIL {problem}")
            return 1
        print("PASS source clean; public package won; trusted rebuild disagrees")
        return 0


if __name__ == "__main__":
    sys.exit(main())
