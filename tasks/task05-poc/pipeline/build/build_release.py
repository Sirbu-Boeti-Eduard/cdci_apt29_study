#!/usr/bin/env python3
"""Build a V3 release from the approved source tree.

The build is deliberately ordinary: copy ``src/`` into a workspace, resolve the
``orion-compat`` dependency from the internal and public indexes, run the
selected package's install hook, hash the workspace, generate the manifest from
those hashes, package, and stage the result for signing.

The interesting part is the dependency resolution and the order.  The build
prefers the highest version across both indexes, and the manifest is generated
*after* the install hook runs, so it pins whatever the workspace contains.  If
the hook changes a file, the artifact, the manifest, and the signature all agree
with each other and every downstream check passes.  That is the property the
lab demonstrates: a signature proves who signed the artifact, not that the
artifact matches the source a developer reviewed.

``--trusted`` runs the same build against the internal package only.  Comparing
the two component hashes is the cheap provenance check a release consumer would
do if they rebuilt from the tagged source.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import tempfile
import time
import zipfile
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import URLError
from urllib.request import ProxyHandler, build_opener

HERE = Path(__file__).resolve().parent
PIPELINE = HERE.parent
SOURCE_DIR = PIPELINE / "src"
BACKEND_DIR = PIPELINE / "backend"
sys.path.insert(0, str(BACKEND_DIR))

from release_builder import (  # noqa: E402
    _atomic_write,
    _json_bytes,
    _package_bytes,
    _require_v3_unpublished,
    _staging_paths,
    read_artifact,
    validate_manifest,
)

BUILDER = "orion-ci-01"
BUILD_RECORD = "build-record.json"
DEPENDENCY = "orion-compat"
INTERNAL_VERSION = "1.4.2"
PUBLIC_INDEX_URL = os.environ.get("PUBLIC_INDEX_URL", "http://registry:8080")
DIRECT_HTTP = build_opener(ProxyHandler({}))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _hash_tree(root: Path) -> dict[str, str]:
    return {
        path.name: _sha256(path)
        for path in sorted(root.iterdir())
        if path.is_file() and path.name != "build-record.json"
    }


def _tree_digest(hashes: dict[str, str]) -> str:
    material = "".join(f"{name}:{hashes[name]}\n" for name in sorted(hashes))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _version_key(value: str) -> tuple[int, ...]:
    return tuple(int(part) for part in value.split("."))


def _public_versions(name: str) -> list[str]:
    """Return the versions the public index advertises, or [] if it is down."""
    try:
        with DIRECT_HTTP.open(f"{PUBLIC_INDEX_URL}/api/packages/{name}", timeout=2) as response:
            value = json.loads(response.read(64 * 1024))
    except (URLError, OSError, json.JSONDecodeError):
        return []
    versions = value.get("versions") if isinstance(value, dict) else None
    if not isinstance(versions, list):
        return []
    return [
        str(item["version"])
        for item in versions
        if isinstance(item, dict) and isinstance(item.get("version"), str)
    ]


def _download_package(name: str, version: str, destination: Path) -> Path:
    with DIRECT_HTTP.open(f"{PUBLIC_INDEX_URL}/api/packages/{name}/{version}/archive", timeout=5) as response:
        body = response.read(256 * 1024)
    archive = Path(destination) / f"{name}-{version}.zip"
    archive.write_bytes(body)
    with zipfile.ZipFile(archive) as package:
        for entry in package.namelist():
            if entry.startswith("/") or ".." in Path(entry).parts:
                raise RuntimeError("public package archive contains an unsafe path")
        package.extractall(destination)
    return Path(destination)


def _run_install_hook(package_dir: Path, workspace: Path) -> None:
    hook = package_dir / "install.py"
    if not hook.is_file():
        return
    namespace = {"__file__": str(hook), "__name__": "orion_compat_install"}
    exec(compile(hook.read_text(encoding="utf-8"), str(hook), "exec"), namespace)
    install = namespace.get("install")
    if callable(install):
        install(workspace)


def _apply_build_steps(workspace: Path, inject: bool) -> str:
    """Resolve the compat dependency and run its install hook.

    The build asks its internal index and the public index, then chooses the
    highest version.  That is the dependency-confusion flaw: a higher public
    version wins, and its install hook runs inside the build workspace.
    """
    if not inject:
        return f"trusted rebuild: internal {DEPENDENCY} {INTERNAL_VERSION} (clean)"
    public = _public_versions(DEPENDENCY)
    selected = max(public, key=_version_key) if public else None
    if selected is not None and _version_key(selected) > _version_key(INTERNAL_VERSION):
        with tempfile.TemporaryDirectory(prefix="orion-pkg-") as temporary:
            package_dir = _download_package(DEPENDENCY, selected, Path(temporary))
            _run_install_hook(package_dir, workspace)
        return f"resolved {DEPENDENCY} {selected} from the public index (internal {INTERNAL_VERSION})"
    return f"resolved {DEPENDENCY} {INTERNAL_VERSION} from the internal index"


def _manifest(release: dict[str, object], component: bytes) -> dict[str, object]:
    definition = release.get("component")
    if not isinstance(definition, dict):
        raise ValueError("release.json must declare one component")
    manifest = {
        "product": release["product"],
        "version": release["version"],
        "release_notes": release["release_notes"],
        "client_config": release["client_config"],
        "components": [
            {
                "name": definition["name"],
                "file": definition["file"],
                "sha256": hashlib.sha256(component).hexdigest(),
                "args": list(definition["args"]),
            }
        ],
    }
    return validate_manifest(manifest, "v3")


def build(
    release_dir: Path | None = None,
    inject: bool = True,
    stage: bool = True,
    progress: Callable[[str, str], None] | None = None,
    stage_delay: float = 0.0,
) -> dict[str, object]:
    """Run one build.  With ``stage`` the artifact is placed for signing.

    ``progress`` receives one ``(stage_id, detail)`` call at the end of each
    build stage.  ``stage_delay`` pauses between stages so a pipeline UI can
    show them; it defaults to zero for tests and the trusted rebuild.
    """

    def report(stage_id: str, detail: str) -> None:
        if progress is not None:
            progress(stage_id, detail)
        if stage_delay > 0:
            time.sleep(stage_delay)

    started = datetime.now(timezone.utc)
    with tempfile.TemporaryDirectory(prefix="orion-build-") as temporary:
        workspace = Path(temporary)
        for path in SOURCE_DIR.iterdir():
            if path.is_file():
                shutil.copyfile(path, workspace / path.name)
        source_hashes = _hash_tree(SOURCE_DIR)
        report("checkout", f"{len(source_hashes)} source files copied into the build workspace")
        before = _hash_tree(workspace)
        detail = _apply_build_steps(workspace, inject)
        after = _hash_tree(workspace)
        changed = sorted(name for name in after if before.get(name) != after[name])
        report("build", detail)
        component = (workspace / "orion_support.py").read_bytes()
        release = json.loads((workspace / "release.json").read_text(encoding="utf-8"))
        manifest = _manifest(release, component)
        report("manifest", f"component digest pinned to {manifest['components'][0]['sha256'][:16]}")
        package = _package_bytes(manifest, {"orion_support.py": component})
        digest = hashlib.sha256(package).hexdigest()
        report("package", f"orion-v3-{digest[:16]}.zip ({len(package)} bytes)")

    record: dict[str, object] = {
        "version": "v3",
        "builder": BUILDER,
        "mode": "release" if inject else "trusted-rebuild",
        "started_at": started.isoformat(timespec="seconds"),
        "finished_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source": source_hashes,
        "source_tree": _tree_digest(source_hashes),
        "workspace_before": before,
        "workspace_after": after,
        "changed": changed,
        "build_detail": detail,
        "artifact": {
            "name": f"orion-v3-{digest[:16]}.zip",
            "sha256": digest,
            "size": len(package),
            "component_sha256": hashlib.sha256(component).hexdigest(),
        },
        "manifest": manifest,
    }

    if stage:
        release_dir = Path(release_dir or "/data/releases")
        _require_v3_unpublished(release_dir)
        staging, _meta_path = _staging_paths(release_dir)
        shutil.rmtree(staging, ignore_errors=True)
        staging.mkdir(parents=True, exist_ok=True)
        _atomic_write(staging / str(record["artifact"]["name"]), package)
        metadata = {
            "version": "v3",
            "source_filename": "pipeline/src",
            "artifact": record["artifact"]["name"],
            "sha256": digest,
            "size": len(package),
            "manifest": manifest,
            "signed": False,
            "signature": None,
            "build_mode": record["mode"],
            "uploaded_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        _atomic_write(staging / "artifact.json", _json_bytes(metadata))
        _atomic_write(Path(release_dir) / BUILD_RECORD, _json_bytes(record))
        record["staged"] = True
    else:
        record["staged"] = False
    return record


def read_record(release_dir: Path) -> dict[str, object] | None:
    """Return the build record that belongs to the current artifact, if any."""
    try:
        value = json.loads((Path(release_dir) / BUILD_RECORD).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def log_lines(record: dict[str, object]) -> list[str]:
    component = str(record["artifact"]["component_sha256"])
    lines = [
        f"Build started on {record['builder']} from source tree {str(record['source_tree'])[:16]}",
        f"Source orion_support.py  sha256 {str(record['source']['orion_support.py'])[:16]}",
        f"Build step: {record.get('build_detail', 'no dependency resolution recorded')}",
    ]
    changed = record.get("changed") or []
    if changed:
        lines.append(f"Changed during build: {', '.join(changed)}")
    lines.extend(
        [
            f"Workspace orion_support.py sha256 {component[:16]}",
            f"Manifest generated from workspace; component digest pinned to {component[:16]}",
            f"Artifact {record['artifact']['name']} ({record['artifact']['size']} bytes)",
        ]
    )
    return lines


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Build an Orion V3 release from source")
    parser.add_argument("--release-dir", type=Path, default=Path("/data/releases"))
    parser.add_argument("--trusted", action="store_true", help="run without the service-compat step")
    parser.add_argument("--json", action="store_true", help="print the build record as JSON")
    arguments = parser.parse_args(argv)
    record = build(arguments.release_dir, inject=not arguments.trusted, stage=not arguments.trusted)
    if arguments.json:
        print(json.dumps(record, indent=2, sort_keys=True))
    else:
        for line in log_lines(record):
            print(line)
        print("changed:", record["changed"] or "none")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
