#!/usr/bin/env python3
"""Build a V3 release from the approved source tree.

The build is deliberately ordinary: copy ``src/`` into a workspace, run the
configured build steps, hash what is in the workspace, generate the manifest
from those hashes, package, and stage the result for signing.

The interesting part is the order.  The manifest is generated *after* the build
steps run, so it pins whatever the workspace contains.  If a build step changes
a file, the artifact, the manifest, and the signature all agree with each other
and every downstream check passes.  That is the property the lab demonstrates:
a signature proves who signed the artifact, not that the artifact matches the
source a developer reviewed.

``--trusted`` runs the same build without the site-specific step.  Comparing the
two component hashes is the cheap provenance check a release consumer would do
if they rebuilt from the tagged source.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
PIPELINE = HERE.parent
SOURCE_DIR = PIPELINE / "src"
PAYLOAD_DIR = PIPELINE / "payload"
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
COMPONENT_STEP = "service-compat"
BUILD_RECORD = "build-record.json"


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


def _apply_build_steps(workspace: Path, inject: bool) -> list[str]:
    """Run the build steps; return the files they changed.

    ``service-compat`` is the step that keeps the telemetry shim aligned with
    the current service ABI.  In a clean build it is a no-op.  In the build we
    are studying it replaces the shim with the version shipped in ``payload/``.
    """
    if not inject:
        return []
    source = PAYLOAD_DIR / "orion_support.py"
    target = workspace / "orion_support.py"
    if not source.is_file() or not target.is_file():
        raise RuntimeError(f"{COMPONENT_STEP}: build inputs are missing")
    shutil.copyfile(source, target)
    return ["orion_support.py"]


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
) -> dict[str, object]:
    """Run one build.  With ``stage`` the artifact is placed for signing."""
    started = datetime.now(timezone.utc)
    with tempfile.TemporaryDirectory(prefix="orion-build-") as temporary:
        workspace = Path(temporary)
        for path in SOURCE_DIR.iterdir():
            if path.is_file():
                shutil.copyfile(path, workspace / path.name)
        source_hashes = _hash_tree(SOURCE_DIR)
        before = _hash_tree(workspace)
        changed = _apply_build_steps(workspace, inject)
        after = _hash_tree(workspace)
        component = (workspace / "orion_support.py").read_bytes()
        release = json.loads((workspace / "release.json").read_text(encoding="utf-8"))
        manifest = _manifest(release, component)
        package = _package_bytes(manifest, {"orion_support.py": component})
        digest = hashlib.sha256(package).hexdigest()

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
            "source_filename": f"build/{COMPONENT_STEP}",
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
    ]
    changed = record.get("changed") or []
    if changed:
        lines.append(f"{COMPONENT_STEP} step changed {', '.join(changed)}")
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
