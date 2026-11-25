#!/usr/bin/env python3
"""Prove the build-swap property without Docker.

Run from the repository:

    python3 pipeline/build/test_build_swap.py

It creates a throwaway release channel with a throwaway RSA key, builds V3 from
clean source, signs it, then rebuilds the same source without the
service-compat step.  Passing means:

  * the source tree is clean before the build,
  * the artifact carries a component the source never contained,
  * the manifest and the signature agree with the artifact,
  * a trusted rebuild disagrees with the artifact's component hash.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "backend"))

import build_release  # noqa: E402
import release_builder  # noqa: E402


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

        record = build_release.build(release_dir, inject=True)
        release_builder.sign_artifact(release_dir)
        artifact = release_builder.read_artifact(release_dir)

        trusted = build_release.build(release_dir, inject=False, stage=False)

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

        if record.get("changed") != ["orion_support.py"]:
            problems.append(f"build step did not report the swap: {record.get('changed')}")
        if source == workspace:
            problems.append("workspace component hash matches source; no swap happened")
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
        print("build-swap self-test")
        print("-" * width)
        print(f"{'source orion_support.py':<34} {source[:24]}")
        print(f"{'workspace after build step':<34} {workspace[:24]}")
        print(f"{'artifact component':<34} {packaged[:24]}")
        print(f"{'manifest pins':<34} {manifest_digest[:24]}")
        print(f"{'trusted rebuild (no step)':<34} {trusted_component[:24]}")
        print(f"{'files changed during build':<34} {', '.join(record.get('changed') or []) or 'none'}")
        print(f"{'artifact signed':<34} {artifact.get('signed') if artifact else False}")
        print("-" * width)
        if problems:
            for problem in problems:
                print(f"FAIL {problem}")
            return 1
        print("PASS source clean; artifact tampered; trusted rebuild disagrees")
        return 0


if __name__ == "__main__":
    sys.exit(main())
