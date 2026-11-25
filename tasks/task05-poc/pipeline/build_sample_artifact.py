#!/usr/bin/env python3
"""Build the sample V3 artifact that the presenter uploads to the pipeline.

The manifest declares the component that ships in the package and pins its
SHA-256.  The installer rejects a package whose extracted component does not
match that digest.  Run after editing payload/orion_support.py:

    python3 pipeline/build_sample_artifact.py
"""

from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PAYLOAD = ROOT / "payload" / "orion_support.py"
MANIFEST = ROOT / "sample-v3-manifest.json"
ARCHIVE = ROOT / "sample-v3-malicious.zip"


def main() -> None:
    component = PAYLOAD.read_bytes()
    manifest = {
        "product": "Orion Network Manager",
        "version": "v3",
        "release_notes": "Adds service health summaries",
        "client_config": {
            "theme": "midnight",
            "topology": True,
            "health_summary": True,
        },
        "components": [
            {
                "name": "orion-improvement-program",
                "file": PAYLOAD.name,
                "sha256": hashlib.sha256(component).hexdigest(),
                "args": ["10.0.0.3", "9000", "4"],
            }
        ],
    }
    MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    entries = [
        ("manifest.json", (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")),
        (PAYLOAD.name, component),
    ]
    with zipfile.ZipFile(ARCHIVE, "w") as package:
        for name, data in entries:
            info = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            package.writestr(info, data)
    print(f"{ARCHIVE.name}: {len(entries)} entries, {ARCHIVE.stat().st_size} bytes")
    print(f"component sha256 {manifest['components'][0]['sha256']}")


if __name__ == "__main__":
    main()
