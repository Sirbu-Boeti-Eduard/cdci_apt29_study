"""Create, sign, stage, and publish data-only Orion release artifacts."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import zipfile
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from typing import Any


PRODUCT = "Orion Network Manager"
STAGING_DIR = "staging"
ARTIFACT_META = "artifact.json"
RELEASES = ("v1", "v2", "v3")
PRIVATE_KEY = Path(os.environ.get("SIGNING_PRIVATE_KEY", "/keys/signing-private.pem"))


def default_manifest(version: str) -> dict[str, Any]:
    settings = {
        "v1": {
            "theme": "classic",
            "topology": False,
            "health_summary": False,
            "release_notes": "Initial network operations release",
        },
        "v2": {
            "theme": "midnight",
            "topology": True,
            "health_summary": False,
            "release_notes": "Adds the topology view and midnight theme",
        },
    }
    if version not in settings:
        raise ValueError("Unknown release version.")
    config = settings[version]
    return {
        "product": PRODUCT,
        "version": version,
        "release_notes": config["release_notes"],
        "client_config": {
            "theme": config["theme"],
            "topology": config["topology"],
            "health_summary": config["health_summary"],
        },
        "exercise": {"diagnostic_checkin": False},
    }


def validate_manifest(value: object, expected_version: str = "v3") -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"product", "version", "release_notes", "client_config", "exercise"}:
        raise ValueError("Manifest fields do not match the V3 release format.")
    if value.get("product") != PRODUCT or value.get("version") != expected_version:
        raise ValueError(f"Upload a {expected_version.upper()} manifest for {PRODUCT}.")
    release_notes = value.get("release_notes")
    if not isinstance(release_notes, str) or len(release_notes) > 240:
        raise ValueError("Release notes must be text up to 240 characters.")
    config = value.get("client_config")
    if not isinstance(config, dict) or set(config) != {"theme", "topology", "health_summary"}:
        raise ValueError("Client configuration fields are invalid.")
    theme = config.get("theme")
    if not isinstance(theme, str) or theme not in {"classic", "midnight"}:
        raise ValueError("Theme must be classic or midnight.")
    if not isinstance(config.get("topology"), bool) or not isinstance(config.get("health_summary"), bool):
        raise ValueError("Client feature settings must be true or false.")
    exercise = value.get("exercise")
    if not isinstance(exercise, dict) or set(exercise) != {"diagnostic_checkin"}:
        raise ValueError("Exercise settings are invalid.")
    if not isinstance(exercise.get("diagnostic_checkin"), bool):
        raise ValueError("The V3 diagnostic setting must be true or false.")
    return json.loads(json.dumps(value))


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(data)
    os.replace(temporary, path)


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _package_bytes(manifest: dict[str, Any]) -> bytes:
    buffer = BytesIO()
    info = zipfile.ZipInfo("manifest.json", date_time=(2020, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o100644 << 16
    with zipfile.ZipFile(buffer, "w") as package:
        package.writestr(info, _json_bytes(manifest))
    return buffer.getvalue()


def _sign_artifact(package_path: Path, private_key: Path) -> Path:
    signature_path = package_path.with_suffix(package_path.suffix + ".sig")
    temporary_signature = signature_path.with_suffix(signature_path.suffix + ".tmp")
    subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", str(private_key), "-out", str(temporary_signature), str(package_path)],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    os.replace(temporary_signature, signature_path)
    return signature_path


def _publish_package(release_dir: Path, version: str, manifest: dict[str, Any]) -> dict[str, Any]:
    package_bytes = _package_bytes(manifest)
    digest = hashlib.sha256(package_bytes).hexdigest()
    package_name = f"orion-{version}-{digest[:16]}.zip"
    package_path = release_dir / package_name
    _atomic_write(package_path, package_bytes)
    signature_path = _sign_artifact(package_path, PRIVATE_KEY)
    return {
        "version": version,
        "artifact": package_name,
        "signature": signature_path.name,
        "sha256": digest,
        "size": len(package_bytes),
        "mandatory": False,
        "published_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def read_catalog(release_dir: Path) -> dict[str, Any]:
    try:
        value = json.loads((release_dir / "catalog.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Release catalog is unavailable: {exc}") from exc
    if not isinstance(value, dict) or not isinstance(value.get("releases"), list):
        raise RuntimeError("Release catalog has an invalid format.")
    return value


def _write_catalog(release_dir: Path, releases: list[dict[str, Any]], generation: int) -> None:
    catalog = {"schema_version": 2, "channel": "stable", "generation": generation, "releases": releases}
    _atomic_write(release_dir / "catalog.json", _json_bytes(catalog))


def initialize_channel(release_dir: Path) -> list[str]:
    """Publish signed V1 and V2 and clear any unfinished V3 artifact."""
    release_dir.mkdir(parents=True, exist_ok=True)
    staging = release_dir / STAGING_DIR
    shutil.rmtree(staging, ignore_errors=True)
    staging.mkdir(parents=True, exist_ok=True)
    log = [
        "Stable release channel initialized",
        "Orion Network Manager release pipeline online",
        "Signing trust: RSA/SHA-256",
    ]
    releases: list[dict[str, Any]] = []
    for version in ("v1", "v2"):
        entry = _publish_package(release_dir, version, default_manifest(version))
        releases.append(entry)
        log.append(f"Published {entry['artifact']} ({entry['size']} bytes)")
    _write_catalog(release_dir, releases, generation=1)
    log.append("Catalog generation 1 written")
    return log


def load_or_initialize_channel(release_dir: Path) -> list[str]:
    """Preserve a published channel across supplier app container restarts."""
    try:
        catalog = read_catalog(release_dir)
    except RuntimeError:
        return initialize_channel(release_dir)
    if catalog.get("schema_version") != 2 or catalog.get("channel") != "stable":
        return initialize_channel(release_dir)
    releases = catalog["releases"]
    if not all(isinstance(entry, dict) for entry in releases):
        return initialize_channel(release_dir)
    versions = [entry.get("version") for entry in releases]
    if (
        not all(isinstance(version, str) for version in versions)
        or len(versions) != len(set(versions))
        or not {"v1", "v2"}.issubset(versions)
    ):
        return initialize_channel(release_dir)
    for entry in releases:
        version = entry.get("version")
        artifact = entry.get("artifact")
        digest = entry.get("sha256")
        if (
            version not in RELEASES
            or not isinstance(artifact, str)
            or not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or artifact != f"orion-{version}-{digest[:16]}.zip"
            or entry.get("signature") != f"{artifact}.sig"
            or not isinstance(entry.get("mandatory"), bool)
            or type(entry.get("size")) is not int
            or not (release_dir / artifact).is_file()
            or not (release_dir / f"{artifact}.sig").is_file()
        ):
            return initialize_channel(release_dir)
    return [
        f"Loaded stable catalog generation {catalog.get('generation', 0)}",
        f"{len(catalog['releases'])} release(s) available",
    ]


def _require_v3_unpublished(release_dir: Path) -> dict[str, Any]:
    catalog = read_catalog(release_dir)
    if any(isinstance(entry, dict) and entry.get("version") == "v3" for entry in catalog["releases"]):
        raise ValueError("V3 is already published. Reset the demo before preparing another V3 release.")
    return catalog


def _staging_paths(release_dir: Path) -> tuple[Path, Path]:
    staging = release_dir / STAGING_DIR
    return staging, staging / ARTIFACT_META


def read_artifact(release_dir: Path) -> dict[str, Any] | None:
    staging, meta_path = _staging_paths(release_dir)
    try:
        value = json.loads(meta_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(value, dict):
        return None
    required = {"version", "artifact", "sha256", "size", "manifest", "signed", "signature"}
    if not required.issubset(value):
        return None
    artifact = value.get("artifact")
    if not isinstance(artifact, str) or not (staging / artifact).is_file():
        return None
    if value.get("signed") is True:
        signature = value.get("signature")
        if not isinstance(signature, str) or not (staging / signature).is_file():
            return None
    return value


def upload_artifact(release_dir: Path, filename: str, content: bytes) -> tuple[dict[str, Any], list[str]]:
    _require_v3_unpublished(release_dir)
    if not isinstance(filename, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,120}\.zip", filename):
        raise ValueError("Upload a .zip build artifact.")
    if not content:
        raise ValueError("The uploaded artifact is empty.")
    if len(content) > 256 * 1024:
        raise ValueError("Artifact exceeds the 256 KB lab limit.")
    try:
        with zipfile.ZipFile(BytesIO(content)) as package:
            if package.namelist() != ["manifest.json"]:
                raise ValueError("Artifact must contain only manifest.json.")
            info = package.getinfo("manifest.json")
            if info.file_size > 16 * 1024:
                raise ValueError("Manifest exceeds the 16 KB lab limit.")
            manifest = validate_manifest(json.loads(package.read(info)))
    except zipfile.BadZipFile as exc:
        raise ValueError("Artifact is not a valid ZIP package.") from exc
    except json.JSONDecodeError as exc:
        raise ValueError("Artifact manifest is not valid JSON.") from exc
    digest = hashlib.sha256(content).hexdigest()
    artifact_name = f"orion-v3-{digest[:16]}.zip"
    staging, meta_path = _staging_paths(release_dir)
    shutil.rmtree(staging, ignore_errors=True)
    staging.mkdir(parents=True, exist_ok=True)
    _atomic_write(staging / artifact_name, content)
    metadata = {
        "version": "v3",
        "source_filename": filename,
        "artifact": artifact_name,
        "sha256": digest,
        "size": len(content),
        "manifest": manifest,
        "signed": False,
        "signature": None,
        "uploaded_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    _atomic_write(meta_path, _json_bytes(metadata))
    log = [
        f"Artifact received: {filename} ({len(content)} bytes)",
        f"SHA-256 {digest}",
        "Manifest validated for Orion Network Manager v3",
    ]
    return metadata, log


def sign_artifact(release_dir: Path) -> tuple[dict[str, Any], list[str]]:
    metadata = read_artifact(release_dir)
    if metadata is None:
        raise ValueError("Upload a V3 build artifact first.")
    if metadata.get("signed") is True:
        raise ValueError("The artifact is already signed.")
    staging, meta_path = _staging_paths(release_dir)
    artifact_name = str(metadata["artifact"])
    artifact_path = staging / artifact_name
    try:
        signature_path = _sign_artifact(artifact_path, PRIVATE_KEY)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise RuntimeError(f"Signing failed: {exc}") from exc
    metadata.update({
        "signed": True,
        "signature": signature_path.name,
        "signed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    })
    _atomic_write(meta_path, _json_bytes(metadata))
    log = [
        f"Signing {artifact_name} with release key (RSA/SHA-256)",
        f"Signature written: {signature_path.name}",
    ]
    return metadata, log


def publish_artifact(release_dir: Path, rollout: str) -> tuple[dict[str, Any], list[str]]:
    if rollout not in {"available", "mandatory"}:
        raise ValueError("Choose available or mandatory rollout.")
    metadata = read_artifact(release_dir)
    if metadata is None:
        raise ValueError("Upload a V3 build artifact first.")
    if metadata.get("signed") is not True:
        raise ValueError("Sign the artifact before publishing.")
    catalog = _require_v3_unpublished(release_dir)
    staging, _meta_path = _staging_paths(release_dir)
    artifact_name = str(metadata["artifact"])
    signature_name = str(metadata["signature"])
    artifact_path = staging / artifact_name
    signature_path = staging / signature_name
    if not artifact_path.is_file() or not signature_path.is_file():
        raise ValueError("The signed artifact files are missing. Upload and sign again.")
    _atomic_write(release_dir / artifact_name, artifact_path.read_bytes())
    _atomic_write(release_dir / signature_name, signature_path.read_bytes())
    releases = list(catalog["releases"])
    entry = {
        "version": "v3",
        "artifact": artifact_name,
        "signature": signature_name,
        "sha256": metadata["sha256"],
        "size": metadata["size"],
        "mandatory": rollout == "mandatory",
        "published_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    releases.append(entry)
    generation = int(catalog.get("generation", 0)) + 1
    _write_catalog(release_dir, releases, generation)
    shutil.rmtree(staging, ignore_errors=True)
    log = [
        f"Catalog generation {generation} prepared",
        f"Published {artifact_name} to stable ({rollout})",
    ]
    return entry, log
