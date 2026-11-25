"""Shared process state and log helpers for the headless Mininet lab engine."""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path


WORK_DIR = Path("/tmp/task05-poc")
RELEASE_DIR = Path("/app/releases")
CAPTURE_DIR = WORK_DIR / "capture"
MODE_PATH = WORK_DIR / "mode.json"
UPDATE_LOG = WORK_DIR / "update.log"
DNS_LOG = WORK_DIR / "dns.log"
RECEIVER_LOG = WORK_DIR / "receiver.log"
TASK_PATH = WORK_DIR / "task.json"
BEACONS_PATH = WORK_DIR / "beacons.json"
RESULTS_PATH = WORK_DIR / "results.json"
RESULT_LOG = WORK_DIR / "result.log"
PCAP_PATH = CAPTURE_DIR / "c2-traffic.pcap"
CAPTURE_ERROR_PATH = CAPTURE_DIR / "capture.stderr.log"
SENSOR_DIR = WORK_DIR / "sensor"
SENSOR_STATE_PATH = SENSOR_DIR / "state.json"
SENSOR_ERROR_PATH = SENSOR_DIR / "sensor.stderr.log"

state_lock = threading.RLock()
lab_io_lock = threading.RLock()
current_version = "v1"
installed_manifest: dict[str, object] = {}
coordinator_mode = "passive"
install_generation = 0
last_callback = "No V3 check-in yet"
dns_block_active = False
dns_block_previous_mode = "passive"
update_status: dict[str, object] = {
    "state": "starting",
    "message": "Update service is starting",
    "available_version": None,
    "last_check": None,
    "percent": 0,
}
update_history: list[dict[str, str]] = []


def append_history(message: str) -> None:
    with state_lock:
        update_history.append({"time": datetime.now(timezone.utc).strftime("%H:%M:%S"), "message": message})
        del update_history[:-40]


def read_lines(path: Path, limit: int = 40) -> list[str]:
    try:
        return path.read_text(encoding="utf-8").splitlines()[-limit:]
    except OSError:
        return []


def read_timeline(sources: tuple[tuple[str, Path], ...], limit_per_source: int = 60) -> list[str]:
    entries: list[tuple[str, int, str]] = []
    sequence = 0
    for source, path in sources:
        for line in read_lines(path, limit_per_source):
            timestamp, separator, detail = line.partition(" ")
            valid_timestamp = len(timestamp) == 8 and timestamp[2] == ":" and timestamp[5] == ":"
            sort_key = timestamp if valid_timestamp else "00:00:00"
            entry = f"{timestamp} [{source}] {detail}" if separator else f"[{source}] {line}"
            entries.append((sort_key, sequence, entry))
            sequence += 1
    entries.sort(key=lambda item: (item[0], item[1]))
    return [entry for _timestamp, _sequence, entry in entries[-100:]]


def read_sensor_state() -> dict[str, object]:
    """Return the sensor's last published snapshot, or an empty snapshot."""
    try:
        value = json.loads(SENSOR_STATE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def clear_response_state() -> None:
    """Drop defender response flags; the tap restart on reset calls this."""
    global dns_block_active, dns_block_previous_mode
    with state_lock:
        dns_block_active = False
        dns_block_previous_mode = "passive"
