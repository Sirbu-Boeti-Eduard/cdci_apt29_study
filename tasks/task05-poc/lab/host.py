"""Host process sensor for the Task 5 victim.

The network tap can show that the victim sent a DNS label and an HTTP POST, but
it cannot show which process sent them or which process started which child.
This module fills that gap from ``/proc``: it watches the registered component
and its descendants, records process starts and stops, and publishes a small
snapshot for the Blue Team app.

It is deliberately simple and polling-based.  A short-lived command can finish
between polls, so the demo uses a command that lives for at least a second
(``id; sleep 1; uname -a``).  A production sensor would use auditd, eBPF, or a
process-accounting facility instead.
"""

from __future__ import annotations

import json
import os
import pwd
import threading
import time
from pathlib import Path

import state

POLL_SECONDS = 0.25
MAX_EVENTS = 240
INSTALL_ROOT = state.WORK_DIR / "install"
INVENTORY = state.WORK_DIR / "installed-components.json"
COMPONENT_MARKERS = ("orion_support.py", str(INSTALL_ROOT))

_lock = threading.RLock()
_processes: dict[int, dict[str, object]] = {}
_events: list[dict[str, object]] = []
_thread: threading.Thread | None = None


def _read(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _inventory() -> list[dict[str, object]]:
    try:
        value = json.loads(INVENTORY.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    components = value.get("components") if isinstance(value, dict) else None
    return [item for item in components if isinstance(item, dict)] if isinstance(components, list) else []


def _proc(pid: int) -> dict[str, object] | None:
    stat = _read(f"/proc/{pid}/stat")
    if not stat:
        return None
    try:
        after = stat.rsplit(")", 1)[1].split()
        ppid = int(after[1])
    except (IndexError, ValueError):
        return None
    cmdline = _read(f"/proc/{pid}/cmdline").replace("\x00", " ").strip()
    if not cmdline:
        return None
    try:
        exe = os.readlink(f"/proc/{pid}/exe")
    except OSError:
        exe = ""
    user = ""
    for line in _read(f"/proc/{pid}/status").splitlines():
        if line.startswith("Uid:"):
            try:
                uid = int(line.split()[1])
                user = pwd.getpwuid(uid).pw_name
            except (IndexError, ValueError, KeyError):
                user = ""
            break
    return {
        "pid": pid,
        "ppid": ppid,
        "cmdline": cmdline[:400],
        "exe": exe,
        "user": user,
    }


def _is_descendant(pid: int, by_pid: dict[int, dict[str, object]], roots: set[int]) -> bool:
    seen: set[int] = set()
    parent = int(by_pid.get(pid, {}).get("ppid", 0))
    while parent > 0 and parent not in seen:
        if parent in roots:
            return True
        seen.add(parent)
        parent = int(by_pid.get(parent, {}).get("ppid", 0))
    return False


def _scan() -> None:
    by_pid: dict[int, dict[str, object]] = {}
    for entry in os.listdir("/proc"):
        if entry.isdigit():
            proc = _proc(int(entry))
            if proc is not None:
                by_pid[int(entry)] = proc
    if not by_pid:
        return
    component_pids = {
        int(item["pid"])
        for item in _inventory()
        if str(item.get("pid", "")).isdigit()
    }
    roots = {
        pid
        for pid, proc in by_pid.items()
        if pid in component_pids
        or any(marker in str(proc.get("cmdline", "")) for marker in COMPONENT_MARKERS)
    }
    interesting: dict[int, dict[str, object]] = {}
    for pid, proc in by_pid.items():
        cmd = str(proc.get("cmdline", ""))
        if pid not in roots and not _is_descendant(pid, by_pid, roots):
            continue
        if pid in component_pids or ("python" in str(proc.get("exe", "")) and "orion_support.py" in cmd):
            role = "component"
        elif "orion_support.py" in cmd or str(INSTALL_ROOT) in cmd:
            role = "launcher"
        else:
            role = "child"
        proc["role"] = role
        interesting[pid] = proc

    now = time.strftime("%H:%M:%S")
    stamp = time.time()
    with _lock:
        for pid, proc in interesting.items():
            if pid not in _processes:
                _events.append({
                    "time": now,
                    "ts": stamp,
                    "event": "start",
                    "pid": pid,
                    "ppid": proc["ppid"],
                    "user": proc["user"],
                    "role": proc["role"],
                    "cmdline": proc["cmdline"],
                })
            _processes[pid] = proc
        for pid in list(_processes):
            if pid not in interesting:
                gone = _processes.pop(pid)
                _events.append({
                    "time": now,
                    "ts": stamp,
                    "event": "stop",
                    "pid": pid,
                    "role": gone.get("role", ""),
                    "cmdline": gone.get("cmdline", ""),
                })
        del _events[:-MAX_EVENTS]


def _loop() -> None:
    while True:
        try:
            _scan()
        except Exception:
            pass
        time.sleep(POLL_SECONDS)


def start() -> None:
    global _thread
    if _thread is not None and _thread.is_alive():
        return
    _thread = threading.Thread(target=_loop, name="host-sensor", daemon=True)
    _thread.start()


def clear() -> None:
    with _lock:
        _processes.clear()
        _events.clear()


def snapshot() -> dict[str, object]:
    with _lock:
        return {
            "processes": sorted(_processes.values(), key=lambda item: int(item["pid"])),
            "events": list(reversed(_events[-60:])),
            "components": _inventory(),
            "updated": time.strftime("%H:%M:%S"),
        }
