"""Orion Network Manager service-health reporter.

This is the approved source component.  It writes a local health snapshot on a
fixed interval and nothing else: no DNS, no HTTP, no tasking.  That is the
contrast the lab needs: the clean build must not look like a beacon, and the
implant only exists when the public package wins the dependency resolution.
"""

from __future__ import annotations

import getpass
import json
import platform
import signal
import socket
import sys
import time
from pathlib import Path

HEALTH_PATH = Path("/tmp/task05-poc/health.json")
START_DELAY_SECONDS = 3.0
DEFAULT_INTERVAL_SECONDS = 60.0

_STOP = False


def _snapshot() -> dict[str, str]:
    return {
        "hostname": socket.gethostname(),
        "username": getpass.getuser(),
        "os": f"{platform.system()} {platform.release()}",
        "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def _terminate(_signum: int, _frame: object) -> None:
    global _STOP
    _STOP = True


def run(interval: float) -> int:
    signal.signal(signal.SIGTERM, _terminate)
    signal.signal(signal.SIGINT, _terminate)
    time.sleep(START_DELAY_SECONDS)
    while not _STOP:
        try:
            HEALTH_PATH.parent.mkdir(parents=True, exist_ok=True)
            HEALTH_PATH.write_text(json.dumps(_snapshot(), indent=2) + "\n", encoding="utf-8")
        except OSError:
            pass
        deadline = time.monotonic() + interval
        while not _STOP and time.monotonic() < deadline:
            time.sleep(0.2)
    return 0


def main(argv: list[str]) -> int:
    try:
        interval = float(argv[3]) if len(argv) > 3 else DEFAULT_INTERVAL_SECONDS
    except ValueError:
        interval = DEFAULT_INTERVAL_SECONDS
    return run(max(interval, 5.0))


if __name__ == "__main__":
    sys.exit(main(sys.argv))
