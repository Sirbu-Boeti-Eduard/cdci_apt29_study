#!/usr/bin/env python3
"""Backstage presenter controls for the Task 5 lab."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parent
PIPELINE_URL = "http://localhost:8080"
LAB_INTERNAL_URL = "http://127.0.0.1:8080"


def pipeline_post(path: str, payload: dict[str, object]) -> dict[str, object]:
    request = urllib.request.Request(
        PIPELINE_URL + path,
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={"Content-Type": "application/json", "Origin": PIPELINE_URL},
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read())


def lab_post(path: str, payload: dict[str, object]) -> dict[str, object]:
    code = (
        "import json, urllib.request; "
        f"request = urllib.request.Request({LAB_INTERNAL_URL + path!r}, "
        f"data=json.dumps({payload!r}).encode(), method='POST', "
        "headers={'Content-Type': 'application/json'}); "
        "print(urllib.request.urlopen(request, timeout=10).read().decode())"
    )
    result = subprocess.run(
        ["docker", "compose", "exec", "-T", "lab", "python3", "-c", code],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "lab command failed")
    return json.loads(result.stdout.strip().splitlines()[-1])


def main() -> int:
    parser = argparse.ArgumentParser(description="Task 5 presenter controls")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("reset", help="Reset the release channel, client, coordinator, beacons, and capture")
    install = sub.add_parser("install", help="Install a published client version")
    install.add_argument("version", choices=["v1", "v2", "v3"])
    sub.add_parser("check", help="Trigger a client update check")
    args = parser.parse_args()
    try:
        if args.command == "reset":
            print(pipeline_post("/api/reset", {}).get("message", "Release channel reset."))
            print(lab_post("/api/reset", {}).get("message", "Lab reset."))
        elif args.command == "install":
            print(lab_post("/api/select-version", {"version": args.version})["message"])
        elif args.command == "check":
            print(lab_post("/api/check-updates", {})["message"])
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
