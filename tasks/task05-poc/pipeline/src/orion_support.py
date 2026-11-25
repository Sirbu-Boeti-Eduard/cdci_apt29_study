"""Orion Network Manager service health reporter.

This is the component a normal V3 build ships.  It reads the local identity,
resolves the telemetry receiver through the DNS coordinator, and posts a
service-health record on a fixed interval.  It does not encode check-in
labels, does not fetch tasks, and does not execute commands.

The repository keeps this file as the approved source.  A release is built by
copying this tree into a workspace, running the build steps, and packaging the
result, so this file is the input to the build rather than the artifact.
"""

from __future__ import annotations

import getpass
import hashlib
import json
import os
import platform
import signal
import socket
import struct
import sys
import time
from urllib.request import ProxyHandler, Request, build_opener

TELEMETRY_PATH = "/swip/upd/orion.improvementprogram.asmx"
USER_AGENT = "Orion/2020.2.4 (Windows NT 10.0; Win64; x64)"
PROTOCOL_VERSION = "2020.2.4"
RECEIVER_NAME = "receiver.orion-lab.test"
START_DELAY_SECONDS = 3.0
DEFAULT_INTERVAL_SECONDS = 60.0

OPENER = build_opener(ProxyHandler({}))
_STOP = False


def _encode_name(name: str) -> bytes:
    parts = name.rstrip(".").split(".")
    return b"".join(bytes((len(part),)) + part.encode("ascii") for part in parts) + b"\0"


def _read_name(packet: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    next_offset = offset
    jumped = False
    for _ in range(32):
        size = packet[offset]
        if size & 0xC0 == 0xC0:
            if not jumped:
                next_offset = offset + 2
            offset = ((size & 0x3F) << 8) | packet[offset + 1]
            jumped = True
            continue
        offset += 1
        if size == 0:
            if not jumped:
                next_offset = offset
            break
        labels.append(packet[offset : offset + size].decode("ascii", "replace"))
        offset += size
    return ".".join(labels).lower(), next_offset


def resolve(server_ip: str, name: str) -> str | None:
    """Ask one A question and return the first address in the answer."""
    transaction_id = int.from_bytes(os.urandom(2), "big")
    packet = struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)
    packet += _encode_name(name) + struct.pack("!HH", 1, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(2)
        client.sendto(packet, (server_ip, 53))
        response, _address = client.recvfrom(2048)
    if len(response) < 12:
        return None
    response_id, flags, questions, answers = struct.unpack("!HHHH", response[:8])
    if response_id != transaction_id or not flags & 0x8000 or flags & 0x000F:
        return None
    _question, offset = _read_name(response, 12)
    offset += 4
    for _ in range(min(answers, 8)):
        _owner, offset = _read_name(response, offset)
        rrtype, _rrclass, _ttl, length = struct.unpack("!HHIH", response[offset : offset + 10])
        offset += 10
        data = response[offset : offset + length]
        offset += length
        if rrtype == 1 and len(data) == 4:
            return socket.inet_ntoa(data)
    return None


def _local_ip(receiver_ip: str) -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.connect((receiver_ip, 9))
        return probe.getsockname()[0]


def _identity(hostname: str, username: str, ip: str) -> dict[str, str]:
    return {
        "victim_id": "v-" + hashlib.sha256(f"{hostname}|{ip}".encode()).hexdigest()[:12],
        "hostname": hostname,
        "username": username,
        "os": f"{platform.system()} {platform.release()}",
        "ip": ip,
        "version": "v3",
        "process": os.path.basename(sys.argv[0]) or "orion_support.py",
        "pid": str(os.getpid()),
        "arch": platform.machine(),
    }


def report(base_url: str, identity: dict[str, str]) -> None:
    body = {
        "version": PROTOCOL_VERSION,
        "messageId": os.urandom(8).hex(),
        "customerId": identity["victim_id"],
        "machineName": identity["hostname"],
        "userName": identity["username"],
        "domain": "orion-lab.test",
        "osVersion": identity["os"],
        "ipAddress": identity["ip"],
        "processName": identity["process"],
        "processId": identity["pid"],
        "architecture": identity["arch"],
        "clientVersion": identity["version"],
        "improvementProgram": {"enabled": True, "intervalSeconds": 60},
    }
    request = Request(
        base_url.rstrip("/") + TELEMETRY_PATH,
        data=json.dumps(body).encode("utf-8"),
        method="POST",
        headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
    )
    with OPENER.open(request, timeout=2) as response:
        response.read()


def _terminate(_signum: int, _frame: object) -> None:
    global _STOP
    _STOP = True


def run(dns_ip: str, http_port: int, interval: float) -> int:
    signal.signal(signal.SIGTERM, _terminate)
    signal.signal(signal.SIGINT, _terminate)
    time.sleep(START_DELAY_SECONDS)
    hostname = socket.gethostname()
    username = getpass.getuser()
    while not _STOP:
        try:
            receiver_ip = resolve(dns_ip, RECEIVER_NAME)
            if receiver_ip:
                identity = _identity(hostname, username, _local_ip(receiver_ip))
                report(f"http://{receiver_ip}:{http_port}", identity)
        except (OSError, ValueError):
            pass
        deadline = time.monotonic() + interval
        while not _STOP and time.monotonic() < deadline:
            time.sleep(0.2)
    return 0


def main(argv: list[str]) -> int:
    dns_ip = argv[1] if len(argv) > 1 else "10.0.0.3"
    http_port = int(argv[2]) if len(argv) > 2 and argv[2].isdigit() else 9000
    try:
        interval = float(argv[3]) if len(argv) > 3 else DEFAULT_INTERVAL_SECONDS
    except ValueError:
        interval = DEFAULT_INTERVAL_SECONDS
    return run(dns_ip, http_port, max(interval, 5.0))


if __name__ == "__main__":
    sys.exit(main(sys.argv))
