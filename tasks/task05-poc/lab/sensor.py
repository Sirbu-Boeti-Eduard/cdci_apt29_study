"""Inline packet sensor: named detection rules over the tap's own pcap.

The lab puts a bridge between the victim and the switch.  ``topology.py`` runs
``tcpdump -w`` on that bridge and starts this process in the same network
namespace, so every packet the rules score is a packet the victim actually
sent and the sensor actually carried.  Nothing here reads the DNS or HTTP
service logs, and no rule knows what the scenario is about to do: the sensor
tails the pcap file that tcpdump writes and turns observed packets into
alerts.

Run modes::

    python3 sensor.py --pcap <file> --state-dir <dir>            # live tail
    python3 sensor.py --replay <file>                            # parse once, print
    python3 sensor.py --selftest                                 # host-side checks

Every alert carries the rule id and name, a timestamp, the flow, a short
reason, and a packet excerpt.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import signal
import statistics
import struct
import sys
import time
from pathlib import Path

import dga

SENSOR_VERSION = 1
CHECKIN_SUFFIX = dga.CHECKIN_SUFFIX

# Rule metadata is also served to the Blue Team app, so the empty state can
# list what the sensor would look for instead of showing a blank table.
RULES: tuple[dict[str, str], ...] = (
    {
        "id": "T5-DGA-001",
        "name": "Encoded label under the check-in suffix",
    },
    {
        "id": "T5-DGA-002",
        "name": "Checksum-valid encoded decode",
    },
    {
        "id": "T5-DGA-003",
        "name": "Decode failure on a lookalike label",
    },
    {
        "id": "T5-DGA-004",
        "name": "Encoded label reused from a new source",
    },
    {
        "id": "T5-BCN-001",
        "name": "Fixed-interval beaconing",
    },
    {
        "id": "T5-C2-001",
        "name": "First contact with a new destination",
    },
    {
        "id": "T5-C2-002",
        "name": "Improvement Program upload to a bare IP",
    },
    {
        "id": "T5-EXFIL-001",
        "name": "Large telemetry upload",
    },
)

RULE_INDEX = {rule["id"]: rule for rule in RULES}

# A POST path that imitates vendor telemetry.  Deliberately a shape, not one
# exact endpoint: the lab's C2 uses the Improvement Program path, and SUNBURST-style
# tooling reuses updater paths such as /swip/upd/.
TELEMETRY_PATH = re.compile(r"(?i)(?:^|/)(checkin|result|swip|oip|upd|improvement|telemetry)(?:/|$)")
ORION_AGENT = re.compile(r"(?i)^orion/")
REQUEST_LINE = re.compile(r"^(GET|POST|PUT|HEAD|OPTIONS|PATCH) (\S+) HTTP/1\.[01]$")
MAX_ALERTS = 200
MAX_DECODES = 60
MAX_FLOWS = 60
HEX_BYTES = 96

# dga.looks_encoded is the shared pre-filter for every name a sensor sees; it
# skips labels that start with common vendor prefixes to cut noise.  Inside the
# check-in suffix that exclusion would drop roughly one encoded label in
# thirty, so the suffix-scoped rules test the length and alphabet only.
BASE32_ALPHABET = set("abcdefghijklmnopqrstuvwxyz234567")


def _encoded_shape(label: str) -> bool:
    return 32 <= len(label) <= 63 and set(label) <= BASE32_ALPHABET


def _is_global(address: str) -> bool:
    """False for private, shared, loopback, and test-net ranges."""
    try:
        return ipaddress.ip_address(address).is_global
    except ValueError:
        return True


PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e-6),
    b"\xa1\xb2\xc3\xd4": (">", 1e-6),
    b"\x4d\x3c\xb2\xa1": ("<", 1e-9),
    b"\xa1\xb2\x3c\x4d": (">", 1e-9),
}


def _clock(ts: float) -> str:
    return time.strftime("%H:%M:%S", time.localtime(ts))


def _iso(ts: float | None) -> str | None:
    if not ts:
        return None
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def _hexdump(frame: bytes) -> str:
    return frame[:HEX_BYTES].hex(" ")


# --- packet decoding -------------------------------------------------------


def parse_frame(frame: bytes) -> dict[str, object] | None:
    """Return the IPv4 header fields and transport payload for one frame."""
    if len(frame) < 14:
        return None
    ethertype = int.from_bytes(frame[12:14], "big")
    offset = 14
    while ethertype in (0x8100, 0x88A8) and len(frame) >= offset + 4:
        ethertype = int.from_bytes(frame[offset + 2 : offset + 4], "big")
        offset += 4
    if ethertype != 0x0800 or len(frame) < offset + 20:
        return None
    version = frame[offset] >> 4
    header_length = (frame[offset] & 0x0F) * 4
    if version != 4 or header_length < 20 or len(frame) < offset + header_length:
        return None
    total_length = int.from_bytes(frame[offset + 2 : offset + 4], "big")
    fragment = int.from_bytes(frame[offset + 6 : offset + 8], "big")
    if fragment & 0x1FFF:
        return None  # only the first fragment carries a transport header
    protocol = frame[offset + 9]
    packet: dict[str, object] = {
        "src": ".".join(str(byte) for byte in frame[offset + 12 : offset + 16]),
        "dst": ".".join(str(byte) for byte in frame[offset + 16 : offset + 20]),
        "proto": protocol,
        "protocol": {6: "TCP", 17: "UDP"}.get(protocol, str(protocol)),
        "sport": 0,
        "dport": 0,
        "flags": 0,
        "payload": b"",
    }
    end = offset + total_length if total_length >= header_length else len(frame)
    payload = frame[offset + header_length : min(len(frame), end)]
    if protocol == 6 and len(payload) >= 20:
        packet["sport"] = int.from_bytes(payload[0:2], "big")
        packet["dport"] = int.from_bytes(payload[2:4], "big")
        packet["flags"] = payload[13]
        data_offset = (payload[12] >> 4) * 4
        packet["payload"] = payload[data_offset:] if data_offset >= 20 else b""
    elif protocol == 17 and len(payload) >= 8:
        packet["sport"] = int.from_bytes(payload[0:2], "big")
        packet["dport"] = int.from_bytes(payload[2:4], "big")
        packet["payload"] = payload[8:]
    return packet


def parse_dns_name(packet: bytes, offset: int) -> tuple[str, int]:
    """Decode a possibly compressed DNS name; raise ValueError on garbage."""
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
                raise ValueError("invalid DNS pointer")
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
        if size > 63 or offset + size > len(packet):
            raise ValueError("invalid DNS label")
        labels.append(packet[offset : offset + size].decode("ascii", errors="replace"))
        wire_length += size + 1
        if wire_length > 255:
            raise ValueError("oversized DNS name")
        offset += size
    return ".".join(labels).lower(), next_offset


def parse_dns(payload: bytes) -> dict[str, object] | None:
    """Return {id, flags, name, qtype, answers[]} for a DNS message."""
    if len(payload) < 12:
        return None
    transaction_id, flags, questions, answers = struct.unpack("!HHHH", payload[:8])
    if flags & 0x8000:
        return None  # a response, handled separately
    if questions != 1:
        return None
    try:
        name, offset = parse_dns_name(payload, 12)
    except (ValueError, UnicodeDecodeError):
        return None
    if offset + 4 > len(payload):
        return None
    qtype = int.from_bytes(payload[offset : offset + 2], "big")
    return {"id": transaction_id, "flags": flags, "name": name, "qtype": qtype, "answers": []}


def parse_dns_response(payload: bytes) -> dict[str, object] | None:
    """Return {name, rcode, records[(type, value)]} for a DNS response."""
    if len(payload) < 12:
        return None
    _transaction_id, flags, questions, answer_count = struct.unpack("!HHHH", payload[:8])
    if not flags & 0x8000 or questions != 1:
        return None
    try:
        name, offset = parse_dns_name(payload, 12)
    except (ValueError, UnicodeDecodeError):
        return None
    if offset + 4 > len(payload):
        return None
    offset += 4
    records: list[tuple[int, str]] = []
    for _ in range(min(answer_count, 16)):
        try:
            _owner, offset = parse_dns_name(payload, offset)
        except (ValueError, UnicodeDecodeError):
            break
        if offset + 10 > len(payload):
            break
        record_type, _record_class, _ttl, length = struct.unpack("!HHIH", payload[offset : offset + 10])
        offset += 10
        data = payload[offset : offset + length]
        offset += length
        if record_type == 1 and len(data) == 4:
            records.append((record_type, ".".join(str(byte) for byte in data)))
        elif record_type == 5:
            try:
                target, _end = parse_dns_name(payload, offset - length)
            except (ValueError, UnicodeDecodeError):
                continue
            records.append((record_type, target))
    return {"name": name, "rcode": flags & 0x000F, "records": records}


def parse_http_request(payload: bytes) -> dict[str, object] | None:
    if not payload:
        return None
    head = payload.split(b"\r\n\r\n", 1)[0].decode("latin-1", errors="replace")
    lines = head.split("\r\n")
    match = REQUEST_LINE.match(lines[0].strip())
    if match is None:
        return None
    headers: dict[str, str] = {}
    for line in lines[1:40]:
        field, separator, value = line.partition(":")
        if separator:
            headers[field.strip().lower()] = value.strip()
    try:
        content_length = int(headers.get("content-length", "0"))
    except ValueError:
        content_length = 0
    return {
        "method": match.group(1),
        "path": match.group(2),
        "host": headers.get("host", ""),
        "agent": headers.get("user-agent", ""),
        "content_length": content_length,
    }


# --- detector --------------------------------------------------------------


class Detector:
    """Stateful rules over packets pulled from the tap's capture file."""

    def __init__(self) -> None:
        self.alerts: list[dict[str, object]] = []
        self.decodes: dict[tuple[str, str], dict[str, object]] = {}
        self.flows: dict[tuple[str, str, int, str], dict[str, object]] = {}
        self.beacons: dict[str, dict[str, object]] = {}
        self.labels: dict[str, str] = {}
        self.dns_answers: dict[str, dict[str, str]] = {}
        self.http_connections: set[tuple[str, int, str, int]] = set()
        self.fired: set[tuple[str, str]] = set()
        self.sequence = 0
        self.packets = 0
        self.bytes = 0
        self.queries = 0
        self.http_requests = 0
        self.started = time.time()
        self.last_packet: float | None = None
        self.first_packet: float | None = None
        self.state_path: Path | None = None
        self.dirty = True

    # -- alert plumbing -----------------------------------------------------

    def alert(self, rule_id: str, ts: float, packet: dict[str, object], frame: bytes, summary: str, evidence: str, fields: list[list[str]], key: str) -> None:
        if (rule_id, key) in self.fired:
            return
        self.fired.add((rule_id, key))
        rule = RULE_INDEX[rule_id]
        self.sequence += 1
        self.alerts.append(
            {
                "id": f"a{self.sequence:05d}",
                "rule": rule["id"],
                "name": rule["name"],
                "time": _clock(ts),
                "ts": round(ts, 3),
                "iso": _iso(ts),
                "src": packet["src"],
                "dst": packet["dst"],
                "sport": packet["sport"],
                "dport": packet["dport"],
                "protocol": packet["protocol"],
                "flow": f"{packet['src']}:{packet['sport']} -> {packet['dst']}:{packet['dport']} {packet['protocol']}",
                "summary": summary,
                "evidence": evidence,
                "fields": fields,
                "packet_bytes": len(frame),
                "hex": _hexdump(frame),
            }
        )
        del self.alerts[:-MAX_ALERTS]
        self.dirty = True

    # -- per packet ---------------------------------------------------------

    def observe(self, ts: float, frame: bytes) -> None:
        self.packets += 1
        self.bytes += len(frame)
        if self.first_packet is None:
            self.first_packet = ts
        self.last_packet = ts
        self.dirty = True
        packet = parse_frame(frame)
        if packet is None:
            return
        self.track_flow(ts, packet, frame)
        if packet["proto"] == 17:
            self.on_udp(ts, packet, frame)
        elif packet["proto"] == 6:
            self.on_tcp(ts, packet, frame)

    def track_flow(self, ts: float, packet: dict[str, object], frame: bytes) -> None:
        key = (str(packet["src"]), str(packet["dst"]), int(packet["dport"]), str(packet["protocol"]))
        flow = self.flows.get(key)
        new_flow = False
        if flow is None:
            # A reply carries the server's source port as the destination of
            # the reverse tuple.  Credit it to the conversation instead of
            # opening an ephemeral one-way row for every response.
            reply = self.flows.get((str(packet["dst"]), str(packet["src"]), int(packet["sport"]), str(packet["protocol"])))
            is_syn = packet["proto"] == 6 and int(packet["flags"]) & 0x02 and not int(packet["flags"]) & 0x10
            if reply is not None and not is_syn:
                flow = reply
            else:
                flow = {
                    "src": packet["src"],
                    "dst": packet["dst"],
                    "port": packet["dport"],
                    "protocol": packet["protocol"],
                    "first": ts,
                    "last": ts,
                    "packets": 0,
                    "bytes": 0,
                }
                self.flows[key] = flow
                new_flow = True
        flow["last"] = ts
        flow["packets"] = int(flow["packets"]) + 1
        flow["bytes"] = int(flow["bytes"]) + len(frame)
        first_packet = new_flow and (
            (packet["proto"] == 6 and int(packet["flags"]) & 0x02 and not int(packet["flags"]) & 0x10)
            or (packet["proto"] == 17 and int(packet["dport"]) == 53)
        )
        if not first_packet:
            return
        sources = {flow_key[0] for flow_key, value in self.flows.items() if value["dst"] == packet["dst"]}
        self.alert(
            "T5-C2-001",
            ts,
            packet,
            frame,
            f"first packet from {packet['src']} to {packet['dst']}:{packet['dport']}",
            f"{packet['protocol']} {packet['src']}:{packet['sport']} -> {packet['dst']}:{packet['dport']}",
            [
                ["destination", f"{packet['dst']}:{packet['dport']}"],
                ["sources seen", str(len(sources))],
                ["rare", "yes" if len(sources) == 1 else "no"],
            ],
            f"{packet['src']}|{packet['dst']}|{packet['dport']}",
        )

    def on_udp(self, ts: float, packet: dict[str, object], frame: bytes) -> None:
        payload = packet["payload"]
        if not isinstance(payload, bytes):
            return
        if int(packet["dport"]) == 53:
            message = parse_dns(payload)
            if message is not None:
                self.on_query(ts, packet, frame, message)
        elif int(packet["sport"]) == 53:
            message = parse_dns_response(payload)
            if message is not None:
                for _record_type, value in message["records"]:
                    self.dns_answers.setdefault(value, {})[str(message["name"])] = str(packet["src"])

    def on_query(self, ts: float, packet: dict[str, object], frame: bytes, message: dict[str, object]) -> None:
        name = str(message["name"])
        if name != CHECKIN_SUFFIX and not name.endswith("." + CHECKIN_SUFFIX):
            return
        self.queries += 1
        self.track_beacon(ts, packet, frame, name)
        label = dga.split_query(name)
        if label is None or not _encoded_shape(label):
            return
        self.alert(
            "T5-DGA-001",
            ts,
            packet,
            frame,
            f"encoded label {label[:24]}… ({len(label)} chars) under {CHECKIN_SUFFIX}",
            f"A? {name} | {len(label)}-char base32 label",
            [["label length", str(len(label))], ["label", label]],
            f"{packet['src']}|{label}",
        )
        try:
            decoded = dga.decode_label(label)
        except ValueError as exc:
            self._decode_row(
                (str(packet["src"]), label),
                {
                    "time": _clock(ts),
                    "ts": round(ts, 3),
                    "src": packet["src"],
                    "hostname": "",
                    "username": "",
                    "uid": "",
                    "mode": "",
                    "checksum": "invalid",
                    "label": label,
                    "decode_ok": False,
                    "note": str(exc),
                },
            )
            self.alert(
                "T5-DGA-003",
                ts,
                packet,
                frame,
                f"label {label[:24]}… has the encoded shape but does not decode",
                f"A? {name} | {exc}",
                [["label", label], ["decode error", str(exc)]],
                f"{packet['src']}|{label}",
            )
            return
        previous = self.labels.get(label)
        self.labels.setdefault(label, str(packet["src"]))
        self._decode_row(
            (str(packet["src"]), label),
            {
                "time": _clock(ts),
                "ts": round(ts, 3),
                "src": packet["src"],
                "hostname": decoded["hostname"],
                "username": decoded["username"],
                "uid": decoded["uid"],
                "mode": f"{decoded['mode']} ({decoded['mode_name']})",
                "checksum": f"valid {decoded['checksum']}",
                "label": label,
                "decode_ok": True,
                "note": f"{decoded['record_bytes']} byte record",
            },
        )
        self.alert(
            "T5-DGA-002",
            ts,
            packet,
            frame,
            f"label decodes to {decoded['hostname']} / {decoded['username']} (mode {decoded['mode_name']})",
            f"A? {name} | CRC-16 {decoded['checksum']} ok, uid {decoded['uid']}",
            [
                ["hostname", str(decoded["hostname"])],
                ["username", str(decoded["username"])],
                ["victim uid", str(decoded["uid"])],
                ["mode", f"{decoded['mode']} ({decoded['mode_name']})"],
                ["crc16", str(decoded["checksum"])],
            ],
            f"{packet['src']}|{label}",
        )
        if previous is not None and previous != str(packet["src"]):
            self.alert(
                "T5-DGA-004",
                ts,
                packet,
                frame,
                f"label first seen from {previous} now arrives from {packet['src']}",
                f"A? {name} | identical encoded identity, new source",
                [["first source", previous], ["new source", str(packet["src"])], ["label", label]],
                f"{packet['src']}|{label}",
            )

    def _decode_row(self, key: tuple[str, str], row: dict[str, object]) -> None:
        """Keep one row per source and label, with a repeat count."""
        existing = self.decodes.get(key)
        if existing is None:
            row["count"] = 1
            row["last"] = row["time"]
            self.decodes[key] = row
            if len(self.decodes) > MAX_DECODES:
                oldest = min(self.decodes, key=lambda item: float(self.decodes[item]["ts"]))
                del self.decodes[oldest]
            return
        existing["count"] = int(existing["count"]) + 1
        existing["last"] = row["time"]

    def track_beacon(self, ts: float, packet: dict[str, object], frame: bytes, name: str) -> None:
        src = str(packet["src"])
        entry = self.beacons.setdefault(src, {"times": [], "stats": None})
        times = entry["times"]
        if not isinstance(times, list):
            return
        times.append(ts)
        del times[:-12]
        if len(times) < 2:
            return
        intervals = [round(right - left, 3) for left, right in zip(times, times[1:])]
        mean = statistics.fmean(intervals)
        spread = statistics.stdev(intervals) if len(intervals) > 1 else 0.0
        coefficient = spread / mean if mean else 0.0
        periodic = len(intervals) >= 3 and mean >= 0.5 and spread <= max(0.3, mean * 0.12)
        entry["stats"] = {
            "src": src,
            "samples": len(times),
            "intervals": len(intervals),
            "mean": round(mean, 2),
            "spread": round(spread, 3),
            "cv": round(coefficient, 3),
            "first": _clock(times[0]),
            "last": _clock(times[-1]),
            # Sticky once the rule fired: a later gap does not un-prove the
            # earlier measurement.  "current" keeps the live spacing visible.
            "periodic": periodic or bool(entry.get("alerted")),
            "current": periodic,
        }
        if not periodic or entry.get("alerted"):
            return
        entry["alerted"] = True
        self.alert(
            "T5-BCN-001",
            ts,
            packet,
            frame,
            f"{src} beacons every {mean:.2f}s ± {spread:.2f}s over {len(intervals)} intervals",
            f"{name}: intervals {', '.join(f'{value:.2f}s' for value in intervals[-5:])}",
            [
                ["source", src],
                ["samples", str(len(times))],
                ["mean interval", f"{mean:.2f}s"],
                ["spread", f"{spread:.3f}s"],
                ["coefficient of variation", f"{coefficient:.3f}"],
            ],
            src,
        )

    def on_tcp(self, ts: float, packet: dict[str, object], frame: bytes) -> None:
        payload = packet["payload"]
        if not isinstance(payload, bytes) or not payload:
            return
        key = (str(packet["src"]), int(packet["sport"]), str(packet["dst"]), int(packet["dport"]))
        request = parse_http_request(payload)
        if request is None:
            return
        if key in self.http_connections:
            return
        self.http_connections.add(key)
        self.http_requests += 1
        if request["method"] != "POST" or _is_global(str(packet["dst"])):
            return
        agent = request["agent"]
        length = int(request.get("content_length") or 0)
        if length > 4096:
            self.alert(
                "T5-EXFIL-001",
                ts,
                packet,
                frame,
                f"POST {request['path']} carries {length} bytes",
                f"{request['method']} {request['path']} · Content-Length: {length} · UA: {agent or '(none)'}",
                [
                    ["path", str(request["path"])],
                    ["content length", str(length)],
                    ["user-agent", agent or "(none)"],
                ],
                f"{packet['src']}|{packet['dst']}|{request['path']}|exfil",
            )
        if TELEMETRY_PATH.search(request["path"]) is None and ORION_AGENT.match(agent) is None:
            return
        provenance = self.dns_answers.get(str(packet["dst"]), {})
        names = ", ".join(sorted(provenance)) or "(no DNS answer seen)"
        servers = sorted(set(provenance.values()))
        internal = [server for server in servers if not _is_global(server)]
        if provenance:
            scope = ("internal resolver " + ", ".join(internal)) if internal else ("public resolver " + ", ".join(servers))
        else:
            scope = "configured address, no DNS answer in this capture"
        self.alert(
            "T5-C2-002",
            ts,
            packet,
            frame,
            f"POST {request['path']} to bare {packet['dst']}:{packet['dport']}",
            f"{request['method']} {request['path']} HTTP/1.1 · Host: {request['host'] or '(none)'} · UA: {agent or '(none)'}",
            [
                ["method", request["method"]],
                ["path", request["path"]],
                ["host header", request["host"] or "(none)"],
                ["user-agent", agent or "(none)"],
                ["destination global", "no"],
                ["resolved from", names],
                ["resolver", scope],
            ],
            f"{packet['src']}|{packet['dst']}|{request['method']}|{request['path']}",
        )

    # -- published snapshot -------------------------------------------------

    def snapshot(self) -> dict[str, object]:
        flows = sorted(self.flows.values(), key=lambda flow: int(flow["bytes"]), reverse=True)[:MAX_FLOWS]
        beacons = [entry["stats"] for entry in self.beacons.values() if entry["stats"]]
        beacons.sort(key=lambda stats: str(stats["src"]))
        return {
            "version": SENSOR_VERSION,
            "started": _iso(self.started),
            "updated": _iso(time.time()),
            "packets": self.packets,
            "bytes": self.bytes,
            "first_packet": _iso(self.first_packet),
            "last_packet": _iso(self.last_packet),
            "counters": {
                "queries": self.queries,
                "http": self.http_requests,
                "encoded_labels": sum(1 for _label in self.labels),
                "alerts": len(self.alerts),
            },
            "alerts": list(reversed(self.alerts)),
            "decodes": sorted(self.decodes.values(), key=lambda row: float(row["ts"]), reverse=True),
            "beacons": beacons,
            "flows": [
                {
                    "src": flow["src"],
                    "dst": flow["dst"],
                    "port": flow["port"],
                    "protocol": flow["protocol"],
                    "first": _clock(float(flow["first"])),
                    "last": _clock(float(flow["last"])),
                    "packets": flow["packets"],
                    "bytes": flow["bytes"],
                }
                for flow in flows
            ],
        }

    def write(self) -> None:
        if self.state_path is None or not self.dirty:
            return
        temporary = self.state_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(self.snapshot(), indent=2) + "\n", encoding="utf-8")
        os.replace(temporary, self.state_path)
        self.dirty = False


# --- capture tail ----------------------------------------------------------


class PcapTail:
    """Read pcap records that tcpdump appends; recover when the file resets."""

    def __init__(self, path: Path, handle_record) -> None:
        self.path = path
        self.handle_record = handle_record
        self.handle = None
        self.inode: int | None = None
        self.endian = "<"
        self.scale = 1e-6
        self.linktype = 1
        self.buffer = b""

    def poll(self) -> bool:
        try:
            stat = os.stat(self.path)
        except OSError:
            return False
        if self.handle is None or stat.st_ino != self.inode or stat.st_size < self.handle.tell():
            self.close()
            try:
                self.handle = self.path.open("rb")
            except OSError:
                return False
            self.inode = stat.st_ino
            header = self.handle.read(24)
            if len(header) < 24:
                return False
            magic = header[:4]
            if magic not in PCAP_MAGIC:
                return False
            self.endian, self.scale = PCAP_MAGIC[magic]
            self.linktype = struct.unpack(f"{self.endian}I", header[20:24])[0]
            self.buffer = b""
        chunk = self.handle.read()
        if not chunk:
            return False
        self.buffer += chunk
        while True:
            if len(self.buffer) < 16:
                return True
            seconds, fraction, captured, _original = struct.unpack(f"{self.endian}IIII", self.buffer[:16])
            if captured > 262144:
                self.buffer = b""
                return True
            if len(self.buffer) < 16 + captured:
                return True
            frame = self.buffer[16 : 16 + captured]
            self.buffer = self.buffer[16 + captured :]
            if self.linktype == 1:
                self.handle_record(seconds + fraction * self.scale, frame)
            elif self.linktype == 113 and len(frame) > 16:
                self.handle_record(seconds + fraction * self.scale, frame[16:])

    def close(self) -> None:
        if self.handle is not None:
            try:
                self.handle.close()
            except OSError:
                pass
        self.handle = None
        self.buffer = b""


# --- self test -------------------------------------------------------------


def _ethernet(src_ip: str, dst_ip: str, proto: int, sport: int, dport: int, payload: bytes, flags: int = 0x18) -> bytes:
    if proto == 17:
        transport = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    else:
        transport = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 5 << 4, flags, 8192, 0, 0) + payload
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(transport),
        0,
        0,
        64,
        proto,
        0,
        bytes(int(part) for part in src_ip.split(".")),
        bytes(int(part) for part in dst_ip.split(".")),
    )
    return b"\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x02\x08\x00" + header + transport


def _dns_query(suffix: str, name: str, query_id: int = 7) -> bytes:
    encoded = b""
    for label in name.split("."):
        encoded += bytes([len(label)]) + label.encode("ascii")
    return struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0) + encoded + b"\x00" + struct.pack("!HH", 1, 1)


def selftest() -> int:
    """Feed the detector real packet bytes built by the shared encoder."""
    detector = Detector()
    label = dga.encode_label("orion-01", "analyst", dga.MODE_ACTIVE)
    name = f"{label}.{CHECKIN_SUFFIX}"
    base = 1_700_000_000.0
    for index in range(5):
        ts = base + index * 4.0
        frame = _ethernet("10.0.0.5", "10.0.0.3", 17, 41000 + index, 53, _dns_query(CHECKIN_SUFFIX, name, index))
        detector.observe(ts, frame)
    # A lookalike: same length and alphabet, one character changed.
    swapped = "q" if label[10] != "q" else "r"
    lookalike = label[:10] + swapped + label[11:]
    detector.observe(base + 24, _ethernet("10.0.0.7", "10.0.0.3", 17, 41100, 53, _dns_query(CHECKIN_SUFFIX, f"{lookalike}.{CHECKIN_SUFFIX}")))
    # Same label from a second address: replay from another host.
    detector.observe(base + 28, _ethernet("10.0.0.9", "10.0.0.3", 17, 41101, 53, _dns_query(CHECKIN_SUFFIX, name, 9)))
    # Bare-IP HTTP check-in.
    request = b"POST /swip/upd/orion.improvementprogram.asmx HTTP/1.1\r\nHost: 10.0.0.4:9000\r\nContent-Type: application/json\r\nUser-Agent: Orion/2020.2.4 (Windows NT 10.0; Win64; x64)\r\n\r\n{}"
    detector.observe(base + 32, _ethernet("10.0.0.5", "10.0.0.4", 6, 41200, 9000, request))
    # A large telemetry result, the shape a collect task produces.
    upload = (
        b"POST /swip/upd/orion.improvementprogram.asmx HTTP/1.1\r\n"
        b"Host: 10.0.0.4:9000\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: 6000\r\n"
        b"User-Agent: Orion/2020.2.4 (Windows NT 10.0; Win64; x64)\r\n\r\n"
        + b"A" * 6000
    )
    detector.observe(base + 36, _ethernet("10.0.0.5", "10.0.0.4", 6, 41201, 9000, upload))

    fired = {alert["rule"] for alert in detector.alerts}
    expected = {
        "T5-DGA-001",
        "T5-DGA-002",
        "T5-DGA-003",
        "T5-DGA-004",
        "T5-BCN-001",
        "T5-C2-002",
        "T5-EXFIL-001",
    }
    problems: list[str] = []
    missing = expected - fired
    if missing:
        problems.append(f"rules did not fire: {sorted(missing)}")
    decodes = [row for row in detector.snapshot()["decodes"] if row["decode_ok"]]
    victim_row = next((row for row in decodes if row["src"] == "10.0.0.5"), None)
    if victim_row is None or victim_row["hostname"] != "orion-01" or victim_row["username"] != "analyst":
        problems.append(f"decoded identity wrong: {decodes[:1]}")
    if victim_row and victim_row["checksum"] != "valid " + dga.decode_label(label)["checksum"]:
        problems.append("checksum field not reported")
    if victim_row and victim_row["count"] != 5:
        problems.append(f"decode row repeat count wrong: {victim_row['count']}")
    beacon = detector.beacons.get("10.0.0.5", {}).get("stats")
    if not beacon or abs(float(beacon["mean"]) - 4.0) > 0.01:
        problems.append(f"beacon statistics wrong: {beacon}")
    if "T5-C2-002" in fired:
        match = next(alert for alert in detector.alerts if alert["rule"] == "T5-C2-002")
        if "Host: 10.0.0.4:9000" not in str(match["evidence"]):
            problems.append("HTTP evidence excerpt missing the Host header")
    empty = Detector()
    if empty.snapshot()["alerts"]:
        problems.append("quiet traffic produced alerts")
    if not _encoded_shape("c" + label[1:]) or not dga.looks_encoded("c" + label[1:]):
        problems.append("suffix shape check should keep a c-prefixed encoded label")
    for problem in problems:
        print(f"FAIL {problem}")
    if problems:
        return 1
    print(f"selftest ok: {len(detector.alerts)} alerts, rules fired {', '.join(sorted(fired))}")
    print(f"decoded: {decodes[0]['hostname']} / {decodes[0]['username']} uid {decodes[0]['uid']} checksum {decodes[0]['checksum']}")
    print(f"beacon: mean {beacon['mean']}s spread {beacon['spread']}s over {beacon['intervals']} intervals")
    return 0


def replay(path: Path) -> int:
    detector = Detector()
    tail = PcapTail(path, detector.observe)
    tail.poll()
    while tail.poll():
        pass
    tail.close()
    snapshot = detector.snapshot()
    print(json.dumps(snapshot, indent=2))
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Task 5 inline sensor")
    parser.add_argument("--pcap", type=Path, help="capture file to tail")
    parser.add_argument("--state-dir", type=Path, help="directory for the published snapshot")
    parser.add_argument("--iface", default="br0", help="interface tcpdump captures")
    parser.add_argument("--replay", type=Path, help="parse a finished capture and print JSON")
    parser.add_argument("--selftest", action="store_true", help="run packet-level checks")
    parser.add_argument("--interval", type=float, default=1.0, help="snapshot write interval")
    arguments = parser.parse_args(argv)

    if arguments.selftest:
        return selftest()
    if arguments.replay:
        return replay(arguments.replay)
    if arguments.pcap is None or arguments.state_dir is None:
        parser.error("--pcap and --state-dir are required for live mode")

    arguments.state_dir.mkdir(parents=True, exist_ok=True)
    detector = Detector()
    detector.state_path = arguments.state_dir / "state.json"
    detector.dirty = True
    detector.write()
    tail = PcapTail(arguments.pcap, detector.observe)
    stopping = False

    def stop(_signum: int, _frame: object) -> None:
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    print(f"sensor watching {arguments.pcap} on {arguments.iface}", flush=True)
    last_write = 0.0
    while not stopping:
        try:
            tail.poll()
        except OSError as exc:
            print(f"sensor capture read failed: {exc}", flush=True)
        now = time.monotonic()
        if now - last_write >= arguments.interval:
            detector.write()
            last_write = now
        time.sleep(0.2)
    detector.write()
    tail.close()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
