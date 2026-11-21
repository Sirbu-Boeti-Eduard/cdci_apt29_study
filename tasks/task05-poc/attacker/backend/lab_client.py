"""Private HTTP client for the attacker console's simulated coordinator controls."""

from __future__ import annotations

import json
import os
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener


LAB_URL = os.environ.get("LAB_URL", "http://lab:8080")
DIRECT_HTTP = build_opener(ProxyHandler({}))


def call_lab(path: str, method: str = "GET", payload: dict[str, object] | None = None) -> dict[str, object]:
    body = json.dumps(payload or {}).encode("utf-8") if method == "POST" else None
    request = Request(f"{LAB_URL}{path}", data=body, method=method)
    if body is not None:
        request.add_header("Content-Type", "application/json")
    try:
        with DIRECT_HTTP.open(request, timeout=5) as response:
            value = json.loads(response.read() or b"{}")
            if not isinstance(value, dict):
                raise RuntimeError("Lab engine returned an invalid response.")
            return value
    except HTTPError as exc:
        try:
            value = json.loads(exc.read() or b"{}")
            if isinstance(value, dict):
                raise RuntimeError(value.get("error", str(exc))) from exc
        except json.JSONDecodeError:
            pass
        raise RuntimeError(str(exc)) from exc
    except (URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Lab engine is unavailable: {exc}") from exc


def fetch_capture() -> bytes:
    try:
        with DIRECT_HTTP.open(f"{LAB_URL}/capture.pcap", timeout=4) as response:
            return response.read()
    except (HTTPError, URLError, TimeoutError) as exc:
        raise RuntimeError(f"Capture unavailable: {exc}") from exc
