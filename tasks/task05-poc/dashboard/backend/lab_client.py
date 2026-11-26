"""Private HTTP clients for the presentation dashboard."""

from __future__ import annotations

import json
import os
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener


LAB_URL = os.environ.get("LAB_URL", "http://lab:8080")
PIPELINE_URL = os.environ.get("PIPELINE_URL", "http://pipeline:8080")
REGISTRY_URL = os.environ.get("REGISTRY_URL", "http://registry:8080")
DIRECT_HTTP = build_opener(ProxyHandler({}))


def _call(url: str, method: str = "GET", payload: dict[str, object] | None = None, headers: dict[str, str] | None = None) -> dict[str, object]:
    body = json.dumps(payload or {}).encode("utf-8") if method == "POST" else None
    request = Request(url, data=body, method=method, headers=headers or {})
    if body is not None:
        request.add_header("Content-Type", "application/json")
    try:
        with DIRECT_HTTP.open(request, timeout=5) as response:
            value = json.loads(response.read() or b"{}")
            if not isinstance(value, dict):
                raise RuntimeError("Service returned an invalid response.")
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
        raise RuntimeError(f"Service is unavailable: {exc}") from exc


def call_lab(path: str, method: str = "GET", payload: dict[str, object] | None = None) -> dict[str, object]:
    return _call(LAB_URL + path, method, payload)


def call_pipeline(
    path: str,
    method: str = "GET",
    payload: dict[str, object] | None = None,
    presenter: bool = False,
) -> dict[str, object]:
    headers = {"X-Presenter-Request": "true"} if presenter else None
    return _call(PIPELINE_URL + path, method, payload, headers)


def call_registry(
    path: str,
    method: str = "GET",
    payload: dict[str, object] | None = None,
    presenter: bool = False,
) -> dict[str, object]:
    headers = {"X-Presenter-Request": "true"} if presenter else None
    return _call(REGISTRY_URL + path, method, payload, headers)
