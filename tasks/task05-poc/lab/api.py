"""Private HTTP control API for the Mininet lab engine; no user interface lives here."""

from __future__ import annotations

import json
import signal
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import config
import host
import scenario
import sensor
import state
import topology
from state import BEACONS_PATH, DNS_LOG, RECEIVER_LOG, RESULT_LOG, RESULTS_PATH, UPDATE_LOG, WORK_DIR, append_history


httpd: ThreadingHTTPServer | None = None


def blue_state() -> dict[str, object]:
    """Sensor snapshot plus the state of the two enforcement points."""
    snapshot = state.read_sensor_state()
    with state.state_lock:
        mode = state.coordinator_mode
        blocked = state.dns_block_active
        previous = state.dns_block_previous_mode
    return {
        "sensor": topology.sensor_status(),
        "rules": [dict(rule) for rule in sensor.RULES],
        "alerts": snapshot.get("alerts", []),
        "decodes": snapshot.get("decodes", []),
        "beacons": snapshot.get("beacons", []),
        "flows": snapshot.get("flows", []),
        "counters": snapshot.get("counters", {}),
        "suffix": sensor.CHECKIN_SUFFIX,
        "resolver": {"blocked": blocked, "previous_mode": previous, "mode": mode},
        "host": host.snapshot(),
    }


def apply_response(action: str) -> str:
    """Run one defender response; each one changes real lab state."""
    if action == "block-dns":
        with state.state_lock:
            if state.dns_block_active:
                return "The resolver already answers NXDOMAIN for the check-in suffix."
            state.dns_block_previous_mode = state.coordinator_mode
        scenario.write_mode("disabled")
        with state.state_lock:
            state.dns_block_active = True
        return (
            f"Resolver block on: the coordinator now answers NXDOMAIN for {sensor.CHECKIN_SUFFIX}. "
            "The beacon loop stops at its next check-in."
        )
    if action == "unblock-dns":
        with state.state_lock:
            if not state.dns_block_active:
                return "No resolver block is active."
            previous = state.dns_block_previous_mode
        scenario.write_mode(previous)
        with state.state_lock:
            state.dns_block_active = False
        return f"Resolver block cleared: the coordinator is back to {previous}."
    if action == "isolate":
        detail = topology.set_isolation(True)
        return (
            f"Tap isolation on: the bridge drops traffic from {config.VICTIM_IP} "
            f"at {detail.get('mechanism') or 'the bridge'}. Beacons stop immediately."
        )
    if action == "restore-tap":
        topology.set_isolation(False)
        return "Tap isolation cleared: the bridge forwards the victim's traffic again."
    raise ValueError("Unknown response action.")


class LabApiHandler(BaseHTTPRequestHandler):
    def send_json(self, status: int, value: dict[str, object]) -> None:
        body = json.dumps(value).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if path == "/health":
            self.send_json(200, {"ready": True})
        elif path == "/api/client-state":
            self.send_json(200, scenario.client_state())
        elif path == "/api/attacker-state":
            self.send_json(200, scenario.attacker_state())
        elif path == "/api/blue-state":
            self.send_json(200, blue_state())
        elif path == "/capture.pcap":
            if not topology.capture_is_ready():
                self.send_json(404, {"error": topology.capture_error or "No packet capture is ready yet."})
                return
            try:
                body = state.PCAP_PATH.read_bytes()
            except OSError:
                self.send_json(404, {"error": "No packet capture is ready yet."})
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/vnd.tcpdump.pcap")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_json(404, {"error": "Not found."})

    def do_POST(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        try:
            length = int(self.headers.get("Content-Length", "-1"))
            if length < 0 or length > 4096:
                raise ValueError("invalid body length")
            body = json.loads(self.rfile.read(length))
            if not isinstance(body, dict):
                raise ValueError("JSON body must be an object")
        except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
            self.send_json(400, {"error": "Invalid request body."})
            return
        try:
            if path == "/api/check-updates":
                message = scenario.check_for_updates()
            elif path == "/api/install-update":
                message = scenario.install_available_update()
            elif path == "/api/select-version":
                message = scenario.select_version(str(body.get("version", "")))
            elif path == "/api/set-mode":
                mode = str(body.get("mode", ""))
                with state.state_lock:
                    blocked = state.dns_block_active
                if blocked and mode != "disabled":
                    raise ValueError(
                        "A resolver block is active, so the coordinator stays disabled. "
                        "Clear the block in the Blue Team app before changing the mode."
                    )
                scenario.write_mode(mode)
                display = "active" if mode == "selected" else mode
                message = f"Coordinator response is {display} for V3 check-ins until changed or reset."
            elif path == "/api/queue-task":
                message = scenario.queue_task(str(body.get("command", "")), str(body.get("target", "all")))
            elif path == "/api/response":
                message = apply_response(str(body.get("action", "")))
            elif path == "/api/reset":
                topology.set_isolation(False)
                state.clear_response_state()
                message = scenario.reset_demo()
            else:
                self.send_json(404, {"error": "Not found."})
                return
            self.send_json(200, {"message": message})
        except (ValueError, RuntimeError, OSError, json.JSONDecodeError) as exc:
            self.send_json(400, {"error": str(exc)})

    def log_message(self, _format: str, *_args: object) -> None:
        return


def shutdown(_signum: int, _frame: object) -> None:
    if httpd is not None:
        threading.Thread(target=httpd.shutdown, daemon=True).start()


def main() -> None:
    global httpd
    WORK_DIR.mkdir(parents=True, exist_ok=True)
    for path in (UPDATE_LOG, DNS_LOG, RECEIVER_LOG, RESULT_LOG):
        path.write_text("", encoding="utf-8")
    for path in (state.TASK_PATH, BEACONS_PATH, RESULTS_PATH):
        try:
            path.unlink()
        except FileNotFoundError:
            pass
    scenario.write_mode("passive")
    try:
        topology.start_mininet()
        topology.wait_for_services()
        host.start()
        for path in (UPDATE_LOG, DNS_LOG, RECEIVER_LOG, RESULT_LOG):
            path.write_text("", encoding="utf-8")
        topology.start_capture()
        scenario.install_version("v2", "Initial client install", schedule_callback=False, record_history=False)
        append_history("Update agent started on V2; stable channel checked.")
        httpd = ThreadingHTTPServer(("0.0.0.0", 8080), LabApiHandler)
        httpd.daemon_threads = True
        scenario.start_update_monitor()
        signal.signal(signal.SIGTERM, shutdown)
        signal.signal(signal.SIGINT, shutdown)
        print("Mininet lab engine ready on internal port 8080", flush=True)
        httpd.serve_forever(poll_interval=0.5)
    finally:
        scenario.stop_update_monitor()
        if httpd is not None:
            httpd.server_close()
        topology.cleanup()


if __name__ == "__main__":
    main()
