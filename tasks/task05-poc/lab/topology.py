"""Mininet topology, local service startup, and the inline sensor tap.

The victim is no longer attached to the switch directly.  It has one link to a
``sensor`` host that bridges that link to the switch, so the only path between
the victim and the lab services crosses the bridge:

    victim <-> sensor-eth0 [br0] sensor-eth1 <-> s1 <-> updater / dns / receiver

``br0`` carries the management address from ``config.SENSOR_MGMT_IP`` and is the
interface tcpdump captures, so every packet the detector scores was carried by
the tap.  Isolation is a real packet filter on the bridge: a ``tc`` egress
filter on the switch-side port drops everything the victim sends.  The filter
runs after the bridge clones the frame to the capture point, so the pcap keeps
showing the victim's queries while no answer ever comes back.
"""

from __future__ import annotations

import os
import shlex
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.nodelib import LinuxBridge

import config
import state as lab_state
from state import (
    CAPTURE_DIR,
    CAPTURE_ERROR_PATH,
    PCAP_PATH,
    RELEASE_DIR,
    SENSOR_DIR,
    SENSOR_ERROR_PATH,
    SENSOR_STATE_PATH,
    WORK_DIR,
    lab_io_lock,
    read_lines,
)

SENSOR_BRIDGE = "br0"
SENSOR_HOST = "sensor"
CAPTURE_FILTER = f"udp port {config.DNS_PORT} or tcp port {config.RECEIVER_PORT} or tcp port {config.UPDATE_PORT}"

net: Mininet | None = None
hosts: dict[str, object] = {}
sensor_interfaces: dict[str, str] = {}
service_processes: list[subprocess.Popen[bytes]] = []
capture_process: subprocess.Popen[bytes] | None = None
detector_process: subprocess.Popen[bytes] | None = None
capture_error: str | None = None
isolation: dict[str, object] = {"active": False, "mechanism": None, "since": None, "error": None}


def host_command(name: str, arguments: list[str]) -> str:
    with lab_io_lock:
        host = hosts.get(name)
        if host is None:
            raise RuntimeError("Mininet lab is not ready")
        command = " ".join(shlex.quote(item) for item in arguments)
        return host.cmd(command)


def _sensor_command(arguments: list[str]) -> str:
    sensor = hosts.get(SENSOR_HOST)
    if sensor is None:
        return ""
    command = " ".join(shlex.quote(item) for item in arguments)
    return sensor.cmd(command)


def _configure_sensor() -> None:
    """Build the bridge that carries the victim's only path to the switch."""
    global sensor_interfaces
    sensor = net.get(SENSOR_HOST) if net is not None else None
    victim = net.get("victim") if net is not None else None
    switch = net.get("s1") if net is not None else None
    if sensor is None or victim is None or switch is None:
        raise RuntimeError("Mininet topology is incomplete")
    downlink = sensor.connectionsTo(victim)[0][0].name
    uplink = sensor.connectionsTo(switch)[0][0].name
    sensor_interfaces = {"downlink": downlink, "uplink": uplink}
    commands = (
        ["ip", "link", "add", "name", SENSOR_BRIDGE, "type", "bridge"],
        ["ip", "link", "set", "dev", SENSOR_BRIDGE, "type", "bridge", "forward_delay", "0", "stp_state", "0"],
        ["ip", "link", "set", "dev", downlink, "master", SENSOR_BRIDGE],
        ["ip", "link", "set", "dev", uplink, "master", SENSOR_BRIDGE],
        ["ip", "link", "set", "dev", downlink, "up"],
        ["ip", "link", "set", "dev", uplink, "up"],
        ["ip", "link", "set", "dev", SENSOR_BRIDGE, "up"],
        ["ip", "address", "add", f"{config.SENSOR_MGMT_IP}/24", "dev", SENSOR_BRIDGE],
    )
    for command in commands:
        output = _sensor_command(command)
        if "File exists" in output or "already" in output:
            continue
        if "Error" in output or "Cannot" in output or "not permitted" in output or "not found" in output:
            raise RuntimeError(f"Sensor bridge setup failed at {' '.join(command)}: {output.strip()}")
    addresses = _sensor_command(["ip", "-brief", "address", "show", SENSOR_BRIDGE])
    if config.SENSOR_MGMT_IP not in addresses:
        raise RuntimeError(f"Sensor bridge has no management address: {addresses.strip() or 'no output'}")
    members = _sensor_command(["bridge", "link", "show", "master", SENSOR_BRIDGE])
    missing = [name for name in (downlink, uplink) if name not in members]
    if missing:
        raise RuntimeError(f"Sensor bridge is missing ports {', '.join(missing)}: {members.strip() or 'no output'}")


def start_mininet() -> None:
    global net, hosts, service_processes
    setLogLevel("warning")
    net = Mininet(controller=None, switch=LinuxBridge, build=False, autoSetMacs=True)
    addresses = {
        "updater": f"{config.UPDATER_IP}/24",
        "dns": f"{config.DNS_IP}/24",
        "receiver": f"{config.RECEIVER_IP}/24",
        "victim": f"{config.VICTIM_IP}/24",
    }
    for name, address in addresses.items():
        net.addHost(name, ip=address)
    switch = net.addSwitch("s1")
    for name in ("updater", "dns", "receiver"):
        net.addLink(net.get(name), switch)
    sensor_host = net.addHost(SENSOR_HOST, ip=None)
    net.addLink(sensor_host, switch)
    net.addLink(net.get("victim"), sensor_host)
    net.build()
    net.start()
    hosts = {name: net.get(name) for name in (*addresses, SENSOR_HOST)}
    _configure_sensor()
    service_processes = [
        hosts["updater"].popen([sys.executable, "/app/services.py", "updates", str(RELEASE_DIR), str(WORK_DIR / "update.log")]),
        hosts["dns"].popen([sys.executable, "/app/services.py", "dns", str(WORK_DIR / "mode.json"), str(WORK_DIR / "dns.log")]),
        hosts["receiver"].popen([
            sys.executable,
            "/app/services.py",
            "receiver",
            str(WORK_DIR / "receiver.log"),
            str(WORK_DIR / "task.json"),
            str(WORK_DIR / "beacons.json"),
            str(WORK_DIR / "results.json"),
            str(WORK_DIR / "result.log"),
        ]),
    ]


def wait_for_services(timeout: float = 15) -> None:
    deadline = time.monotonic() + timeout
    last_error = "local services did not become ready"
    while time.monotonic() < deadline:
        for role, process in zip(("updater", "DNS coordinator", "receiver"), service_processes):
            code = process.poll()
            if code is not None:
                raise RuntimeError(f"The {role} service exited during startup (code {code}).")
        try:
            output = host_command(
                "victim",
                [
                    sys.executable,
                    "/app/services.py",
                    "probe",
                    config.UPDATER_IP,
                    config.DNS_IP,
                    config.RECEIVER_IP,
                ],
            )
            if "ready" in output.splitlines():
                return
            last_error = output.strip() or last_error
        except (OSError, RuntimeError) as exc:
            last_error = str(exc)
        time.sleep(0.25)
    raise RuntimeError(f"Lab services did not become ready: {last_error}")


def start_capture() -> None:
    """Start (or restart) the tap: tcpdump on the bridge plus the detector."""
    global capture_process, detector_process, capture_error
    with lab_io_lock:
        set_isolation(False)
        lab_state.clear_response_state()
        sensor = hosts.get(SENSOR_HOST)
        if sensor is None or not sensor_interfaces:
            capture_error = "Packet capture is unavailable: the sensor host is not ready."
            return
        CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
        os.chmod(CAPTURE_DIR, 0o1777)
        SENSOR_DIR.mkdir(parents=True, exist_ok=True)
        os.chmod(SENSOR_DIR, 0o1777)
        for path in (PCAP_PATH, CAPTURE_ERROR_PATH, SENSOR_STATE_PATH, SENSOR_ERROR_PATH):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        capture_process = None
        detector_process = None
        capture_error = None
        try:
            with CAPTURE_ERROR_PATH.open("ab") as error_log:
                capture_process = sensor.popen(
                    [
                        "tcpdump",
                        "-U",
                        "-n",
                        "-i",
                        SENSOR_BRIDGE,
                        "-w",
                        str(PCAP_PATH),
                        CAPTURE_FILTER,
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=error_log,
                )
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                if capture_process.poll() is not None:
                    break
                try:
                    if PCAP_PATH.stat().st_size >= 24:
                        break
                except OSError:
                    pass
                time.sleep(0.05)
            if capture_process.poll() is not None:
                capture_error = "Packet capture exited: " + (" ".join(read_lines(CAPTURE_ERROR_PATH, 4)) or "tcpdump did not start")
                print(capture_error, flush=True)
                stop_capture()
                return
            if not PCAP_PATH.exists() or PCAP_PATH.stat().st_size < 24:
                capture_error = "Packet capture did not create a readable capture file."
                print(capture_error, flush=True)
                stop_capture()
                return
            with SENSOR_ERROR_PATH.open("ab") as error_log:
                detector_process = sensor.popen(
                    [
                        sys.executable,
                        "/app/sensor.py",
                        "--pcap",
                        str(PCAP_PATH),
                        "--state-dir",
                        str(SENSOR_DIR),
                        "--iface",
                        SENSOR_BRIDGE,
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=error_log,
                )
        except OSError as exc:
            capture_error = f"Packet capture did not start: {exc}"
            print(capture_error, flush=True)


def stop_capture() -> None:
    global capture_process, detector_process
    with lab_io_lock:
        for process in (detector_process, capture_process):
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
        detector_process = None
        capture_process = None


def capture_is_ready() -> bool:
    global capture_error
    process = capture_process
    if process is None:
        return False
    exit_code = process.poll()
    if exit_code is not None:
        if capture_error is None:
            detail = " ".join(read_lines(CAPTURE_ERROR_PATH, 4))
            capture_error = f"Packet capture stopped (code {exit_code}). {detail}".strip()
        return False
    try:
        return PCAP_PATH.stat().st_size >= 24
    except OSError:
        return False


def set_isolation(active: bool) -> dict[str, object]:
    """Drop (or restore) the victim's traffic at the bridge."""
    with lab_io_lock:
        uplink = sensor_interfaces.get("uplink")
        if hosts.get(SENSOR_HOST) is None or not uplink:
            raise RuntimeError("The sensor is not ready, so the tap cannot be controlled.")
        if active == bool(isolation["active"]):
            return dict(isolation)
        if active:
            _sensor_command(["tc", "qdisc", "replace", "dev", uplink, "clsact"])
            _sensor_command(["tc", "filter", "replace", "dev", uplink, "egress", "pref", "1", "matchall", "action", "drop"])
            filters = _sensor_command(["tc", "filter", "show", "dev", uplink, "egress"])
            if "drop" in filters:
                mechanism = "tc egress drop"
                error = None
            else:
                _sensor_command(["tc", "qdisc", "del", "dev", uplink, "clsact"])
                _sensor_command(["ip", "link", "set", "dev", uplink, "down"])
                mechanism = "uplink port down"
                error = f"tc filter unavailable on {uplink}; the uplink port was set down instead"
            isolation.update(
                active=True,
                mechanism=mechanism,
                since=datetime.now(timezone.utc).strftime("%H:%M:%S"),
                error=error,
            )
        else:
            _sensor_command(["tc", "qdisc", "del", "dev", uplink, "clsact"])
            _sensor_command(["ip", "link", "set", "dev", uplink, "up"])
            isolation.update(active=False, mechanism=None, since=None, error=None)
        return dict(isolation)


def sensor_status() -> dict[str, object]:
    """Live view of the tap for the Blue Team app."""
    snapshot = lab_state.read_sensor_state()
    process = detector_process
    running = process is not None and process.poll() is None
    detail = ""
    if process is not None and process.poll() is not None and process.returncode not in (0, -15):
        detail = " ".join(read_lines(SENSOR_ERROR_PATH, 4))
    age = None
    try:
        age = round(time.time() - SENSOR_STATE_PATH.stat().st_mtime, 1)
    except OSError:
        age = None
    return {
        "running": running,
        "capture_ready": capture_is_ready(),
        "capture_file": PCAP_PATH.name,
        "capture_error": capture_error,
        "interface": SENSOR_BRIDGE,
        "management": config.SENSOR_MGMT_IP,
        "uplink": sensor_interfaces.get("uplink"),
        "downlink": sensor_interfaces.get("downlink"),
        "filter": CAPTURE_FILTER,
        "isolation": dict(isolation),
        "error": detail or None,
        "state_age": age,
        "packets": snapshot.get("packets", 0),
        "last_packet": snapshot.get("last_packet"),
        "started": snapshot.get("started"),
    }


def cleanup() -> None:
    stop_capture()
    for process in service_processes:
        if process.poll() is None:
            process.terminate()
    if net is not None:
        net.stop()
