"""Mininet topology, local service startup, and victim packet capture."""

from __future__ import annotations

import os
import shlex
import subprocess
import sys
import time
from pathlib import Path

from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.nodelib import LinuxBridge

import config
from state import (
    CAPTURE_DIR,
    CAPTURE_ERROR_PATH,
    PCAP_PATH,
    RELEASE_DIR,
    WORK_DIR,
    lab_io_lock,
    read_lines,
)


net: Mininet | None = None
hosts: dict[str, object] = {}
service_processes: list[subprocess.Popen[bytes]] = []
capture_process: subprocess.Popen[bytes] | None = None
capture_error: str | None = None


def host_command(name: str, arguments: list[str]) -> str:
    with lab_io_lock:
        host = hosts.get(name)
        if host is None:
            raise RuntimeError("Mininet lab is not ready")
        command = " ".join(shlex.quote(item) for item in arguments)
        return host.cmd(command)


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
    for name in addresses:
        net.addLink(net.get(name), switch)
    net.build()
    net.start()
    hosts = {name: net.get(name) for name in addresses}
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
    global capture_process, capture_error
    with lab_io_lock:
        victim = hosts.get("victim")
        if victim is None:
            capture_error = "Packet capture is unavailable: Mininet victim is not ready."
            return
        CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
        os.chmod(CAPTURE_DIR, 0o1777)
        for path in (PCAP_PATH, CAPTURE_ERROR_PATH):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        capture_process = None
        capture_error = None
        try:
            with CAPTURE_ERROR_PATH.open("ab") as error_log:
                capture_process = victim.popen(
                    [
                        "tcpdump",
                        "-U",
                        "-n",
                        "-i",
                        "victim-eth0",
                        "-w",
                        str(PCAP_PATH),
                        f"udp port {config.DNS_PORT} or tcp port {config.RECEIVER_PORT}",
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
                        return
                except OSError:
                    pass
                time.sleep(0.05)
            if capture_process.poll() is not None:
                capture_error = "Packet capture exited: " + (" ".join(read_lines(CAPTURE_ERROR_PATH, 4)) or "tcpdump did not start")
            else:
                capture_error = "Packet capture did not create a readable capture file."
            print(capture_error, flush=True)
            stop_capture()
        except OSError as exc:
            capture_error = f"Packet capture did not start: {exc}"
            print(capture_error, flush=True)


def stop_capture() -> None:
    global capture_process
    with lab_io_lock:
        process = capture_process
        capture_process = None
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()


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


def cleanup() -> None:
    stop_capture()
    for process in service_processes:
        if process.poll() is None:
            process.terminate()
    if net is not None:
        net.stop()
