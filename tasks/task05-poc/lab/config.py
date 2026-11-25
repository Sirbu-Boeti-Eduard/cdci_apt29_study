"""Single source for the Task 5 lab network addresses and service names."""

UPDATER_IP = "10.0.0.2"
DNS_IP = "10.0.0.3"
RECEIVER_IP = "10.0.0.4"
VICTIM_IP = "10.0.0.5"
SENSOR_MGMT_IP = "10.0.0.6"

DNS_PORT = 53
UPDATE_PORT = 8000
RECEIVER_PORT = 9000

CHECKIN_NAME = "checkin.orion-lab.test"
HANDOFF_NAME = "handoff.orion-lab.test"
RECEIVER_NAME = "receiver.orion-lab.test"
COORDINATOR_NAME = "coordinator.orion-lab.test"

MODE_IPS = {
    "passive": "192.0.2.10",
    "selected": "192.0.2.20",
}

# The C2 endpoint and agent string.  Both sides of the lab agree on these, and
# the request body imitates the vendor's Improvement Program upload.
TELEMETRY_PATH = "/swip/upd/orion.improvementprogram.asmx"
TELEMETRY_AGENT = "Orion/2020.2.4 (Windows NT 10.0; Win64; x64)"
TELEMETRY_VERSION = "2020.2.4"
