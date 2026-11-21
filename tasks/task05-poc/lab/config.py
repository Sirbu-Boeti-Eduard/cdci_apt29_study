"""Single source for the Task 5 lab network addresses and service names."""

UPDATER_IP = "10.0.0.2"
DNS_IP = "10.0.0.3"
RECEIVER_IP = "10.0.0.4"
VICTIM_IP = "10.0.0.5"

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
