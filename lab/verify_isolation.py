"""Inspect isolation without sending an out-of-lab probe."""

import json
import subprocess

COMPOSE = ["docker", "compose", "-f", "lab/docker-compose.lab.yml"]
network = json.loads(
    subprocess.check_output(["docker", "network", "inspect", "labscan_isolated"], text=True)
)[0]
assert network["Internal"] is True
assert network["IPAM"]["Config"][0]["Subnet"] == "172.30.0.0/24"
ids = subprocess.check_output(COMPOSE + ["ps", "-q"], text=True).split()
assert len(ids) == 5, "Expected all five target containers running"
for item in json.loads(subprocess.check_output(["docker", "inspect", *ids], text=True)):
    assert list(item["NetworkSettings"]["Networks"]) == ["labscan_isolated"]
    assert not item["HostConfig"]["PortBindings"]
code = (
    "from pathlib import Path; "
    "rows=Path('/proc/net/route').read_text().splitlines()[1:]; "
    "assert not any(r.split()[1] == '00000000' for r in rows); "
    "print('No default IPv4 route in scanner')"
)
subprocess.run(
    COMPOSE + ["run", "--rm", "-T", "--entrypoint", "python", "scanner", "-c", code], check=True
)
print("Isolation checks passed: internal bridge, single network, no ports or default route")
