"""Reject collisions with nondefault host routes and existing Docker networks."""

import ipaddress
import json
import subprocess

LAB = ipaddress.IPv4Network("172.30.0.0/24")


def main() -> None:
    routes = json.loads(subprocess.check_output(["ip", "-j", "-4", "route"], text=True))
    for route in routes:
        prefix = route.get("dst", "default")
        if prefix != "default" and ipaddress.IPv4Network(prefix, strict=False).overlaps(LAB):
            raise SystemExit(f"Collision with host route {prefix}; stop before creating the lab")
    ids = subprocess.check_output(["docker", "network", "ls", "-q"], text=True).split()
    if ids:
        networks = json.loads(
            subprocess.check_output(["docker", "network", "inspect", *ids], text=True)
        )
        for network in networks:
            for config in network.get("IPAM", {}).get("Config", []) or []:
                subnet = config.get("Subnet")
                if subnet and ":" not in subnet and ipaddress.IPv4Network(subnet).overlaps(LAB):
                    if network["Name"] != "labscan_isolated" or not network["Internal"]:
                        raise SystemExit(f"Collision with Docker network {network['Name']}")
    print("No local route/Docker collision. Check Windows/LAN routes separately.")


if __name__ == "__main__":
    main()
