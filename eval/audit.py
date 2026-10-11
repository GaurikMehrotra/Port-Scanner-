"""Repository literal/CI audit; complements review rather than proving security."""

import ipaddress
import re
from pathlib import Path

ALLOWED = tuple(
    ipaddress.IPv4Network(x)
    for x in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
    )
)
IGNORED = {
    ".git",
    ".venv",
    "results",
    "dist",
    "build",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".hypothesis",
}


def audit_capture(path: Path) -> None:
    from collections.abc import Iterable
    from typing import Any, cast

    from scapy.layers.inet import IP
    from scapy.layers.inet6 import IPv6
    from scapy.utils import PcapReader

    lab = ipaddress.IPv4Network("172.30.0.0/24")
    with PcapReader(str(path)) as packets:
        for packet in cast(Iterable[Any], packets):
            if packet.haslayer(IP):
                for address in (packet[IP].src, packet[IP].dst):
                    if ipaddress.IPv4Address(address) not in lab:
                        raise SystemExit(f"Capture packet outside lab: {path}")
            if packet.haslayer(IPv6):
                for address in (packet[IPv6].src, packet[IPv6].dst):
                    v6 = ipaddress.IPv6Address(address)
                    local_multicast = v6.is_multicast and (v6.packed[1] & 15) in (1, 2)
                    if v6.is_global and not local_multicast:
                        raise SystemExit(f"Global IPv6 capture packet: {path}")


def audit(root: Path) -> None:
    checked = 0
    failures = []
    for path in root.rglob("*"):
        if not path.is_file() or any(
            part in IGNORED or part.endswith(".egg-info") for part in path.relative_to(root).parts
        ):
            continue
        if path.suffix in (".png", ".pcap", ".pcapng"):
            if path.suffix in (".pcap", ".pcapng"):
                audit_capture(path)
            continue
        text = path.read_text(encoding="utf-8")
        checked += 1
        for token in re.findall(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])", text):
            try:
                address = ipaddress.IPv4Address(token)
            except ValueError:
                continue
            if address.is_unspecified:
                continue  # Bind address and intentionally rejected broad-policy tests.
            if not any(address in network for network in ALLOWED):
                failures.append(f"Nonexample/nonprivate IPv4 literal: {path}:{token}")
        for token in re.findall(r"(?<![\w:])(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f:.]*", text):
            try:
                v6 = ipaddress.IPv6Address(token)
            except ValueError:
                continue
            if v6.is_global:
                failures.append(f"Nonexample global IPv6 literal: {path}:{token}")
    ci = (root / ".github/workflows/ci.yml").read_text()
    if "make check" not in ci or "make install" not in ci:
        failures.append("CI must install and run the checked test workflow")
    for line in ci.splitlines():
        if line.strip().startswith("- run:") and line.strip() not in (
            "- run: make install",
            "- run: make check",
        ):
            failures.append("Unexpected CI run command; manually review its networking")
    if failures:
        raise SystemExit("\n".join(failures))
    print(f"Audited {checked} text files: IP literal and CI command policy passed")


if __name__ == "__main__":
    audit(Path.cwd())
