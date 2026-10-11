"""Fail closed when the CLI is outside the expected internal Linux lab network."""

import ipaddress
import struct
from pathlib import Path

from labscan.scope import LAB, ScopeError


def validate_routes(text: str) -> None:
    connected = False
    for row in text.splitlines()[1:]:
        fields = row.split()
        if len(fields) < 8:
            raise ScopeError("Cannot inspect lab routes")
        destination = ipaddress.IPv4Address(struct.pack("<I", int(fields[1], 16)))
        mask = ipaddress.IPv4Address(struct.pack("<I", int(fields[7], 16)))
        if int(mask) == 0 and int(fields[3], 16) & 1:
            raise ScopeError("Default route present; run only in the internal scanner container")
        if destination == LAB.network_address and mask == LAB.netmask and fields[2] == "00000000":
            connected = True
    if not connected:
        raise ScopeError("Missing directly connected lab route; run inside the internal lab")


def check_lab_routes() -> None:
    """No CLI flag or environment variable can disable this check."""
    validate_routes(Path("/proc/net/route").read_text())
