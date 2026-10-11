"""Strict address policy and one-time DNS pinning; no bypass switch."""

from __future__ import annotations

import ipaddress
import re
import socket
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

Address = ipaddress.IPv4Address | ipaddress.IPv6Address
Network = ipaddress.IPv4Network | ipaddress.IPv6Network
Resolver = Callable[..., list[tuple[Any, ...]]]
LAB = ipaddress.IPv4Network("172.30.0.0/24")
TEST_LOOPBACK = ipaddress.IPv4Network("127.0.0.0/8")
HOST_LABEL = re.compile(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\Z")


class ScopeError(ValueError):
    """An input is ambiguous or outside the fixed authorization boundary."""


@dataclass(frozen=True)
class ScopeGuard:
    """Network policy; tests explicitly construct loopback-only guards in Python."""

    networks: tuple[Network, ...]

    def __post_init__(self) -> None:
        if not self.networks:
            raise ScopeError("Empty scope")
        for net in self.networks:
            if not any(
                isinstance(net, ipaddress.IPv4Network) and net.subnet_of(base)
                for base in (LAB, TEST_LOOPBACK)
            ):
                raise ScopeError("Scope cannot extend beyond lab or test loopback")

    @classmethod
    def from_file(cls, path: Path) -> ScopeGuard:
        data = yaml.safe_load(path.read_text())
        if not isinstance(data, dict) or set(data) != {"networks"}:
            raise ScopeError("Scope file must contain only networks")
        nets = tuple(ipaddress.ip_network(x, strict=True) for x in data["networks"])
        # CLI configuration cannot authorize loopback; it is reserved for unit tests.
        if any(not isinstance(n, ipaddress.IPv4Network) or not n.subnet_of(LAB) for n in nets):
            raise ScopeError("CLI scope must be a subnet of 172.30.0.0/24")
        return cls(nets)

    def check(self, value: str | Address) -> Address:
        """Revalidate the exact numeric address used by a socket or packet send."""
        raw = str(value)
        if not raw.isascii() or raw != raw.strip() or "%" in raw:
            raise ScopeError("Noncanonical address")
        try:
            address = ipaddress.ip_address(raw)
        except ValueError as exc:
            raise ScopeError("Expected a canonical IP address") from exc
        # Reject mapped forms instead of silently changing address families.
        if isinstance(address, ipaddress.IPv6Address):
            raise ScopeError("IPv6 and mapped IPv6 are not authorized in this IPv4 lab")
        if not any(address.version == net.version and address in net for net in self.networks):
            raise ScopeError("Address outside authorized scope")
        return address

    def resolve(self, value: str, resolver: Resolver = socket.getaddrinfo) -> tuple[str, ...]:
        """Resolve once; reject the entire name if any answer is outside scope."""
        if not value or not value.isascii() or value != value.strip():
            raise ScopeError("Empty, whitespace, or Unicode target")
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            address = None
        if address is not None:
            return (str(self.check(address)),)
        # Numeric aliases must never reach legacy resolver parsing.
        labels = value.split(".")
        if (
            value.endswith(".")
            or len(value) > 253
            or ":" in value
            or "/" in value
            or re.fullmatch(r"[0-9.]+", value)
            or any(x.lower().startswith("0x") for x in labels)
            or not all(HOST_LABEL.fullmatch(x) for x in labels)
        ):
            raise ScopeError("Ambiguous address or invalid hostname")
        answers = resolver(value, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        pinned = {str(self.check(answer[4][0])) for answer in answers}
        if not pinned:
            raise ScopeError("Hostname has no addresses")
        return tuple(sorted(pinned, key=ipaddress.ip_address))

    def expand(self, token: str, max_hosts: int) -> tuple[str, ...]:
        """Bound CIDR expansion before allocating addresses."""
        if "/" not in token:
            return self.resolve(token)
        if not token.isascii() or token != token.strip():
            raise ScopeError("Noncanonical CIDR")
        try:
            net = ipaddress.ip_network(token, strict=True)
        except ValueError as exc:
            raise ScopeError("Invalid canonical CIDR") from exc
        if net.num_addresses > max_hosts:
            raise ScopeError("CIDR exceeds host cap")
        if not any(
            isinstance(net, ipaddress.IPv4Network)
            and isinstance(allowed, ipaddress.IPv4Network)
            and net.subnet_of(allowed)
            for allowed in self.networks
        ):
            raise ScopeError("CIDR outside scope")
        return tuple(str(self.check(ip)) for ip in net.hosts())

    def check_all(self, addresses: Iterable[str]) -> None:
        for address in addresses:
            self.check(address)
