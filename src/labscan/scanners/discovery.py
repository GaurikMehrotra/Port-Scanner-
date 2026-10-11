"""TCP and on-link ARP discovery; absence of response does not prove absence."""

import asyncio
from typing import Any

from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp1

from labscan.models import Limits
from labscan.ratelimit import TokenBucket
from labscan.scanners.connect import connect_one
from labscan.scope import ScopeGuard


async def tcp_discover(host: str, guard: ScopeGuard, limits: Limits, bucket: TokenBucket) -> bool:
    for port in (22, 80, 6379):
        result = await connect_one(host, port, guard, limits, bucket)
        if result.state in ("open", "closed"):
            return True
    return False


def _arp(host: str, guard: ScopeGuard, timeout: float) -> Any:
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=host)
    guard.check(host)
    return srp1(packet, timeout=timeout, verbose=False)


async def arp_discover(host: str, guard: ScopeGuard, limits: Limits, bucket: TokenBucket) -> bool:
    await bucket.acquire()
    guard.check(host)
    reply = await asyncio.to_thread(_arp, host, guard, limits.timeout)
    return bool(
        reply is not None
        and reply.haslayer(ARP)
        and int(reply[ARP].op) == 2
        and str(reply[ARP].psrc) == host
    )
