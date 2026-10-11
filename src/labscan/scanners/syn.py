"""Scoped Scapy SYN scan; kernel RSTs are left enabled."""

from __future__ import annotations

import asyncio
import secrets
from typing import Any

from scapy.layers.inet import ICMP, IP, TCP
from scapy.sendrecv import sr1

from labscan.models import Limits, PortResult, State
from labscan.ratelimit import TokenBucket
from labscan.scope import ScopeGuard


def classify_syn(reply: Any) -> tuple[State, str]:
    if reply is None:
        return "filtered", "no response; inference"
    if reply.haslayer(TCP):
        flags = int(reply[TCP].flags)
        if flags & 0x04:
            return "closed", "TCP RST"
        if flags & 0x12 == 0x12:
            return "open", "TCP SYN-ACK"
    if reply.haslayer(ICMP) and int(reply[ICMP].type) == 3:
        return "filtered", "ICMP unreachable; inference"
    return "filtered", "unexpected response; inference"


def _exchange(host: str, port: int, guard: ScopeGuard, timeout: float) -> Any:
    # All outbound SYNs use actual local routing/source; no source spoofing or evasion.
    packet = IP(dst=host) / TCP(
        dport=port, sport=secrets.randbelow(16384) + 49152, flags="S", seq=secrets.randbits(32)
    )
    guard.check(host)
    return sr1(packet, timeout=timeout, verbose=False)


async def syn_one(
    host: str, port: int, guard: ScopeGuard, limits: Limits, bucket: TokenBucket
) -> PortResult:
    for attempt in range(limits.retries + 1):
        await bucket.acquire()
        guard.check(host)
        reply = await asyncio.to_thread(_exchange, host, port, guard, limits.timeout)
        state, reason = classify_syn(reply)
        if state != "filtered" or attempt == limits.retries:
            return PortResult(host=host, port=port, state=state, reason=reason)
    raise AssertionError("Unreachable")
