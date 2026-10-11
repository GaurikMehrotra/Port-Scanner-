"""Bounded protocol-aware reads on an already authorized connection."""

import asyncio

from labscan.fingerprint.probes import tcp_probe
from labscan.output.sanitize import sanitize
from labscan.ratelimit import TokenBucket
from labscan.scope import ScopeGuard


async def grab(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    host: str,
    port: int,
    guard: ScopeGuard,
    timeout: float,
    limit: int,
    bucket: TokenBucket,
) -> str:
    probe = tcp_probe(port)
    try:
        if probe:
            await bucket.acquire()
            guard.check(host)
            writer.write(probe)
            await asyncio.wait_for(writer.drain(), timeout)
        data = await asyncio.wait_for(reader.read(limit), timeout)
        return sanitize(data, limit)
    except (asyncio.TimeoutError, OSError):
        return ""
