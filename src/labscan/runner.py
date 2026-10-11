"""One bounded worker pool for all transports and discovery."""

import asyncio
import time
from datetime import datetime, timezone

from labscan import __version__
from labscan.models import Limits, PortResult, Report
from labscan.ratelimit import TokenBucket
from labscan.scanners.connect import connect_one
from labscan.scanners.discovery import arp_discover, tcp_discover
from labscan.scanners.syn import syn_one
from labscan.scanners.udp import udp_one
from labscan.scope import ScopeGuard


async def run_scan(
    hosts: list[str],
    ports: list[int],
    scan_type: str,
    guard: ScopeGuard,
    limits: Limits,
    banners: bool = False,
    discovery: str = "skip",
) -> Report:
    guard.check_all(hosts)
    if len(hosts) > limits.max_hosts or len(ports) > limits.max_ports:
        raise ValueError("Run exceeds resource limits")
    if scan_type not in ("connect", "syn", "udp") or discovery not in ("skip", "tcp", "arp"):
        raise ValueError("Unknown scan or discovery type")
    started = datetime.now(timezone.utc).isoformat()
    tick = time.monotonic()
    bucket = TokenBucket(limits.rate)
    if discovery != "skip":
        discover = tcp_discover if discovery == "tcp" else arp_discover
        active = []
        for host in hosts:
            if await discover(host, guard, limits, bucket):
                active.append(host)
        hosts = active
    queue: asyncio.Queue[tuple[str, int]] = asyncio.Queue()
    for host in hosts:
        for port in ports:
            if not 1 <= port <= 65535:
                raise ValueError("Invalid port")
            queue.put_nowait((host, port))
    results: list[PortResult] = []

    async def worker() -> None:
        while True:
            try:
                host, port = queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            if scan_type == "connect":
                result = await connect_one(host, port, guard, limits, bucket, banners)
            elif scan_type == "syn":
                result = await syn_one(host, port, guard, limits, bucket)
            else:
                result = await udp_one(host, port, guard, limits, bucket)
            results.append(result)
            queue.task_done()

    tasks = [asyncio.create_task(worker()) for _ in range(min(limits.concurrency, queue.qsize()))]
    try:
        await asyncio.gather(*tasks)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    return Report(
        scanner_version=__version__,
        scan_type=scan_type,
        started=started,
        ended=datetime.now(timezone.utc).isoformat(),
        duration=time.monotonic() - tick,
        settings=limits,
        banners=banners,
        discovery=discovery,
        targets=hosts,
        ports=sorted(ports),
        results=sorted(
            results, key=lambda r: (tuple(map(int, r.host.split("."))), r.protocol, r.port)
        ),
    )
