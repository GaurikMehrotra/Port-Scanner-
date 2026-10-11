"""Async TCP connect scan. Socket creation always follows a scope recheck."""

import asyncio
import errno
import socket

from labscan.fingerprint.banners import grab
from labscan.fingerprint.signatures import identify
from labscan.models import Limits, PortResult
from labscan.ratelimit import TokenBucket
from labscan.scope import ScopeGuard


async def connect_one(
    host: str,
    port: int,
    guard: ScopeGuard,
    limits: Limits,
    bucket: TokenBucket,
    banners: bool = False,
) -> PortResult:
    for attempt in range(limits.retries + 1):
        await bucket.acquire()
        guard.check(host)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setblocking(False)
        try:
            # Numeric, pinned destination. Recheck immediately before the syscall.
            guard.check(host)
            await asyncio.wait_for(
                asyncio.get_running_loop().sock_connect(sock, (host, port)), limits.timeout
            )
            result = PortResult(host=host, port=port, state="open", reason="connect succeeded")
            if banners:
                reader, writer = await asyncio.open_connection(sock=sock)
                try:
                    result.banner = await grab(
                        reader,
                        writer,
                        host,
                        port,
                        guard,
                        limits.timeout,
                        limits.banner_bytes,
                        bucket,
                    )
                    result.service, result.product, result.version = identify(result.banner)
                finally:
                    writer.close()
                    try:
                        await asyncio.wait_for(writer.wait_closed(), limits.timeout)
                    except (OSError, asyncio.TimeoutError):
                        pass
            return result
        except (OSError, asyncio.TimeoutError) as exc:
            error_number = getattr(exc, "errno", None)
            if error_number == errno.ECONNREFUSED:
                return PortResult(host=host, port=port, state="closed", reason="connection refused")
            if error_number not in (
                None,
                errno.ETIMEDOUT,
                errno.EHOSTUNREACH,
                errno.ENETUNREACH,
                errno.ECONNRESET,
            ):
                raise
            if attempt == limits.retries:
                return PortResult(
                    host=host,
                    port=port,
                    state="filtered",
                    reason="timeout or unreachable; inference",
                )
        finally:
            sock.close()
    raise AssertionError("Unreachable retry path")
