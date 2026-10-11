"""Basic UDP scan through a connected socket, including DNS validation."""

import asyncio
import errno
import socket

from labscan.fingerprint.probes import dns_query, valid_dns_reply
from labscan.models import Limits, PortResult, State
from labscan.output.sanitize import sanitize
from labscan.ratelimit import TokenBucket
from labscan.scope import ScopeGuard


async def udp_one(
    host: str, port: int, guard: ScopeGuard, limits: Limits, bucket: TokenBucket
) -> PortResult:
    for attempt in range(limits.retries + 1):
        await bucket.acquire()
        guard.check(host)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        loop = asyncio.get_running_loop()
        try:
            guard.check(host)
            sock.connect((host, port))
            guard.check(host)
            await loop.sock_sendall(sock, dns_query() if port == 53 else b"labscan\n")
            data = await asyncio.wait_for(loop.sock_recv(sock, limits.banner_bytes), limits.timeout)
            result = PortResult(
                host=host,
                port=port,
                protocol="udp",
                state="open",
                reason="UDP reply",
                banner=sanitize(data, limits.banner_bytes),
            )
            if port == 53 and valid_dns_reply(data):
                result.service = "dns"
                result.banner = "Validated DNS reply"
            return result
        except (OSError, asyncio.TimeoutError) as exc:
            error_number = getattr(exc, "errno", None)
            if error_number == errno.ECONNREFUSED:
                return PortResult(
                    host=host,
                    port=port,
                    protocol="udp",
                    state="closed",
                    reason="ICMP port unreachable reported by connected socket",
                )
            if error_number not in (None, errno.ETIMEDOUT, errno.EHOSTUNREACH, errno.ENETUNREACH):
                raise
            if attempt == limits.retries:
                state: State = (
                    "open|filtered" if error_number in (None, errno.ETIMEDOUT) else "filtered"
                )
                return PortResult(
                    host=host,
                    port=port,
                    protocol="udp",
                    state=state,
                    reason="silence or unreachable; inference",
                )
        finally:
            sock.close()
    raise AssertionError("Unreachable")
