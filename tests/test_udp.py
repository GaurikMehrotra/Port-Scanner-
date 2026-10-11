import asyncio
import ipaddress
from typing import cast
from unittest.mock import patch

import pytest

from labscan.models import Limits
from labscan.ratelimit import TokenBucket
from labscan.scanners.udp import udp_one
from labscan.scope import ScopeError, ScopeGuard

GUARD = ScopeGuard((ipaddress.ip_network("127.0.0.0/8"),))


class Echo(asyncio.DatagramProtocol):
    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = cast(asyncio.DatagramTransport, transport)

    def datagram_received(self, data: bytes, address: tuple[str, int]) -> None:
        self.transport.sendto(b"LAB-ECHO/1.0", address)


async def test_udp_open_closed_silent() -> None:
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(Echo, local_addr=("127.0.0.1", 0))
    port = transport.get_extra_info("sockname")[1]
    result = await udp_one("127.0.0.1", port, GUARD, Limits(timeout=0.1), TokenBucket(100))
    assert result.state == "open"
    transport.close()
    await asyncio.sleep(0.02)
    result = await udp_one("127.0.0.1", port, GUARD, Limits(timeout=0.1), TokenBucket(100))
    assert result.state == "closed"
    silent, _ = await loop.create_datagram_endpoint(
        asyncio.DatagramProtocol, local_addr=("127.0.0.1", 0)
    )
    try:
        port = silent.get_extra_info("sockname")[1]
        result = await udp_one("127.0.0.1", port, GUARD, Limits(timeout=0.05), TokenBucket(100))
        assert result.state == "open|filtered"
    finally:
        silent.close()


async def test_udp_recheck() -> None:
    with patch("labscan.scanners.udp.socket.socket") as sock:
        with pytest.raises(ScopeError):
            await udp_one("192.0.2.1", 80, GUARD, Limits(), TokenBucket(100))
        sock.assert_not_called()
