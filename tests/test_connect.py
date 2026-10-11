import asyncio
import ipaddress
from unittest.mock import patch

import pytest

from labscan.models import Limits
from labscan.ratelimit import TokenBucket
from labscan.runner import run_scan
from labscan.scanners.connect import connect_one
from labscan.scope import ScopeError, ScopeGuard

GUARD = ScopeGuard((ipaddress.ip_network("127.0.0.0/8"),))


async def test_open_closed_banner() -> None:
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.write(b"SSH-2.0-LabSSH_1.0\x1b[31m\r\n")
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    async with server:
        report = await run_scan(
            ["127.0.0.1"], [port], "connect", GUARD, Limits(timeout=0.2), banners=True
        )
    assert report.results[0].state == "open"
    assert report.results[0].product == "LabSSH"
    assert "\x1b" not in report.results[0].banner
    result = await connect_one("127.0.0.1", port, GUARD, Limits(), TokenBucket(100))
    assert result.state == "closed"


async def test_transport_recheck_blocks_parse_bypass() -> None:
    with patch("labscan.scanners.connect.socket.socket") as sock:
        with pytest.raises(ScopeError):
            await connect_one("192.0.2.1", 80, GUARD, Limits(), TokenBucket(100))
        sock.assert_not_called()


async def test_timeout_and_retry() -> None:
    with patch(
        "asyncio.selector_events.BaseSelectorEventLoop.sock_connect", side_effect=TimeoutError
    ) as call:
        result = await connect_one(
            "127.0.0.1", 80, GUARD, Limits(timeout=0.05, retries=2), TokenBucket(100)
        )
    assert result.state == "filtered"
    assert call.call_count == 3


async def test_dns_answer_is_pinned_before_connection() -> None:
    from unittest.mock import Mock

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    resolver = Mock(return_value=[(2, 1, 6, "", ("127.0.0.1", 0))])
    pinned = GUARD.resolve("service.lab", resolver)[0]
    resolver.return_value = [(2, 1, 6, "", ("192.0.2.1", 0))]
    async with server:
        port = server.sockets[0].getsockname()[1]
        result = await connect_one(pinned, port, GUARD, Limits(), TokenBucket(100))
    assert result.state == "open"
    resolver.assert_called_once()
