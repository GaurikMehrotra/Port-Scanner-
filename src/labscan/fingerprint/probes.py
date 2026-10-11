"""Small original, harmless probes. No external probe database."""

import struct

DNS_ID = 0x4C53


def dns_query() -> bytes:
    # Fixed lab-only name, A record, no recursion requested.
    return struct.pack("!6H", DNS_ID, 0, 1, 0, 0, 0) + b"\x03lab\x04test\x00\x00\x01\x00\x01"


def valid_dns_reply(data: bytes) -> bool:
    if len(data) < 12:
        return False
    ident, flags = struct.unpack("!HH", data[:4])
    return ident == DNS_ID and bool(flags & 0x8000)


def tcp_probe(port: int) -> bytes | None:
    if port in (80, 8000):
        return b"HEAD / HTTP/1.0\r\nHost: lab.test\r\nConnection: close\r\n\r\n"
    if port == 6379:
        return b"*1\r\n$4\r\nPING\r\n"
    return None
