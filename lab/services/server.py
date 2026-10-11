"""Small bounded custom banner and DNS fixtures, not production servers."""

import asyncio
import os
import struct
from typing import cast

MODE = os.environ.get("MODE", "echo")


async def client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        if MODE == "http":
            await asyncio.wait_for(reader.read(1024), 2)
            writer.write(b"HTTP/1.0 200 OK\r\nServer: LabWeb/1.0\r\nContent-Length: 0\r\n\r\n")
        elif MODE == "ssh-banner":
            writer.write(b"SSH-2.0-LabSSH_1.0\r\n")
        else:
            writer.write(b"LAB-ECHO/1.0 hello\r\n")
        await writer.drain()
    except (asyncio.TimeoutError, OSError):
        pass
    finally:
        writer.close()
        await writer.wait_closed()


class DNS(asyncio.DatagramProtocol):
    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = cast(asyncio.DatagramTransport, transport)

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        if len(data) < 12 or len(data) > 512:
            return
        ident, _, count, _, _, _ = struct.unpack("!6H", data[:12])
        if count != 1 or data[12:] != b"\x03lab\x04test\x00\x00\x01\x00\x01":
            return
        response = struct.pack("!6H", ident, 0x8400, 1, 1, 0, 0) + data[12:]
        response += b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\xac\x1e\x00\x0a"
        self.transport.sendto(response, addr)


async def main() -> None:
    if MODE == "dns":
        await asyncio.get_running_loop().create_datagram_endpoint(DNS, local_addr=("0.0.0.0", 53))
        await asyncio.Event().wait()
    else:
        port = {"http": 80, "ssh-banner": 22, "echo": 8000}[MODE]
        server = await asyncio.start_server(client, "0.0.0.0", port)
        async with server:
            await server.serve_forever()


asyncio.run(main())
