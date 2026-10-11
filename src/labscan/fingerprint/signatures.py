"""Original conservative service identification rules; never infer a version."""

import re


def identify(banner: str) -> tuple[str | None, str | None, str | None]:
    ssh = re.match(r"SSH-[0-9.]+-([A-Za-z][A-Za-z0-9-]*)(?:_([A-Za-z0-9.p-]+))?", banner)
    if ssh:
        return "ssh", ssh.group(1), ssh.group(2)
    server = re.search(r"Server: ([A-Za-z][A-Za-z0-9-]*)(?:/([A-Za-z0-9._-]+))?", banner, re.I)
    if banner.startswith("HTTP/"):
        return "http", server.group(1) if server else None, server.group(2) if server else None
    if banner.startswith("+PONG"):
        return "redis-compatible", None, None
    if banner.startswith("LAB-ECHO/"):
        return "lab-echo", "lab-echo", banner.split("/", 1)[1].split(" ", 1)[0]
    return None, None, None
