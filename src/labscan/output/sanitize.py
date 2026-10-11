"""Remove terminal escapes, controls, and Unicode formatting characters."""

import re
import unicodedata

ANSI = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\))")


def sanitize(value: str | bytes, limit: int = 1024) -> str:
    text = (
        value[:limit].decode("utf-8", errors="replace")
        if isinstance(value, bytes)
        else value[:limit]
    )
    text = ANSI.sub("", text)
    text = text.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    return "".join(c for c in text if not unicodedata.category(c).startswith("C"))[:limit].strip()
