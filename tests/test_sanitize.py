import unicodedata

from hypothesis import given
from hypothesis import strategies as st

from labscan.fingerprint.signatures import identify
from labscan.output.sanitize import sanitize


def test_escape_removal() -> None:
    assert sanitize(b"\x1b[31mhello\x1b[0m\r\n\x00") == "hello"
    assert sanitize("\x1b]8;;https://lab.test\x07link\x1b]8;;\x07") == "link"
    assert sanitize("a\u202eb") == "ab"
    assert len(sanitize(b"x" * 5000, 32)) == 32


@given(st.binary(max_size=5000))
def test_no_controls(data: bytes) -> None:
    output = sanitize(data, 100)
    assert len(output) <= 100
    assert all(not unicodedata.category(c).startswith("C") for c in output)


def test_signatures() -> None:
    assert identify("SSH-2.0-OpenSSH_9.2p1") == ("ssh", "OpenSSH", "9.2p1")
    assert identify("HTTP/1.0 200 OK  Server: LabWeb/1.0  Content-Length: 0") == (
        "http",
        "LabWeb",
        "1.0",
    )
    assert identify("+PONG") == ("redis-compatible", None, None)
