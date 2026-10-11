import ipaddress
from pathlib import Path
from unittest.mock import Mock

import pytest

from labscan.scope import LAB, ScopeError, ScopeGuard

BAD = [
    "192.0.2.1",
    "198.51.100.1",
    "203.0.113.1",
    "10.0.0.1",
    "172.30.1.1",
    "::1",
    "::ffff:172.30.0.10",
    "2001:db8::1",
    "0xac1e000a",
    "2887647242",
    "0254.036.0.012",
    "172.030.0.10",
    "172.30.0.10.",
    " 172.30.0.10",
    "172.30.0.10\n",
    "１７２.３０.０.１０",
    "172.30.0.10%eth0",
    "172.30.0.10/0",
]


@pytest.mark.parametrize("value", BAD)
def test_hostile_inputs(value: str) -> None:
    resolver = Mock(side_effect=AssertionError("Ambiguous input reached DNS"))
    with pytest.raises(ScopeError):
        ScopeGuard((LAB,)).resolve(value, resolver)


def test_dns_pin_and_reject_mixed_answers() -> None:
    resolver = Mock(return_value=[(2, 1, 6, "", ("172.30.0.10", 0))])
    guard = ScopeGuard((LAB,))
    assert guard.resolve("web.lab", resolver) == ("172.30.0.10",)
    resolver.assert_called_once()
    resolver.return_value.append((2, 1, 6, "", ("192.0.2.1", 0)))
    with pytest.raises(ScopeError):
        guard.resolve("web.lab", resolver)


def test_cidr_caps() -> None:
    guard = ScopeGuard((LAB,))
    assert guard.expand("172.30.0.8/30", 4) == ("172.30.0.9", "172.30.0.10")
    for token in ("172.30.0.0/24", "172.30.0.10/24", "192.0.2.0/28"):
        with pytest.raises(ScopeError):
            guard.expand(token, 32)


def test_config_cannot_widen(tmp_path: Path) -> None:
    path = tmp_path / "scope.yaml"
    for net in ("0.0.0.0/0", "127.0.0.0/8", "172.30.0.0/16"):
        path.write_text(f"networks: [{net}]\n")
        with pytest.raises(ScopeError):
            ScopeGuard.from_file(path)
    with pytest.raises(ScopeError):
        ScopeGuard((ipaddress.ip_network("192.0.2.0/24"),))


@pytest.mark.parametrize(
    "value",
    [
        "172.30.0.10\t",
        "\t172.30.0.10",
        "172.30.0.10\x00",
        "172.30.0.10\x1b[31m",
        "172.30.0.10\u200b",
        "172.30.0.10\u202e",
        "172.30.0.１０",
        "\uff11\uff17\uff12.30.0.10",
        "172.30.0",
        "172.30",
        "0172.30.0.10",
        "172.30.00.10",
        "172.30.0.0010",
        "0XAC1E000A",
        "0xac.0x1e.0x00.0x0a",
        "0xAC.30.0.10",
        "2887647242.",
        "172.30.0.10/32",
        "172.30.0.10:80",
        "[172.30.0.10]",
        "[::1]",
        "::ffff:ac1e:a",
        "lab.test.",
        "-lab.test",
        "lab-.test",
        "lab..test",
        "a" * 64 + ".test",
        "a." * 130 + "test",
        "lab_test",
        "lab/test",
        "lab@172.30.0.10",
        "lab.test ",
    ],
)
def test_more_hostile_encodings(value: str) -> None:
    resolver = Mock(side_effect=AssertionError("Invalid input reached DNS"))
    with pytest.raises(ScopeError):
        ScopeGuard((LAB,)).resolve(value, resolver)


@pytest.mark.parametrize(
    "outside", ["192.0.2.1", "198.51.100.1", "203.0.113.1", "10.0.0.1", "::1", "::ffff:172.30.0.10"]
)
def test_hostname_outside_answers(outside: str) -> None:
    resolver = Mock(return_value=[(2, 1, 6, "", (outside, 0))])
    with pytest.raises(ScopeError):
        ScopeGuard((LAB,)).resolve("outside.lab", resolver)
