import pytest

from labscan.ports import parse_ports
from labscan.scope import LAB, ScopeError, ScopeGuard
from labscan.targets import parse_targets


def test_targets_sorted_deduplicated() -> None:
    assert parse_targets("172.30.0.11,172.30.0.10,172.30.0.11", ScopeGuard((LAB,)), 2) == [
        "172.30.0.10",
        "172.30.0.11",
    ]
    with pytest.raises(ScopeError):
        parse_targets("172.30.0.10,172.30.0.11", ScopeGuard((LAB,)), 1)


@pytest.mark.parametrize("bad", ["", "0", "65536", "4-2", "1-65535", " 80", "８０", "0x50", "1,,2"])
def test_bad_ports(bad: str) -> None:
    with pytest.raises(ValueError):
        parse_ports(bad, 128)


def test_ports() -> None:
    assert parse_ports("80,22-24,80", 5) == [22, 23, 24, 80]
    assert 53 in parse_ports("common", 128)
    with pytest.raises(ValueError):
        parse_ports("common", 1)
