from typing import Any
from unittest.mock import patch

import pytest
from scapy.layers.inet import ICMP, IP, TCP

from labscan.scanners.discovery import _arp
from labscan.scanners.syn import _exchange, classify_syn
from labscan.scope import LAB, ScopeError, ScopeGuard


@pytest.mark.parametrize(
    "reply,state",
    [
        (None, "filtered"),
        (IP() / TCP(flags="SA"), "open"),
        (IP() / TCP(flags="RA"), "closed"),
        (IP() / ICMP(type=3, code=13), "filtered"),
    ],
)
def test_syn_classification(reply: Any, state: str) -> None:
    assert classify_syn(reply)[0] == state


def test_raw_transport_rechecks() -> None:
    guard = ScopeGuard((LAB,))
    with patch("labscan.scanners.syn.sr1") as send:
        with pytest.raises(ScopeError):
            _exchange("192.0.2.1", 80, guard, 0.1)
        send.assert_not_called()
    with patch("labscan.scanners.discovery.srp1") as send:
        with pytest.raises(ScopeError):
            _arp("192.0.2.1", guard, 0.1)
        send.assert_not_called()
