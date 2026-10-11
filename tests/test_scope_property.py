import ipaddress

from hypothesis import given, settings
from hypothesis import strategies as st

from labscan.scope import LAB, ScopeError, ScopeGuard


@settings(max_examples=1000, derandomize=True)
@given(st.integers(min_value=0, max_value=2**32 - 1))
def test_no_out_of_scope_ipv4_accepted(value: int) -> None:
    address = ipaddress.IPv4Address(value)
    guard = ScopeGuard((LAB,))
    try:
        accepted = guard.check(str(address))
    except ScopeError:
        assert address not in LAB
    else:
        assert accepted in LAB


@settings(max_examples=500, derandomize=True)
@given(st.text(max_size=100))
def test_arbitrary_text_check(value: str) -> None:
    try:
        accepted = ScopeGuard((LAB,)).check(value)
    except ScopeError:
        return
    assert accepted in LAB


@settings(max_examples=256, derandomize=True)
@given(st.integers(min_value=0, max_value=255))
def test_lab_positive_examples(value: int) -> None:
    assert ScopeGuard((LAB,)).check(f"172.30.0.{value}") in LAB


@settings(max_examples=256, derandomize=True)
@given(st.integers(min_value=0, max_value=2**128 - 1))
def test_all_ipv6_rejected(value: int) -> None:
    try:
        ScopeGuard((LAB,)).check(str(ipaddress.IPv6Address(value)))
    except ScopeError:
        return
    raise AssertionError("IPv6 was accepted")
