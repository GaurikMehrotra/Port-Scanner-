import pytest

from labscan.isolation import validate_routes
from labscan.scope import ScopeError

HEADER = "Iface Destination Gateway Flags RefCnt Use Metric Mask\n"
LAB_ROUTE = "eth0 00001EAC 00000000 0001 0 0 0 00FFFFFF\n"
DEFAULT = "eth0 00000000 01001EAC 0003 0 0 0 00000000\n"


def test_lab_only_routes() -> None:
    validate_routes(HEADER + LAB_ROUTE)
    for routes in (HEADER, HEADER + DEFAULT, HEADER + LAB_ROUTE + DEFAULT):
        with pytest.raises(ScopeError):
            validate_routes(routes)
