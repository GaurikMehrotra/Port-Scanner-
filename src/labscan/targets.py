"""Bounded target specification parsing and DNS pinning."""

import ipaddress

from labscan.scope import ScopeError, ScopeGuard


def parse_targets(spec: str, guard: ScopeGuard, max_hosts: int) -> list[str]:
    targets: set[str] = set()
    for token in spec.split(","):
        targets.update(guard.expand(token, max_hosts))
        if len(targets) > max_hosts:
            raise ScopeError("Target count exceeds host cap")
    if not targets:
        raise ScopeError("No targets")
    return sorted(targets, key=ipaddress.ip_address)
