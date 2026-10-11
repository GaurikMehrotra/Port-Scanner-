"""Run in the scanner container; measure actual scanner process CPU and peak RSS."""

import asyncio
import json
import resource
import sys
from pathlib import Path

from labscan.isolation import check_lab_routes
from labscan.models import Limits
from labscan.ports import parse_ports
from labscan.runner import run_scan
from labscan.scope import ScopeGuard
from labscan.targets import parse_targets

check_lab_routes()
config = json.loads(sys.argv[1])
guard = ScopeGuard.from_file(Path("configs/scope.yaml"))
limits = Limits.model_validate(config["limits"])
hosts = parse_targets(config["targets"], guard, limits.max_hosts)
ports = parse_ports(config["ports"], limits.max_ports)
before = resource.getrusage(resource.RUSAGE_SELF)
report = asyncio.run(run_scan(hosts, ports, config["scan_type"], guard, limits))
after = resource.getrusage(resource.RUSAGE_SELF)
output = report.model_dump()
output["resources"] = {
    "cpu_seconds": after.ru_utime + after.ru_stime - before.ru_utime - before.ru_stime,
    "peak_rss_kib": after.ru_maxrss,
    "ports_per_second": len(report.results) / report.duration,
}
print(json.dumps(output, sort_keys=True))
