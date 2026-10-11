"""Offline, bounded-window SYN fan-out detector for lab-only PCAP files."""

import argparse
import ipaddress
import json
from collections import defaultdict, deque
from collections.abc import Iterable
from pathlib import Path
from typing import Any, cast

from scapy.layers.inet import IP, TCP
from scapy.utils import PcapReader

from labscan.scope import LAB


def detect(path: Path, window: float, threshold: int) -> list[dict[str, object]]:
    events: dict[str, deque[tuple[float, str, int]]] = defaultdict(deque)
    alerts = []
    alerted = set()
    with PcapReader(str(path)) as packets:
        for packet in cast(Iterable[Any], packets):
            if not packet.haslayer(IP) or not packet.haslayer(TCP):
                continue
            if (
                ipaddress.IPv4Address(packet[IP].src) not in LAB
                or ipaddress.IPv4Address(packet[IP].dst) not in LAB
            ):
                raise ValueError("Capture contains traffic outside the lab")
            if int(packet[TCP].flags) & 0x12 != 0x02:
                continue
            source, timestamp = str(packet[IP].src), float(packet.time)
            queue = events[source]
            queue.append((timestamp, str(packet[IP].dst), int(packet[TCP].dport)))
            while queue and timestamp - queue[0][0] > window:
                queue.popleft()
            distinct = {(host, port) for _, host, port in queue}
            if len(distinct) >= threshold and source not in alerted:
                alerts.append(
                    {"source": source, "timestamp": timestamp, "distinct_ports": len(distinct)}
                )
                alerted.add(source)
    return alerts


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("pcap", type=Path)
    parser.add_argument("--window", type=float, default=5)
    parser.add_argument("--threshold", type=int, default=10)
    args = parser.parse_args()
    if args.window <= 0 or args.threshold < 2:
        parser.error("positive window and threshold >= 2 required")
    print(json.dumps(detect(args.pcap, args.window, args.threshold), indent=2))
