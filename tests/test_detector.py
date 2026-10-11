import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "eval"))
from detect import detect
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap


def test_synthetic_scan_and_benign(tmp_path: Path) -> None:
    scan = []
    for port in range(8000, 8012):
        packet = Ether() / IP(src="172.30.0.20", dst="172.30.0.10") / TCP(dport=port, flags="S")
        packet.time = 1 + (port - 8000) / 20
        scan.append(packet)
    path = tmp_path / "scan.pcap"
    wrpcap(str(path), scan)
    assert len(detect(path, 5, 10)) == 1
    wrpcap(str(path), scan[:3])
    assert detect(path, 5, 10) == []
