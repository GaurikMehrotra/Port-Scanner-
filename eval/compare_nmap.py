"""Nmap is a reference, not truth; XML parser uses standard ElementTree."""

import argparse
import json
from pathlib import Path
from xml.etree import ElementTree

from ground_truth import load_truth


def compare(report_path: Path, nmap_path: Path, truth_path: Path) -> dict[str, object]:
    report = json.loads(report_path.read_text())
    ours = {(r["host"], r["protocol"], r["port"]): r["state"] for r in report["results"]}
    reference = {}
    for host in ElementTree.parse(nmap_path).getroot().findall("host"):
        address = host.find("address")
        if address is None:
            continue
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is not None:
                reference[
                    (address.attrib["addr"], port.attrib["protocol"], int(port.attrib["portid"]))
                ] = state.attrib["state"]
    protocol = "udp" if report["scan_type"] == "udp" else "tcp"
    truth = load_truth(truth_path, protocol)
    disagreements = []
    for key in sorted(set(ours) | set(reference)):
        if ours.get(key, "missing") != reference.get(key, "missing"):
            disagreements.append(
                {
                    "host": key[0],
                    "protocol": key[1],
                    "port": key[2],
                    "labscan": ours.get(key, "missing"),
                    "nmap": reference.get(key, "missing"),
                    "truth": truth.get(key),
                }
            )
    return {
        "disagreements": disagreements,
        "reference_count": len(reference),
        "labscan_count": len(ours),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    parser.add_argument("nmap", type=Path)
    parser.add_argument("--truth", type=Path, default=Path("lab/ground_truth.yaml"))
    args = parser.parse_args()
    print(json.dumps(compare(args.report, args.nmap, args.truth), indent=2))
