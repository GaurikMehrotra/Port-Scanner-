"""Evaluate exactly the declared measurement domain, never impute unscanned ports."""

import argparse
import json
from pathlib import Path
from typing import Any

import yaml
from metrics import metrics


def load_truth(path: Path, protocol: str) -> dict[tuple[str, str, int], str]:
    data = yaml.safe_load(path.read_text())
    return {
        (host, protocol, int(port)): state
        for host, values in data["hosts"].items()
        for port, state in values[protocol].items()
    }


def evaluate(truth_path: Path, report_path: Path) -> dict[str, Any]:
    report = json.loads(report_path.read_text())
    protocol = "udp" if report["scan_type"] == "udp" else "tcp"
    truth = load_truth(truth_path, protocol)
    observed = {(r["host"], r["protocol"], r["port"]): r["state"] for r in report["results"]}
    return metrics(truth, observed)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    parser.add_argument("--truth", type=Path, default=Path("lab/ground_truth.yaml"))
    args = parser.parse_args()
    print(json.dumps(evaluate(args.truth, args.report), indent=2, sort_keys=True))
