"""Fixed, repeatable one-factor ablations; no unbounded target arguments."""

import argparse
import csv
import json
import subprocess
from pathlib import Path

from ground_truth import evaluate

COMPOSE = ["docker", "compose", "-f", "lab/docker-compose.lab.yml"]
TARGETS = "172.30.0.10,172.30.0.11,172.30.0.12,172.30.0.13,172.30.0.14"


def run_case(
    output: Path,
    tag: str,
    kind: str,
    concurrency: int,
    timeout: float,
    retries: int,
    rate: float,
    targets: str = TARGETS,
    ports: str = "common",
) -> dict[str, object]:
    config = {
        "targets": targets,
        "ports": ports,
        "scan_type": kind,
        "limits": {
            "concurrency": concurrency,
            "timeout": timeout,
            "retries": retries,
            "rate": rate,
        },
    }
    service = "raw" if kind == "syn" else "scanner"
    result = subprocess.run(
        COMPOSE
        + [
            "run",
            "--rm",
            "-T",
            "--entrypoint",
            "python",
            service,
            "eval/worker.py",
            json.dumps(config),
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    report = json.loads(result.stdout)
    path = output / f"{tag}.json"
    path.write_text(json.dumps(report, indent=2))
    score = evaluate(Path("lab/ground_truth.yaml"), path)
    return {
        "tag": tag,
        "scan_type": kind,
        "concurrency": concurrency,
        "timeout": timeout,
        "retries": retries,
        "rate": rate,
        "duration": report["duration"],
        **report["resources"],
        "exact_accuracy": score["exact_accuracy"],
        "open_precision": score["open_precision"],
        "open_recall": score["open_recall"],
    }


def save_summary(output: Path, rows: list[dict[str, object]]) -> None:
    with (output / "summary.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    (output / "summary.json").write_text(json.dumps(rows, indent=2))
    from plots import plot_summary

    plot_summary(output / "summary.csv")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("results/benchmarks"))
    parser.add_argument("--trials", type=int, default=3)
    args = parser.parse_args()
    if not 1 <= args.trials <= 10:
        parser.error("trials must be 1..10")
    args.output.mkdir(parents=True, exist_ok=True)
    rows = []
    cases = [
        ("baseline", 10, 1.0, 0, 20),
        ("c1", 1, 1.0, 0, 20),
        ("c20", 20, 1.0, 0, 20),
        ("t025", 10, 0.25, 0, 20),
        ("t2", 10, 2.0, 0, 20),
        ("r1", 10, 1.0, 1, 20),
        ("rate5", 10, 1.0, 0, 5),
        ("rate50", 10, 1.0, 0, 50),
    ]
    for trial in range(args.trials):
        for kind in ("connect", "syn", "udp"):
            for name, concurrency, timeout, retries, rate in cases:
                tag = f"{kind}-{name}-{trial}"
                print(tag, flush=True)
                rows.append(run_case(args.output, tag, kind, concurrency, timeout, retries, rate))
    save_summary(args.output, rows)
