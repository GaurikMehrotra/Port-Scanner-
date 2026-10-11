"""Controlled target-only netem experiment, with honest blocked outcomes."""

import argparse
import json
import subprocess
import sys
from pathlib import Path

from benchmarks import COMPOSE, run_case, save_summary


def tc(*args: str) -> None:
    result = subprocess.run(
        COMPOSE + ["exec", "-T", "firewall", "tc", *args], capture_output=True, text=True
    )
    if result.returncode:
        raise RuntimeError(f"tc {' '.join(args)}: {result.stderr.strip()}")


def experiment(output: Path, trials: int) -> None:
    rows = []
    applied = False
    # Netem uses kernel randomness; no claim of a seed on kernels without seed support.
    try:
        for label, impairment in [
            ("control", ["delay", "0ms"]),
            ("delay", ["delay", "200ms"]),
            ("loss", ["delay", "200ms", "loss", "10%"]),
        ]:
            tc("qdisc", "replace", "dev", "eth0", "root", "netem", *impairment)
            applied = True
            for trial in range(trials):
                for kind in ("connect", "syn"):
                    for timeout, retries in [(0.1, 0), (1.0, 0), (1.0, 2)]:
                        tag = f"{label}-{kind}-{timeout}-{retries}-{trial}"
                        print(tag, flush=True)
                        rows.append(run_case(output, tag, kind, 10, timeout, retries, 20))
    finally:
        # Never delete the original qdisc when installation failed.
        if applied:
            tc("qdisc", "del", "dev", "eth0", "root")
    save_summary(output, rows)
    (output / "status.json").write_text(json.dumps({"status": "complete", "runs": len(rows)}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("results/impairment"))
    parser.add_argument("--trials", type=int, default=3)
    args = parser.parse_args()
    if not 1 <= args.trials <= 10:
        parser.error("trials must be 1..10")
    args.output.mkdir(parents=True, exist_ok=True)
    try:
        experiment(args.output, args.trials)
    except (RuntimeError, subprocess.CalledProcessError) as exc:
        status = {
            "status": "blocked",
            "reason": str(exc),
            "action": "Use a Linux/WSL2 kernel with sch_netem support; do not use privileged mode",
        }
        (args.output / "status.json").write_text(json.dumps(status, indent=2))
        print(str(exc), file=sys.stderr)
        raise SystemExit(1) from exc
