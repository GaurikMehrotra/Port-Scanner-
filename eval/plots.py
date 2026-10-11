"""Publication artifacts: means and sample SD, with actual replicate counts."""

import argparse
import csv
import os
import statistics
import tempfile
from collections import defaultdict
from pathlib import Path

os.environ.setdefault("MPLCONFIGDIR", str(Path(tempfile.gettempdir()) / "labscan-matplotlib"))
os.environ.setdefault("XDG_CACHE_HOME", str(Path(tempfile.gettempdir()) / "labscan-fontcache"))
import matplotlib

matplotlib.use("Agg")
from matplotlib import pyplot as plt


def plot_summary(csv_path: Path) -> None:
    groups: dict[str, list[dict[str, str]]] = defaultdict(list)
    with csv_path.open() as stream:
        for row in csv.DictReader(stream):
            groups[row["tag"].rsplit("-", 1)[0]].append(row)
    labels = sorted(groups)
    figure, axes = plt.subplots(2, 2, figsize=(16, 12), layout="constrained")
    metrics = [
        ("ports_per_second", "Ports / second"),
        ("exact_accuracy", "Exact state accuracy"),
        ("cpu_seconds", "Scanner CPU seconds"),
        ("peak_rss_kib", "Peak scanner RSS (KiB)"),
    ]
    for axis, (field, title) in zip(axes.flat, metrics):
        samples = [[float(row[field]) for row in groups[label]] for label in labels]
        means = [statistics.mean(values) for values in samples]
        errors = [statistics.stdev(values) if len(values) > 1 else 0 for values in samples]
        axis.bar(range(len(labels)), means, yerr=errors, capsize=3, color="#3978ac")
        axis.set_title(title)
        axis.set_xticks(
            range(len(labels)),
            [f"{label} (n={len(groups[label])})" for label in labels],
            rotation=80,
            ha="right",
            fontsize=7,
        )
        axis.grid(axis="y", alpha=0.25)
    figure.suptitle(
        "Isolated lab measurements: mean ± sample SD; cloud results are not laptop results"
    )
    figure.savefig(csv_path.parent / "measurements.svg")
    figure.savefig(csv_path.parent / "measurements.png", dpi=150)
    plt.close(figure)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("csv", type=Path)
    args = parser.parse_args()
    plot_summary(args.csv)
