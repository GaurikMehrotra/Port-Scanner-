"""Explicit unknown/missing outcomes and open-state precision/recall."""

from collections import Counter
from typing import Any


def metrics(
    truth: dict[tuple[str, str, int], str], reported: dict[tuple[str, str, int], str]
) -> dict[str, Any]:
    counts: Counter[str] = Counter()
    tp = fp = fn = 0
    for key, actual in truth.items():
        observed = reported.get(key, "missing")
        counts[f"{actual} -> {observed}"] += 1
        tp += actual == "open" and observed == "open"
        fp += actual != "open" and observed == "open"
        fn += actual == "open" and observed != "open"
    return {
        "confusion_matrix": dict(sorted(counts.items())),
        "expected": len(truth),
        "observed": len(reported),
        "missing": len(set(truth) - set(reported)),
        "unexpected": len(set(reported) - set(truth)),
        "open_precision": tp / (tp + fp) if tp + fp else None,
        "open_recall": tp / (tp + fn) if tp + fn else None,
        "exact_accuracy": sum(reported.get(k) == v for k, v in truth.items()) / len(truth),
    }
