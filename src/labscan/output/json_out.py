"""Stable JSON serialization."""

import json

from labscan.models import Report


def render(report: Report) -> str:
    return json.dumps(report.model_dump(), indent=2, sort_keys=True)
