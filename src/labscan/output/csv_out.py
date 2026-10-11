"""CSV includes scan metadata on each row; formula-like banners are neutralized."""

import csv
import io

from labscan.models import Report


def render(report: Report) -> str:
    output = io.StringIO()
    fields = [
        "host",
        "port",
        "protocol",
        "state",
        "reason",
        "service",
        "product",
        "version",
        "banner",
    ]
    meta = [
        "scan_type",
        "scanner_version",
        "started",
        "ended",
        "duration",
        "settings",
        "banners",
        "discovery",
    ]
    writer = csv.DictWriter(output, fieldnames=fields + meta)
    writer.writeheader()
    for result in report.results:
        row = result.model_dump()
        for key in ("banner", "product", "version"):
            if isinstance(row[key], str) and row[key].startswith(("=", "+", "-", "@")):
                row[key] = "'" + row[key]
        row.update({key: getattr(report, key) for key in meta if key != "settings"})
        row["settings"] = report.settings.model_dump_json()
        writer.writerow(row)
    return output.getvalue()
