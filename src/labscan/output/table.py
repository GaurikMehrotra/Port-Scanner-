"""Rich human output treats every remote value as literal text."""

from rich.table import Table

from labscan.models import Report


def render(report: Report) -> Table:
    table = Table(title=f"labscan {report.scan_type}: {len(report.results)} ports")
    for heading in ("Host", "Port", "State", "Service", "Product", "Version", "Banner"):
        table.add_column(heading, overflow="fold")
    from rich.text import Text

    for r in report.results:
        table.add_row(
            *(
                Text(str(x or ""))
                for x in (
                    r.host,
                    f"{r.port}/{r.protocol}",
                    r.state,
                    r.service,
                    r.product,
                    r.version,
                    r.banner,
                )
            )
        )
    return table
