"""Lab-only CLI. Dry runs do not resolve names or send packets."""

import asyncio
import ipaddress
import json
from pathlib import Path
from typing import Annotated

import typer
import yaml
from pydantic import ValidationError
from rich.console import Console

from labscan.isolation import check_lab_routes
from labscan.models import Limits
from labscan.output import csv_out, json_out, nmap_xml, table
from labscan.ports import parse_ports
from labscan.runner import run_scan
from labscan.scope import ScopeError, ScopeGuard
from labscan.targets import parse_targets

app = typer.Typer(add_completion=False, help="Authorized isolated-lab scanner. No scope bypass.")


@app.command()
def scan(
    targets: Annotated[str, typer.Argument(help="Canonical IPs/CIDRs or names; comma separated")],
    ports: str = "common",
    scan_type: str = "connect",
    scope: Path = Path("configs/scope.yaml"),
    limits_file: Path = Path("configs/limits.yaml"),
    output_format: str = "table",
    output: Path | None = None,
    rate: float | None = None,
    concurrency: int | None = None,
    timeout: float | None = None,
    retries: int | None = None,
    banners: bool = False,
    discovery: str = "skip",
    dry_run: bool = False,
) -> None:
    """Scan the fixed isolated lab; exit 2 for invalid input, 1 for runtime errors."""
    console = Console(stderr=True)
    try:
        guard = ScopeGuard.from_file(scope)
        settings = yaml.safe_load(limits_file.read_text())
        for name, value in (
            ("rate", rate),
            ("concurrency", concurrency),
            ("timeout", timeout),
            ("retries", retries),
        ):
            if value is not None:
                settings[name] = value
        limits = Limits.model_validate(settings)
        selected_ports = parse_ports(ports, limits.max_ports)
        if scan_type not in ("connect", "syn", "udp"):
            raise ValueError("scan-type must be connect, syn, or udp")
        if discovery not in ("skip", "tcp", "arp"):
            raise ValueError("discovery must be skip, tcp, or arp")
        if output_format not in ("table", "json", "csv", "xml"):
            raise ValueError("output-format must be table, json, csv, or xml")
        if banners and scan_type != "connect":
            raise ValueError("TCP banners require connect scan; UDP identifies DNS itself")
        if dry_run:
            # DNS itself emits traffic, so dry-run intentionally accepts numeric targets only.
            for token in targets.split(","):
                try:
                    ipaddress.ip_network(token, strict=True)
                except ValueError as exc:
                    raise ValueError(
                        "Dry-run accepts only canonical numeric IPs/CIDRs; no DNS"
                    ) from exc
        if not dry_run:
            check_lab_routes()
        hosts = parse_targets(targets, guard, limits.max_hosts)
        if dry_run:
            typer.echo(
                json.dumps(
                    {
                        "targets": hosts,
                        "ports": selected_ports,
                        "scan_type": scan_type,
                        "settings": limits.model_dump(),
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return
        with console.status("Scanning authorized lab targets..."):
            report = asyncio.run(
                run_scan(hosts, selected_ports, scan_type, guard, limits, banners, discovery)
            )
        if output_format == "table":
            if output:
                raise ValueError("Use JSON/CSV/XML for file output")
            Console().print(table.render(report))
        else:
            renderer = {"json": json_out.render, "csv": csv_out.render, "xml": nmap_xml.render}
            text = renderer[output_format](report)
            if output:
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(text + "\n")
            else:
                typer.echo(text)
    except (ScopeError, ValueError, ValidationError, FileNotFoundError) as exc:
        console.print(f"Rejected: {exc}", markup=False)
        raise typer.Exit(2) from exc
    except OSError as exc:
        console.print(
            f"Runtime failure: {exc}. Check lab routes and NET_RAW for raw scans.", markup=False
        )
        raise typer.Exit(1) from exc
