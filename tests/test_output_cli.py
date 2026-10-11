import json

from typer.testing import CliRunner

from labscan.cli import app
from labscan.models import Limits, PortResult, Report
from labscan.output import csv_out, json_out, nmap_xml


def test_serializers() -> None:
    report = Report(
        scanner_version="0.1.0",
        scan_type="connect",
        started="a",
        ended="b",
        duration=1,
        settings=Limits(),
        targets=["127.0.0.1"],
        ports=[1],
        results=[PortResult(host="127.0.0.1", port=1, state="open", reason="test")],
    )
    assert json.loads(json_out.render(report))["results"][0]["state"] == "open"
    assert "scan_type" in csv_out.render(report)
    assert 'scanner="labscan"' in nmap_xml.render(report)


def test_cli_dry_run() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["172.30.0.10", "--dry-run"])
    assert result.exit_code == 0
    assert json.loads(result.stdout)["targets"] == ["172.30.0.10"]
    for target in ("192.0.2.1", "lab.test", "::1"):
        assert runner.invoke(app, [target, "--dry-run"]).exit_code == 2
    assert runner.invoke(app, ["172.30.0.10", "--force"]).exit_code == 2
