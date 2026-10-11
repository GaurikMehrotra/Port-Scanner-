import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "eval"))
from impairment import experiment


def test_failed_install_preserves_original_qdisc(tmp_path: Path) -> None:
    with patch("impairment.tc", side_effect=RuntimeError("unknown qdisc")) as command:
        with pytest.raises(RuntimeError, match="unknown qdisc"):
            experiment(tmp_path, 1)
        assert command.call_count == 1


def test_scan_failure_cleans_installed_qdisc(tmp_path: Path) -> None:
    with (
        patch("impairment.tc") as command,
        patch("impairment.run_case", side_effect=RuntimeError("scan failed")),
    ):
        with pytest.raises(RuntimeError, match="scan failed"):
            experiment(tmp_path, 1)
        assert command.call_args.args == ("qdisc", "del", "dev", "eth0", "root")
