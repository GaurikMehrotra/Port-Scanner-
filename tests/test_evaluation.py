import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "eval"))
from metrics import metrics


def test_confusion_and_missing() -> None:
    truth = {("127.0.0.1", "tcp", 1): "open", ("127.0.0.1", "tcp", 2): "closed"}
    result = metrics(truth, {("127.0.0.1", "tcp", 1): "closed"})
    assert result["missing"] == 1
    assert result["open_recall"] == 0
    assert result["open_precision"] is None
    assert result["exact_accuracy"] == 0
