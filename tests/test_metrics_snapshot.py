"""Tests for scripts/metrics_snapshot.py.

The diff tool is only useful if a real regression actually fails the build,
so these tests mutate a known-good snapshot and assert the exit code. Without
them, a broken comparator would report "no regressions" forever and look fine.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

# The script lives outside the package; add its directory to the path
_SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(_SCRIPTS))

import metrics_snapshot  # noqa: E402 - imported after sys.path setup


@pytest.fixture
def good_snapshot() -> dict[str, Any]:
    """A minimal, internally consistent report dict."""
    return {
        "total": 6,
        "attacks": 4,
        "legitimate": 2,
        "attacks_blocked": 4,
        "false_negatives": 0,
        "false_positives": 0,
        "defense_rate": 1.0,
        "false_positive_rate": 0.0,
        "per_mechanism": {"Auth": 1, "NoAmp": 1, "Fresh": 1, "FlowOK": 1},
        "latency_p50_ms": 0.02,
        "latency_p95_ms": 0.04,
        "latency_p99_ms": 0.04,
        "annotations": 7,
        "tcb_lines": 3030,
    }


def _write(path: Path, data: dict[str, Any]) -> Path:
    path.write_text(json.dumps(data))
    return path


def _compare(
    tmp_path: Path,
    before: dict[str, Any],
    after: dict[str, Any],
) -> int:
    b = _write(tmp_path / "before.json", before)
    a = _write(tmp_path / "after.json", after)
    return metrics_snapshot.compare(b, a)


class TestRegressionDetection:
    def test_identical_snapshots_pass(self, tmp_path: Path, good_snapshot: dict[str, Any]) -> None:
        assert _compare(tmp_path, good_snapshot, good_snapshot) == 0

    def test_false_positives_increase_is_regression(
        self, tmp_path: Path, good_snapshot: dict[str, Any]
    ) -> None:
        after = dict(good_snapshot, false_positives=3)
        assert _compare(tmp_path, good_snapshot, after) == 1

    def test_false_negatives_increase_is_regression(
        self, tmp_path: Path, good_snapshot: dict[str, Any]
    ) -> None:
        """An allowed attack is the most serious regression there is."""
        after = dict(good_snapshot, false_negatives=1)
        assert _compare(tmp_path, good_snapshot, after) == 1

    def test_defense_rate_drop_is_regression(
        self, tmp_path: Path, good_snapshot: dict[str, Any]
    ) -> None:
        after = dict(good_snapshot, defense_rate=0.75)
        assert _compare(tmp_path, good_snapshot, after) == 1

    def test_improvement_is_not_a_regression(
        self, tmp_path: Path, good_snapshot: dict[str, Any]
    ) -> None:
        after = dict(good_snapshot, false_positives=0, annotations=3)
        before = dict(good_snapshot, false_positives=1, annotations=7)
        assert _compare(tmp_path, before, after) == 0


class TestScenarioSetGuard:
    def test_different_scenario_set_refuses_comparison(
        self, tmp_path: Path, good_snapshot: dict[str, Any]
    ) -> None:
        """Diffing across scenario sets is meaningless — exit 2, not 0 or 1."""
        after = dict(good_snapshot, total=99)
        assert _compare(tmp_path, good_snapshot, after) == 2

    def test_different_attack_count_refuses(
        self, tmp_path: Path, good_snapshot: dict[str, Any]
    ) -> None:
        after = dict(good_snapshot, attacks=5)
        assert _compare(tmp_path, good_snapshot, after) == 2


class TestLatencyTolerance:
    def test_small_latency_noise_is_ignored(self) -> None:
        """Sub-millisecond jitter on a shared machine must not fail a build."""
        assert metrics_snapshot._is_regression("latency_p95_ms", 0.04, 0.05) is False

    def test_large_latency_jump_is_flagged(self) -> None:
        assert metrics_snapshot._is_regression("latency_p95_ms", 0.04, 0.40) is True

    def test_non_latency_metrics_have_no_tolerance(self) -> None:
        assert metrics_snapshot._is_regression("false_positives", 0, 1) is True


class TestFileErrors:
    def test_missing_snapshot_returns_2(
        self, tmp_path: Path, good_snapshot: dict[str, Any]
    ) -> None:
        b = _write(tmp_path / "before.json", good_snapshot)
        assert metrics_snapshot.compare(b, tmp_path / "absent.json") == 2

    def test_malformed_json_returns_2(self, tmp_path: Path, good_snapshot: dict[str, Any]) -> None:
        b = _write(tmp_path / "before.json", good_snapshot)
        bad = tmp_path / "bad.json"
        bad.write_text("{not json")
        assert metrics_snapshot.compare(b, bad) == 2


class TestFlatten:
    def test_nested_dicts_are_flattened(self) -> None:
        flat = metrics_snapshot._flatten({"a": {"b": 1}, "c": 2})
        assert flat == {"a.b": 1, "c": 2}

    def test_non_numeric_values_are_skipped(self) -> None:
        """Strings and lists are metadata, not metrics — they must not diff."""
        flat = metrics_snapshot._flatten({"label": "x", "items": [1, 2], "n": 5})
        assert flat == {"n": 5}
