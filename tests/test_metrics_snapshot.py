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


class TestLatencyIsAdvisory:
    """Latency is reported, not gated.

    With 6 scenarios, `p95` and `p99` ARE the sample maximum: one scheduler
    hiccup moves them. Measured here, 8 re-snapshots of unchanged code gave p99
    between 0.0342 and 0.0948 ms (2.8x) and the old tolerance failed 1 run in 8
    on noise. A gate that fires on noise teaches people to re-run instead of to
    look, which is worse than no gate.
    """

    def test_a_large_jump_does_not_fail_the_gate(self) -> None:
        assert metrics_snapshot._is_regression("latency_p95_ms", 0.04, 0.40) is False

    def test_small_noise_does_not_fail_the_gate(self) -> None:
        assert metrics_snapshot._is_regression("latency_p95_ms", 0.04, 0.05) is False

    def test_every_latency_field_is_advisory(self) -> None:
        for key in ("latency_p50_ms", "latency_p95_ms", "latency_p99_ms"):
            assert key in metrics_snapshot._ADVISORY

    def test_it_is_still_printed(
        self, tmp_path: Path, good_snapshot: dict[str, Any], capsys: pytest.CaptureFixture[str]
    ) -> None:
        after = dict(good_snapshot, latency_p95_ms=0.99)
        assert _compare(tmp_path, good_snapshot, after) == 0
        out = capsys.readouterr().out
        assert "latency_p95_ms" in out, "advisory must mean reported, not dropped"

    def test_correctness_metrics_have_no_tolerance(self) -> None:
        """Counts of security outcomes are not timings; a tolerance would hide a
        real failure."""
        assert metrics_snapshot._is_regression("false_positives", 0, 1) is True
        assert metrics_snapshot._is_regression("false_negatives", 0, 1) is True


class TestTcbIsAdvisory:
    """TCB size is reported, not gated.

    It was listed as lower-is-better, which made every security fix look like a
    regression and deleting a module look like an improvement — the opposite of
    the incentive a CI gate should encode. The size still moves in both
    directions on correct changes, so it is argued in review.
    """

    def test_growth_is_not_a_regression(self) -> None:
        assert metrics_snapshot._is_regression("tcb_lines", 2163, 2400) is False

    def test_shrinkage_is_not_an_improvement_gate(self) -> None:
        """Deleting trusted code is not automatically good, either."""
        assert metrics_snapshot._is_regression("tcb_lines", 2400, 2163) is False

    def test_it_still_appears_in_the_diff(
        self, tmp_path: Path, good_snapshot: dict[str, Any], capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Advisory must mean 'reported', not 'silently dropped'."""
        after = dict(good_snapshot, tcb_lines=3300)
        assert _compare(tmp_path, good_snapshot, after) == 0
        out = capsys.readouterr().out
        assert "tcb_lines" in out
        assert "advisory" in out

    def test_a_real_regression_still_fails_alongside_it(
        self, tmp_path: Path, good_snapshot: dict[str, Any]
    ) -> None:
        """Advisory TCB must not mask a false positive."""
        after = dict(good_snapshot, tcb_lines=3300, false_positives=2)
        assert _compare(tmp_path, good_snapshot, after) == 1


class TestModuleEntryPoint:
    """`python -m effect_broker.metrics` must run the report it is named for."""

    def test_default_runs_the_regression_report(self) -> None:
        from effect_broker.metrics import main

        assert main([]) == 0

    def test_diagnostic_flag_is_separate(self) -> None:
        from effect_broker.metrics import main

        assert main(["--diagnostic"]) == 0

    def test_unknown_argument_is_rejected(self) -> None:
        from effect_broker.metrics import main

        assert main(["--nope"]) == 2

    def test_only_one_main_guard_remains(self) -> None:
        """Two `if __name__` blocks made print_report() unreachable."""
        import ast

        source = (
            Path(__file__).resolve().parent.parent / "effect_broker" / "metrics.py"
        ).read_text()

        def is_main_guard(node: ast.stmt) -> bool:
            # Structural comparison: `ast.unparse` normalizes quote style, so
            # matching the source text would be brittle.
            return (
                isinstance(node, ast.If)
                and isinstance(node.test, ast.Compare)
                and isinstance(node.test.left, ast.Name)
                and node.test.left.id == "__name__"
                and len(node.test.comparators) == 1
                and isinstance(node.test.comparators[0], ast.Constant)
                and node.test.comparators[0].value == "__main__"
            )

        guards = [n for n in ast.parse(source).body if is_main_guard(n)]
        assert len(guards) == 1, (
            f"found {len(guards)} module-level __main__ guards; the first wins and "
            f"the rest never run"
        )


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


class TestTheBaselineIsUsableInCI:
    """A reference file a fresh checkout cannot see turns the gate into a no-op.

    The baseline was first placed in `docs/`, which this repository gitignores.
    CI would then have found no baseline, and the step would have failed on a
    missing file rather than on a regression — or worse, been "fixed" by making
    it optional. These tests pin the file to a tracked path.
    """

    BASELINE = Path(__file__).resolve().parent / "data" / "metrics_baseline.json"

    def test_the_baseline_exists(self) -> None:
        assert self.BASELINE.exists(), f"{self.BASELINE} is missing"

    def test_the_baseline_is_tracked_by_git(self) -> None:
        import subprocess

        rel = self.BASELINE.relative_to(Path(__file__).resolve().parent.parent)
        result = subprocess.run(
            ["git", "ls-files", "--error-unmatch", str(rel)],
            cwd=Path(__file__).resolve().parent.parent,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, (
            f"{rel} is not tracked by git, so a CI checkout would not have it and "
            f"the regression gate could not run. git said: {result.stderr.strip()}"
        )

    def test_the_baseline_is_a_complete_snapshot(self) -> None:
        data = json.loads(self.BASELINE.read_text())
        for key in ("total", "attacks", "legitimate", "defense_rate", "tcb_lines"):
            assert key in data, f"baseline is missing {key!r}; the diff would skip it"

    def test_the_baseline_matches_the_current_scenario_set(self) -> None:
        """If the labeled set changes, the baseline must be re-recorded, not left
        to fail the next run with a confusing exit 2."""
        import metrics_snapshot as snap

        current = snap.snapshot()
        data = json.loads(self.BASELINE.read_text())
        for key in snap._IDENTITY_KEYS:
            assert data.get(key) == current.get(key), (
                f"baseline and current differ on {key!r}: {data.get(key)!r} vs "
                f"{current.get(key)!r}. Re-record with --out."
            )

    def test_the_committed_baseline_passes_against_itself(self) -> None:
        """The gate must be green on unchanged code, or nobody will read it."""
        assert metrics_snapshot.compare(self.BASELINE, self.BASELINE) == 0
