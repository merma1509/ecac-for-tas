"""Tests for the evaluation reporting metrics

These tests verify the metrics module computes all of those on REAL broker
behavior (not hardcoded), and that the numbers are non-vacuous:
  - defense rate / false negatives / false positives
  - per-mechanism contribution spans multiple predicates
  - latency percentiles are populated
  - TCB size is a real line count
"""

from __future__ import annotations

import pytest

from effect_broker.metrics import build_report, compute_metrics, tcb_size


@pytest.fixture(scope="module")
def report() -> dict:
    return build_report()


class TestMetricsComputed:
    """Every §6 metric is present and non-vacuous."""

    def test_report_has_all_metric_keys(self, report: dict) -> None:
        for key in (
            "total",
            "attacks",
            "legitimate",
            "attacks_blocked",
            "false_negatives",
            "false_positives",
            "defense_rate",
            "false_positive_rate",
            "per_mechanism",
            "latency_p50_ms",
            "latency_p95_ms",
            "latency_p99_ms",
            "annotations",
            "tcb_lines",
        ):
            assert key in report, f"Missing metric: {key}"

    def test_defense_rate_is_one_on_labeled_set(self, report: dict) -> None:
        """All labeled attacks are blocked -> defense rate 100% (regression)."""
        assert report["attacks"] >= 4, "Need a meaningful number of labeled attacks"
        assert report["defense_rate"] == 1.0, (
            f"All labeled attacks should be blocked (defense rate 100%), "
            f"got {report['defense_rate']:.0%}. false_negatives={report['false_negatives']}"
        )
        assert report["false_negatives"] == 0

    def test_per_mechanism_spans_multiple_predicates(self, report: dict) -> None:
        """Per-mechanism contribution must span >= 3 distinct predicates.

        This proves the report attributes blocks to the RIGHT mechanism
        (Auth/FlowOK/NoAmp/Fresh), not a single coincidental predicate.
        """
        mech = report["per_mechanism"]
        assert len(mech) >= 3, (
            f"Per-mechanism contribution should span >= 3 predicates, got {mech}"
        )
        # The four named predicates are the expected contributors.
        assert set(mech) <= {"Auth", "FlowOK", "NoAmp", "Fresh", "ApprovalBinding", "Structural"}

    def test_latencies_populated_and_ordered(self, report: dict) -> None:
        """Latency percentiles are measured (positive) and p50 <= p95 <= p99."""
        p50, p95, p99 = report["latency_p50_ms"], report["latency_p95_ms"], report["latency_p99_ms"]
        assert p50 > 0 and p95 > 0 and p99 > 0, "Latencies should be measured (positive)"
        assert p50 <= p95 <= p99, f"Percentiles must be ordered, got {p50},{p95},{p99}"

    def test_annotations_count_scenario_grants_not_seeded(self, report: dict) -> None:
        """Annotation burden counts the scenario's explicit grants (small),
        NOT the broker's ~190 seeded capabilities (would be a bug)."""
        assert 0 < report["annotations"] <= 20, (
            f"Annotation burden should reflect scenario grants (small), "
            f"got {report['annotations']} — likely counting seeded capabilities"
        )

    def test_tcb_size_is_real_line_count(self) -> None:
        """TCB size is a real, non-trivial line count of broker.py + model.py."""
        n = tcb_size()
        assert n > 1000, f"TCB size should be a real line count, got {n}"

    def test_false_positives_zero_on_labeled_legit(self, report: dict) -> None:
        """Labeled legitimate operations are allowed (no false positives)."""
        assert report["legitimate"] >= 2
        assert report["false_positives"] == 0, (
            f"Labeled legit operations should be allowed, got {report['false_positives']} blocked"
        )

    def test_compute_metrics_is_pure_and_repeatable(self) -> None:
        """compute_metrics() is deterministic on the fixed labeled set."""
        m1 = compute_metrics()
        m2 = compute_metrics()
        assert m1.defense_rate == m2.defense_rate
        assert m1.per_mechanism == m2.per_mechanism
        assert m1.annotations == m2.annotations


class TestSessionTaintReporting:
    """honest taint accounting in the evaluation report.

    taint_rate (cost of the conservative session taint) and
    false_denial_proxy (over-blocking signal) are DISTINCT and both present.
    """

    def test_report_includes_session_taint(self, report: dict) -> None:
        assert "session_taint" in report, "report must expose session_taint"
        st = report["session_taint"]
        for key in (
            "total_reads",
            "reads_that_tainted",
            "sends_blocked_by_taint",
            "blocked_sends_later_declassed",
            "taint_rate",
            "false_denial_proxy",
        ):
            assert key in st, f"session_taint missing {key}"

    def test_taint_rate_and_false_denial_not_conflated(self) -> None:
        """Both proxy demo blocks the send and then declassifies (proxy=1).

        taint_rate counts the READ that tainted; false_denial_proxy counts
        the blocked send that was later lifted. They must both be reported
        and NOT collapsed into a single number.
        """
        from effect_broker.metrics import session_taint_metrics

        st = session_taint_metrics()
        assert st["reads_that_tainted"] >= 1
        assert st["total_reads"] >= 1
        assert st["taint_rate"] > 0.0
        assert st["sends_blocked_by_taint"] >= 1
        assert st["blocked_sends_later_declassed"] == st["sends_blocked_by_taint"]
        assert st["false_denial_proxy"] == 1.0
        assert "taint_rate" in st and "false_denial_proxy" in st
