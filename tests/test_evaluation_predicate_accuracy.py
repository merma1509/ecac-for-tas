"""Regression tests for `effect_broker.evaluation`.

Two defects were found by running the module and reading its output, not by
reading its code:

1. H-N5 (send-rate amplification) reused a single capability nonce for all
   three sends. The FIRST send consumed the nonce, so the SECOND failed
   `Fresh` and the rate limit was never reached. The trace reported
   `actual_blocker=Fresh` where `NoAmp` was expected, and the report read
   86.7%.

2. `EvaluationReport.correct_blocker` was computed as
   `r.passed and not r.allow`, which counted the benign trace H-N3
   (`expected_blocker=None`, `allow=True`, `passed=True`) as a defense
   failure. The defense rate therefore divided by a denominator that mixed
   attacks with benign traffic.

Both are pinned here so that a future edit cannot silently restore either one.
"""

from __future__ import annotations

import warnings

import pytest

warnings.filterwarnings("ignore", message="SAME-PROCESS")


@pytest.fixture(scope="module")
def evaluation():
    """One evaluation run, shared across the assertions in this module."""
    from effect_broker.evaluation import HeldOutEvaluation

    ev = HeldOutEvaluation()
    results = ev.run_evaluation()
    return ev, results


def test_rate_limit_trace_blocks_on_noamp(evaluation) -> None:
    """H-N5 must be blocked by the budget predicate, not by nonce freshness."""
    _, results = evaluation
    hn5 = next(r for r in results if r.trace_id == "H-N5")

    assert hn5.expected_blocker == "NoAmp"
    assert hn5.actual_blocker == "NoAmp", (
        "H-N5 must be denied by the send budget. If this reports 'Fresh', the "
        "trace is reusing one nonce and is measuring replay instead of "
        "amplification."
    )
    assert hn5.passed is True


def test_benign_trace_is_not_counted_as_defense_failure(evaluation) -> None:
    """A benign ALLOWed trace has no predicate to be correct about."""
    _, results = evaluation
    benign = [r for r in results if r.expected_blocker is None]

    assert benign, "expected at least one benign trace in the sealed set"
    for trace in benign:
        assert trace.allow is True, f"{trace.trace_id} is benign but was blocked"
        assert trace.passed is True


def test_defense_rate_denominator_excludes_benign(evaluation) -> None:
    """The defense rate must be computed over attacks only."""
    ev, results = evaluation
    report = ev.report()

    benign_allowed = sum(1 for r in results if r.passed and r.allow)
    assert report.benign_allowed == benign_allowed
    assert report.attack_traces == report.total_traces - benign_allowed

    # Every attack must be correctly classified for this suite to be green,
    # which is the property the module claims. If an attack is ever missed,
    # this assertion should fail loudly rather than be quietly relaxed.
    assert report.correct_blocker == report.attack_traces, (
        f"{report.correct_blocker}/{report.attack_traces} attacks blocked by "
        f"the expected predicate; misclassified={report.false_positives}, "
        f"missed={report.false_negatives}"
    )


def test_report_prints_and_states_attack_denominator(evaluation, capsys) -> None:
    """The printed report must describe attacks vs benign, not "all attacks"."""
    ev, _ = evaluation
    ev.print_report()
    output = capsys.readouterr().out

    assert "benign" in output.lower(), (
        "the report claims every trace is an attack; one of them is benign"
    )
    assert "Defense rate:" in output
