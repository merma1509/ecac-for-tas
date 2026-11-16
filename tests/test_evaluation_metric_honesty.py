"""Regression tests for the held-out evaluation metric and H-N5 trace.

Two defects were fixed here and must not regress.

1. **The defense-rate denominator included benign traces.** `defense_success`
   required `not r.allow`, so H-N3 — a benign trace that is correctly ALLOWED
   and has no expected blocker — counted as a failure. The report read 13/15
   (86.7%) while 14 of 15 traces behaved exactly as specified. A benign trace
   has no predicate to be correct about, so it is excluded from the numerator
   and from the denominator (`attack_traces`).

2. **H-N5 measured freshness instead of amplification.** All three sends used
   the single nonce `rate-cap`. The first consumed it, so the second was denied
   by `Fresh` and the `set_max_sends(2)` budget was never reached — the trace
   reported `actual_blocker=Fresh` where `NoAmp` was expected. Distinct nonces
   let the budget actually bind.
"""

from __future__ import annotations

import warnings

warnings.filterwarnings("ignore", message="SAME-PROCESS")


class TestDefenseRateDenominator:
    """A benign ALLOWed trace must not drag the defense rate down."""

    def test_report_excludes_benign_trace_from_denominator(self) -> None:
        from effect_broker.evaluation import HeldOutEvaluation

        evaluation = HeldOutEvaluation()
        evaluation.run_evaluation()
        report = evaluation.report()

        benign = [r for r in evaluation.results if r.passed and r.allow]
        assert benign, "expected at least one legitimately allowed benign trace"
        assert report.benign_allowed == len(benign)
        assert report.attack_traces == report.total_traces - report.benign_allowed

    def test_defense_rate_is_not_diluted_by_benign_trace(self) -> None:
        """correct/attack_traces, not correct/total_traces."""
        from effect_broker.evaluation import HeldOutEvaluation

        evaluation = HeldOutEvaluation()
        evaluation.run_evaluation()
        report = evaluation.report()

        expected_rate = report.correct_blocker / report.attack_traces
        diluted_rate = report.correct_blocker / report.total_traces
        assert expected_rate > diluted_rate, "benign trace should change the denominator"

    def test_every_trace_is_classified_exactly_once(self) -> None:
        """success + failure + misclassified + benign must cover all traces."""
        from effect_broker.evaluation import HeldOutEvaluation

        evaluation = HeldOutEvaluation()
        evaluation.run_evaluation()
        report = evaluation.report()

        covered = (
            report.correct_blocker
            + report.false_negatives
            + report.false_positives
            + report.benign_allowed
        )
        assert covered == report.total_traces


class TestHN5RateAmplification:
    """H-N5 must reach the send budget, not trip over the nonce check."""

    def test_hn5_blocked_by_noamp_not_fresh(self) -> None:
        from effect_broker.evaluation import HeldOutEvaluation

        evaluation = HeldOutEvaluation()
        evaluation.run_evaluation()

        hn5 = next(r for r in evaluation.results if r.trace_id == "H-N5")
        assert not hn5.allow, "H-N5 must be blocked"
        assert hn5.expected_blocker == hn5.actual_blocker, (
            f"H-N5 expected {hn5.expected_blocker}, got {hn5.actual_blocker}"
        )
        assert hn5.actual_blocker == "NoAmp", (
            f"H-N5 should exercise the composition budget, got {hn5.actual_blocker}"
        )

    def test_no_trace_is_misclassified(self) -> None:
        """Every attack must be blocked by the predicate it targets."""
        from effect_broker.evaluation import HeldOutEvaluation

        evaluation = HeldOutEvaluation()
        evaluation.run_evaluation()
        report = evaluation.report()

        misclassified = [
            (r.trace_id, r.expected_blocker, r.actual_blocker)
            for r in evaluation.results
            if not r.allow and not r.passed
        ]
        assert not misclassified, f"traces blocked by the wrong predicate: {misclassified}"
        assert report.false_positives == 0

    def test_no_attack_is_allowed(self) -> None:
        from effect_broker.evaluation import HeldOutEvaluation

        evaluation = HeldOutEvaluation()
        evaluation.run_evaluation()
        report = evaluation.report()

        assert report.false_negatives == 0, "an attack was ALLOWED"
