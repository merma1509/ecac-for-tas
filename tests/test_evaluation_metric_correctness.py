"""Regression tests for the held-out evaluation metric and trace H-N5.

Two defects were found by running `python -m effect_broker.evaluation` and
comparing its output with what the reports claimed:

1. **Denominator / numerator.** `report()` required `not r.allow` for a trace to
   count as a defense success. The benign trace H-N3 (`expected_blocker=None`)
   is ALLOWED and passed, so it was silently excluded from the numerator while
   still counted in `total_traces`. The printed rate was therefore 13/15
   (86.7%) although 14 of 15 traces behaved exactly as specified.

2. **H-N5 could not reach its own predicate.** All three sends used the single
   nonce `rate-cap`. The first consumed it, so the second failed `Fresh` and the
   rate limit set with `set_max_sends(2)` was never the deciding predicate —
   the trace recorded `actual_blocker=Fresh` where `NoAmp` was expected.

These tests pin the corrected behaviour: a benign ALLOW is not a defense
failure, the rate is computed over attack traces only, and H-N5 is blocked by
`NoAmp`.
"""

from __future__ import annotations

import warnings

import pytest


@pytest.fixture(scope="module")
def sealed_report():
    """Run the sealed evaluation once; module-scoped because it is deterministic."""
    warnings.filterwarnings("ignore", message="SAME-PROCESS")
    from effect_broker.evaluation import HeldOutEvaluation

    evaluation = HeldOutEvaluation()
    results = evaluation.run_evaluation()
    return evaluation, results, evaluation.report()


class TestBenignTraceIsNotDefenseFailure:
    """H-N3 is benign; allowing it must not be scored as a failed defense."""

    def test_benign_trace_is_allowed_and_passed(self, sealed_report) -> None:
        _evaluation, results, _report = sealed_report
        benign = [r for r in results if r.expected_blocker is None]

        assert benign, "expected at least one benign trace in the sealed set"
        for result in benign:
            assert result.allow, f"{result.trace_id} is benign but was blocked"
            assert result.passed, f"{result.trace_id} is benign but did not pass"

    def test_benign_trace_excluded_from_attack_denominator(self, sealed_report) -> None:
        _evaluation, _results, report = sealed_report

        assert report.benign_allowed >= 1
        assert report.attack_traces == report.total_traces - report.benign_allowed
        assert report.attack_traces < report.total_traces, (
            "benign traces must not inflate the defense-rate denominator"
        )

    def test_defense_rate_uses_attack_denominator(self, sealed_report) -> None:
        _evaluation, _results, report = sealed_report

        # The metric is correct blocks over attack traces, not over all traces.
        expected_rate = report.correct_blocker / report.attack_traces * 100
        naive_rate = report.correct_blocker / report.total_traces * 100

        assert expected_rate >= naive_rate, (
            "counting the benign allow in the denominator can only lower the rate"
        )
        assert report.correct_blocker == 14
        assert report.attack_traces == 14


class TestSendRateAmplificationReachesNoAmp:
    """H-N5 must be decided by the send budget (NoAmp), not by nonce reuse."""

    def test_h_n5_blocked_by_noamp(self, sealed_report) -> None:
        _evaluation, results, _report = sealed_report
        trace = next(r for r in results if r.trace_id == "H-N5")

        assert trace.allow is False
        assert trace.actual_blocker == "NoAmp", (
            "H-N5 is a rate-amplification trace; a Fresh block means the nonce was "
            f"reused and the budget was never reached (got {trace.actual_blocker})"
        )
        assert trace.passed is True

    def test_two_sends_fit_budget_third_exceeds_it(self) -> None:
        """Direct check: distinct nonces reach the NoAmp budget at max_sends=2."""
        warnings.filterwarnings("ignore", message="SAME-PROCESS")
        from effect_broker.broker import EffectBroker
        from effect_broker.model import (
            Capability,
            Commit,
            Confidentiality,
            Data,
            Domain,
            Effect,
            Integrity,
            Task,
        )

        broker = EffectBroker()
        broker.store._unsafe_bootstrap_email("internal@corp.com", Domain.INTERNAL)

        capabilities: dict[str, Capability] = {}
        for index in range(3):
            nonce = f"rate-cap-{index}"
            capability = Capability(
                owner="User",
                holder="Agent",
                right="send",
                target="internal@corp.com",
                scope=frozenset({"internal"}),
                expiry=float("inf"),
                nonce=nonce,
                derives_from=None,
            )
            broker.capabilities[nonce] = capability
            capabilities[nonce] = capability

        task = Task(task_id="rate-test", owner="User", ceiling=capabilities["rate-cap-0"])
        assert task.session is not None
        task.session.set_max_sends(2)

        blockers: list[str | None] = []
        for index in range(3):
            effect = Effect(
                etype="send",
                target="internal@corp.com",
                metadata={"body": f"message {index}"},
                provenance=(Data("msg", Confidentiality.INTERNAL, Integrity.USER),),
                capability_nonce=f"rate-cap-{index}",
                delegation_chain=(),
            )
            allowed, evidence = broker.commit(Commit(effect, task))
            blockers.append(None if allowed else evidence.get("primary_blocker"))

        assert blockers[:2] == [None, None], f"first two sends must fit the budget: {blockers}"
        assert blockers[2] == "NoAmp", f"third send must exceed the budget via NoAmp: {blockers}"
        assert task.session.send_count == 2


class TestEvaluationReportIsSerialisable:
    """The new `benign_allowed` field must not break report construction."""

    def test_report_fields_consistent(self, sealed_report) -> None:
        _evaluation, results, report = sealed_report

        blocked_correctly = sum(1 for r in results if r.passed and not r.allow)
        allowed_benign = sum(1 for r in results if r.passed and r.allow)

        assert report.correct_blocker == blocked_correctly
        assert report.benign_allowed == allowed_benign
        assert report.false_negatives == 0, "no attack may be allowed in the sealed set"
        assert report.false_positives == 0, "no trace may be blocked by the wrong predicate"
