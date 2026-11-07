"""The two accounts of an effect must agree.

`verify()` (the verdict) and `outcome_of()` (the published counts) read the same
ledger entries but asked their question in opposite orders. `verify()` let
evidence veto an optimistic observation; `outcome_of()` consulted the source
string FIRST and never reached the evidence at all.

So an executor that labelled its observation `executor.apply` while its own
measurement said `unknown` was tallied as **committed** by the metrics and
reported as **UNKNOWN** by the verdict. The metrics are the optimistic half of
that contradiction, which is the worst direction for a number a reader trusts.

These tests pin the agreement rather than either function alone.
"""

from __future__ import annotations

import pytest

from effect_broker.ledger import (
    OUTCOME_COMMITTED,
    OUTCOME_UNKNOWN,
    IndependentEffectLedger,
    LedgerVerdict,
    UnknownLedgerResult,
)
from effect_broker.model import EffectEvidence, state_from_evidence


def _evidenced_ledger(outcome: str) -> IndependentEffectLedger:
    """Authorized + observed with a committing source, but evidence says `outcome`."""
    led = IndependentEffectLedger()
    led.record_authorization("t", "n", frozenset({"x"}), source="executor.gate")
    led.record_dispatched("t", "n")
    led.record_observation("t", "n", frozenset({"x"}), source="executor.apply")
    led.record_evidence(
        "t",
        "n",
        EffectEvidence(
            effect_id="n",
            outcome=outcome,  # type: ignore[arg-type]
            source="shim_real.write.syscall",
            window=(0.0, 1.0),
            observed_targets=frozenset({"x"}),
            transport_response="250 OK" if outcome == "committed" else None,
        ),
    )
    return led


class TestEvidenceOutranksTheSourceString:
    def test_counts_do_not_call_it_committed_when_evidence_says_unknown(self) -> None:
        led = _evidenced_ledger("unknown")

        counts = led.outcome_counts()
        assert counts.committed == 0, (
            "the executor's measurement said unknown; counting it as committed "
            "makes the published metrics the optimistic half of a contradiction"
        )
        assert counts.unknown == 1

    def test_counts_and_verdict_agree(self) -> None:
        led = _evidenced_ledger("unknown")

        counted = led.outcome_of("t", "n")
        verdict = led.verify("t", "n")

        assert counted == OUTCOME_UNKNOWN
        assert isinstance(verdict, UnknownLedgerResult)

    def test_a_committed_measurement_still_counts_as_committed(self) -> None:
        """The fix must not turn every evidenced effect into `unknown`."""
        led = _evidenced_ledger("committed")

        assert led.outcome_of("t", "n") == OUTCOME_COMMITTED
        assert led.verify("t", "n") is LedgerVerdict.CONFIRMED_COMMITTED

    def test_state_machine_agrees_with_the_counts(self) -> None:
        """state_from_evidence and outcome_of must not tell different stories."""
        led = _evidenced_ledger("unknown")
        evidence = led.evidence_for("t", "n")

        state = state_from_evidence(evidence, was_allowed=True)
        counted = led.outcome_of("t", "n")

        assert state.value == "unknown"
        assert counted == OUTCOME_UNKNOWN


class TestUnejudicatedEffectsStayUnknown:
    """No evidence at all is still not a commit for an allowed effect."""

    def test_state_from_evidence_without_evidence_is_unknown(self) -> None:
        assert state_from_evidence(None, was_allowed=True).value == "unknown"

    def test_state_from_evidence_without_evidence_and_denied(self) -> None:
        assert state_from_evidence(None, was_allowed=False).value == "denied"

    @pytest.mark.parametrize("outcome", ["failed", "unknown"])
    def test_non_committed_outcomes_all_land_in_unknown(self, outcome: str) -> None:
        """`failed` is UNKNOWN, not DENIED: the gate allowed it, so it may have landed."""
        assert state_from_evidence(
            EffectEvidence(
                effect_id="e",
                outcome=outcome,  # type: ignore[arg-type]
                source="s",
                window=(0.0, 1.0),
            ),
            was_allowed=True,
        ).value == "unknown"
