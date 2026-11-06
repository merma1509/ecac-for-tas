"""Commit ordering: evidence-based outcome recording.

The property under test is not "the state machine works" but the sharper
claim: **COMMITTED may be recorded only from evidence produced by
the executor that performed the protected operation**. Most of these tests
assert that an unbacked commit is IMPOSSIBLE to construct, which is why they
live in the model rather than in the executor
"""

from __future__ import annotations

import pytest

from effect_broker.model import (
    ALLOWED_TRANSITIONS,
    EffectEvidence,
    EffectState,
    EvidenceInsufficient,
    can_transition,
    state_from_evidence,
)


# Helpers
def committed_evidence(**overrides: object) -> EffectEvidence:
    """Evidence that legitimately establishes a commit."""
    base: dict[str, object] = {
        "effect_id": "nonce-1",
        "outcome": "committed",
        "source": "smtp-envelope",
        "window": (1.0, 1.5),
        "observed_bytes": 1024,
        "observed_targets": frozenset({"mailto:a@b.c"}),
        "transport_response": "250 OK",
    }
    base.update(overrides)
    return EffectEvidence(**base)  # type: ignore[arg-type]


def failed_evidence(**overrides: object) -> EffectEvidence:
    base: dict[str, object] = {
        "effect_id": "nonce-1",
        "outcome": "failed",
        "source": "smtp-envelope",
        "window": (1.0, 1.5),
        "transport_response": "errno 111 connection refused",
    }
    base.update(overrides)
    return EffectEvidence(**base)  # type: ignore[arg-type]

# The central property: no unbacked commits
class TestCommittedRequiresEvidence:
    def test_committed_without_transport_response_is_rejected(self) -> None:
        """This is the exact auth=1/obs=0 state the ledger calls UNKNOWN."""
        with pytest.raises(EvidenceInsufficient, match="transport_response"):
            committed_evidence(transport_response=None)

    def test_committed_with_empty_transport_response_is_rejected(self) -> None:
        with pytest.raises(EvidenceInsufficient, match="transport_response"):
            committed_evidence(transport_response="")

    def test_committed_without_observed_targets_is_rejected(self) -> None:
        """The request's targets are attacker-controlled and do not count."""
        with pytest.raises(EvidenceInsufficient, match="observed target"):
            committed_evidence(observed_targets=None)

    def test_committed_with_empty_observed_targets_is_rejected(self) -> None:
        with pytest.raises(EvidenceInsufficient, match="observed target"):
            committed_evidence(observed_targets=frozenset())

    def test_fully_backed_commit_is_accepted(self) -> None:
        ev = committed_evidence()
        assert ev.to_state() is EffectState.COMMITTED

    def test_empty_source_is_rejected(self) -> None:
        """Evidence must name where it came from, else it is an assertion."""
        with pytest.raises(EvidenceInsufficient, match="source"):
            committed_evidence(source="")

    def test_inverted_window_is_rejected(self) -> None:
        with pytest.raises(EvidenceInsufficient, match="inverted"):
            committed_evidence(window=(5.0, 1.0))

    def test_unknown_with_transport_response_is_rejected(self) -> None:
        """If the transport replied, we are not in the dark."""
        with pytest.raises(EvidenceInsufficient, match="unknown"):
            EffectEvidence(
                effect_id="n",
                outcome="unknown",
                source="smtp-envelope",
                window=(1.0, 2.0),
                transport_response="250 OK",
            )

# Transport failure is UNKNOWN, never DENIED
class TestTransportFailureIsUnknown:
    def test_failed_maps_to_unknown(self) -> None:
        """A timeout may still have delivered — it is not a denial."""
        assert failed_evidence().to_state() is EffectState.UNKNOWN

    def test_failed_is_not_denied(self) -> None:
        """Conflating the two would blame the policy for a network fault."""
        assert failed_evidence().to_state() is not EffectState.DENIED

    def test_failed_outcome_is_conclusive(self) -> None:
        """We know the attempt ended, even if not whether it landed."""
        assert failed_evidence().is_conclusive is True

# No evidence => the gate decision alone is not an outcome
class TestStateFromEvidence:
    def test_allowed_without_evidence_is_unknown(self) -> None:
        """Something may have escaped; silence is not a commit and not a denial."""
        assert state_from_evidence(None, was_allowed=True) is EffectState.UNKNOWN

    def test_denied_without_evidence_is_denied(self) -> None:
        """For a denial the gate decision IS the evidence: nothing dispatched."""
        assert state_from_evidence(None, was_allowed=False) is EffectState.DENIED

    def test_evidence_overrides_the_gate_decision(self) -> None:
        """An allowed effect that failed is UNKNOWN, not AUTHORIZED forever."""
        assert state_from_evidence(failed_evidence(), was_allowed=True) is EffectState.UNKNOWN

    def test_backed_commit_yields_committed(self) -> None:
        assert state_from_evidence(committed_evidence(), was_allowed=True) is EffectState.COMMITTED

# State machine
class TestStateMachine:
    def test_terminal_states_have_no_outgoing_transitions(self) -> None:
        for state in (EffectState.COMMITTED, EffectState.DENIED,
                      EffectState.ABANDONED, EffectState.UNKNOWN):
            assert state.is_terminal
            assert ALLOWED_TRANSITIONS[state] == frozenset()

    def test_in_flight_cannot_reach_authorized(self) -> None:
        """Once dispatched, the only outcomes are committed or unknown."""
        assert can_transition(EffectState.IN_FLIGHT, EffectState.COMMITTED)
        assert can_transition(EffectState.IN_FLIGHT, EffectState.UNKNOWN)
        assert not can_transition(EffectState.IN_FLIGHT, EffectState.AUTHORIZED)
        assert not can_transition(EffectState.IN_FLIGHT, EffectState.DENIED)

    def test_prepared_can_be_denied_or_authorized(self) -> None:
        assert can_transition(EffectState.PREPARED, EffectState.AUTHORIZED)
        assert can_transition(EffectState.PREPARED, EffectState.DENIED)

    def test_authorized_can_abandon(self) -> None:
        """Capability expiry before dispatch is ABANDONED, not DENIED."""
        assert can_transition(EffectState.AUTHORIZED, EffectState.ABANDONED)

    def test_no_transition_out_of_terminal(self) -> None:
        for terminal in (EffectState.COMMITTED, EffectState.DENIED,
                         EffectState.ABANDONED, EffectState.UNKNOWN):
            for target in EffectState:
                assert not can_transition(terminal, target)

    def test_every_state_appears_in_the_transition_table(self) -> None:
        """A missing key would raise KeyError at runtime instead of denying."""
        assert set(ALLOWED_TRANSITIONS) == set(EffectState)


# Post-authorization transport failure is not a security event
class TestTransportFailureClassification:
    """A failed MTA is a fault, not an attack. Mislabeling it is the defect."""

    def test_post_auth_failure_is_not_a_security_error(self) -> None:
        from effect_broker.shim_email import EmailSecurityError, PostAuthorizationFailure

        assert not issubclass(PostAuthorizationFailure, EmailSecurityError)

    def test_post_auth_failure_reports_unknown_outcome(self) -> None:
        from effect_broker.shim_email import PostAuthorizationFailure

        exc = PostAuthorizationFailure("delivery failed", effect_id="n-1")
        assert exc.outcome == "failed"
        assert exc.effect_id == "n-1"

    def test_post_auth_failure_keeps_the_cause(self) -> None:
        from effect_broker.shim_email import PostAuthorizationFailure, SMTPError

        cause = SMTPError("timeout")
        exc = PostAuthorizationFailure("delivery failed", effect_id="n-1", cause=cause)
        assert exc.cause is cause

    def test_failed_outcome_is_unknown_not_denied(self) -> None:
        """The gate allowed it, so the policy is not the thing that failed."""
        from effect_broker.shim_email import PostAuthorizationFailure

        ev = EffectEvidence(
            effect_id="n-1",
            outcome=PostAuthorizationFailure("x", effect_id="n-1").outcome,  # type: ignore[arg-type]
            source="smtp-envelope",
            window=(1.0, 2.0),
            transport_response="timeout",
        )
        assert ev.to_state() is EffectState.UNKNOWN


# ---------------------------------------------------------------------------
# P4-2: a crash between dispatch and outcome record yields UNKNOWN
# ---------------------------------------------------------------------------
class TestCrashBetweenDispatchAndRecord:
    """The window this closes: process dies mid-operation.

    These construct the post-crash state directly, which pins how `verify()`
    reads it. Whether that state is REACHABLE after a real kill is a separate
    question, answered by tests/test_crash_harness.py, which SIGKILLs a child
    process and rebuilds the ledger from the journal it left on disk.
    """

    def _ledger(self):
        from effect_broker.ledger import IndependentEffectLedger

        return IndependentEffectLedger()

    def test_dispatch_without_observation_is_outcome_unknown(self) -> None:
        from effect_broker.ledger import DISPOSITION_UNKNOWN, UnknownLedgerResult

        led = self._ledger()
        led.record_authorization("t1", "n1", frozenset({"file:x"}), source="executor.execute")
        led.record_dispatched("t1", "n1", source="shim_real.dispatch")
        verdict = led.verify("t1", "n1")
        assert isinstance(verdict, UnknownLedgerResult)
        assert DISPOSITION_UNKNOWN in verdict.reason

    def test_dispatch_is_distinguished_from_plain_bypass_gap(self) -> None:
        """Two different operational meanings must not collapse into one string."""
        led_a = self._ledger()
        led_a.record_authorization("t", "n", frozenset({"x"}), source="executor.execute")
        led_a.record_dispatched("t", "n")
        dispatched_reason = led_a.verify("t", "n").reason  # type: ignore[union-attr]

        led_b = self._ledger()
        led_b.record_authorization("t", "n", frozenset({"x"}), source="executor.execute")
        bypass_reason = led_b.verify("t", "n").reason  # type: ignore[union-attr]

        assert dispatched_reason != bypass_reason
        assert "possible_bypass" in bypass_reason

    def test_dispatch_never_yields_confirmed_committed(self) -> None:
        """A dispatch claim is intent, not evidence — anyone can assert intent."""
        from effect_broker.ledger import LedgerVerdict

        led = self._ledger()
        led.record_authorization("t", "n", frozenset({"x"}), source="executor.execute")
        led.record_dispatched("t", "n")
        assert led.verify("t", "n") != LedgerVerdict.CONFIRMED_COMMITTED

    def test_was_dispatched_reflects_the_marker(self) -> None:
        led = self._ledger()
        led.record_authorization("t", "n", frozenset({"x"}), source="executor.execute")
        assert led.was_dispatched("t", "n") is False
        led.record_dispatched("t", "n")
        assert led.was_dispatched("t", "n") is True

    def test_observation_after_dispatch_still_commits(self) -> None:
        """The happy path must not regress: dispatch then observe = COMMITTED."""
        from effect_broker.ledger import LedgerVerdict

        led = self._ledger()
        led.record_authorization("t", "n", frozenset({"x"}), source="executor.execute")
        led.record_dispatched("t", "n")
        led.record_observation("t", "n", frozenset({"x"}), source="executor.apply")
        assert led.verify("t", "n") is LedgerVerdict.CONFIRMED_COMMITTED

    def test_dispatch_does_not_rescue_an_unauthorized_effect(self) -> None:
        """Dispatching without authorization is still unauthorized."""
        from effect_broker.ledger import LedgerVerdict

        led = self._ledger()
        led.record_dispatched("t", "n")
        led.record_observation("t", "n", frozenset({"x"}), source="executor.apply")
        assert led.verify("t", "n") != LedgerVerdict.CONFIRMED_COMMITTED
