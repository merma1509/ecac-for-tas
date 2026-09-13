"""Tests for IndependentEffectLedger exact occurrence-count matching.

Verifies kill-criterion #3: the ledger returns UnknownLedgerResult for
effects it cannot verify ("unknown, not safe"). Specifically:

  1. One auth + one obs → CONFIRMED_COMMITTED (exact match, effect verified)
  2. One auth + zero obs → UnknownLedgerResult (cannot rule out direct bypass)
  3. One auth + two obs → UnknownLedgerResult (over-observed, "unknown, not safe")
  4. Zero auth + zero obs → UnknownLedgerResult (cannot rule out direct bypass)
  5. Replay within task → UnknownLedgerResult (observed > authorized)
  6. BCC extra target observed but not in auth → UnknownLedgerResult
  7. Different tasks tracked independently per nonce
  8. verify_all catches over-observed nonces across tasks
"""

from __future__ import annotations

from effect_broker.ledger import (
    IndependentEffectLedger,
    LedgerVerdict,
    UnknownLedgerResult,
)


class TestEffectObserverExactMatching:
    """Verify IndependentEffectLedger.verify() performs exact occurrence counting."""

    def test_one_auth_one_obs_exact_match(self) -> None:
        """One authorization, one observation → CONFIRMED_COMMITTED."""
        ledger = IndependentEffectLedger()
        ledger.record_authorization("default", "cap:read", frozenset({"file:///reports"}))
        ledger.record_observation("default", "cap:read", frozenset({"file:///reports"}))

        verdict = ledger.verify("default", "cap:read")
        assert verdict == LedgerVerdict.CONFIRMED_COMMITTED

    def test_one_auth_zero_obs_authorized_but_not_observed(self) -> None:
        """One authorization, zero observations → UnknownLedgerResult (FIXED).

        In the same-process model, (auth > 0, obs = 0) means the ledger
        CANNOT determine whether the effect was blocked by the gate or
        bypassed via direct store mutation. The correct verdict is UNKNOWN,
        not CONFIRMED_BLOCKED — this is the "unknown, not safe" guarantee.
        """
        ledger = IndependentEffectLedger()
        ledger.record_authorization("default", "cap:read", frozenset({"file:///reports"}))

        verdict = ledger.verify("default", "cap:read")
        assert isinstance(verdict, UnknownLedgerResult), (
            f"(auth>0, obs=0) should be UnknownLedgerResult, got {verdict}"
        )
        assert (
            "authorized_not_observed" in verdict.reason
            or "possible_bypass" in verdict.reason
        ), f"Unexpected reason: {verdict.reason}"

    def test_one_auth_multiple_obs_over_observed(self) -> None:
        """One auth, two obs → UnknownLedgerResult (over-observed: "unknown, not safe")."""
        ledger = IndependentEffectLedger()
        ledger.record_authorization("default", "cap:read", frozenset({"file:///reports"}))
        ledger.record_observation("default", "cap:read", frozenset({"file:///reports"}))
        ledger.record_observation("default", "cap:read", frozenset({"file:///reports"}))

        verdict = ledger.verify("default", "cap:read")
        assert isinstance(verdict, UnknownLedgerResult)
        # Ledger tracks auth=1 but obs=2 (both observations recorded separately)
        assert "over-observed" in verdict.reason or "authorized_not_observed" in verdict.reason

    def test_no_auth_no_obs_unknown(self) -> None:
        """No auth, no obs → UnknownLedgerResult (cannot rule out direct bypass)."""
        ledger = IndependentEffectLedger()

        verdict = ledger.verify("default", "fake-nonce")
        assert isinstance(verdict, UnknownLedgerResult)
        assert "no_record" in verdict.reason or "not_observed" in verdict.reason

    def test_replay_blocked_within_task(self) -> None:
        """Same nonce used twice, only authorized once → UnknownLedgerResult."""
        ledger = IndependentEffectLedger()
        ledger.record_authorization("default", "cap:send", frozenset({"internal@corp.com"}))
        ledger.record_observation("default", "cap:send", frozenset({"internal@corp.com"}))
        ledger.record_observation("default", "cap:send", frozenset({"internal@corp.com"}))

        verdict = ledger.verify("default", "cap:send")
        assert isinstance(verdict, UnknownLedgerResult)

    def test_bcc_extra_target_observed_not_in_authorization(self) -> None:
        """BCC target observed but NOT authorized → UnknownLedgerResult."""
        ledger = IndependentEffectLedger()
        ledger.record_authorization(
            "default", "cap:send", frozenset({"internal@corp.com"})
        )
        ledger.record_observation(
            "default", "cap:send",
            frozenset({"internal@corp.com", "attacker@elsewhere.com"})
        )

        verdict = ledger.verify("default", "cap:send")
        assert isinstance(verdict, UnknownLedgerResult)
        # Correctly detects: attacker target was observed but NOT in authorization
        assert "extra_observed" in verdict.reason

    def test_different_tasks_independent(self) -> None:
        """Same nonce in different tasks tracked independently — each has its own count."""
        ledger = IndependentEffectLedger()
        ledger.record_authorization("task-A", "cap:read", frozenset({"file:///a"}))
        ledger.record_authorization("task-B", "cap:read", frozenset({"file:///b"}))
        ledger.record_observation("task-A", "cap:read", frozenset({"file:///a"}))
        ledger.record_observation("task-B", "cap:read", frozenset({"file:///b"}))

        # Each task independently: 1 auth + 1 obs → exact match
        assert ledger.verify("task-A", "cap:read") == LedgerVerdict.CONFIRMED_COMMITTED
        assert ledger.verify("task-B", "cap:read") == LedgerVerdict.CONFIRMED_COMMITTED

        # Replay in task-A: adding a second unauthorized observation triggers over-observed
        ledger.record_observation(
            "task-A", "cap:read", frozenset({"file:///a", "file:///extra"})
        )
        verdict_replay = ledger.verify("task-A", "cap:read")
        assert isinstance(verdict_replay, UnknownLedgerResult)

        # task-B is unaffected
        assert ledger.verify("task-B", "cap:read") == LedgerVerdict.CONFIRMED_COMMITTED

    def test_verify_all_uses_ledger_verify(self) -> None:
        """verify_all delegates to verify() for each nonce.

        When a nonce is over-observed, verify() returns UnknownLedgerResult,
        which verify_all converts to a failure message.

        Note: in the standalone unit test, we pre-populate the ledger's
        internal state. In the full integration (broker + executor + ledger),
        authorization is recorded by the broker and observation by the executor.
        """
        ledger = IndependentEffectLedger()
        # Pre-populate internal state (simulating broker records auth + executor records obs)
        ledger.record_authorization(
            "task-A", "cap:send", frozenset({"internal@corp.com"})
        )
        ledger.record_observation(
            "task-A", "cap:send",
            frozenset({"internal@corp.com", "attacker@elsewhere.com"})
        )

        # verify() directly catches the over-observed case
        verdict = ledger.verify("task-A", "cap:send")
        assert isinstance(verdict, UnknownLedgerResult)

        # verify_all gets the failure from verify()
        # We pass an auth record for the same (task_id, nonce)
        authorized_records = {("task-A", "cap:send"): frozenset({"internal@corp.com"})}
        failures = ledger.verify_all(authorized_records)
        assert len(failures) > 0
        assert any("UNKNOWN" in f for f in failures)

    def test_confirmed_blocked_requires_explicit_empty_observation(self) -> None:
        """CONFIRMED_BLOCKED requires explicit empty observation (0-state).

        When the broker BLOCKs an effect, the executor records an observation
        with empty frozenset() AND source="broker.commit:BLOCKED" or
        "executor.execute:BLOCKED". This distinguishes CONFIRMED_BLOCKED from
        UNKNOWN (no record at all) or CONFIRMED_COMMITTED (normal apply).
        """
        ledger = IndependentEffectLedger()
        ledger.record_authorization("default", "cap:send", frozenset({"internal@corp.com"}))
        # Record with BLOCKED source (simulating broker BLOCK at gate)
        ledger.record_observation(
            "default", "cap:send", frozenset(), source="broker.commit:BLOCKED"
        )

        verdict = ledger.verify("default", "cap:send")
        assert verdict == LedgerVerdict.CONFIRMED_BLOCKED

    def test_empty_observation_vs_no_observation_are_different(self) -> None:
        """Empty frozenset observation != no observation at all.

        Ledger: auth=1, obs=frozenset() with BLOCKED source → CONFIRMED_BLOCKED (saw the attempt)
        Ledger: auth=1, obs=∅ (no record) → UNKNOWN (possible bypass)
        """
        # Case 1: explicit empty observation with BLOCKED source → CONFIRMED_BLOCKED
        ledger_blocked = IndependentEffectLedger()
        ledger_blocked.record_authorization("default", "blocked", frozenset({"target"}))
        ledger_blocked.record_observation(
            "default", "blocked", frozenset(), source="broker.commit:BLOCKED"
        )
        assert ledger_blocked.verify("default", "blocked") == LedgerVerdict.CONFIRMED_BLOCKED

        # Case 2: no observation record at all → UNKNOWN
        ledger_unknown = IndependentEffectLedger()
        ledger_unknown.record_authorization("default", "unknown", frozenset({"target"}))
        # No observation record
        assert isinstance(ledger_unknown.verify("default", "unknown"), UnknownLedgerResult)
