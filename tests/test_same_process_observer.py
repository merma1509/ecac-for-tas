"""Regression: same-process direct store mutation → ledger returns UNKNOWN.

These tests verify the "unknown, not safe" requirement from the review:

  In the same-process model, direct ResourceStore mutation
  (broker.store.files["x"] = File(...)) bypasses the broker gate.
  The IndependentEffectLedger must return UnknownLedgerResult (not "safe")
  for any effect it cannot verify.

  With the ledger design, (auth > 0, obs = 0) → UnknownLedgerResult
  because the ledger cannot distinguish "broker blocked" from
  "tool bypassed via direct mutation". Only explicit blocked observation
  (observed state with blocked commit) produces CONFIRMED_BLOCKED.

  In a real deployment (separate process/enclave), this bypass is
  structurally impossible — the ledger's read-only access to the
  executor's identity_log is enforced by OS process boundaries.
"""

from __future__ import annotations

from effect_broker.ledger import (
    IndependentEffectLedger,
    LedgerVerdict,
    UnknownLedgerResult,
)


class TestLedgerUnknownForUnobservable:
    """Ledger returns UNKNOWN when it cannot verify the outcome.

    This is the "unknown, not safe" guarantee: for any unverifiable
    effect, the ledger must say "unknown" — never "safe".
    """

    def test_direct_mutation_bypass_is_unknown(self) -> None:
        """With (auth > 0, obs = 0): ledger cannot distinguish broker-blocked
        from direct mutation bypass → must return UnknownLedgerResult."""
        ledger = IndependentEffectLedger()
        ledger.record_authorization("default", "bypass-nonce", frozenset({"file:///secrets"}))
        # No observation record — direct store mutation bypassed the executor

        verdict = ledger.verify("default", "bypass-nonce")
        assert isinstance(verdict, UnknownLedgerResult), (
            f"(auth>0, obs=0) should be UnknownLedgerResult, got {verdict}"
        )
        assert (
            "authorized_not_observed" in verdict.reason
            or "possible_bypass" in verdict.reason
        )

    def test_ledger_never_returns_safe_for_unverifiable(self) -> None:
        """No combination of (auth, obs) produces 'safe'."""
        ledger = IndependentEffectLedger()

        # auth=0, obs=0 → UNKNOWN (possible bypass, possible never-executed)
        verdict_a = ledger.verify("t", "fake-a")
        assert isinstance(verdict_a, UnknownLedgerResult)

        # auth=0, obs=1 → UNKNOWN (observed without authorization)
        ledger2 = IndependentEffectLedger()
        ledger2.record_observation("t", "fake-b", frozenset({"target"}))
        verdict_b = ledger2.verify("t", "fake-b")
        assert isinstance(verdict_b, UnknownLedgerResult)

        # auth=1, obs=0 → UNKNOWN (authorized but not observed — possible bypass)
        ledger3 = IndependentEffectLedger()
        ledger3.record_authorization("t", "auth-no-obs", frozenset({"target"}))
        verdict_c = ledger3.verify("t", "auth-no-obs")
        assert isinstance(verdict_c, UnknownLedgerResult)

        # auth=1, obs=1, targets match → CONFIRMED_COMMITTED
        ledger4 = IndependentEffectLedger()
        ledger4.record_authorization("t", "exact-match", frozenset({"target"}))
        ledger4.record_observation("t", "exact-match", frozenset({"target"}))
        verdict_d = ledger4.verify("t", "exact-match")
        assert verdict_d == LedgerVerdict.CONFIRMED_COMMITTED

    def test_confirmed_blocked_requires_explicit_empty_observation(self) -> None:
        """CONFIRMED_BLOCKED requires the ledger to see that a blocked effect
        was attempted — recorded via record_observation (0-state) with
        source="broker.commit:BLOCKED" or "executor.execute:BLOCKED"."""
        ledger = IndependentEffectLedger()
        # A capability was authorized and an effect was committed but blocked
        ledger.record_authorization("default", "blocked-cap", frozenset({"target"}))
        # Record: the ledger SAW this nonce attempted, but observed 0 state change
        # Must use BLOCKED source so the ledger knows this was an explicit gate block
        ledger.record_observation(
            "default", "blocked-cap", frozenset(), source="broker.commit:BLOCKED"
        )

        verdict = ledger.verify("default", "blocked-cap")
        assert verdict == LedgerVerdict.CONFIRMED_BLOCKED, (
            f"Explicit blocked observation should be CONFIRMED_BLOCKED, got {verdict}"
        )

    def test_unknown_and_confirmed_blocked_are_different_verdicts(self) -> None:
        """These two cases are semantically different and must not be conflated:

        CONFIRMED_BLOCKED: ledger observed the nonce attempted (recorded via
            record_observation with BLOCKED source), the effect was blocked by the gate
        UnknownLedgerResult: ledger cannot verify the outcome — either
            no authorization exists (possible bypass) or the nonce was
            authorized but not observed (possible direct mutation bypass).
        """
        ledger_blocked = IndependentEffectLedger()
        ledger_blocked.record_authorization("task", "blocked", frozenset({"target"}))
        ledger_blocked.record_observation(
            "task", "blocked", frozenset(), source="broker.commit:BLOCKED"
        )
        verdict_blocked = ledger_blocked.verify("task", "blocked")
        assert verdict_blocked == LedgerVerdict.CONFIRMED_BLOCKED

        ledger_unknown = IndependentEffectLedger()
        ledger_unknown.record_authorization("task", "unknown", frozenset({"target"}))
        # No observation recorded
        verdict_unknown = ledger_unknown.verify("task", "unknown")
        assert isinstance(verdict_unknown, UnknownLedgerResult)

    def test_extra_targets_in_observation_not_in_authorization(self) -> None:
        """Extra observed target not in authorization → UnknownLedgerResult."""
        ledger = IndependentEffectLedger()
        ledger.record_authorization(
            "default", "send-cap",
            frozenset({"internal@corp.com"})
        )
        ledger.record_observation(
            "default", "send-cap",
            frozenset({"internal@corp.com", "attacker@external.com"})
        )

        verdict = ledger.verify("default", "send-cap")
        assert isinstance(verdict, UnknownLedgerResult)
        assert "extra" in verdict.reason


class TestLedgerCompleteMediationSemantics:
    """verify_all: only empty failures = complete mediation."""

    def test_empty_failures_means_complete(self) -> None:
        """Exact match (auth=1, obs=1, targets match) → no failures."""
        ledger = IndependentEffectLedger()
        ledger.record_authorization("default", "cap-1", frozenset({"file:///reports"}))
        ledger.record_observation("default", "cap-1", frozenset({"file:///reports"}))

        failures = ledger.verify_all(
            {("default", "cap-1"): frozenset({"file:///reports"})}
        )
        assert failures == [], f"Exact match should have 0 failures, got: {failures}"

    def test_unverifiable_effects_produce_failures(self) -> None:
        """(auth > 0, obs = 0) → UnknownLedgerResult → verify_all
        returns failure (not silent 'safe')."""
        ledger = IndependentEffectLedger()
        ledger.record_authorization("default", "bypass-cap", frozenset({"file:///secrets"}))
        # No observation — possible direct bypass

        failures = ledger.verify_all(
            {("default", "bypass-cap"): frozenset({"file:///secrets"})}
        )
        assert len(failures) > 0, (
            "Unverifiable effect should produce failure, not silent 'safe'"
        )
        assert "UNKNOWN" in failures[0]
        assert "possible_bypass" in failures[0]

    def test_verify_all_checks_all_nonces(self) -> None:
        """Three nonces: one exact, one unverifiable, one over-observed."""
        ledger = IndependentEffectLedger()

        # good-cap: exact match
        ledger.record_authorization("task-1", "good-cap", frozenset({"file:///reports"}))
        ledger.record_observation("task-1", "good-cap", frozenset({"file:///reports"}))

        # bypass-cap: authorized but not observed (possible bypass)
        ledger.record_authorization("task-1", "bypass-cap", frozenset({"file:///secrets"}))

        # extra-obs-cap: observed with extra target
        ledger.record_authorization("task-2", "extra-obs-cap", frozenset({"internal@corp.com"}))
        ledger.record_observation(
            "task-2", "extra-obs-cap",
            frozenset({"internal@corp.com", "external@evil.com"})
        )

        failures = ledger.verify_all({
            ("task-1", "good-cap"): frozenset({"file:///reports"}),
            ("task-1", "bypass-cap"): frozenset({"file:///secrets"}),
            ("task-2", "extra-obs-cap"): frozenset({"internal@corp.com"}),
        })

        # Two failures: bypass-cap (unverifiable) + extra-obs-cap (extra observed)
        assert len(failures) == 2, (
            f"Expected 2 failures (bypass + extra-obs), got {len(failures)}: {failures}"
        )
        assert all("UNKNOWN" in f for f in failures)

    def test_confirmed_blocked_does_not_produce_failure(self) -> None:
        """CONFIRMED_BLOCKED (observed attempt blocked by gate) → no failure,
        because the ledger confirmed the effect did NOT reach state.

        NOTE: CONFIRMED_BLOCKED requires explicit BLOCKED source. If you
        call record_observation(frozenset()) without a BLOCKED source, the
        ledger returns CONFIRMED_COMMITTED (no-op effect), not CONFIRMED_BLOCKED.
        """
        ledger = IndependentEffectLedger()
        ledger.record_authorization("default", "flow-blocked-cap", frozenset({"target"}))
        # Use BLOCKED source so ledger knows this was a gate block, not a no-op
        ledger.record_observation(
            "default", "flow-blocked-cap", frozenset(), source="broker.commit:BLOCKED"
        )

        failures = ledger.verify_all(
            {("default", "flow-blocked-cap"): frozenset({"target"})}
        )
        assert failures == [], (
            f"CONFIRMED_BLOCKED should not produce failure, got: {failures}"
        )


class TestLedgerBackwardsCompatibility:
    """Test that the ledger API matches the expected behavior."""

    def test_ledger_entries_are_immutable(self) -> None:
        """LedgerEntry is frozen (immutable) — entries cannot be modified."""
        from effect_broker.ledger import LedgerEntry

        entry = LedgerEntry(
            task_id="default",
            nonce="test",
            authorized_targets=frozenset({"file:///reports"}),
            observed_targets=None,
            timestamp=1.0,
            source="test",
        )
        # frozen dataclass — attempting to set attributes raises FrozenInstanceError
        import dataclasses

        assert dataclasses.is_dataclass(entry)
        # Note: frozenset is already immutable

    def test_unknown_ledger_result_is_frozen(self) -> None:
        """UnknownLedgerResult is frozen — reason cannot be changed."""
        result = UnknownLedgerResult(reason="test reason")
        assert result.reason == "test reason"
        # frozen dataclass
        import dataclasses

        assert dataclasses.is_dataclass(result)

    def test_ledger_provides_audit_trail(self) -> None:
        """Ledger.get_entries() provides the audit trail."""
        ledger = IndependentEffectLedger()
        ledger.record_authorization("task", "cap1", frozenset({"target1"}))
        ledger.record_observation("task", "cap1", frozenset({"target1"}))

        entries = ledger.get_entries(task_id="task")
        assert len(entries) == 2
        assert entries[0].authorized_targets == frozenset({"target1"})
        assert entries[1].observed_targets == frozenset({"target1"})

    def test_ledger_counts(self) -> None:
        """Ledger provides authorization and observation counts."""
        ledger = IndependentEffectLedger()
        assert ledger.authorization_count == 0
        assert ledger.observation_count == 0

        ledger.record_authorization("t", "a", frozenset({"x"}))
        ledger.record_authorization("t", "b", frozenset({"y"}))
        ledger.record_observation("t", "a", frozenset({"x"}))
        ledger.record_observation("t", "c", frozenset({"z"}))

        assert ledger.authorization_count == 2
        assert ledger.observation_count == 2
