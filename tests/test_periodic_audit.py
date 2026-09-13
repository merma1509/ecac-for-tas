"""Tests for periodic audit mechanism.

Verifies that PeriodicAuditor can detect unverifiable effects on a schedule
and report delta changes between audit runs.
"""

from __future__ import annotations

from effect_broker.ledger import (
    AuditSnapshot,
    IndependentEffectLedger,
    PeriodicAuditor,
)


class TestPeriodicAuditor:
    """PeriodicAuditor detects unverifiable effects on a schedule."""

    def test_first_audit_is_complete_with_empty_ledger(self) -> None:
        """Empty ledger → audit is complete (no failures)."""
        ledger = IndependentEffectLedger()
        auditor = PeriodicAuditor(ledger)

        result = auditor.audit()

        assert result.is_complete is True
        assert result.failures == []
        assert result.previous_snapshot is None

    def test_first_audit_with_verified_effects_is_complete(self) -> None:
        """Authorized + observed effect → audit is complete."""
        ledger = IndependentEffectLedger()
        ledger.record_authorization("task", "cap1", frozenset({"target"}))
        ledger.record_observation("task", "cap1", frozenset({"target"}))

        auditor = PeriodicAuditor(ledger)
        result = auditor.audit()

        assert result.is_complete is True
        assert result.failures == []

    def test_audit_detects_unverifiable_effect(self) -> None:
        """Authorized but not observed → audit reports UNKNOWN failure."""
        ledger = IndependentEffectLedger()
        ledger.record_authorization("task", "cap1", frozenset({"target"}))
        # No observation — possible direct bypass

        auditor = PeriodicAuditor(ledger)
        result = auditor.audit()

        assert result.is_complete is False
        assert len(result.failures) == 1
        assert "UNKNOWN" in result.failures[0]
        assert "authorized_not_observed" in result.failures[0]

    def test_audit_detects_unauthorized_observation(self) -> None:
        """Observed without authorization → audit reports UNKNOWN failure.

        When an observation exists but there is no corresponding authorization,
        the nonce appears only in _observations (not _authorizations).
        verify_all() now detects these and adds a failure.
        """
        ledger = IndependentEffectLedger()
        ledger.record_observation("task", "cap1", frozenset({"target"}))

        auditor = PeriodicAuditor(ledger)
        result = auditor.audit()

        # Snapshot captures the observation, but verify_all detects
        # "observed without authorization" from the authorized_records dict
        assert result.snapshot.observation_count == 1
        # verify_all checks: is every observed key in authorized_records?
        # cap1 is observed but NOT authorized → UNKNOWN failure
        assert result.is_complete is False
        assert len(result.failures) == 1
        assert "observed_without_authorization" in result.failures[0]

    def test_audit_detects_multiple_failures(self) -> None:
        """Multiple unverifiable effects → audit reports all failures."""
        ledger = IndependentEffectLedger()
        ledger.record_authorization("task1", "cap1", frozenset({"target1"}))
        ledger.record_authorization("task2", "cap2", frozenset({"target2"}))
        ledger.record_observation("task1", "cap1", frozenset({"target1"}))
        # task2: cap2 authorized but not observed

        auditor = PeriodicAuditor(ledger)
        result = auditor.audit()

        assert result.is_complete is False
        assert len(result.failures) == 1
        assert "cap2" in result.failures[0]

    def test_audit_reports_delta_since_last_run(self) -> None:
        """Second audit reports new authorizations/observations since first."""
        ledger = IndependentEffectLedger()
        auditor = PeriodicAuditor(ledger)

        # First audit: empty ledger
        result1 = auditor.audit()
        assert result1.new_authorizations == 0
        assert result1.new_observations == 0

        # Add entries between audits
        ledger.record_authorization("task", "cap1", frozenset({"target1"}))
        ledger.record_observation("task", "cap1", frozenset({"target1"}))
        ledger.record_authorization("task", "cap2", frozenset({"target2"}))
        # cap2: not observed (unverifiable)

        # Second audit: reports 2 new auth, 1 new obs
        result2 = auditor.audit()
        assert result2.new_authorizations == 2
        assert result2.new_observations == 1
        assert result2.is_complete is False  # cap2 not observed

    def test_snapshot_contains_correct_counts(self) -> None:
        """Audit snapshot captures authorization_count, observation_count."""
        ledger = IndependentEffectLedger()
        ledger.record_authorization("t", "a", frozenset({"x"}))
        ledger.record_authorization("t", "b", frozenset({"y"}))
        ledger.record_observation("t", "a", frozenset({"x"}))

        auditor = PeriodicAuditor(ledger)
        result = auditor.audit()

        assert result.snapshot.authorization_count == 2
        assert result.snapshot.observation_count == 1
        assert result.snapshot.task_ids == frozenset({"t"})
        assert result.snapshot.nonces == frozenset({"a", "b"})

    def test_reset_clears_history(self) -> None:
        """reset() clears the previous snapshot.

        The reset audit compares against empty state (baseline), so new_auth=0.
        But the unverifiable authorization is still detected as a failure.
        """
        ledger = IndependentEffectLedger()
        ledger.record_authorization("t", "cap1", frozenset({"target"}))

        auditor = PeriodicAuditor(ledger)

        # First audit: baseline (0→1 auth, unverifiable)
        result1 = auditor.audit()
        assert result1.new_authorizations == 0  # baseline, no previous snapshot
        assert result1.is_complete is False

        # Reset clears history
        auditor.reset()

        # After reset: baseline comparison (new_auth=0), but unverifiable entry persists
        result2 = auditor.audit()
        assert result2.new_authorizations == 0  # reset means baseline comparison
        assert result2.is_complete is False  # still unverifiable

    def test_confirmed_blocked_does_not_produce_failure(self) -> None:
        """CONFIRMED_BLOCKED (explicit blocked source) → audit is complete."""
        ledger = IndependentEffectLedger()
        ledger.record_authorization("task", "blocked", frozenset({"target"}))
        ledger.record_observation("task", "blocked", frozenset(), source="broker.commit:BLOCKED")

        auditor = PeriodicAuditor(ledger)
        result = auditor.audit()

        assert result.is_complete is True
        assert result.failures == []

    def test_audit_result_stores_previous_snapshot(self) -> None:
        """AuditResult.previous_snapshot is set after first audit."""
        ledger = IndependentEffectLedger()
        auditor = PeriodicAuditor(ledger)

        # First audit: previous_snapshot is None
        result1 = auditor.audit()
        assert result1.previous_snapshot is None

        # Second audit: previous_snapshot is result1's snapshot
        result2 = auditor.audit()
        assert result2.previous_snapshot == result1.snapshot

    def test_last_snapshot_returns_none_before_first_audit(self) -> None:
        """last_snapshot() returns None if audit() was never called."""
        ledger = IndependentEffectLedger()
        auditor = PeriodicAuditor(ledger)

        assert auditor.last_snapshot() is None

    def test_last_snapshot_returns_correct_value_after_audit(self) -> None:
        """last_snapshot() returns the snapshot from the most recent audit."""
        ledger = IndependentEffectLedger()
        auditor = PeriodicAuditor(ledger)

        auditor.audit()
        snapshot = auditor.last_snapshot()

        assert snapshot is not None
        assert snapshot.authorization_count == 0
        assert snapshot.observation_count == 0

    def test_multiple_consecutive_audits_work(self) -> None:
        """Five consecutive audits all work correctly."""
        ledger = IndependentEffectLedger()
        auditor = PeriodicAuditor(ledger)

        for i in range(5):
            result = auditor.audit()
            assert result.is_complete is True
            assert len(result.failures) == 0
            # previous_snapshot is None for the first audit, set after
            if i == 0:
                assert result.previous_snapshot is None
            else:
                assert result.previous_snapshot is not None


class TestAuditSnapshot:
    """AuditSnapshot delta computation."""

    def test_new_authorizations_since(self) -> None:
        """new_authorizations_since computes correct delta."""
        prev = AuditSnapshot(
            timestamp=1.0,
            authorization_count=5,
            observation_count=5,
            task_ids=frozenset(),
            nonces=frozenset(),
        )
        current = AuditSnapshot(
            timestamp=2.0,
            authorization_count=8,
            observation_count=5,
            task_ids=frozenset(),
            nonces=frozenset(),
        )

        assert current.new_authorizations_since(prev) == 3
        assert current.new_observations_since(prev) == 0

    def test_new_observations_since(self) -> None:
        """new_observations_since computes correct delta."""
        prev = AuditSnapshot(
            timestamp=1.0,
            authorization_count=3,
            observation_count=2,
            task_ids=frozenset(),
            nonces=frozenset(),
        )
        current = AuditSnapshot(
            timestamp=2.0,
            authorization_count=3,
            observation_count=5,
            task_ids=frozenset(),
            nonces=frozenset(),
        )

        assert current.new_authorizations_since(prev) == 0
        assert current.new_observations_since(prev) == 3
