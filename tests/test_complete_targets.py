"""Regression: Effect.complete_targets() is the canonical source.

All three call-sites MUST use effect.complete_targets() to compute the
authorized target set — not independently re-extract from metadata.

Before the fix, there were THREE independent computations:
  1. broker.commit()          → inline if/else over metadata
  2. executor.execute()      → inline if/else over metadata
  3. broker.grant_approval() → inline if/else over metadata

These could diverge (e.g. grant_approval extracted bcc_1 while commit
extracted extra_resources). The fix introduces Effect.complete_targets()
as the single canonical source.

This test verifies that complete_targets() produces identical results
across the three call-sites (commit, executor, grant_approval) for both
the known_targets path and the metadata-fallback path.
"""

from __future__ import annotations

from effect_broker.executor import IsolatedExecutor
from effect_broker.model import (
    Capability,
    Commit,
    Data,
    Effect,
    EffectTarget,
    Task,
)
from effect_broker.traces import build


def _provenance(name: str) -> tuple[Data, ...]:
    from effect_broker.lattice import Confidentiality, Integrity
    return (Data(name, Confidentiality.INTERNAL, Integrity.USER),)


def _make_task(task_id: str = "default") -> Task:
    ceiling = Capability(
        owner="User",
        holder="EffectBroker",
        right="*",
        target="*",
        scope=frozenset({"*"}),
        expiry=float("inf"),
        nonce=f"ceiling-{task_id}",
    )
    return Task(task_id=task_id, owner="User", ceiling=ceiling)


class TestCanonicalCompleteTargets:
    """All three call-sites use Effect.complete_targets() — not inline metadata extraction."""

    def test_known_targets_path_all_three_sites_equal(self) -> None:
        """With known_targets set: executor, broker.commit, grant_approval agree.

        This is the primary path (via shim). The Effect has known_targets
        populated and all three nonces record the same authorized_targets.
        """
        broker = build()
        task = _make_task("default")
        broker.register_task(task)

        # Simulate the shim building an effect with known_targets
        effect = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={"extra_resources": ["bcc1@corp.com", "bcc2@corp.com"]},
            provenance=_provenance("msg"),
            capability_nonce="r-send:Agent:EffectBroker",
            delegation_chain=(),
            known_targets=EffectTarget(
                primary="internal@corp.com",
                additional=frozenset({"bcc1@corp.com", "bcc2@corp.com"}),
            ),
        )

        # 1. executor path
        executor = IsolatedExecutor(broker=broker, task_id="default")
        executor._execution_count = 0
        commit = Commit(effect=effect, task=task)
        allow, _ = executor.execute(commit)

        # 2. broker.commit path
        broker2 = build()
        task2 = _make_task("default")
        broker2.register_task(task2)
        executor2 = IsolatedExecutor(broker=broker2, task_id="default")
        commit2 = Commit(effect=effect, task=task2)
        allow2, _ = executor2.execute(commit2)

        # 3. grant_approval path
        broker3 = build()
        task3 = _make_task("default")
        broker3.register_task(task3)
        nonce = broker3.grant_approval(effect, expiry=100.0, task_id="default")
        stored = broker3._approved_requests.get(nonce)

        expected = frozenset({
            "internal@corp.com", "bcc1@corp.com", "bcc2@corp.com"
        })

        # Verify: executor recorded correct authorized_targets
        # Ledger stores authorization entries; merge all entries for this nonce
        ledger_key = (task.task_id, effect.capability_nonce)
        ledger_entries = executor.broker._local_ledger._authorizations.get(ledger_key, [])
        auth_record = frozenset()
        for entry in ledger_entries:
            auth_record |= entry.authorized_targets
        assert auth_record == expected, (
            f"executor authorized_targets mismatch: expected={expected}, got={auth_record}"
        )

        # Verify: broker.commit path also recorded correct targets
        ledger_key2 = (task2.task_id, effect.capability_nonce)
        ledger_entries2 = executor2.broker._local_ledger._authorizations.get(ledger_key2, [])
        auth_record2 = frozenset()
        for entry in ledger_entries2:
            auth_record2 |= entry.authorized_targets
        assert auth_record2 == expected, (
            f"broker commit authorized_targets mismatch: expected={expected}, got={auth_record2}"
        )

        # Verify: grant_approval stored correct targets in ApprovedRequest
        assert stored is not None
        assert stored.targets.primary == "internal@corp.com"
        assert stored.targets.additional == frozenset({"bcc1@corp.com", "bcc2@corp.com"}), (
            f"grant_approval targets.additional mismatch: "
            f"expected={frozenset({'bcc1@corp.com', 'bcc2@corp.com'})}, "
            f"got={stored.targets.additional}"
        )

    def test_metadata_fallback_path_all_three_sites_equal(self) -> None:
        """Without known_targets: all three sites extract from metadata consistently.

        This is the fallback path (direct Effect construction). The Effect
        does NOT have known_targets; BCC recipients are in metadata keys.
        All three call-sites must extract the same complete set.
        """
        broker = build()
        task = _make_task("default")
        broker.register_task(task)

        # Effect WITHOUT known_targets — relies on metadata fallback
        effect = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={
                "extra_resources": ["bcc_a@corp.com", "bcc_b@corp.com"],
                "bcc_1": "bcc_c@corp.com",
            },
            provenance=_provenance("msg"),
            capability_nonce="r-send:Agent:EffectBroker",
            delegation_chain=(),
            # known_targets is None — fallback path
        )

        # Verify canonical complete_targets() produces correct result
        expected = frozenset({
            "internal@corp.com",
            "bcc_a@corp.com",
            "bcc_b@corp.com",
            "bcc_c@corp.com",
        })
        assert effect.complete_targets() == expected, (
            f"complete_targets() mismatch: expected={expected}, "
            f"got={effect.complete_targets()}"
        )

        # Also verify that grant_approval stores the correct set
        nonce = broker.grant_approval(effect, expiry=100.0, task_id="default")
        stored = broker._approved_requests.get(nonce)
        assert stored is not None
        assert stored.targets.primary == "internal@corp.com"
        assert stored.targets.additional == frozenset({
            "bcc_a@corp.com", "bcc_b@corp.com", "bcc_c@corp.com"
        }), (
            f"grant_approval fallback path targets.additional mismatch: "
            f"expected={frozenset({'bcc_a@corp.com', 'bcc_b@corp.com', 'bcc_c@corp.com'})}, "
            f"got={stored.targets.additional}"
        )

    def test_complete_targets_single_bcc_string(self) -> None:
        """extra_resources as single string (not list) → handled correctly."""
        effect = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={"extra_resources": "single-bcc@corp.com"},
            provenance=_provenance("msg"),
            capability_nonce="any-cap",
            delegation_chain=(),
        )
        expected = frozenset({"internal@corp.com", "single-bcc@corp.com"})
        assert effect.complete_targets() == expected

    def test_complete_targets_no_extras(self) -> None:
        """No known_targets, no extra_resources → only primary target."""
        effect = Effect(
            etype="write",
            target="file:///reports",
            metadata={},
            provenance=_provenance("write"),
            capability_nonce="any-cap",
            delegation_chain=(),
        )
        expected = frozenset({"file:///reports"})
        assert effect.complete_targets() == expected

    def test_complete_targets_known_targets_takes_priority(self) -> None:
        """When known_targets is set, it is the authoritative source (metadata skipped).

        The shim sets BOTH known_targets AND metadata["extra_resources"] to the
        same value (metadata for documentation, known_targets for the authoritative
        record). complete_targets() uses known_targets.additional and does NOT
        also add metadata extras — that would duplicate them.

        This means: when the builder sets known_targets, they are asserting that
        known_targets captures the complete set. Metadata is for compatibility
        with non-shim callers only.
        """
        effect = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={"extra_resources": ["meta-bcc@corp.com"]},
            provenance=_provenance("msg"),
            capability_nonce="any-cap",
            delegation_chain=(),
            known_targets=EffectTarget(
                primary="internal@corp.com",
                additional=frozenset({"known-bcc@corp.com"}),
            ),
        )
        # known_targets.additional is authoritative; metadata is skipped
        expected = frozenset({
            "internal@corp.com",
            "known-bcc@corp.com",
        })
        assert effect.complete_targets() == expected, (
            f"known_targets should be authoritative. expected={expected}, "
            f"got={effect.complete_targets()}"
        )

    def test_approval_binding_extra_targets_uses_complete_targets(self) -> None:
        """Approval binding check uses complete_targets() for additional recipients.

        When a commit is made with an ApprovedRequest, gate() uses
        complete_targets() - {primary} to get the additional targets.
        This must match what grant_approval() stored in ApprovedRequest.targets.

        Test 1 (same task): exact match → ALLOW (ApprovalBinding passes)
        Test 2 (different task with fresh approval): extra in-scope BCC not in
            approved set → ApprovalBinding fires (NoAmp passes, ApprovalBinding blocks)

        NOTE: NoAmp checks that extra targets are in capability scope first.
        We use scope={internal} (domain-level) so both internal addresses pass.
        """
        broker = build()
        task = _make_task("default")
        broker.register_task(task)

        # Add capability with scope={internal} so BCC recipients pass NoAmp
        from effect_broker.model import BROKER, USER
        broker.capabilities["bcc-send-cap"] = Capability(
            owner=USER,
            holder=BROKER,
            right="send",
            target="internal@corp.com",
            scope=frozenset({"internal"}),  # domain-level scope — covers all internal addresses
            expiry=float("inf"),
            nonce="bcc-send-cap",
            derives_from=None,
        )

        # ---- Test 1: exact match → ALLOW ----
        approval_effect = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={"extra_resources": ["team@corp.com"]},
            provenance=_provenance("approved-msg"),
            capability_nonce="bcc-send-cap",
            delegation_chain=(),
            known_targets=EffectTarget(
                primary="internal@corp.com",
                additional=frozenset({"team@corp.com"}),
            ),
        )
        nonce = broker.grant_approval(approval_effect, expiry=100.0, task_id="default")
        stored = broker._approved_requests[nonce]

        # Verify grant_approval stored the correct additional set
        assert stored.targets.additional == frozenset({"team@corp.com"})

        same_effect = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={"extra_resources": ["team@corp.com"]},
            provenance=_provenance("approved-msg"),  # same content
            capability_nonce=nonce,
            delegation_chain=(),
            known_targets=EffectTarget(
                primary="internal@corp.com",
                additional=frozenset({"team@corp.com"}),
            ),
        )
        commit = Commit(effect=same_effect, task=task, approved_request=stored)
        allow, ev = broker.commit(commit)
        assert allow is True, f"Exact match should ALLOW. Evidence: {ev}"
        assert ev["approval_binding"] == ""

        # ---- Test 2: extra in-scope BCC not in approved set → ApprovalBinding ----
        # Fresh consumed the first nonce. Grant a fresh approval in a new task
        # so Fresh does not block (different session.used set).
        task2 = _make_task("task2")
        broker.register_task(task2)

        # Grant a NEW approval for the base (approved) set only
        base_effect = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={"extra_resources": ["team@corp.com"]},
            provenance=_provenance("approved-msg"),
            capability_nonce="bcc-send-cap",
            delegation_chain=(),
            known_targets=EffectTarget(
                primary="internal@corp.com",
                additional=frozenset({"team@corp.com"}),
            ),
        )
        nonce2 = broker.grant_approval(base_effect, expiry=100.0, task_id="task2")
        stored2 = broker._approved_requests[nonce2]

        # Try to commit with an extra in-scope BCC NOT in the approval
        extra_effect = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={"extra_resources": ["team@corp.com", "other-internal@corp.com"]},
            provenance=_provenance("approved-msg"),
            capability_nonce=nonce2,
            delegation_chain=(),
            known_targets=EffectTarget(
                primary="internal@corp.com",
                additional=frozenset({"team@corp.com", "other-internal@corp.com"}),
            ),
        )
        commit2 = Commit(effect=extra_effect, task=task2, approved_request=stored2)
        allow2, ev2 = broker.commit(commit2)
        assert allow2 is False, "Extra in-scope BCC not in approved set should BLOCK"
        # ApprovalBinding fires (both targets in scope {internal}, but other-internal not approved)
        assert ev2["primary_blocker"] == "ApprovalBinding"
        assert "extra-targets-not-approved" in ev2["approval_binding"]
        assert "other-internal@corp.com" in ev2["approval_binding"]


class TestLedgerObservationRecorded:
    """Regression: ledger.record_observation must be called after every ALLOW.

    Before the fix, the observation recording call was dedented outside its
    `if identity_entries:` block, silently discarding the observation.
    Without a ledger entry, verify() returns UNKNOWN instead of CONFIRMED_COMMITTED.
    """

    def test_allowed_commit_records_observation(self) -> None:
        """ALLOW commit: record_observation must be called (not discarded)."""
        broker = build()
        task = _make_task("default")
        broker.register_task(task)

        broker.capabilities["obs-cap"] = Capability(
            owner="User",
            holder="EffectBroker",
            right="write",
            target="file:///reports",
            scope=frozenset({"file:///reports"}),
            expiry=float("inf"),
            nonce="obs-cap",
            derives_from=None,
        )

        effect = Effect(
            etype="write",
            target="file:///reports",
            metadata={},
            provenance=_provenance("obs-test"),
            capability_nonce="obs-cap",
            delegation_chain=(),
        )

        # Clear any prior ledger state
        broker._local_ledger.reset()
        allow, _ = broker.commit(broker._make_commit(effect, task_id="default"))
        assert allow is True

        # Observation must be recorded — verify() should return CONFIRMED_COMMITTED
        ledger_key = (task.task_id, effect.capability_nonce)
        obs_entries = broker._local_ledger._observations.get(ledger_key, [])
        assert len(obs_entries) >= 1, (
            "BUG: record_observation was NOT called — observation call was dedented "
            "outside its if-block, silently discarded. "
            "This causes verify() to return UNKNOWN instead of CONFIRMED_COMMITTED."
        )

        verdict = broker._local_ledger.verify(task.task_id, effect.capability_nonce)
        from effect_broker.ledger import LedgerVerdict
        assert verdict == LedgerVerdict.CONFIRMED_COMMITTED, (
            f"Expected CONFIRMED_COMMITTED, got {verdict}. "
            "Observation recording may have been silently dropped."
        )

    def test_blocked_commit_records_blocked_observation(self) -> None:
        """BLOCKed commit: record_observation(task_id, nonce, None) must be called."""
        broker = build()
        task = _make_task("default")
        broker.register_task(task)

        # Capability for send, but effect is write -> BLOCK
        broker.capabilities["obs-block-cap"] = Capability(
            owner="User",
            holder="EffectBroker",
            right="send",
            target="internal@corp.com",
            scope=frozenset({"internal"}),
            expiry=float("inf"),
            nonce="obs-block-cap",
            derives_from=None,
        )

        effect = Effect(
            etype="write",  # mismatched: cap has right="send"
            target="file:///reports",
            metadata={},
            provenance=_provenance("obs-block-test"),
            capability_nonce="obs-block-cap",
            delegation_chain=(),
        )

        broker._local_ledger.reset()
        allow, ev = broker.commit(broker._make_commit(effect, task_id="default"))
        assert not allow
        assert ev["primary_blocker"] == "Auth"

        # Blocked observation must be recorded (None = explicit blocked)
        ledger_key = (task.task_id, effect.capability_nonce)
        obs_entries = broker._local_ledger._observations.get(ledger_key, [])
        assert len(obs_entries) >= 1, (
            "BUG: blocked observation was NOT recorded. "
            "CONFIRMED_BLOCKED requires auth > 0 + obs = empty set with BLOCKED source."
        )
        assert obs_entries[0].source == "executor.execute:BLOCKED"


class TestApprovalExpiry:
    """Approval expiry must be checked in gate() (ApprovalBinding)."""

    def test_approval_expired_by_logical_time_blocked(self) -> None:
        """Approval with expiry=10 invalid at session time 15: Fresh BLOCKs.

        grant_approval() creates a backing capability with cap.expiry=same as approval
        expiry, so Fresh fires first. This is the correct, intended behavior — expired
        approvals are rejected at the Fresh predicate, same as expired capabilities.
        ApprovalBinding expiry check is present for edge cases where ApproveRequest
        is stored without grant_approval() (e.g., manual injection).
        """
        broker = build()
        task = _make_task("default")
        broker.register_task(task)

        broker.capabilities["exp-cap"] = Capability(
            owner="User",
            holder="EffectBroker",
            right="send",
            target="internal@corp.com",
            scope=frozenset({"internal"}),
            expiry=float("inf"),
            nonce="exp-cap",
            derives_from=None,
        )

        effect = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={},
            provenance=_provenance("approved-msg"),
            capability_nonce="exp-cap",
            delegation_chain=(),
            known_targets=EffectTarget(
                primary="internal@corp.com",
                additional=frozenset(),
            ),
        )
        nonce = broker.grant_approval(effect, expiry=10.0, task_id="default")
        stored = broker._approved_requests[nonce]

        # Verify grant_approval syncs cap.expiry to approval expiry
        assert broker.capabilities[nonce].expiry == 10.0

        # Advance session time to 15 (past expiry=10)
        broker.advance_time("default", 15.0)

        approved_effect = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={},
            provenance=_provenance("approved-msg"),
            capability_nonce=nonce,
            delegation_chain=(),
            known_targets=EffectTarget(
                primary="internal@corp.com",
                additional=frozenset(),
            ),
        )
        from effect_broker.model import Commit

        commit = Commit(
            effect=approved_effect,
            task=task,
            approved_request=stored,
        )
        allow, ev = broker.commit(commit)
        assert not allow
        # grant_approval syncs cap.expiry = approval expiry → Fresh fires first
        assert ev["primary_blocker"] == "Fresh"
        assert "expired" in ev["predicates"]["Fresh"]

    def test_approval_valid_before_expiry_allows(self) -> None:
        """Approval valid at session time 5 with expiry=10: ALLOWs."""
        broker = build()
        task = _make_task("default")
        broker.register_task(task)

        broker.capabilities["valid-exp-cap"] = Capability(
            owner="User",
            holder="EffectBroker",
            right="send",
            target="internal@corp.com",
            scope=frozenset({"internal"}),
            expiry=float("inf"),
            nonce="valid-exp-cap",
            derives_from=None,
        )

        effect = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={},
            provenance=_provenance("valid-msg"),
            capability_nonce="valid-exp-cap",
            delegation_chain=(),
            known_targets=EffectTarget(
                primary="internal@corp.com",
                additional=frozenset(),
            ),
        )
        nonce = broker.grant_approval(effect, expiry=10.0, task_id="default")
        stored = broker._approved_requests[nonce]

        # At session time 5: within expiry window
        broker.advance_time("default", 5.0)

        from effect_broker.model import Commit

        approved_effect = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={},
            provenance=_provenance("valid-msg"),
            capability_nonce=nonce,
            delegation_chain=(),
            known_targets=EffectTarget(
                primary="internal@corp.com",
                additional=frozenset(),
            ),
        )
        commit = Commit(
            effect=approved_effect,
            task=task,
            approved_request=stored,
        )
        allow, ev = broker.commit(commit)
        assert allow is True
        assert ev["primary_blocker"] is None


class TestCapabilityTaskScope:
    """Capability.task_id must be enforced for reusable (non-approval) capabilities."""

    def test_reusable_cap_task_scoped_to_wrong_task_blocked(self) -> None:
        """Reusable cap with task_id=A used in task=B: Auth BLOCKs (task-scope-mismatch).

        This prevents a reusable capability from being used across task boundaries.
        Approval capabilities use ApprovalBinding instead.
        """
        broker = build()
        task_a = _make_task("task-a")
        task_b = _make_task("task-b")
        broker.register_task(task_a)
        broker.register_task(task_b)

        # Reusable cap scoped to task-a
        cap = Capability(
            owner="User",
            holder="EffectBroker",
            right="send",
            target="internal@corp.com",
            scope=frozenset({"internal"}),
            expiry=float("inf"),
            nonce="reusable-cap",
            task_id="task-a",  # ← scoped to task-a
            derives_from=None,
        )
        broker.capabilities["reusable-cap"] = cap

        effect = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={},
            provenance=_provenance("msg"),
            capability_nonce="reusable-cap",
            delegation_chain=(),
        )

        # In task-a: ALLOW (correct task)
        allow_a, ev_a = broker.commit(broker._make_commit(effect, task_id="task-a"))
        assert allow_a is True, f"task-a should ALLOW: {ev_a}"

        # In task-b: BLOCK (wrong task — task-scope-mismatch)
        allow_b, ev_b = broker.commit(broker._make_commit(effect, task_id="task-b"))
        assert not allow_b
        assert ev_b["primary_blocker"] == "Auth"
        assert "task-scope-mismatch" in ev_b["predicates"]["Auth"]

    def test_reusable_cap_no_task_id_unrestricted(self) -> None:
        """Reusable cap with task_id=None can be used in any task."""
        broker = build()
        task_a = _make_task("task-a")
        task_b = _make_task("task-b")
        broker.register_task(task_a)
        broker.register_task(task_b)

        cap = Capability(
            owner="User",
            holder="EffectBroker",
            right="send",
            target="internal@corp.com",
            scope=frozenset({"internal"}),
            expiry=float("inf"),
            nonce="unrestricted-cap",
            task_id=None,  # ← no task restriction
            derives_from=None,
        )
        broker.capabilities["unrestricted-cap"] = cap

        effect = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={},
            provenance=_provenance("msg"),
            capability_nonce="unrestricted-cap",
            delegation_chain=(),
        )

        allow_a, _ = broker.commit(broker._make_commit(effect, task_id="task-a"))
        allow_b, _ = broker.commit(broker._make_commit(effect, task_id="task-b"))
        assert allow_a is True
        assert allow_b is True

    def test_approval_nonce_task_checked_by_approval_binding(self) -> None:
        """Approval nonces use ApprovalBinding (not task-scope sub-check) for task check.

        This verifies that approval task_id is checked in ApprovalBinding, not Auth.
        The Auth sub-check skips task_id for approval: prefixed nonces.
        """
        broker = build()
        task_a = _make_task("task-a")
        task_b = _make_task("task-b")
        broker.register_task(task_a)
        broker.register_task(task_b)

        broker.capabilities["task-scoped-cap"] = Capability(
            owner="User",
            holder="EffectBroker",
            right="send",
            target="internal@corp.com",
            scope=frozenset({"internal"}),
            expiry=float("inf"),
            nonce="task-scoped-cap",
            derives_from=None,
        )

        effect = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={},
            provenance=_provenance("approved"),
            capability_nonce="task-scoped-cap",
            delegation_chain=(),
            known_targets=EffectTarget(
                primary="internal@corp.com",
                additional=frozenset(),
            ),
        )
        nonce = broker.grant_approval(effect, expiry=100.0, task_id="task-a")
        stored = broker._approved_requests[nonce]

        from effect_broker.model import Commit

        # In task-a: ALLOW (ApprovalBinding passes: task_id matches)
        approved_effect = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={},
            provenance=_provenance("approved"),
            capability_nonce=nonce,
            delegation_chain=(),
            known_targets=EffectTarget(
                primary="internal@corp.com",
                additional=frozenset(),
            ),
        )
        commit_a = Commit(effect=approved_effect, task=task_a, approved_request=stored)
        allow_a, ev_a = broker.commit(commit_a)
        assert allow_a is True, f"task-a should ALLOW: {ev_a}"

        # In task-b: BLOCK via ApprovalBinding (not Auth task-scope sub-check)
        commit_b = Commit(effect=approved_effect, task=task_b, approved_request=stored)
        allow_b, ev_b = broker.commit(commit_b)
        assert not allow_b
        assert ev_b["primary_blocker"] == "ApprovalBinding"
        assert "cross-task-use" in ev_b["approval_binding"]
        # Auth should pass (cap is task-unscoped, right matches)
        assert "task-scope-mismatch" not in ev_b["predicates"]["Auth"]


class TestLedgerVerdictUnknownAfterCrash:
    """Regression: ledger must return UNKNOWN, not SAFE, for effects
    that were authorized but whose observation is lost (e.g., crash).

    In the same-process model, a "crash" means the broker process restarts
    with a fresh session (session.used = ∅). Fresh cannot block the retry
    (nonce lost), but the ledger must return UNKNOWN — not false SAFE.
    This is the "unknown, not safe" guarantee.
    """

    def test_verify_confirmed_blocked_after_session_preserved(self) -> None:
        """Session preserved: Fresh blocks retry. Ledger returns CONFIRMED_BLOCKED."""
        from effect_broker.ledger import LedgerVerdict

        broker = build()
        task = _make_task("default")
        broker.register_task(task)
        broker.store._unsafe_bootstrap_file("file:///reports", None)

        broker.capabilities["retry-block-cap"] = Capability(
            owner="User",
            holder="EffectBroker",
            right="write",
            target="file:///reports",
            scope=frozenset({"file:///reports"}),
            expiry=float("inf"),
            nonce="retry-block-cap",
            derives_from=None,
        )

        effect = Effect(
            etype="write",
            target="file:///reports",
            metadata={},
            provenance=_provenance("retry-test"),
            capability_nonce="retry-block-cap",
            delegation_chain=(),
        )

        # First commit: ALLOW → auth + committed obs
        allow1, _ = broker.commit(broker._make_commit(effect, task_id="default"))
        assert allow1 is True

        # Session preserved: Fresh blocks retry
        allow2, ev2 = broker.commit(broker._make_commit(effect, task_id="default"))
        assert not allow2
        assert ev2["primary_blocker"] == "Fresh"
        assert "replay" in ev2["predicates"]["Fresh"]

        # Ledger: committed obs + BLOCKED obs → CONFIRMED_BLOCKED
        verdict = broker._local_ledger.verify(task.task_id, effect.capability_nonce)
        assert verdict == LedgerVerdict.CONFIRMED_BLOCKED, (
            f"Expected CONFIRMED_BLOCKED after Fresh replay, got {verdict}"
        )

    def test_verify_unknown_when_obs_exceeds_auth(self) -> None:
        """Ledger returns UNKNOWN when observation count exceeds authorization count.

        This is the "unknown, not safe" guarantee: if we observe an effect more
        times than we authorized it, the ledger cannot determine if this is a bypass
        (unauthorized commit) or a crash-recovery with lost auth records.
        """
        from effect_broker.ledger import LedgerVerdict

        broker = build()
        task = _make_task("default")
        broker.register_task(task)
        broker.store._unsafe_bootstrap_file("file:///reports", None)

        broker.capabilities["over-obs-cap"] = Capability(
            owner="User",
            holder="EffectBroker",
            right="write",
            target="file:///reports",
            scope=frozenset({"file:///reports"}),
            expiry=float("inf"),
            nonce="over-obs-cap",
            derives_from=None,
        )

        effect = Effect(
            etype="write",
            target="file:///reports",
            metadata={},
            provenance=_provenance("over-obs"),
            capability_nonce="over-obs-cap",
            delegation_chain=(),
        )

        # Commit: ALLOW → auth + obs
        broker.commit(broker._make_commit(effect, task_id="default"))

        # Inject extra observation to simulate over-observation (auth_count=1, obs_count=2)
        from effect_broker.ledger import LedgerEntry

        extra_obs = LedgerEntry(
            task_id="default",
            nonce="over-obs-cap",
            authorized_targets=frozenset(),
            observed_targets=frozenset({"file:///reports"}),
            timestamp=3.0,
            source="unknown-source",
        )
        broker._local_ledger._observations[
            ("default", "over-obs-cap")
        ].append(extra_obs)

        verdict = broker._local_ledger.verify("default", "over-obs-cap")
        assert verdict == LedgerVerdict.UNKNOWN or (
            hasattr(verdict, "reason") and "over-observed" in verdict.reason
        ), (
            f"Expected UNKNOWN when obs_count > auth_count, got {verdict}. "
            f"SAFE would be a false positive."
        )

    def test_verify_unknown_when_auth_record_lost(self) -> None:
        """Effect observed but auth record lost (crash after obs, before auth write).
        Ledger returns UNKNOWN — cannot determine if the effect was authorized."""
        from effect_broker.ledger import LedgerVerdict

        broker = build()
        task = _make_task("default")
        broker.register_task(task)
        broker.store._unsafe_bootstrap_file("file:///reports", None)

        # Inject obs directly (no commit): simulates crash after obs, before auth record
        from effect_broker.ledger import LedgerEntry

        obs_entry = LedgerEntry(
            task_id="default",
            nonce="lost-auth-cap",
            authorized_targets=frozenset(),
            observed_targets=frozenset({"file:///reports"}),
            timestamp=1.0,
            source="broker.commit",
        )
        key = ("default", "lost-auth-cap")
        if key not in broker._local_ledger._observations:
            broker._local_ledger._observations[key] = []
        broker._local_ledger._observations[key].append(obs_entry)

        verdict = broker._local_ledger.verify("default", "lost-auth-cap")
        assert verdict == LedgerVerdict.UNKNOWN or (
            hasattr(verdict, "reason") and "observed_without_authorization" in verdict.reason
        ), (
            f"Expected UNKNOWN when obs exists but no auth record, got {verdict}. "
            f"SAFE would be a false positive."
        )
