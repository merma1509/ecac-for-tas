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
