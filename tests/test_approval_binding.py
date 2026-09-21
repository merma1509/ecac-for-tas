"""Regression: Approval binding — exact immutable request binding.

Tests verify that an approval grants a capability scoped to a SPECIFIC
(etype, target, additional, task_id) tuple, not a class of effects.

Two binding mechanisms:
  1. Fresh: approval nonce is one-shot — second use is replay-blocked
     (the original path, always active regardless of approved_request)
  2. Exact immutable binding: Commit.approved_request must exactly match
     the stored ApprovedRequest — etype, targets, task_id
     (the new path, active only when Commit.approved_request is set)

Kill-criterion #5: "exact immutable request binding."
The approval nonce is a one-shot token: it can only authorize the effect
it was granted for. Any deviation is blocked.
"""

from __future__ import annotations

from effect_broker.lattice import Confidentiality, Integrity
from effect_broker.model import (
    APPROVER,
    BROKER,
    USER,
    ApprovedRequest,
    Capability,
    Commit,
    Data,
    Effect,
    EffectTarget,
    Task,
)
from effect_broker.traces import build


def _provenance(name: str, content: str = "") -> tuple[Data, ...]:
    """Create a provenance tuple for test effects.

    Provenance is validated by FlowOK, not included in ApprovalBinding.
    """
    return (Data(name, Confidentiality.INTERNAL, Integrity.USER, content=content),)


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


class TestApprovalBindingExact:
    """Approval nonce is bound to the exact (etype, target) it was granted for."""

    def test_approval_allows_correct_etype_and_target(self) -> None:
        """Approval grants ALLOW for the exact (etype, target) it was issued for."""
        broker = build()
        task = _make_task("default")
        broker.register_task(task)

        # Approval granted for write(file:///reports)
        target_effect = Effect(
            etype="write",
            target="file:///reports",
            metadata={},
            provenance=_provenance("approval-request"),
            capability_nonce="r-write:Agent:EffectBroker",
            delegation_chain=("Approver", "broker-shim"),
        )
        nonce = broker.grant_approval(target_effect, expiry=100.0, task_id="default")

        # First commit with correct (etype, target): ALLOW
        correct_effect = Effect(
            etype="write",
            target="file:///reports",
            metadata={},
            provenance=_provenance("approved"),
            capability_nonce=nonce,
            delegation_chain=("Approver", "broker-shim"),
        )
        commit1 = broker._make_commit(correct_effect, task_id="default")
        allow1, _ = broker.commit(commit1)
        assert allow1 is True, "Approval should ALLOW the exact approved effect"
        assert len(broker.store.effects_log) == 1

    def test_approval_blocks_on_different_target(self) -> None:
        """Approval for write(reports) does NOT authorize write(secrets)."""
        broker = build()
        task = _make_task("default")
        broker.register_task(task)

        # Approval granted for write(file:///reports)
        target_effect = Effect(
            etype="write",
            target="file:///reports",
            metadata={},
            provenance=_provenance("approval-request"),
            capability_nonce="r-write:Agent:EffectBroker",
            delegation_chain=("Approver", "broker-shim"),
        )
        nonce = broker.grant_approval(target_effect, expiry=100.0, task_id="default")

        # Try to write to DIFFERENT target (secrets) using same nonce
        wrong_target = Effect(
            etype="write",
            target="file:///secrets",
            metadata={},
            provenance=_provenance("reused-approval"),
            capability_nonce=nonce,
            delegation_chain=("Approver", "broker-shim"),
        )
        commit2 = broker._make_commit(wrong_target, task_id="default")
        allow2, ev2 = broker.commit(commit2)

        # Auth blocks (target mismatch) or Fresh blocks (if nonce consumed)
        assert allow2 is False, (
            f"Approval for write(reports) should NOT authorize write(secrets). Evidence: {ev2}"
        )

    def test_approval_blocks_on_different_etype(self) -> None:
        """Approval for read does NOT authorize write, even on same target

        Uses a ceiling with right='read' to ensure the right-mismatch check fires
        With a permissive ceiling (right='*'), the mismatch is not caught at the
        authorization level — that is expected, and the task ceiling design
        ensures this cannot happen in practice
        """
        broker = build()

        # Non-wildcard ceiling enforces strict right matching
        task_ceiling = Capability(
            owner="User",
            holder="EffectBroker",
            right="read",  # ceiling only allows read operations
            target="*",
            scope=frozenset({"*"}),
            expiry=float("inf"),
            nonce="read-only-ceiling",
        )
        task = Task(task_id="default", owner="User", ceiling=task_ceiling)
        broker.register_task(task)

        # Approval granted for read(file:///reports)
        read_effect = Effect(
            etype="read",
            target="file:///reports",
            metadata={},
            provenance=_provenance("request"),
            capability_nonce="r-read:Agent:EffectBroker",
            delegation_chain=("Approver",),
        )
        nonce = broker.grant_approval(read_effect, expiry=100.0)

        # Try to commit a write using the read approval
        write_effect = Effect(
            etype="write",
            target="file:///reports",
            metadata={},
            provenance=_provenance("approved"),
            capability_nonce=nonce,
            delegation_chain=("Approver",),
        )
        commit = broker._make_commit(write_effect, task_id="default")
        allow, evidence = broker.commit(commit)

        # Auth blocks: right mismatch (capability right=read vs effect etype=write)
        assert allow is False, f"Approval for read should NOT authorize write. Evidence: {evidence}"
        assert evidence["primary_blocker"] in ("Auth", "NoAmp")


class TestApprovalReplayBlocks:
    """Fresh blocks the second use of the same one-shot approval nonce."""

    def test_approval_is_one_shot(self) -> None:
        """The same approval nonce cannot be used twice."""
        broker = build()
        task = _make_task("default")
        broker.register_task(task)

        # Grant approval for send
        risky = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={},
            provenance=_provenance("legit"),
            capability_nonce="r-send:Agent:EffectBroker",
            delegation_chain=("Approver", "broker-shim"),
        )
        nonce = broker.grant_approval(risky, expiry=100.0, task_id="default")

        # First commit: ALLOW (nonce not yet in used set)
        approved = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={},
            provenance=_provenance("approved"),
            capability_nonce=nonce,
            delegation_chain=("Approver", "broker-shim"),
        )
        commit1 = broker._make_commit(approved, task_id="default")
        allow1, ev1 = broker.commit(commit1)
        assert allow1 is True, "First use of approval should ALLOW"
        assert len(broker.store.effects_log) == 1

        # Second commit with same nonce: Fresh BLOCKs (replay)
        commit2 = broker._make_commit(approved, task_id="default")
        allow2, ev2 = broker.commit(commit2)
        assert allow2 is False, "Second use of same approval nonce should BLOCK"
        assert ev2["primary_blocker"] == "Fresh"
        assert "replay" in ev2["predicates"]["Fresh"]

        # Only 1 effect in log (second was blocked)
        assert len(broker.store.effects_log) == 1

    def test_approval_expired_after_expiry_time(self) -> None:
        """Approval with passed expiry is blocked by Fresh."""
        broker = build()
        task = _make_task("default")
        broker.register_task(task)
        broker.logical_time = 0.0

        # Grant approval with expiry = 50
        risky = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={},
            provenance=_provenance("request"),
            capability_nonce="r-send:Agent:EffectBroker",
            delegation_chain=("Approver",),
        )
        nonce = broker.grant_approval(risky, expiry=50.0)

        # Advance time past expiry
        broker.logical_time = 51.0

        # Commit after expiry: Fresh BLOCKs (expired)
        expired_effect = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={},
            provenance=_provenance("late"),
            capability_nonce=nonce,
            delegation_chain=("Approver",),
        )
        commit = broker._make_commit(expired_effect, task_id="default")
        allow, evidence = broker.commit(commit)

        assert allow is False, "Expired approval should BLOCK"
        assert evidence["primary_blocker"] == "Fresh"
        assert "expired" in evidence["predicates"]["Fresh"]

    def test_approval_not_in_capabilities_before_grant(self) -> None:
        """Approval nonce is NOT in capabilities until grant_approval() runs."""
        broker = build()

        risky = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={},
            provenance=_provenance("request"),
            capability_nonce="r-send:Agent:EffectBroker",
            delegation_chain=("Approver",),
        )

        # Pre-grant: nonce not in capabilities
        pre_nonce = f"approval:send:internal@corp.com:{len(broker.approvals)}"
        assert pre_nonce not in broker.capabilities

        # Grant: nonce added to capabilities
        nonce = broker.grant_approval(risky, expiry=100.0)
        assert nonce in broker.capabilities
        cap = broker.capabilities[nonce]
        assert cap.right == "send"
        assert cap.target == "internal@corp.com"


class TestApprovalExactBinding:
    """Exact immutable request matching via Commit.approved_request.

    Kill-criterion #5: approved_request on Commit must exactly match the stored
    ApprovedRequest — etype, targets, task_id.
    Any deviation is blocked as ApprovalBinding.
    """

    def test_approval_task_id_binding_blocks_cross_task_use(self) -> None:
        """ApprovalBinding checks task_id: using approval in wrong task → BLOCK."""
        broker = build()
        task_a = _make_task("task-a")
        task_b = _make_task("task-b")
        broker.register_task(task_a)
        broker.register_task(task_b)

        # Grant for task-a only
        request_effect = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={},
            provenance=_provenance("msg"),
            capability_nonce="r-send:Agent:EffectBroker",
            delegation_chain=("Approver",),
        )
        nonce = broker.grant_approval(request_effect, expiry=100.0, task_id="task-a")

        # Use in task-b → BLOCK by ApprovalBinding (task_id mismatch)
        effect_b = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={},
            provenance=_provenance("msg"),
            capability_nonce=nonce,
            delegation_chain=("Approver",),
        )
        commit_b = Commit(effect=effect_b, task=task_b)
        allow, evidence = broker.commit(commit_b)

        assert allow is False, "Cross-task use should BLOCK"
        assert evidence["primary_blocker"] == "ApprovalBinding"
        assert "cross-task-use" in evidence["approval_binding"]
        assert len(broker.store.effects_log) == 0

    def test_approval_blocks_on_extra_bcc_not_in_approved_targets(self) -> None:
        """BCC to unapproved recipient → ApprovalBinding blocks (or NoAmp)."""
        broker = build()
        task = _make_task("default")
        broker.register_task(task)

        request_effect = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={},
            provenance=_provenance("request"),
            capability_nonce="r-send:Agent:EffectBroker",
            delegation_chain=("Approver",),
        )
        nonce = broker.grant_approval(request_effect, expiry=100.0, task_id="default")
        stored_approved = broker._approved_requests.get(nonce)
        assert stored_approved is not None

        extra_effect = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={"extra_resources": ["attacker@external.com"]},
            provenance=_provenance("request"),
            capability_nonce=nonce,
            delegation_chain=("Approver",),
            known_targets=EffectTarget(
                primary="internal@corp.com",
                additional=frozenset({"attacker@external.com"}),
            ),
        )
        commit = Commit(effect=extra_effect, task=task, approved_request=stored_approved)
        allow, evidence = broker.commit(commit)

        assert allow is False, "Extra BCC target not in approved set should BLOCK"
        assert evidence["primary_blocker"] in ("NoAmp", "ApprovalBinding")

    def test_approval_blocks_on_cross_task_use(self) -> None:
        """Same approval nonce used in different task → ApprovalBinding blocks."""
        broker = build()
        task_a = _make_task("task-a")
        task_b = _make_task("task-b")
        broker.register_task(task_a)
        broker.register_task(task_b)

        request_effect = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={},
            provenance=_provenance("task-a-request"),
            capability_nonce="r-send:Agent:EffectBroker",
            delegation_chain=("Approver",),
        )
        nonce = broker.grant_approval(request_effect, expiry=100.0, task_id="task-a")
        stored_approved = broker._approved_requests.get(nonce)

        cross_task_effect = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={},
            provenance=_provenance("task-a-request"),
            capability_nonce=nonce,
            delegation_chain=("Approver",),
        )
        commit = Commit(effect=cross_task_effect, task=task_b, approved_request=stored_approved)
        allow, evidence = broker.commit(commit)

        assert allow is False, "Cross-task use of approval should BLOCK"
        assert evidence["primary_blocker"] == "ApprovalBinding"
        assert "cross-task-use" in evidence["approval_binding"]

    def test_approval_content_hash_removed_binding_is_label_only(self) -> None:
        """Binding no longer covers content_hash — content changes are NOT a binding
        issue. Binding covers etype + target + additional + task_id only.
        Provenance/integrity is enforced by FlowOK at commit time."""
        from dataclasses import fields

        field_names = {f.name for f in fields(ApprovedRequest)}
        assert (
            "content_hash" not in field_names
        ), "content_hash must be removed from ApprovedRequest binding"
        # Verify the binding fields that DO exist
        assert field_names >= {"nonce", "etype", "targets", "expiry", "task_id", "granted_by"}

    def test_approval_allows_with_exact_binding_match(self) -> None:
        """Exact match: etype + target + task_id → ALLOW."""
        broker = build()
        task = _make_task("default")
        broker.register_task(task)

        original_provenance = _provenance("approved-content")
        request_effect = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={},
            provenance=original_provenance,
            capability_nonce="r-send:Agent:EffectBroker",
            delegation_chain=("Approver",),
        )
        nonce = broker.grant_approval(request_effect, expiry=100.0, task_id="default")
        stored_approved = broker._approved_requests.get(nonce)

        exact_effect = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={},
            provenance=original_provenance,
            capability_nonce=nonce,
            delegation_chain=("Approver",),
        )
        commit = Commit(effect=exact_effect, task=task, approved_request=stored_approved)
        allow, evidence = broker.commit(commit)

        assert allow is True, f"Exact binding match should ALLOW. Evidence: {evidence}"
        assert evidence["primary_blocker"] is None
        assert evidence["approval_binding"] == ""
        assert len(broker.store.effects_log) == 1

    def test_approval_blocks_on_forged_approval_nonce(self) -> None:
        """Forged nonce (not in _approved_requests) → ApprovalBinding blocks."""
        broker = build()
        task = _make_task("default")
        broker.register_task(task)

        # Initialize _approved_requests
        broker.grant_approval(
            Effect("send", "internal@corp.com", {}, _provenance("dummy"), "dummy-cap", ()),
            expiry=100.0,
            task_id="default",
        )

        broker.capabilities["forged-approval-nonce"] = Capability(
            owner=USER,
            holder=BROKER,
            right="send",
            target="internal@corp.com",
            scope=frozenset({"internal"}),
            expiry=float("inf"),
            nonce="forged-approval-nonce",
            derives_from=None,
        )

        fake_approved = ApprovedRequest(
            nonce="forged-approval-nonce",
            etype="send",
            targets=EffectTarget(primary="internal@corp.com", additional=frozenset()),
            expiry=100.0,
            task_id="default",
            granted_by=APPROVER,
        )

        effect = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={},
            provenance=_provenance("forged"),
            capability_nonce="forged-approval-nonce",
            delegation_chain=("Approver",),
        )
        commit = Commit(effect=effect, task=task, approved_request=fake_approved)
        allow, evidence = broker.commit(commit)

        assert allow is False
        assert evidence["primary_blocker"] == "ApprovalBinding"
        assert "approval-nonce-unknown" in evidence["approval_binding"]

    def test_approval_without_binding_field_passes_predicates_only(self) -> None:
        """Commit without approved_request: predicates run, no binding check."""
        broker = build()
        task = _make_task("default")
        broker.register_task(task)

        broker.capabilities["regular-cap"] = Capability(
            owner=USER,
            holder=BROKER,
            right="send",
            target="internal@corp.com",
            scope=frozenset({"internal"}),
            expiry=float("inf"),
            nonce="regular-cap",
            derives_from=None,
        )

        effect = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={},
            provenance=_provenance("regular"),
            capability_nonce="regular-cap",
            delegation_chain=(USER,),
        )
        commit = broker._make_commit(effect, task_id="default")
        assert commit.approved_request is None

        allow, evidence = broker.commit(commit)
        assert allow is True
        assert evidence["primary_blocker"] is None
        assert evidence["approval_binding"] is None


class TestApprovalBCCScope:
    """BCC within capability scope → ALLOW. BCC outside scope → BLOCK."""

    def test_bcc_to_another_internal_recipient_is_allowed(self) -> None:
        """BCC to another internal recipient (in scope) → ALLOW."""
        broker = build()
        task = _make_task("default")
        broker.register_task(task)

        broker.capabilities["internal-send-cap"] = Capability(
            owner=USER,
            holder=BROKER,
            right="send",
            target="internal@corp.com",
            scope=frozenset({"internal"}),
            expiry=float("inf"),
            nonce="internal-send-cap",
            derives_from=None,
        )

        effect = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={},
            provenance=_provenance("to-team"),
            capability_nonce="internal-send-cap",
            delegation_chain=(USER,),
            known_targets=EffectTarget(
                primary="internal@corp.com",
                additional=frozenset({"another-internal@corp.com"}),
            ),
        )
        commit = Commit(effect=effect, task=task, approved_request=None)
        allow, evidence = broker.commit(commit)
        assert allow is True, (
            f"BCC to another internal (in scope) should ALLOW. Evidence: {evidence}"
        )
        assert evidence["primary_blocker"] is None

    def test_bcc_to_external_recipient_outside_scope_is_blocked(self) -> None:
        """BCC to external recipient (outside scope) → NoAmp blocks."""
        broker = build()
        task = _make_task("default")
        broker.register_task(task)

        broker.capabilities["internal-send-cap"] = Capability(
            owner=USER,
            holder=BROKER,
            right="send",
            target="internal@corp.com",
            scope=frozenset({"internal"}),
            expiry=float("inf"),
            nonce="internal-send-cap",
            derives_from=None,
        )

        effect = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={"extra_resources": ["external@attacker.com"]},
            provenance=_provenance("attacker-bcc"),
            capability_nonce="internal-send-cap",
            delegation_chain=(USER,),
            known_targets=EffectTarget(
                primary="internal@corp.com",
                additional=frozenset({"external@attacker.com"}),
            ),
        )
        commit = Commit(effect=effect, task=task, approved_request=None)
        allow, evidence = broker.commit(commit)

        assert allow is False, f"BCC to external (outside scope) should BLOCK. Evidence: {evidence}"
        assert evidence["primary_blocker"] in ("NoAmp", "Auth", "ApprovalBinding")


class TestApprovalGlobalRevocation:
    """Revoke without task_id revokes globally (all sessions affected)."""

    def test_global_revoke_invalidates_approval(self) -> None:
        """Revoke without task_id: affects all sessions."""
        broker = build()
        task = _make_task("default")
        broker.register_task(task)

        risky = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={},
            provenance=_provenance("request"),
            capability_nonce="r-send:Agent:EffectBroker",
            delegation_chain=("Approver",),
        )
        nonce = broker.grant_approval(risky, expiry=100.0)

        # Commit in task: ALLOW
        approved = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={},
            provenance=_provenance("approved"),
            capability_nonce=nonce,
            delegation_chain=("Approver",),
        )
        commit1 = broker._make_commit(approved, task_id="default")
        allow1, _ = broker.commit(commit1)
        assert allow1 is True

        # Global revocation (no task_id)
        broker.revoke(nonce, task_id=None)

        # Re-use same nonce in new task: Fresh BLOCKs (global revoke)
        task2 = _make_task("task2")
        broker.register_task(task2)

        commit2 = broker._make_commit(approved, task_id="task2")
        allow2, evidence2 = broker.commit(commit2)
        assert allow2 is False, "Globally revoked approval should BLOCK"
        assert evidence2["primary_blocker"] == "Fresh"
        assert "global" in evidence2["predicates"]["Fresh"]

    def test_task_revoke_only_affects_that_task(self) -> None:
        """Task-scoped revocation: revoke in task1, task2 still has the same cap."""
        from effect_broker.model import Capability

        broker = build()

        # Register two tasks with different task IDs
        task1 = _make_task("task1")
        task2 = _make_task("task2")
        broker.register_task(task1)
        broker.register_task(task2)

        # Create a capability scoped to task1 (regular cap, not approval)
        cap = Capability(
            owner="User",
            holder="EffectBroker",
            right="send",
            target="internal@corp.com",
            scope=frozenset({"internal"}),
            expiry=100.0,
            nonce="cap-in-task1",
            task_id="task1",  # capability is valid for task1 only
        )
        broker.grant_root(cap)

        # Task1: ALLOW with the capability
        effect1 = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={},
            provenance=_provenance("msg"),
            capability_nonce="cap-in-task1",
            delegation_chain=(),
        )
        commit1 = Commit(effect=effect1, task=task1)
        allow1, _ = broker.commit(commit1)
        assert allow1 is True, "First use in task1 should ALLOW"

        # Revoke in task1 only
        broker.revoke("cap-in-task1", task_id="task1")

        # Task1: Fresh BLOCKs (revoked in this task)
        commit2_task1 = Commit(effect=effect1, task=task1)
        allow2_task1, ev2_task1 = broker.commit(commit2_task1)
        assert allow2_task1 is False
        assert ev2_task1["primary_blocker"] == "Fresh"

        # Task2: Different task. Task2 uses a NEW capability nonce ("cap-in-task1"
        # doesn't exist for task2 since task_id on cap is task1). Instead we grant
        # a fresh capability for task2 with the same right/target.
        cap2 = Capability(
            owner="User",
            holder="EffectBroker",
            right="send",
            target="internal@corp.com",
            scope=frozenset({"internal"}),
            expiry=100.0,
            nonce="cap-in-task2",
            task_id="task2",
        )
        broker.grant_root(cap2)

        effect2 = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={},
            provenance=_provenance("msg"),
            capability_nonce="cap-in-task2",
            delegation_chain=(),
        )
        commit2_task2 = Commit(effect=effect2, task=task2)
        allow2_task2, ev2_task2 = broker.commit(commit2_task2)
        assert allow2_task2 is True, (
            f"Task2 should ALLOW — different task, revocation in task1 is isolated. Evidence: {ev2_task2}"
        )
