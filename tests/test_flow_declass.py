"""Regression: FlowOK declass/endorse must be broker-recorded grants

These tests verify the "Flow regression" requirement:
  - FlowOK blocks confidentiality/integrity violations (no exceptions)
  - A broker-recorded LabelException is REQUIRED for declass/endorse
  - The LLM may only REQUEST, never perform

Tests use the broker's default task (created automatically) so that
Auth passes for nonces from build().
"""

from __future__ import annotations

import pytest

from effect_broker.lattice import Confidentiality, Integrity
from effect_broker.model import Capability, Commit, Data, Effect, LabelException, Task
from effect_broker.traces import build


def _make_permissive_task(task_id: str) -> Task:
    """Create a task with a ceiling that dominates all rights.

    Note: ceiling.right = "*" means "all rights allowed" (dominates all).
    With the broker.py fix, "*" also makes NoAmp skip the right check.
    """
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


def _effect(
    etype: str,
    target: str,
    nonce: str,
    provenance: tuple[Data, ...],
    label_exceptions: tuple[LabelException, ...] = (),
) -> Effect:
    return Effect(
        etype=etype,
        target=target,
        metadata={},
        provenance=provenance,
        capability_nonce=nonce,
        delegation_chain=(),
        label_exceptions=label_exceptions,
    )


def _grant_for(broker, etype: str, target: str, expiry: float = 100.0) -> tuple[str, Task]:
    """Grant an approval for (etype, target) and return (nonce, task).

    grant_approval creates a capability with the exact target, bypassing
    the mismatch that occurs with build()-seeded capabilities (which are
    scoped to specific targets from the trace setup).
    """
    task = _make_permissive_task("default")
    broker.register_task(task)
    request = Effect(
        etype=etype,
        target=target,
        metadata={},
        provenance=(Data("__request__", Confidentiality.INTERNAL, Integrity.USER),),
        capability_nonce=f"r-{etype}:Agent:EffectBroker",
        delegation_chain=(),
    )
    nonce = broker.grant_approval(request, expiry=expiry, task_id="default")
    return nonce, task


class TestFlowDeclassRegression:
    """Declassification requires a broker-recorded LabelException."""

    def test_flow_blocks_conf_leak_without_declass(self) -> None:
        """Unmitigated conf-leak: FlowOK BLOCKs before anything reaches state."""
        broker = build()
        nonce, task = _grant_for(broker, "read", "file:///secrets")

        high_conf = _effect(
            etype="read",
            target="file:///secrets",
            nonce=nonce,
            provenance=(Data("secret", Confidentiality.CONFIDENTIAL, Integrity.USER),),
        )
        allow, evidence = broker.commit(Commit(high_conf, task))

        assert allow is False
        assert evidence["primary_blocker"] == "FlowOK"
        assert "conf-leak" in evidence["predicates"]["FlowOK"]
        assert len(broker.store.effects_log) == 0

    def test_flow_allows_conf_leak_with_broker_declass(self) -> None:
        """Broker-recorded declass: FlowOK ALLOWs exactly once."""
        broker = build()
        nonce, task = _grant_for(broker, "read", "file:///secrets")

        declass = LabelException(
            kind="declass",
            nonce="declass-secrets",
            match_target="file:///secrets",
            from_label=Confidentiality.CONFIDENTIAL.name,
            to_label=Confidentiality.INTERNAL.name,
            granted_by="User",
        )
        broker.grant_label_exception(declass)

        effect = _effect(
            etype="read",
            target="file:///secrets",
            nonce=nonce,
            provenance=(Data("secret", Confidentiality.CONFIDENTIAL, Integrity.USER),),
            label_exceptions=(declass,),
        )
        allow, evidence = broker.commit(Commit(effect, task))

        assert allow is True, (
            f"FlowOK should ALLOW with broker-recorded declass. Evidence: {evidence}"
        )
        assert len(broker.store.effects_log) == 1

    def test_flow_blocks_if_declass_not_broker_recorded(self) -> None:
        """LLM-requested declass (not recorded by broker): FlowOK BLOCKs."""
        broker = build()
        nonce, task = _grant_for(broker, "read", "file:///secrets")

        # LLM builds a request but broker does NOT record it
        declass_request = LabelException(
            kind="declass",
            nonce="declass-unrecorded",
            match_target="file:///secrets",
            from_label=Confidentiality.CONFIDENTIAL.name,
            to_label=Confidentiality.INTERNAL.name,
            granted_by="User",
        )

        effect = _effect(
            etype="read",
            target="file:///secrets",
            nonce=nonce,
            provenance=(Data("secret", Confidentiality.CONFIDENTIAL, Integrity.USER),),
            label_exceptions=(declass_request,),
        )
        allow, evidence = broker.commit(Commit(effect, task))

        assert allow is False, "Unrecorded declass should BLOCK"
        assert evidence["primary_blocker"] == "FlowOK"

    def test_duplicate_declass_grant_raises(self) -> None:
        """The same declass nonce cannot be registered twice."""
        broker = build()
        declass = LabelException(
            kind="declass",
            nonce="unique-declass",
            match_target="*",
            from_label=Confidentiality.CONFIDENTIAL.name,
            to_label=Confidentiality.INTERNAL.name,
            granted_by="User",
        )
        broker.grant_label_exception(declass)
        with pytest.raises(ValueError, match="duplicate"):
            broker.grant_label_exception(declass)


class TestFlowEndorseRegression:
    """Endorsement requires a broker-recorded LabelException."""

    def test_flow_blocks_low_integrity_without_endorsement(self) -> None:
        """Low-integrity provenance in high-integrity send: FlowOK BLOCKs."""
        broker = build()
        nonce, task = _grant_for(broker, "send", "internal@corp.com")

        effect = _effect(
            etype="send",
            target="internal@corp.com",
            nonce=nonce,
            provenance=(Data("web", Confidentiality.PUBLIC, Integrity.UNTRUSTED),),
        )
        allow, evidence = broker.commit(Commit(effect, task))

        assert allow is False
        assert evidence["primary_blocker"] == "FlowOK"
        assert "low-integrity" in evidence["predicates"]["FlowOK"]
        assert len(broker.store.effects_log) == 0

    def test_flow_allows_low_integrity_with_broker_endorse(self) -> None:
        """Broker-recorded endorse: FlowOK ALLOWs."""
        broker = build()
        nonce, task = _grant_for(broker, "send", "internal@corp.com")

        endorse = LabelException(
            kind="endorse",
            nonce="endorse-web",
            match_target="*",
            from_label=Integrity.UNTRUSTED.name,
            to_label=Integrity.USER.name,
            granted_by="User",
        )
        broker.grant_label_exception(endorse)

        effect = _effect(
            etype="send",
            target="internal@corp.com",
            nonce=nonce,
            provenance=(Data("web", Confidentiality.PUBLIC, Integrity.UNTRUSTED),),
            label_exceptions=(endorse,),
        )
        allow, evidence = broker.commit(Commit(effect, task))

        assert allow is True, (
            f"FlowOK should ALLOW with broker-recorded endorse. Evidence: {evidence}"
        )
        assert len(broker.store.effects_log) == 1

    def test_declass_does_not_cover_integrity_violation(self) -> None:
        """A declass grant does NOT also satisfy an integrity violation."""
        broker = build()
        nonce, task = _grant_for(broker, "send", "internal@corp.com")

        declass = LabelException(
            kind="declass",
            nonce="declass-both",
            match_target="internal@corp.com",
            from_label=Confidentiality.CONFIDENTIAL.name,
            to_label=Confidentiality.INTERNAL.name,
            granted_by="User",
        )
        broker.grant_label_exception(declass)

        # Datum violates confidentiality AND integrity
        effect = _effect(
            etype="send",
            target="internal@corp.com",
            nonce=nonce,
            provenance=(Data("bad", Confidentiality.CONFIDENTIAL, Integrity.UNTRUSTED),),
            label_exceptions=(declass,),
        )
        allow, evidence = broker.commit(Commit(effect, task))

        assert allow is False, "Declass alone does not cover integrity violation"
        assert "low-integrity" in evidence["predicates"]["FlowOK"]


class TestFlowBoundaryTaskScoped:
    """FlowOK uses the task's flow_boundary, not a global lattice."""

    def test_different_tasks_have_different_flow_boundaries(self) -> None:
        """Task A allows CONFIDENTIAL; Task B blocks it (different boundaries)."""
        from effect_broker.model import Capability, Task

        broker = build()

        # Task with wide flow boundary (accepts CONFIDENTIAL data)
        wide_ceiling = Capability(
            owner="User",
            holder="EffectBroker",
            right="read",
            target="*",
            scope=frozenset({"*"}),
            expiry=float("inf"),
            nonce="wide-ceiling",
        )
        task_wide = Task(
            task_id="task-wide",
            owner="User",
            ceiling=wide_ceiling,
            flow_boundary=(Confidentiality.CONFIDENTIAL, Integrity.USER),
        )
        broker.register_task(task_wide)

        # Task with narrow flow boundary (rejects CONFIDENTIAL data)
        narrow_ceiling = Capability(
            owner="User",
            holder="EffectBroker",
            right="read",
            target="*",
            scope=frozenset({"*"}),
            expiry=float("inf"),
            nonce="narrow-ceiling",
        )
        task_narrow = Task(
            task_id="task-narrow",
            owner="User",
            ceiling=narrow_ceiling,
            flow_boundary=(Confidentiality.INTERNAL, Integrity.USER),
        )
        broker.register_task(task_narrow)

        # Same capability (r-read) works for both tasks' files
        conf_effect = _effect(
            etype="read",
            target="file:///trusted",
            nonce="r-read:Agent:EffectBroker",
            provenance=(Data("secret", Confidentiality.CONFIDENTIAL, Integrity.USER),),
        )

        # Wide task: ALLOW
        commit_wide = Commit(conf_effect, task_wide)
        allow_wide, _ = broker.commit(commit_wide)
        assert allow_wide is True, "Wide-flow task should allow CONFIDENTIAL datum"

        # Narrow task: BLOCK
        # NOTE: we need a separate capability for the narrow task's files,
        # or reuse the same one. Since r-read targets file:///trusted and
        # is in capabilities, it should work for both tasks.
        commit_narrow = Commit(conf_effect, task_narrow)
        allow_narrow, ev_narrow = broker.commit(commit_narrow)
        assert allow_narrow is False, (
            f"Narrow-flow task should block CONFIDENTIAL datum. Evidence: {ev_narrow}"
        )
        assert ev_narrow["primary_blocker"] == "FlowOK"
