"""Wildcard declass/endorse grants must be bound to the exact task.

Hole: LabelException.matches_effect() returned True for match_target="*"
BEFORE the task_id check. A grant scoped to task A with a wildcard target
silently matched task B's effect — a cross-task privilege transfer.

Fix: the task_id check runs first and is never wildcardable. A grant with
task_id="task-a" matches only effects from task A, even if match_target="*".

Repro status:
  * test_control_same_task_wildcard_grant : green before AND after (grant.task_id
    is None, so the task check passes for any task).
  * test_attack_cross_task_wildcard_grant : documents the hole — a grant scoped
    to task A matches task B's effect (BEFORE). After the fix, it does not.
  * test_legit_task_scoped_grant_same_task : green before AND after.
"""

from __future__ import annotations

from effect_broker.lattice import Confidentiality, Integrity
from effect_broker.model import (
    Capability,
    Commit,
    Data,
    Effect,
    EffectTarget,
    LabelException,
    Task,
)
from effect_broker.traces import build


def _task(task_id: str) -> Task:
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


def _cap(owner: str, right: str, target: str, scope: frozenset[str], nonce: str) -> Capability:
    return Capability(
        owner=owner,
        holder="EffectBroker",
        right=right,
        target=target,
        scope=scope,
        expiry=float("inf"),
        nonce=nonce,
    )


def _read(target: str, nonce: str) -> Effect:
    return Effect(
        etype="read",
        target=target,
        metadata={},
        provenance=(),
        capability_nonce=nonce,
        delegation_chain=(),
    )


def _send(
    target: str,
    nonce: str,
    provenance: tuple[Data, ...],
    label_exceptions: tuple[LabelException, ...] = (),
    task_id: str | None = None,
) -> Effect:
    return Effect(
        etype="send",
        target=target,
        metadata={},
        provenance=provenance,
        capability_nonce=nonce,
        delegation_chain=(),
        label_exceptions=label_exceptions,
        known_targets=EffectTarget(primary=target),
        task_id=task_id,
    )


def _taint(broker, task, read_nonce: str) -> None:
    """Read the bootstrapped CONFIDENTIAL resource to taint the session."""
    allow, _ = broker.commit(Commit(_read("file:///secrets", read_nonce), task))
    assert allow is True, "Reading a CONFIDENTIAL file (input) should be allowed"
    assert task.session.tainted, "Session must be tainted after reading CONFIDENTIAL"


class TestWildcardGrantTaskBinding:
    """A wildcard-target grant must not cross task boundaries."""

    def test_control_same_task_wildcard_grant(self) -> None:
        """CONTROL: a wildcard grant with task_id=None (any task) works on any task.

        Green before AND after the fix — the task check passes when grant.task_id
        is None. This is the legitimate cross-task-free case.
        """
        broker = build()
        task_a = _task("task-a")
        broker.register_task(task_a)
        broker.capabilities["wt-cap-read"] = _cap("User", "*", "*", frozenset({"*"}), "wt-cap-read")
        broker.capabilities["wt-cap-send"] = _cap(
            "User", "send", "*", frozenset({"*"}), "wt-cap-send"
        )

        _taint(broker, task_a, "wt-cap-read")

        # Wildcard grant, task_id=None (applies to any task).
        declass = LabelException(
            kind="declass",
            match_target="*",
            from_label=Confidentiality.CONFIDENTIAL.name,
            to_label=Confidentiality.INTERNAL.name,
            granted_by="User",
            nonce="declass-wt-control",
            data_resources=frozenset({"file:///secrets"}),
            # task_id=None → applies to any task (legitimate)
        )
        broker.grant_label_exception(declass)

        clean = _send(
            "internal@corp.com",
            "wt-cap-send",
            provenance=(Data("msg", Confidentiality.INTERNAL, Integrity.USER),),
            label_exceptions=(declass,),
            task_id="task-a",
        )
        allow, evidence = broker.commit(Commit(clean, task_a))
        assert allow is True, (
            f"Wildcard grant with task_id=None should work on any task. "
            f"Blocker={evidence.get('primary_blocker')!r}, "
            f"FlowOK={evidence['predicates'].get('FlowOK')!r}"
        )

    def test_attack_cross_task_wildcard_grant(self) -> None:
        """HOLE (BEFORE): a grant scoped to task A with wildcard target matches
        task B's effect. After the fix, the task check runs before the wildcard
        short-circuit, so the grant does NOT match task B.
        """
        broker = build()
        task_a = _task("task-a")
        task_b = _task("task-b")
        broker.register_task(task_a)
        broker.register_task(task_b)

        broker.capabilities["wt-cap-read-b"] = _cap(
            "User", "*", "*", frozenset({"*"}), "wt-cap-read-b"
        )
        broker.capabilities["wt-cap-send-b"] = _cap(
            "User", "send", "*", frozenset({"*"}), "wt-cap-send-b"
        )

        # Taint task B's session.
        _taint(broker, task_b, "wt-cap-read-b")

        # Grant scoped to task A (task_id="task-a"), wildcard target.
        declass_a = LabelException(
            kind="declass",
            match_target="*",
            from_label=Confidentiality.CONFIDENTIAL.name,
            to_label=Confidentiality.INTERNAL.name,
            granted_by="User",
            nonce="declass-wt-attack",
            data_resources=frozenset({"file:///secrets"}),
            task_id="task-a",  # scoped to task A
        )
        broker.grant_label_exception(declass_a)

        # ATTACK: task B's effect tries to use task A's grant.
        cross_task = _send(
            "internal@corp.com",
            "wt-cap-send-b",
            provenance=(Data("msg", Confidentiality.INTERNAL, Integrity.USER),),
            label_exceptions=(declass_a,),
            task_id="task-b",  # effect belongs to task B
        )
        allow, evidence = broker.commit(Commit(cross_task, task_b))

        # the task check runs before the wildcard short-circuit, so a
        # grant scoped to task A does NOT match task B's effect. The taint is
        # not cleared and the send is blocked by session-taint.
        assert allow is False, (
            "A grant scoped to task A must NOT match task B's effect, even "
            f"with wildcard target. Evidence: {evidence}"
        )
        assert evidence["primary_blocker"] == "FlowOK"
        assert "session-taint" in evidence["predicates"]["FlowOK"], (
            f"Cross-task grant must NOT clear task B's taint; expected "
            f"session-taint block, got: {evidence['predicates'].get('FlowOK')!r}"
        )

    def test_legit_task_scoped_grant_same_task(self) -> None:
        """LEGITIMATE: a grant scoped to task A works on task A's effect.
        Green before AND after the fix.
        """
        broker = build()
        task_a = _task("task-a")
        broker.register_task(task_a)
        broker.capabilities["wt-cap-read-l"] = _cap(
            "User", "*", "*", frozenset({"*"}), "wt-cap-read-l"
        )
        broker.capabilities["wt-cap-send-l"] = _cap(
            "User", "send", "*", frozenset({"*"}), "wt-cap-send-l"
        )

        _taint(broker, task_a, "wt-cap-read-l")

        # Grant scoped to task A.
        declass_a = LabelException(
            kind="declass",
            match_target="*",
            from_label=Confidentiality.CONFIDENTIAL.name,
            to_label=Confidentiality.INTERNAL.name,
            granted_by="User",
            nonce="declass-wt-legit",
            data_resources=frozenset({"file:///secrets"}),
            task_id="task-a",  # scoped to task A
        )
        broker.grant_label_exception(declass_a)

        # Task A's effect uses task A's grant — legitimate.
        legit = _send(
            "internal@corp.com",
            "wt-cap-send-l",
            provenance=(Data("msg", Confidentiality.INTERNAL, Integrity.USER),),
            label_exceptions=(declass_a,),
            task_id="task-a",
        )
        allow, evidence = broker.commit(Commit(legit, task_a))
        assert allow is True, (
            f"Task-scoped grant should work on its own task. "
            f"Blocker={evidence.get('primary_blocker')!r}, "
            f"FlowOK={evidence['predicates'].get('FlowOK')!r}"
        )
