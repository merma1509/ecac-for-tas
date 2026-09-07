"""Regression: resource identity — separate mailbox, sender, message, recipient

These tests verify the Plan 1 §6 "Resource-identity regression" requirement.

Key invariants:
  - Same capability_nonce to same target = replay (Fresh BLOCKs)
  - Different nonces to same target = distinct (both ALLOW)
  - Sender's provenance is tracked separately from recipient address (FlowOK)
  - Mailbox is the container/ownership boundary (distinct messages distinguishable)

Tests use grant_approval() to get task-scoped capabilities with correct targets.
"""

from __future__ import annotations

from effect_broker.lattice import Confidentiality, Integrity
from effect_broker.model import Capability, Data, Effect, Task
from effect_broker.traces import build


def _provenance(name: str, conf: Confidentiality = Confidentiality.INTERNAL,
                integ: Integrity = Integrity.USER) -> tuple[Data, ...]:
    return (Data(name, conf, integ),)


def _make_task(task_id: str) -> Task:
    """Permissive task with wildcard ceiling (dominates all rights)."""
    ceiling = Capability(
        owner="User", holder="EffectBroker", right="*", target="*",
        scope=frozenset({"*"}), expiry=float("inf"), nonce=f"ceil-{task_id}",
    )
    return Task(task_id=task_id, owner="User", ceiling=ceiling)


def _grant(broker, task: Task, etype: str, target: str,
           expiry: float = 100.0) -> str:
    """Grant a one-shot approval for (etype, target)."""
    request = Effect(
        etype=etype, target=target, metadata={},
        provenance=_provenance("__req__"),
        capability_nonce=f"r-{etype}:Agent:EffectBroker",
        delegation_chain=(),
    )
    return broker.grant_approval(request, expiry=expiry, task_id=task.task_id)


class TestMailboxVsEmailIdentity:
    """Mailbox identity != Email address != Message identity.

    The three axes are resolved separately:
      - target (recipient address) resolves to Email record
      - Email address resolves to Mailbox (outbox delivery)
      - capability_nonce identifies the specific message (replay detection)
    """

    def test_same_nonce_to_same_target_is_replay(self) -> None:
        """Same nonce to same target: Fresh BLOCKs (replay)."""
        broker = build()
        task = _make_task("default")
        broker.register_task(task)
        nonce = _grant(broker, task, "send", "internal@corp.com")

        effect = Effect(
            etype="send", target="internal@corp.com", metadata={"body": "msg"},
            provenance=_provenance("m"), capability_nonce=nonce,
            delegation_chain=(),
        )

        allow1, _ = broker.commit(broker._make_commit(effect, task_id="default"))
        assert allow1 is True

        allow2, ev2 = broker.commit(broker._make_commit(effect, task_id="default"))
        assert allow2 is False
        assert ev2["primary_blocker"] == "Fresh"
        assert "replay" in ev2["predicates"]["Fresh"]
        assert len(broker.store.effects_log) == 1

    def test_different_nonces_to_same_target_both_allow(self) -> None:
        """Different nonces to same target: both ALLOW (no replay)."""
        broker = build()
        task = _make_task("default")
        broker.register_task(task)

        nonce1 = _grant(broker, task, "send", "internal@corp.com", expiry=200.0)
        nonce2 = _grant(broker, task, "send", "internal@corp.com", expiry=200.0)

        effect1 = Effect(
            etype="send", target="internal@corp.com", metadata={"body": "A"},
            provenance=_provenance("a"), capability_nonce=nonce1,
            delegation_chain=(),
        )
        effect2 = Effect(
            etype="send", target="internal@corp.com", metadata={"body": "B"},
            provenance=_provenance("b"), capability_nonce=nonce2,
            delegation_chain=(),
        )

        allow1, _ = broker.commit(broker._make_commit(effect1, task_id="default"))
        assert allow1 is True

        allow2, _ = broker.commit(broker._make_commit(effect2, task_id="default"))
        assert allow2 is True

        internal_mb = broker.store.mailboxes.get("internal")
        assert internal_mb is not None
        assert len(internal_mb.outbox) == 2


class TestSenderVsRecipientDistinct:
    """Sender provenance is tracked separately from recipient address."""

    def test_untrusted_sender_blocked_despite_trusted_recipient(self) -> None:
        """Untrusted content is BLOCKed by FlowOK even to internal recipient.

        The recipient (internal@corp.com) is trusted for delivery; but the
        sender's content integrity (UNTRUSTED) violates the flow_boundary.
        This proves sender-account provenance is tracked separately.
        """
        broker = build()
        task = _make_task("default")
        broker.register_task(task)
        nonce = _grant(broker, task, "send", "internal@corp.com")

        effect = Effect(
            etype="send", target="internal@corp.com", metadata={},
            provenance=(Data("web", Confidentiality.PUBLIC, Integrity.UNTRUSTED),),
            capability_nonce=nonce, delegation_chain=(),
        )
        allow, evidence = broker.commit(broker._make_commit(effect, task_id="default"))

        assert allow is False, "Untrusted provenance should be BLOCKed"
        assert evidence["primary_blocker"] == "FlowOK"
        assert "low-integrity" in evidence["predicates"]["FlowOK"]


class TestMailboxContainerBoundary:
    """Mailbox is the container/ownership boundary; distinct nonces → distinct
    messages, even when targeting the same mailbox."""

    def test_same_mailbox_receives_distinct_messages(self) -> None:
        """Two distinct effects (different nonces) to the same mailbox both
        succeed and are distinguishable."""
        broker = build()
        task = _make_task("default")
        broker.register_task(task)

        nonce1 = _grant(broker, task, "send", "internal@corp.com", expiry=200.0)
        nonce2 = _grant(broker, task, "send", "internal@corp.com", expiry=200.0)

        effect_a = Effect(
            etype="send", target="internal@corp.com", metadata={"body": "A"},
            provenance=_provenance("a"), capability_nonce=nonce1,
            delegation_chain=(),
        )
        effect_b = Effect(
            etype="send", target="internal@corp.com", metadata={"body": "B"},
            provenance=_provenance("b"), capability_nonce=nonce2,
            delegation_chain=(),
        )

        allow_a, _ = broker.commit(broker._make_commit(effect_a, task_id="default"))
        assert allow_a is True

        allow_b, _ = broker.commit(broker._make_commit(effect_b, task_id="default"))
        assert allow_b is True

        internal_mb = broker.store.mailboxes.get("internal")
        assert internal_mb is not None
        assert len(internal_mb.outbox) == 2

    def test_mailbox_resolves_from_address(self) -> None:
        """Send to an Email address creates/finds the mailbox via mailbox_for.

        The address resolves to mailbox via local-part (local@domain → mailbox=local).
        """
        broker = build()
        task = _make_task("default")
        broker.register_task(task)
        nonce = _grant(broker, task, "send", "internal@corp.com")

        effect = Effect(
            etype="send", target="internal@corp.com", metadata={},
            provenance=_provenance("test"),
            capability_nonce=nonce, delegation_chain=(),
        )
        broker.commit(broker._make_commit(effect, task_id="default"))

        # Address resolves to mailbox via local-part
        internal_mb = broker.store.mailboxes.get("internal")
        assert internal_mb is not None
        assert len(internal_mb.outbox) == 1
