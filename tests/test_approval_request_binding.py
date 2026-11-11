"""the gate must reject a mutated request, not just a mutated hash.

These criteria are about *authorization*, so the tests go through
`broker.commit()`. Testing `CanonicalRequest.request_hash()` alone proved only
that two digests differ; it did not prove the gate consulted them. It did not:
`request_hash` was carried on `ApprovedRequest` but never populated and never
checked, so an approval for sender A authorized sender B, and a swapped
attachment blob slipped through. These tests pin the gate.
"""

from __future__ import annotations

from effect_broker.broker import EffectBroker
from effect_broker.model import (
    Capability,
    Confidentiality,
    Data,
    Effect,
    Integrity,
    Task,
)

_ATTACH_A = {"name": "report.pdf", "bytes": b"ORIGINAL-ATTACHMENT"}
_ATTACH_B = {"name": "report.pdf", "bytes": b"SWAPPED-ATTACHMENT"}


def _provenance(name: str) -> tuple[Data, ...]:
    return (Data(name, Confidentiality.INTERNAL, Integrity.USER, content=b"x"),)


def _broker() -> EffectBroker:
    broker = EffectBroker()
    ceiling = Capability(
        owner="User",
        holder="EffectBroker",
        right="*",
        target="*",
        scope=frozenset({"*"}),
        expiry=float("inf"),
        nonce="ceiling",
    )
    broker.register_task(Task(task_id="default", owner="User", ceiling=ceiling))
    return broker


def _send(**metadata: object) -> Effect:
    return Effect(
        etype="send",
        target="alice@corp.com",
        metadata=dict(metadata),
        provenance=_provenance("req"),
        capability_nonce="r-send:Agent:EffectBroker",
        delegation_chain=("Approver", "broker-shim"),
    )


def _commit_with(
    broker: EffectBroker, nonce: str, effect: Effect
) -> tuple[bool, dict[str, object]]:
    presented = Effect(
        etype=effect.etype,
        target=effect.target,
        metadata=effect.metadata,
        provenance=_provenance("presented"),
        capability_nonce=nonce,
        delegation_chain=("Approver", "broker-shim"),
    )
    return broker.commit(broker._make_commit(presented, task_id="default"))


class TestSenderBinding:
    """P5-9: an approval granted for one sender must not authorize another."""

    def test_swapped_sender_is_denied(self) -> None:
        broker = _broker()
        nonce = broker.grant_approval(
            _send(subject="Q3", body="budget 50k", sender="alice@corp.com"),
            expiry=1e9,
            task_id="default",
        )
        allow, evidence = _commit_with(
            broker, nonce, _send(subject="Q3", body="budget 50k", sender="evil@attacker.com")
        )
        assert allow is False, "approval for alice must not send as evil"
        assert evidence["primary_blocker"] == "ApprovalBinding"

    def test_identical_sender_is_allowed(self) -> None:
        """The binding must not reject the request it was granted for."""
        broker = _broker()
        original = _send(subject="Q3", body="budget 50k", sender="alice@corp.com")
        nonce = broker.grant_approval(original, expiry=1e9, task_id="default")
        allow, evidence = _commit_with(broker, nonce, original)
        assert allow is True, f"legitimate request denied: {evidence.get('approval_binding')}"

    def test_swapped_acting_account_is_denied(self) -> None:
        broker = _broker()
        nonce = broker.grant_approval(
            _send(subject="Q3", body="b", acting_account="alice@corp.com"),
            expiry=1e9,
            task_id="default",
        )
        allow, _ = _commit_with(
            broker, nonce, _send(subject="Q3", body="b", acting_account="bob@corp.com")
        )
        assert allow is False, "approval for alice's mailbox must not act for bob"


class TestAttachmentBinding:
    """a changed attachment blob must break the approval."""

    def test_swapped_attachment_blob_is_denied(self) -> None:
        broker = _broker()
        nonce = broker.grant_approval(
            _send(
                subject="Q3",
                body="see attached",
                sender="a@corp.com",
                attachments=[_ATTACH_A],
            ),
            expiry=1e9,
            task_id="default",
        )
        allow, evidence = _commit_with(
            broker,
            nonce,
            _send(
                subject="Q3",
                body="see attached",
                sender="a@corp.com",
                attachments=[_ATTACH_B],
            ),
        )
        assert allow is False, "identical subject/body must not hide a swapped blob"
        assert evidence["primary_blocker"] == "ApprovalBinding"

    def test_content_hash_alone_would_not_catch_it(self) -> None:
        """Documents why request_hash is needed: content_hash ignores attachments."""
        a = _send(subject="Q3", body="see attached", attachments=[_ATTACH_A])
        b = _send(subject="Q3", body="see attached", attachments=[_ATTACH_B])
        assert a.compute_content_hash() == b.compute_content_hash(), (
            "if this ever differs, the attachment test above stops being evidence "
            "that request_hash is load-bearing"
        )
