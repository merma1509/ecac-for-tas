"""The email approval must bind the body that actually goes on the wire.

Recorded that `shim_email.send()` put `subject` and `body_size` on
the effect but never `body`, and that `_smtp_send` transmits a `raw_msg` built
separately. The consequence was not a missing nicety but a live defect: with no
body on the effect, `compute_content_hash()` returned `sha256("")` for every
send, so the `content-hash-mismatch` branch in `broker.gate()` was unreachable
for email. An approval a human granted for "quarterly numbers are fine"
authorized a wire transfer, because both bodies hashed to the hash of nothing.

`tests/test_approval_request_binding.py` passed throughout, because it built its
effects by hand — with `body` already in the metadata — rather than taking the
effect the shim emits. These tests go through the live shim, which is the only
way to see the gap.

Three things are pinned here:

1. The effect the shim emits carries the body, so the hash is not `sha256("")`.
2. An approval for body A is denied for body B at the gate.
3. The effect survives the IPC boundary (multi-process mode).

The third is a separate fault found alongside the first: the shim's metadata
held a `frozenset`, which `json.dumps` cannot encode, so every email commit in
multi-process mode raised `TypeError` inside payload signing — after the gate
had already authorized.
"""

from __future__ import annotations

import json
from dataclasses import replace
from typing import Any

import pytest

from effect_broker.broker import EffectBroker
from effect_broker.executor_ipc import effect_to_dict
from effect_broker.lattice import Confidentiality, Integrity
from effect_broker.model import Capability, Commit, Domain, Effect, Task
from effect_broker.shim_email import (
    EmailSecurityError,
    PostAuthorizationFailure,
    RealEmailShim,
)

APPROVED_BODY = "Quarterly numbers are fine."
# Deliberately the same byte length as APPROVED_BODY: `body_size` cannot tell
# them apart, so any check resting on size alone would pass this pair.
ATTACK_BODY = "Wire EUR 40000 to DE893704."

_EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def _ceiling(right: str = "*") -> Capability:
    return Capability(
        owner="User",
        holder="EffectBroker",
        right=right,
        target="*",
        scope=frozenset({"*"}),
        expiry=float("inf"),
        nonce="ceiling",
    )


def _broker(mode: str = "same-process") -> EffectBroker:
    broker = EffectBroker(mode=mode)
    broker.store._unsafe_bootstrap_email("mailto:internal@corp.com", Domain.INTERNAL)
    broker.register_task(
        Task(
            task_id="default",
            owner="User",
            ceiling=_ceiling(),
            # Allow the USER-integrity provenance the shim derives for a body.
            flow_boundary=(Confidentiality.CONFIDENTIAL, Integrity.USER),
        )
    )
    broker.capabilities["send-cap"] = Capability(
        owner="User",
        holder="tool-corp",
        right="send",
        target="*",
        scope=frozenset({"*"}),
        expiry=float("inf"),
        nonce="send-cap",
    )
    return broker


def _shim(broker: EffectBroker) -> tuple[RealEmailShim, list[str]]:
    """A shim with the MTA faked out; everything else is real.

    Only the two SMTP calls are stubbed: the probe (so no server is needed) and
    the DATA delivery (so the test can inspect the bytes that would go out). The
    gate, the executor and the approval binding all run for real.
    """
    shim = RealEmailShim(
        broker=broker,
        task_id="default",
        tool_name="tool-corp",
        smtp_host="127.0.0.1",
        smtp_port=1,
    )
    wire: list[str] = []

    def clean_probe(sender: str, declared: frozenset[str]) -> Any:
        return declared, declared, frozenset()

    def capture_send(
        sender: str, recipients: frozenset[str], raw_message: bytes
    ) -> tuple[list[str], str]:
        wire.append(raw_message.decode("utf-8", errors="replace"))
        return sorted(recipients), "data=250 OK"

    shim._smtp_probe = clean_probe  # type: ignore[method-assign]
    shim._smtp_send = capture_send  # type: ignore[method-assign]
    return shim, wire


def _capture_effect(broker: EffectBroker, body: str) -> Effect:
    """Run the shim's own effect construction and keep what it produced.

    The effect is deliberately not hand-built: if the shim stops putting the
    body on it, these tests must fail.
    """
    shim, _ = _shim(broker)
    captured: dict[str, Effect] = {}
    real_execute = broker.executor.execute

    def spy(commit: Commit, mediation: Any = None) -> Any:
        captured["effect"] = commit.effect
        return real_execute(commit, mediation)

    broker.executor.execute = spy  # type: ignore[method-assign]
    try:
        shim.send(sender="alice@corp.com", recipient="internal@corp.com", body=body)
    except EmailSecurityError:
        # An effect is captured whether or not the gate allows it; the decision
        # is not what this helper measures.
        pass
    finally:
        broker.executor.execute = real_execute  # type: ignore[method-assign]

    assert "effect" in captured, "the shim never reached the executor"
    return captured["effect"]


def _approve_only_body(broker: EffectBroker, body: str) -> str:
    """Grant the approval, then leave it as the only send capability.

    This is the shape of a real approval flow: the human's one-shot approval is
    the sole authority the tool holds, so any send it performs spends it.
    """
    nonce = broker.grant_approval(_capture_effect(broker, body), expiry=1e9, task_id="default")
    broker.capabilities.pop("send-cap", None)
    return nonce


class TestBodyIsBound:
    """B4: the body must be on the effect, and the hash must not be sha256("")."""

    def test_shim_effect_carries_the_body(self) -> None:
        effect = _capture_effect(_broker(), APPROVED_BODY)
        assert effect.metadata.get("body") == APPROVED_BODY

    def test_content_hash_is_not_the_hash_of_nothing(self) -> None:
        """The exact failure: an absent body makes every send hash identically."""
        effect = _capture_effect(_broker(), APPROVED_BODY)
        assert effect.compute_content_hash() != _EMPTY_SHA256, (
            "no body on the effect — one approval would authorize any payload"
        )

    def test_different_bodies_produce_different_hashes(self) -> None:
        broker = _broker()
        a = _capture_effect(broker, APPROVED_BODY).compute_content_hash()
        b = _capture_effect(broker, ATTACK_BODY).compute_content_hash()
        assert a != b

    def test_equal_length_bodies_still_differ(self) -> None:
        """`body_size` alone cannot tell these apart; the content hash can."""
        broker = _broker()
        assert len(APPROVED_BODY) == len(ATTACK_BODY)
        a = _capture_effect(broker, APPROVED_BODY).compute_content_hash()
        b = _capture_effect(broker, ATTACK_BODY).compute_content_hash()
        assert a != b

    def test_identity_fields_are_bound(self) -> None:
        """An approval must know whose credentials carry the message (P5-9)."""
        effect = _capture_effect(_broker(), APPROVED_BODY)
        assert effect.metadata.get("sender") == "alice@corp.com"
        assert effect.metadata.get("acting_account") == "alice@corp.com"


class TestGateRejectsSwappedBody:
    """An approval granted for one body must not authorize another."""

    def _commit(self, broker: EffectBroker, nonce: str, body: str) -> tuple[bool, dict[str, Any]]:
        presented = replace(_capture_effect(broker, body), capability_nonce=nonce)
        return broker.commit(Commit(presented, broker.tasks["default"]))

    def test_same_body_is_allowed(self) -> None:
        """The binding must not reject the request it was granted for."""
        broker = _broker()
        nonce = broker.grant_approval(
            _capture_effect(broker, APPROVED_BODY), expiry=1e9, task_id="default"
        )
        allow, evidence = self._commit(broker, nonce, APPROVED_BODY)
        assert allow is True, f"legitimate send denied: {evidence.get('approval_binding')}"

    def test_swapped_body_is_denied(self) -> None:
        broker = _broker()
        nonce = broker.grant_approval(
            _capture_effect(broker, APPROVED_BODY), expiry=1e9, task_id="default"
        )
        allow, evidence = self._commit(broker, nonce, ATTACK_BODY)
        assert allow is False, "an approval for one body authorized another"
        assert evidence["primary_blocker"] == "ApprovalBinding"
        assert "content-hash-mismatch" in str(evidence["approval_binding"])

    def test_empty_body_is_denied(self) -> None:
        """Sending nothing is still a substitution."""
        broker = _broker()
        nonce = broker.grant_approval(
            _capture_effect(broker, APPROVED_BODY), expiry=1e9, task_id="default"
        )
        allow, _ = self._commit(broker, nonce, "")
        assert allow is False

    def test_swapped_sender_is_denied(self) -> None:
        """Same body, different envelope sender — not the same operation."""
        broker = _broker()
        approved = _capture_effect(broker, APPROVED_BODY)
        nonce = broker.grant_approval(approved, expiry=1e9, task_id="default")

        # Rebuild the shim's effect under another identity by hand: the shim
        # derives `sender` from the tool's call, so this is the tool lying.
        forged = replace(
            approved,
            metadata={**approved.metadata, "sender": "ceo@corp.com"},
            capability_nonce=nonce,
        )
        allow, _ = broker.commit(Commit(forged, broker.tasks["default"]))
        assert allow is False, "an approval for alice must not send as the CEO"


class TestEndToEndThroughTheShim:
    """The scenario that matters: the human approves, then the tool sends."""

    def test_tool_cannot_spend_the_approval_on_another_body(self) -> None:
        broker = _broker()
        _approve_only_body(broker, APPROVED_BODY)

        shim, wire = _shim(broker)
        with pytest.raises(EmailSecurityError) as exc_info:
            shim.send(sender="alice@corp.com", recipient="internal@corp.com", body=ATTACK_BODY)

        assert "ApprovalBinding" in str(exc_info.value)
        assert wire == [], "the substituted body reached the transport"

    def test_approved_body_is_delivered_verbatim(self) -> None:
        broker = _broker()
        _approve_only_body(broker, APPROVED_BODY)

        shim, wire = _shim(broker)
        shim.send(sender="alice@corp.com", recipient="internal@corp.com", body=APPROVED_BODY)

        assert len(wire) == 1, "the approved send did not reach the transport"
        assert APPROVED_BODY in wire[0]


class TestEffectCrossesTheIpcBoundary:
    """The shim's payload is signed with json.dumps, so it must be encodable."""

    def test_effect_to_dict_is_json_serializable(self) -> None:
        effect = _capture_effect(_broker(), APPROVED_BODY)
        json.dumps({"effect": effect_to_dict(effect)})  # must not raise

    def test_metadata_holds_no_bare_frozenset(self) -> None:
        """A frozenset here aborted every multi-process commit with a TypeError."""
        effect = _capture_effect(_broker(), APPROVED_BODY)
        for key, value in effect.metadata.items():
            assert not isinstance(value, frozenset | set), (
                f"metadata[{key!r}] is {type(value).__name__}, which json.dumps "
                f"cannot encode — the commit would fail after authorization"
            )

    def test_multi_process_send_reaches_the_transport(self) -> None:
        """Regression: this raised `TypeError: frozenset is not JSON serializable`.

        The failure surfaced as a crash rather than a denial, and only after the
        gate had allowed the effect. Now the commit crosses the boundary and
        fails where a fault belongs: at the transport, as a post-authorization
        fault whose outcome is UNKNOWN.
        """
        broker = _broker(mode="multi-process")
        shim = broker.create_real_email_shim(
            task_id="default", tool_name="tool-corp", smtp_host="127.0.0.1", smtp_port=1
        )
        shim._smtp_probe = lambda sender, declared: (  # type: ignore[method-assign]
            declared,
            declared,
            frozenset(),
        )

        # Port 1 refuses the connection: the send must get past signing and past
        # the gate, then fail at the transport.
        try:
            with pytest.raises(PostAuthorizationFailure):
                shim.send(sender="alice@corp.com", recipient="internal@corp.com", body="hi")
        except TypeError as ex:  # pragma: no cover - the regression itself
            pytest.fail(f"commit did not survive IPC serialization: {ex}")
