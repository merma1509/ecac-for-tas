"""Regression: a wildcard mandate must cover extra targets (CC/BCC).

The bug this pins
-----------------
`EffectBroker._check_no_amplification()` treated `"*"` in `capability.scope` as
a literal string when validating `known_targets.additional`, but as a wildcard
for the primary target a few lines above. A capability with scope `{"*"}` could
therefore address a message but never copy or blind-copy anyone:

    extra-target-outside-scope(bcc@corp.com not under cap-scope={'*'})

The result was the worst of both readings — the mandate said "everything" and
the enforcement said "nothing extra". Worse, tests that expected a BCC to be
blocked passed against a wildcard scope for the wrong reason: they were
measuring this mangling, not confinement.

Truth table this file pins:
  scope contains "*"  → extras allowed, whatever their domain
  scope is a label set → extras must be inside it
"""

from __future__ import annotations

import pytest

from effect_broker.model import (
    Capability,
    Commit,
    Confidentiality,
    Effect,
    EffectTarget,
    Integrity,
    Task,
)
from effect_broker.traces import build


def _broker_with_scope(scope: frozenset[str]) -> tuple[object, Task]:
    broker = build()
    cap = Capability(
        owner="User",
        holder="tool",
        right="*",
        target="*",
        scope=scope,
        expiry=float("inf"),
        nonce="cap",
        task_id="t",
    )
    task = Task(
        task_id="t",
        owner="User",
        ceiling=cap,
        flow_boundary=(Confidentiality.CONFIDENTIAL, Integrity.USER),
    )
    broker.register_task(task)
    broker.capabilities["cap"] = cap
    return broker, task


def _send(primary: str, extra: frozenset[str]) -> Effect:
    return Effect(
        etype="send",
        target=f"mailto:{primary}",
        metadata={"body": "hello", "subject": "s"},
        provenance=(),
        capability_nonce="cap",
        delegation_chain=("tool",),
        task_id="t",
        known_targets=EffectTarget(primary=primary, additional=extra),
    )


class TestWildcardScopeCoversExtras:
    def test_bcc_allowed_under_wildcard_scope(self) -> None:
        """scope={"*"} means everything — an extra target cannot be outside it."""
        broker, task = _broker_with_scope(frozenset({"*"}))
        allow, evidence = broker.commit(
            Commit(_send("internal@corp.com", frozenset({"bcc@corp.com"})), task, "tool")
        )
        assert allow is True, (
            "a wildcard mandate refused an extra target: "
            f"{evidence.get('primary_blocker')}"
        )

    def test_cc_to_another_domain_allowed_under_wildcard(self) -> None:
        broker, task = _broker_with_scope(frozenset({"*"}))
        allow, evidence = broker.commit(
            Commit(_send("internal@corp.com", frozenset({"a@elsewhere.org"})), task, "tool")
        )
        assert allow is True, evidence.get("primary_blocker")

    def test_wildcard_does_not_excuse_flow_violations(self) -> None:
        """A wildcard mandate shifts no other check: taint still blocks a send."""
        broker, task = _broker_with_scope(frozenset({"*"}))
        task.session.taint_for_send(resource="file:///secret", reason="test")
        allow, evidence = broker.commit(
            Commit(_send("internal@corp.com", frozenset({"bcc@corp.com"})), task, "tool")
        )
        assert allow is False
        assert "FlowOK" in str(evidence.get("primary_blocker", ""))


class TestRestrictiveScopeStillBlocksExtras:
    """Fixing the wildcard must not weaken the non-wildcard check."""

    def test_extra_in_scope_domain_allowed(self) -> None:
        broker, task = _broker_with_scope(frozenset({"internal"}))
        allow, evidence = broker.commit(
            Commit(_send("a@internal.corp.com", frozenset({"b@internal.corp.com"})), task, "tool")
        )
        assert allow is True, evidence.get("primary_blocker")

    @pytest.mark.parametrize("extra", ["bcc@external.com", "cc@evil.org"])
    def test_extra_outside_scope_domain_blocked(self, extra: str) -> None:
        broker, task = _broker_with_scope(frozenset({"internal"}))
        allow, evidence = broker.commit(
            Commit(_send("a@internal.corp.com", frozenset({extra})), task, "tool")
        )
        assert allow is False, f"{extra} outside scope 'internal' was allowed"
        assert "NoAmp" in str(evidence.get("primary_blocker", "")), (
            f"expected a NoAmp block, got {evidence.get('primary_blocker')}"
        )

    def test_extra_outside_file_scope_blocked(self) -> None:
        """Non-email extras (temp dirs) must still be scope-checked."""
        broker, task = _broker_with_scope(frozenset({"file:///work"}))
        effect = Effect(
            etype="write",
            target="file:///work/out.txt",
            metadata={},
            provenance=(),
            capability_nonce="cap",
            delegation_chain=("tool",),
            task_id="t",
            known_targets=EffectTarget(
                primary="file:///work/out.txt",
                additional=frozenset({"file:///etc/shadow"}),
            ),
        )
        allow, evidence = broker.commit(Commit(effect, task, "tool"))
        assert allow is False
        assert "NoAmp" in str(evidence.get("primary_blocker", ""))
