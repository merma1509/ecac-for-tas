"""Declass must not bypass integrity (Biba) checks.

FlowOK's session-taint branch returns early on a validated
declass, so the per-datum integrity (Biba) check below it is NEVER reached for a
tainted session. A declassification grant is confidentiality-only, but it is
effectively being used as an endorsement (integrity upgrade): a send whose body
is steered by a LOW-INTEGRITY (UNTRUSTED) source passes FlowOK as soon as the
session is tainted and a declass exists.

Repro status:
  * test_..._before_declass_blocks_tainted_send : control, green now AND after.
  * test_..._before_low_integrity_steered : documents the hole — the
    UNTRUSTED-steered send is ALLOWED today because the declass early-return
    skips the Biba check. After the fix, the flipped assertions (allow False,
    low-integrity) go green.
  * test_..._legit_declass_send : the legitimate case that must stay green.
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

# Helpers (mirror tests/test_mechanism_attacks.py so the setup is identical)
def _task(ceiling_scope: frozenset[str]) -> Task:
    ceiling = Capability(
        owner="User",
        holder="EffectBroker",
        right="*",
        target="*",
        scope=ceiling_scope,
        expiry=float("inf"),
        nonce="ceiling-plan1",
    )
    return Task(task_id="plan1", owner="User", ceiling=ceiling)


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
    )


def _taint(broker, task, read_nonce: str) -> None:
    """Read the bootstrapped CONFIDENTIAL resource to taint the session."""
    allow, _ = broker.commit(Commit(_read("file:///secrets", read_nonce), task))
    assert allow is True, "Reading a CONFIDENTIAL file (input) should be allowed"
    assert task.session.tainted, "Session must be tainted after reading CONFIDENTIAL"


class TestPlan1DeclassIntegrity:
    """Declass (confidentiality-only) must not be used to bypass Biba (integrity)."""

    def test_control_declass_blocks_tainted_send(self) -> None:
        """CONTROL: a tainted send with NO declass is blocked by session-taint.

        Establishes the baseline so the hole is isolated to the declass
        early-return, not to session taint in general. Green before AND after.
        """
        broker = build()
        task = _task(frozenset({"*"}))
        broker.register_task(task)
        broker.capabilities["cap-p1-read"] = _cap("User", "*", "*", frozenset({"*"}), "cap-p1-read")
        broker.capabilities["cap-p1-send"] = _cap("User", "send", "*", frozenset({"*"}), "cap-p1-send")

        _taint(broker, task, "cap-p1-read")

        # No declass -> blocked by session-taint (the conservative guard).
        clean = _send(
            "internal@corp.com",
            "cap-p1-send",
            provenance=(Data("msg", Confidentiality.INTERNAL, Integrity.USER),),
        )
        allow, evidence = broker.commit(Commit(clean, task))
        assert allow is False, "Tainted send without declass must be blocked"
        assert "session-taint" in evidence["predicates"]["FlowOK"]

    def test_attack_declass_does_not_clear_integrity(self) -> None:
        """HOLE (BEFORE): a declass on a tainted session skips the Biba check.

        The send body is steered by a LOW-INTEGRITY (UNTRUSTED) datum. The
        confidentiality gate is satisfied by the declass, and because the
        session-taint branch returns early, the per-datum low-integrity check is
        never reached. So the effect commits today.

        AFTER the fix, the early return falls through to the per-datum loop, the
        UNTRUSTED datum is still flagged, and the send is BLOCKED with
        FlowOK reporting `low-integrity`.
        """
        broker = build()
        task = _task(frozenset({"*"}))
        broker.register_task(task)
        broker.capabilities["cap-p1a-read"] = _cap("User", "*", "*", frozenset({"*"}), "cap-p1a-read")
        broker.capabilities["cap-p1a-send"] = _cap("User", "send", "*", frozenset({"*"}), "cap-p1a-send")

        _taint(broker, task, "cap-p1a-read")

        # A broker-recorded declass for the tainted send (confidentiality-only).
        declass = LabelException(
            kind="declass",
            match_target="internal@corp.com",
            from_label=Confidentiality.CONFIDENTIAL.name,
            to_label=Confidentiality.INTERNAL.name,
            granted_by="User",
            nonce="declass-p1a",
            data_resources=frozenset({"file:///secrets"}),
        )
        broker.grant_label_exception(declass)

        # ATTACK: body steered by UNTRUSTED (low-integrity) data.
        steered = _send(
            "internal@corp.com",
            "cap-p1a-send",
            provenance=(Data("attacker-note", Confidentiality.PUBLIC, Integrity.UNTRUSTED),),
            label_exceptions=(declass,),
        )
        allow, evidence = broker.commit(Commit(steered, task))

        # the declass clears only the taint CONFIDENTIALITY gate; the
        # per-datum INTEGRITY (Biba) check still runs. The UNTRUSTED-steered send
        # is BLOCKED with FlowOK reporting low-integrity — declass is NOT endorse.
        assert allow is False, (
            "A declass must not bypass the integrity (Biba) check; the "
            f"UNTRUSTED-steered send must be blocked. Evidence: {evidence}"
        )
        assert evidence["primary_blocker"] == "FlowOK", (
            f"Integrity block must be attributed to FlowOK, got {evidence['primary_blocker']!r}"
        )
        assert "low-integrity" in evidence["predicates"]["FlowOK"]
        assert "attacker-note" in evidence["predicates"]["FlowOK"]

    def test_legit_declass_clean_send_still_allowed(self) -> None:
        """LEGITIMATE: tainted read -> declass -> send with a CLEAN (USER) provenance
        must remain ALLOWED both before and after the fix.
        """
        broker = build()
        task = _task(frozenset({"*"}))
        broker.register_task(task)
        broker.capabilities["cap-p1l-read"] = _cap("User", "*", "*", frozenset({"*"}), "cap-p1l-read")
        broker.capabilities["cap-p1l-send"] = _cap("User", "send", "*", frozenset({"*"}), "cap-p1l-send")

        _taint(broker, task, "cap-p1l-read")

        declass = LabelException(
            kind="declass",
            match_target="internal@corp.com",
            from_label=Confidentiality.CONFIDENTIAL.name,
            to_label=Confidentiality.INTERNAL.name,
            granted_by="User",
            nonce="declass-p1l",
            data_resources=frozenset({"file:///secrets"}),
        )
        broker.grant_label_exception(declass)

        # Clean body: USER integrity (>= the default sink_integrity), so Biba passes.
        clean = _send(
            "internal@corp.com",
            "cap-p1l-send",
            provenance=(Data("msg", Confidentiality.INTERNAL, Integrity.USER),),
            label_exceptions=(declass,),
        )
        allow, evidence = broker.commit(Commit(clean, task))
        assert allow is True, (
            f"Legit tainted send with declass and clean (USER) provenance must stay allowed. "
            f"Blocker={evidence.get('primary_blocker')!r}, "
            f"FlowOK={evidence['predicates'].get('FlowOK')!r}"
        )
