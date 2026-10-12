"""Attack + legitimate pair tests for each named ECAC mechanism.

Each test here builds a paired scenario:
  - LEGITIMATE: an in-bounds operation the mechanism should ALLOW.
  - ATTACK: a concrete out-of-bounds operation the mechanism should BLOCK,
    and asserts the BLOCKING PREDICATE is the named one (not a coincidental
    fail of a different predicate).

These demonstrate the mechanism ENFORCES its named boundary on supplied
scenarios (regression coverage). They do NOT demonstrate effectiveness
against adaptive/live attackers

Mechanism -> predicate mapping (per broker.py):
  - Cordon  -> Auth task-bounded check (effect target must be within the
               task ceiling scope — the "cordoned" resource set)
  - NoAmp   -> NoAmp extra-target scope check (BCC/CC within cap scope)
  - FlowOK  -> FlowOK session taint (read CONFIDENTIAL -> send needs declass)
  - Fresh   -> Fresh replay check (one capability nonce = one execution)
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


def _task(ceiling_scope: frozenset[str]) -> Task:
    ceiling = Capability(
        owner="User",
        holder="EffectBroker",
        right="*",
        target="*",
        scope=ceiling_scope,
        expiry=float("inf"),
        nonce="ceiling-attack",
    )
    return Task(task_id="attack-pair", owner="User", ceiling=ceiling)


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
    additional: frozenset[str] | None = None,
    label_exceptions: tuple[LabelException, ...] = (),
) -> Effect:
    known = EffectTarget(primary=target, additional=additional) if additional else None
    return Effect(
        etype="send",
        target=target,
        metadata={},
        provenance=(Data("msg", Confidentiality.INTERNAL, Integrity.USER),),
        capability_nonce=nonce,
        delegation_chain=(),
        label_exceptions=label_exceptions,
        known_targets=known,
    )


class TestCordonAttackPair:
    """Cordon: ceiling scoping confines operations to the task's resource set.

    Mechanism under test: Auth task-bounded check — the effect target must be
    within the task ceiling scope (the cordoned resource set). The capability
    is valid (root-anchored, right/target match), so Auth's scope bound is
    the ONLY thing that can block the out-of-scope read.
    """

    def test_ceiling_scoping_legit_allowed_attack_blocked(self) -> None:
        broker = build()
        # Ceiling cords the task to file:///reports (bootstrapped INTERNAL dir).
        task = _task(frozenset({"file:///reports"}))
        broker.register_task(task)

        # Cap grants read over the whole reports tree; ceiling scopes it in.
        cap = _cap("User", "read", "*", frozenset({"file:///reports"}), "cap-cordon")
        broker.capabilities["cap-cordon"] = cap

        # LEGITIMATE: read a file INSIDE the cordoned scope.
        legit = _read("file:///reports/summary.txt", "cap-cordon")
        allow, _ = broker.commit(Commit(legit, task))
        assert allow is True, "In-scope read should be allowed (Cordon permits its own scope)"

        # ATTACK: read a file OUTSIDE the cordoned scope (scope bypass).
        attack = _read("file:///secrets/credentials.json", "cap-cordon")
        allow, evidence = broker.commit(Commit(attack, task))
        assert allow is False, "Out-of-ceiling read must be blocked (Cordon scope confinement)"
        # The blocking predicate MUST be Auth's task-bounded check.
        assert evidence["primary_blocker"] == "Auth", (
            f"Cordon scope bypass must be caught by Auth task-bounding, "
            f"got {evidence['primary_blocker']}"
        )
        assert "task-bounded-fail" in evidence["predicates"]["Auth"]


class TestNoAmpExtraTargetPair:
    """NoAmp: extra targets (BCC/CC) must be within the capability scope.

    Mechanism under test: NoAmp extra-target-outside-scope. A send to an
    approved internal primary is allowed; the SAME send with an external
    BCC (outside cap scope) must be blocked by NoAmp.
    """

    def test_bcc_outside_cap_scope_blocked(self) -> None:
        broker = build()
        task = _task(frozenset({"*"}))  # wildcard ceiling so NoAmp is the sole gate
        broker.register_task(task)

        # Cap scoped to the internal domain only.
        cap = _cap("User", "send", "internal@corp.com", frozenset({"internal"}), "cap-noamp-bcc")
        broker.capabilities["cap-noamp-bcc"] = cap

        # LEGITIMATE: send to the approved internal primary, no hidden recipient.
        legit = _send("internal@corp.com", "cap-noamp-bcc")
        allow, _ = broker.commit(Commit(legit, task))
        assert allow is True, "Send to approved internal primary (no extra) should be allowed"

        # ATTACK: same send but with an external BCC outside cap scope.
        attack = _send(
            "internal@corp.com", "cap-noamp-bcc", additional=frozenset({"victim@evil.com"})
        )
        allow, evidence = broker.commit(Commit(attack, task))
        assert allow is False, "Send with out-of-scope external BCC must be blocked"
        assert evidence["primary_blocker"] == "NoAmp", (
            f"Extra-target scope bypass must be caught by NoAmp, got {evidence['primary_blocker']}"
        )
        assert "extra-target-outside-scope" in evidence["predicates"]["NoAmp"]


class TestFlowOKTaintPair:
    """FlowOK: session taint blocks send after a CONFIDENTIAL read (no declass).

    Mechanism under test: FlowOK session-taint. An untainted session can send;
    a session that read CONFIDENTIAL data is tainted and its send is blocked
    UNLESS a broker-recorded declass exists.
    """

    def test_taint_blocks_send_without_declass(self) -> None:
        broker = build()
        task = _task(frozenset({"*"}))
        broker.register_task(task)
        cap = _cap("User", "*", "*", frozenset({"*"}), "cap-flow-taint")
        broker.capabilities["cap-flow-taint"] = cap

        # Legitimate baseline: an untainted session sends fine.
        fresh_task = _task(frozenset({"*"}))
        fresh_task.task_id = "untainted-pair"  # distinct task so nonces don't replay
        broker.register_task(fresh_task)
        base_send = _send("internal@corp.com", "cap-flow-taint")
        allow_base, _ = broker.commit(Commit(base_send, fresh_task))
        assert allow_base is True, "Untainted session send should be allowed"

        # ATTACK setup: read the CONFIDENTIAL resource (bootstrapped by build()).
        # Resolving the directory target marks the session tainted.
        conf_read = _read("file:///secrets", "cap-flow-taint")
        allow_read, _ = broker.commit(Commit(conf_read, task))
        assert allow_read is True, "Read (input) should be allowed; it taints the session"
        assert task.session.tainted, "Session must be tainted after reading CONFIDENTIAL"

        # ATTACK: exfiltrate via send in the now-tainted session (no declass).
        exfil = _send("internal@corp.com", "cap-flow-taint")
        allow, evidence = broker.commit(Commit(exfil, task))
        assert allow is False, "Send after CONFIDENTIAL read (no declass) must be blocked"
        assert evidence["primary_blocker"] == "FlowOK", (
            "Confidential-exfil via send must be caught by FlowOK, got "
            f"{evidence['primary_blocker']}"
        )
        assert "session-taint" in evidence["predicates"]["FlowOK"]


class TestFlowOKDeclassUnblocksPair:
    """FlowOK: a broker-recorded declass is required to clear the taint."""

    def test_declass_allows_tainted_send(self) -> None:
        broker = build()
        task = _task(frozenset({"*"}))
        broker.register_task(task)
        cap = _cap("User", "*", "*", frozenset({"*"}), "cap-flow-declass")
        broker.capabilities["cap-flow-declass"] = cap

        # Distinct nonces for read vs send (a capability nonce is single-use).
        send_cap = _cap("User", "send", "*", frozenset({"*"}), "cap-flow-declass-send")
        broker.capabilities["cap-flow-declass-send"] = send_cap

        # Taint the session via a CONFIDENTIAL read (bootstrapped resource).
        conf_read = _read("file:///secrets", "cap-flow-declass")
        allow_read, _ = broker.commit(Commit(conf_read, task))
        assert allow_read is True
        assert task.session.tainted

        # Without declass the send is blocked.
        blocked = _send("internal@corp.com", "cap-flow-declass-send")
        allow_blocked, _ = broker.commit(Commit(blocked, task))
        assert allow_blocked is False, "Tainted send without declass must be blocked"

        # Record a broker declass (clears taint for sends to internal domain).
        declass = LabelException(
            kind="declass",
            match_target="internal@corp.com",  # matches send target exactly
            from_label=Confidentiality.CONFIDENTIAL.name,
            to_label=Confidentiality.INTERNAL.name,
            granted_by="User",
            nonce="declass-taint-pair",
        )
        broker.grant_label_exception(declass)

        # With declass the same send is now allowed.
        effect = _send("internal@corp.com", "cap-flow-declass-send", label_exceptions=(declass,))
        allow, _ = broker.commit(Commit(effect, task))
        assert allow is True, "Tainted send WITH broker-recorded declass should be allowed"


class TestFreshReplayPair:
    """Fresh: one capability nonce = one execution (replay blocked).

    Mechanism under test: Fresh replay detection. The first commit consumes
    the nonce; a second commit with the same nonce is a replay and must be
    blocked by Fresh (not Auth/FlowOK/NoAmp).
    """

    def test_nonce_replay_blocked(self) -> None:
        broker = build()
        task = _task(frozenset({"*"}))
        broker.register_task(task)
        cap = _cap(
            "User",
            "read",
            "file:///reports/summary.txt",
            frozenset({"file:///reports"}),
            "cap-fresh",
        )
        broker.capabilities["cap-fresh"] = cap

        # LEGITIMATE: first use of the nonce.
        legit = _read("file:///reports/summary.txt", "cap-fresh")
        allow, _ = broker.commit(Commit(legit, task))
        assert allow is True, "First use of a fresh nonce should be allowed"

        # ATTACK: replay the SAME nonce (same capability, same target).
        replay = _read("file:///reports/summary.txt", "cap-fresh")
        allow, evidence = broker.commit(Commit(replay, task))
        assert allow is False, "Replaying a consumed nonce must be blocked"
        assert evidence["primary_blocker"] == "Fresh", (
            f"Nonce replay must be caught by Fresh, got {evidence['primary_blocker']}"
        )
        assert "replay" in evidence["predicates"]["Fresh"]
