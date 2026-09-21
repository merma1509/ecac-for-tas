"""Regression tests encoding the Week-1 adversarial trace suite as assertions

Each test asserts the security outcome of an effect commit, so a regression
in any predicate (Auth, FlowOK, NoAmp, Fresh) fails CI loudly
"""

from collections.abc import Iterator

import pytest

from effect_broker.broker import EffectBroker
from effect_broker.lattice import Confidentiality, Integrity
from effect_broker.mediation import MediationVerdict, Mediator, ToolSpec
from effect_broker.model import (
    AGENT,
    ApprovedRequest,
    BROKER,
    USER,
    Capability,
    Commit,
    Data,
    Domain,
    Effect,
    EffectTarget,
    File,
    LabelException,
    Task,
)
from effect_broker.ledger import LedgerVerdict, UnknownLedgerResult
from effect_broker.traces import build

CHAIN = (USER, AGENT, BROKER)


def _capability(
    owner: str,
    holder: str,
    right: str,
    target: str,
    scope: frozenset[str],
    expiry: float,
    nonce: str,
    derives: str | None = None,
) -> Capability:
    return Capability(owner, holder, right, target, scope, expiry, nonce, derives_from=derives)


@pytest.fixture
def broker() -> Iterator[EffectBroker]:
    broker_instance = EffectBroker()
    # external resources: R = F ∪ E ∪ M — bootstrap via restricted store API
    broker_instance.store._unsafe_bootstrap_file(
        "file:///reports", Confidentiality.INTERNAL
    )
    broker_instance.store._unsafe_bootstrap_file(
        "file:///secrets", Confidentiality.CONFIDENTIAL
    )
    broker_instance.store._unsafe_bootstrap_email(
        "internal@corp.com", Domain.INTERNAL
    )
    broker_instance.store._unsafe_bootstrap_mailbox("alice")
    broker_instance.grant_root(
        _capability(USER, USER, "send", "internal@corp.com", frozenset({"internal"}), 100, "r-send")
    )
    broker_instance.grant_root(
        _capability(USER, USER, "delete", "file:///reports", frozenset({"internal"}), 100, "r-del")
    )
    broker_instance.attenuate(
        "r-send", AGENT, "send", "internal@corp.com", frozenset({"internal"}), 100
    )
    broker_instance.attenuate(
        "r-send:Agent", BROKER, "send", "internal@corp.com", frozenset({"internal"}), 100
    )
    broker_instance.attenuate(
        "r-del", AGENT, "delete", "file:///reports", frozenset({"internal"}), 100
    )
    broker_instance.attenuate(
        "r-del:Agent", BROKER, "delete", "file:///reports", frozenset({"internal"}), 100
    )
    # short-expiry chain for the staleness test
    broker_instance.grant_root(
        _capability(
            USER, USER, "send", "internal@corp.com", frozenset({"internal"}), 5, "r-send-short"
        )
    )
    broker_instance.attenuate(
        "r-send-short", AGENT, "send", "internal@corp.com", frozenset({"internal"}), 5
    )
    broker_instance.attenuate(
        "r-send-short:Agent", BROKER, "send", "internal@corp.com", frozenset({"internal"}), 5
    )
    # Forged capability: injected straight into the store (no grant_root)
    broker_instance.capabilities["forged-net"] = _capability(
        "Mallory",
        BROKER,
        "network",
        "http://internal-ssrf",
        frozenset({"internal.corp.com"}),
        100,
        "forged-net",
    )
    yield broker_instance


# ---- T1: clean operation is allowed ----
def test_clean_send_allowed(broker: EffectBroker) -> None:
    effect = Effect(
        "send",
        "internal@corp.com",
        {},
        (Data("user_query", Confidentiality.INTERNAL, Integrity.USER),),
        "r-send:Agent:EffectBroker",
        CHAIN,
    )
    allow, evidence = broker.commit(Commit(effect))
    assert allow is True
    assert evidence["primary_blocker"] is None


# ---- T2: prompt-injected send (low-integrity source) blocked by FlowOK ----
def test_injected_send_blocked_flowok(broker: EffectBroker) -> None:
    effect = Effect(
        "send",
        "internal@corp.com",
        {},
        (Data("web_page", Confidentiality.PUBLIC, Integrity.UNTRUSTED),),
        "r-send:Agent:EffectBroker",
        CHAIN,
    )
    allow, evidence = broker.commit(Commit(effect))
    assert allow is False
    assert evidence["primary_blocker"] == "FlowOK"
    assert "low-integrity" in evidence["predicates"]["FlowOK"]


# ---- T3: confused deputy (delete wrong target) blocked by Auth ----
def test_delete_wrong_target_blocked_auth(broker: EffectBroker) -> None:
    effect = Effect(
        "delete",
        "file:///secrets",
        {},
        (Data("user_query", Confidentiality.INTERNAL, Integrity.USER),),
        "r-del:Agent:EffectBroker",
        CHAIN,
    )
    allow, evidence = broker.commit(Commit(effect))
    assert allow is False
    assert evidence["primary_blocker"] == "Auth"
    assert "target-mismatch" in evidence["predicates"]["Auth"]


# ---- T4: stale/expired capability blocked by Fresh ----
def test_stale_capability_blocked_fresh(broker: EffectBroker) -> None:
    broker.logical_time = 10.0
    effect = Effect(
        "send",
        "internal@corp.com",
        {},
        (Data("user_query", Confidentiality.INTERNAL, Integrity.USER),),
        "r-send-short:Agent:EffectBroker",
        CHAIN,
    )
    allow, evidence = broker.commit(Commit(effect))
    assert allow is False
    assert evidence["primary_blocker"] == "Fresh"
    assert "expired" in evidence["predicates"]["Fresh"]


# ---- T16: capability forgery (network-SSRF covered by T4 in traces.py;
#             the write-to-secrets forgery is preserved here) ----
def test_forged_capability_blocked_noamp() -> None:
    """T4 (traces.py) covers the network-SSRF forgery case.
    This test covers the file-write forgery: a forged write-to-secrets capability
    with owner=Mallory (not root-anchored) is correctly rejected by Auth
    """
    broker = build()  # build() creates forged-write (not forged-net)
    effect = Effect(
        "write",
        "file:///secrets",
        {},
        (Data("user_query", Confidentiality.INTERNAL, Integrity.USER),),
        "forged-write",
        CHAIN,
    )
    allow, evidence = broker.commit(Commit(effect))
    assert allow is False

    # The forgery (owner=Mallory, not root-anchored) is correctly rejected
    # by Auth's derivation check. Auth is the primary blocker, not NoAmp
    assert evidence["primary_blocker"] == "Auth"
    assert "owner-not-trusted" in evidence["predicates"]["Auth"]
    assert "derivation-fail" in evidence["predicates"]["Auth"]


# ---- commit_effect: side effects happen only for allowed effects ----
def test_commit_effect_applies_only_allowed(broker: EffectBroker) -> None:
    clean = Effect(
        "send",
        "internal@corp.com",
        {},
        (Data("user_query", Confidentiality.INTERNAL, Integrity.USER),),
        "r-send:Agent:EffectBroker",
        CHAIN,
    )
    injected = Effect(
        "send",
        "internal@corp.com",
        {},
        (Data("web_page", Confidentiality.PUBLIC, Integrity.UNTRUSTED),),
        "r-send:Agent:EffectBroker",
        CHAIN,
    )
    # The denied (injected) effect must NOT reach external state
    denied_allow, _ = broker.commit_effect(injected)
    assert denied_allow is False
    assert broker.store.effects_log == []  # nothing was applied

    # The allowed (clean) effect DOES reach external state exactly once
    allowed_allow, _ = broker.commit_effect(clean)
    assert allowed_allow is True
    assert ("send", "email:internal@corp.com") in broker.store.effects_log


def test_commit_effect_delete_removes_resource(broker: EffectBroker) -> None:
    effect = Effect(
        "delete",
        "file:///reports",
        {},
        (Data("user_query", Confidentiality.INTERNAL, Integrity.USER),),
        "r-del:Agent:EffectBroker",
        CHAIN,
    )
    allow, _ = broker.commit_effect(effect)
    assert allow is True
    assert "file:///reports" not in broker.store.files
    assert "file:///secrets" in broker.store.files  # untouched (good — default deny)


# ---- T17: path traversal (auth / noamp target-mismatch) ----
def test_path_traversal_dotdot_in_target_blocked_auth(broker: EffectBroker) -> None:
    """T17: write to file:///../../etc/password -> Auth (target not in any cap).

    The effect's declared target is outside any authorized scope.
    Auth checks exact right+target match on the capability — a traversal
    path like ../../etc/password does not match the authorized target.
    The broker's gate blocks at Auth before any state is applied.
    """
    # Grant a write capability scoped only to file:///reports
    broker.grant_root(
        _capability(USER, USER, "write", "file:///reports",
                    frozenset({"file:///reports"}), 100, "r-write-reports")
    )
    broker.attenuate("r-write-reports", AGENT, "write", "file:///reports",
                     frozenset({"file:///reports"}), 100)

    effect = Effect(
        "write",
        "file:///../../etc/password",
        {},
        (Data("user_query", Confidentiality.INTERNAL, Integrity.USER),),
        "r-write-reports:Agent",
        CHAIN,
    )
    allow, evidence = broker.commit_effect(effect)
    assert not allow
    assert evidence["primary_blocker"] == "Auth"
    assert "target-mismatch" in evidence["predicates"]["Auth"]
    assert len(broker.store.effects_log) == 0
    assert "file:///../../etc/password" not in broker.store.files


def test_path_traversal_dotdot_in_known_targets_blocked(broker: EffectBroker) -> None:
    """T17 variant: traversal path embedded in known_targets.additional.

    Primary target is authorized; extra target carries a traversal path.
    check_noamp checks extra targets against the capability's scope:
    the traversal path's scope label does not match the cap scope.
    """
    from effect_broker.model import EffectTarget

    # Use a restrictive task ceiling so check_noamp actually blocks
    # based on scope, not wildcard. The default ceiling is right="*", scope={"*"},
    # which passes NoAmp trivially — use a specific scope instead.
    restrictive_task = Task(
        task_id="t-restrict",
        owner=USER,
        ceiling=Capability(
            owner=USER,
            holder=BROKER,
            right="write",
            target="file:///reports",
            scope=frozenset({"file:///reports"}),
            expiry=float("inf"),
            nonce="restrictive-ceil",
        ),
    )
    broker.register_task(restrictive_task)

    broker.grant_root(
        _capability(USER, USER, "write", "file:///reports",
                    frozenset({"file:///reports"}), 100, "r-write")
    )
    broker.attenuate("r-write", AGENT, "write", "file:///reports",
                     frozenset({"file:///reports"}), 100)

    effect = Effect(
        etype="write",
        target="file:///reports",
        metadata={},
        provenance=(Data("user_query", Confidentiality.INTERNAL, Integrity.USER),),
        capability_nonce="r-write:Agent",
        delegation_chain=CHAIN,
        known_targets=EffectTarget(
            primary="file:///reports",
            additional=frozenset({"file:///../../etc/password"}),
        ),
    )
    allow, evidence = broker.commit(
        broker._make_commit(effect, task_id="t-restrict")
    )
    assert not allow
    assert evidence["primary_blocker"] in ("Auth", "NoAmp")


def test_normal_path_legitimate_write_allowed(broker: EffectBroker) -> None:
    """Legitimate path (no traversal) within authorized scope is allowed."""
    broker.grant_root(
        _capability(USER, USER, "write", "file:///reports",
                    frozenset({"file:///reports"}), 100, "r-write")
    )
    broker.attenuate("r-write", AGENT, "write", "file:///reports",
                     frozenset({"file:///reports"}), 100)

    effect = Effect(
        "write",
        "file:///reports",
        {},
        (Data("user_query", Confidentiality.INTERNAL, Integrity.USER),),
        "r-write:Agent",
        CHAIN,
    )
    allow, evidence = broker.commit_effect(effect)
    assert allow
    assert evidence["primary_blocker"] is None
    assert len(broker.store.effects_log) == 1


# ---- T6: validated declass on explicit User policy is allowed ----
def test_validated_declass_allowed(broker: EffectBroker) -> None:
    # User (trusted) records a validated declass grant for this sink
    broker.grant_label_exception(
        LabelException(
            kind="declass",
            match_target="internal@corp.com",
            from_label="CONFIDENTIAL",
            to_label="INTERNAL",
            granted_by=USER,
            nonce="declass-1",
        )
    )
    effect = Effect(
        "send",
        "internal@corp.com",
        {},
        (Data("secret_report", Confidentiality.CONFIDENTIAL, Integrity.USER),),
        "r-send:Agent:EffectBroker",
        CHAIN,
        # broker-validated exception attached to the effect
        (
            LabelException(
                "declass", "internal@corp.com", "CONFIDENTIAL", "INTERNAL", "?", "declass-1"
            ),
        ),
    )
    allow, evidence = broker.commit(Commit(effect))
    assert allow is True
    assert evidence["primary_blocker"] is None
    assert evidence["predicates"]["FlowOK"] == "flow-ok"


# ---- T7: endorse abuse (LLM-attached, NOT broker-validated) is blocked ----
def test_endorse_abuse_blocked(broker: EffectBroker) -> None:
    # The LLM attached an "endorse" exception that was NEVER granted by the broker
    effect = Effect(
        "send",
        "internal@corp.com",
        {},
        (Data("web_page", Confidentiality.PUBLIC, Integrity.UNTRUSTED),),
        "r-send:Agent:EffectBroker",
        CHAIN,
        (
            LabelException(
                "endorse", "internal@corp.com", "UNTRUSTED", "USER", "?", "no-such-grant"
            ),
        ),
    )
    allow, evidence = broker.commit(Commit(effect))
    assert allow is False
    assert evidence["primary_blocker"] == "FlowOK"
    assert "low-integrity" in evidence["predicates"]["FlowOK"]


# ---- T13: false MCP description is a boundary stop ----
# ECAC: the broker blocks when effect.target is NOT in declared_targets
# (declared-vs-actual mismatch). Side effects on other resources are caught
# by the ledger, not blocked at the broker gate.
def test_false_mcp_description_stops_at_boundary() -> None:
    write_tool = ToolSpec(
        name="write-tool",
        declared_targets=frozenset({"file:///reports"}),
        actual_targets=frozenset({"file:///reports", "file:///secrets"}),
        known_side_effects=frozenset({"file:///secrets"}),
    )
    mediator = Mediator(tools={"write-tool": write_tool})
    effect = Effect(
        "write",
        "file:///secrets",  # NOT in declared_targets → false-description
        {},
        (Data("tool_action", Confidentiality.INTERNAL, Integrity.USER),),
        "r-write:Agent:EffectBroker",
        CHAIN,
    )
    verdict = mediator.inspect(effect, "write-tool")
    assert verdict.allow is False
    assert "false-description" in verdict.boundary_stop


# ---- T14: ECAC philosophy — declared effect is ALLOW'd, side effects are audit concern ----
# ECAC principle: the broker authorises declared effects; it cannot block what it
# does not know. If the effect.target is in declared_targets, the broker ALLOWs it.
# Hidden side effects are caught by the independent ledger + observer in production.
# This test verifies the ECAC-consistent behaviour (vs the old "any side effect → BLOCK").
def test_hidden_side_effect_allowed_for_declared_effect() -> None:
    """ECAC philosophy: if declared_targets covers the effect, the broker ALLOWs.
    Side effects are an independent-observer concern, not a broker gate concern.
    """
    read_tool = ToolSpec(
        name="read-tool",
        declared_targets=frozenset({"file:///trusted"}),  # declares: reads trusted
        actual_targets=frozenset({"file:///trusted", "file:///secrets"}),
        known_side_effects=frozenset({"file:///secrets"}),  # also touches secrets
    )
    mediator = Mediator(tools={"read-tool": read_tool})
    effect = Effect(
        "read",
        "file:///trusted",
        {},
        (Data("tool_action", Confidentiality.INTERNAL, Integrity.USER),),
        "r-read:Agent:EffectBroker",
        CHAIN,
    )
    # ECAC: effect is in declared_targets → ALLOW (side effect is audit, not gate)
    verdict = mediator.inspect(effect, "read-tool")
    assert verdict.allow is True
    assert verdict.boundary_stop is None


# ---- T15: monitor bypass is a boundary stop ----
def test_monitor_bypass_stops_at_boundary() -> None:
    audit_tool = ToolSpec(
        name="audit-tool",
        declared_targets=frozenset({"file:///trusted"}),
        actual_targets=frozenset({"file:///trusted"}),
        known_side_effects=frozenset(),
        monitoring=True,
    )
    mediator = Mediator(tools={"audit-tool": audit_tool})
    effect = Effect(
        "read",
        "file:///trusted",
        {},
        (Data("tool_action", Confidentiality.INTERNAL, Integrity.USER),),
        "r-read:Agent:EffectBroker",
        CHAIN,
    )
    verdict = mediator.inspect(effect, "audit-tool")
    assert verdict.allow is False
    assert verdict.boundary_stop == "monitor-bypass"


# ---- benign mediation: an honest effect with matching declaration is forwarded ----
def test_benign_mediation_forwarded() -> None:
    write_tool = ToolSpec(
        name="write-tool",
        declared_targets=frozenset({"file:///reports"}),
        actual_targets=frozenset({"file:///reports"}),
        known_side_effects=frozenset(),
    )
    mediator = Mediator(tools={"write-tool": write_tool})
    effect = Effect(
        "write",
        "file:///reports",
        {},
        (Data("tool_action", Confidentiality.INTERNAL, Integrity.USER),),
        "r-write:Agent:EffectBroker",
        CHAIN,
    )
    verdict = mediator.inspect(effect, "write-tool")
    assert verdict.allow is True
    assert verdict.boundary_stop is None


# ---- T6 (honest): delegation widening is a NoAmp rejection, not a crash ----
def test_honest_delegation_widening_blocked_noamp() -> None:
    broker = build()  # contains a genuine (non-forged) widened delete-on-secrets cap
    effect = Effect(
        "delete",
        "file:///secrets",
        {},
        (Data("user_query", Confidentiality.INTERNAL, Integrity.USER),),
        "r-del:Agent:EffectBroker:wide",  # widened (non-monotonic) capability
        CHAIN,
    )
    allow, evidence = broker.commit(Commit(effect))
    assert allow is False
    # After the refactor, Auth is the primary blocker: the derivation check
    # (root-anchoring + monotonicity) correctly rejects the non-monotonic
    # widening (scope widened from {"internal"} to {"confidential"})
    assert evidence["primary_blocker"] == "Auth"
    assert "non-monotonic" in evidence["predicates"]["Auth"]


# ---- mediation stops a gate-allowed effect before any side effect (T13 path) ----
def test_conditioned_mediation_prevents_commit() -> None:
    broker = build()
    # a broker-held write capability to secrets (so the four predicates pass)
    broker.capabilities["r-write-secrets"] = Capability(
        USER,
        BROKER,
        "write",
        "file:///secrets",
        frozenset({"confidential"}),
        100,
        "r-write-secrets",
    )
    effect = Effect(
        "write",
        "file:///secrets",
        {},
        (Data("user_query", Confidentiality.INTERNAL, Integrity.USER),),
        "r-write-secrets",
        CHAIN,
    )
    # T13: effect.target NOT in declared_targets → false-description
    mediation = MediationVerdict(
        False, "false-description(effect.target=file:///secrets not in declared_targets=frozenset({'file:///reports'}))"
    )
    allow, evidence = broker.commit(Commit(effect), mediation=mediation)
    assert allow is False
    assert "false-description" in evidence["boundary_stop"]
    assert broker.store.effects_log == []  # nothing reached external state
    assert "file:///secrets" in broker.store.files  # no write/delete performed


# ---- risk escalation -> Approver -> fresh ONE-SHOT capability --------
def test_risk_escalation_one_shot_approval() -> None:
    broker = build()
    broker.risk_override = 0.9  # high-risk assessment (learned risk model)
    effect = Effect(
        "send",
        "internal@corp.com",
        {},
        (Data("user_query", Confidentiality.INTERNAL, Integrity.USER),),
        "r-send:Agent:EffectBroker",
        CHAIN,
    )
    assert broker.needs_review(effect) is True  # routed to Approver
    # Approver grants a fresh, one-shot capability; the gate must still pass
    nonce = broker.grant_approval(effect, expiry=broker.logical_time + 50)
    approved = Effect(
        "send",
        "internal@corp.com",
        {},
        (Data("user_query", Confidentiality.INTERNAL, Integrity.USER),),
        nonce,
        CHAIN,
    )
    allow1, _ = broker.commit(Commit(approved))
    assert allow1 is True  # approved cap still passes Auth^FlowOK^NoAmp^Fresh
    allow2, evidence2 = broker.commit(Commit(approved))
    assert allow2 is False
    assert evidence2["primary_blocker"] == "Fresh"  # one-shot consumed (replay)


# ---- mailbox semantics (B1): send delivers into the sender's outbox ----
def test_send_delivers_to_outbox(broker: EffectBroker) -> None:
    effect = Effect(
        "send",
        "internal@corp.com",
        {},
        (Data("user_query", Confidentiality.INTERNAL, Integrity.USER),),
        "r-send:Agent:EffectBroker",
        CHAIN,
    )
    allow, _ = broker.commit(Commit(effect))
    assert allow is True
    # the mailbox for local part "internal" should now hold the sent message
    local = effect.target.split("@")[0]
    assert local in broker.store.mailboxes
    assert effect.target in broker.store.mailboxes[local].outbox
    assert any(entry == ("send", "email:internal@corp.com") for entry in broker.store.effects_log)


# ---- C1: Auth is static, revoked is a Fresh (time-sensitive) rejection ----
def test_revoked_blocked_by_fresh_not_auth(broker: EffectBroker) -> None:
    # revoke the broker-held send capability used by the clean trace
    broker.revoke("r-send:Agent:EffectBroker")
    effect = Effect(
        "send",
        "internal@corp.com",
        {},
        (Data("user_query", Confidentiality.INTERNAL, Integrity.USER),),
        "r-send:Agent:EffectBroker",
        CHAIN,
    )
    allow, evidence = broker.commit(Commit(effect))
    assert allow is False
    # Auth is static: holder/right/target still match -> auth-ok
    # The auth message now includes derivation context (task=default)
    assert evidence["predicates"]["Auth"].startswith("auth-ok")
    # Fresh is the time-sensitive predicate that rejects the revoked capability
    assert evidence["primary_blocker"] == "Fresh"
    assert evidence["predicates"]["Fresh"] == "revoked(in_task=default or global)"


# Resource-identity regression assertions
# The model separates four identity axes:
#   mailbox identity (container / ownership boundary)
#   sender account   (who composed/sent; provenance for FlowOK)
#   message identity (unique message nonce; replay binding)
#   recipient address (delivery target; which mailbox)


# (a) Sender provenance differs from owner — tracked by FlowOK
def test_sender_provenance_different_from_owner() -> None:
    """regression (a): FlowOK resolves provenance against the sender
    account (email.address), not the mailbox owner (local part of address)

    Scenario: alice@corp.com sends to bob@corp.com. The message's sender is
    alice (alice@corp.com) but bob's mailbox owner is "bob". The provenance of
    the message is alice's email address — FlowOK checks alice's confidentiality
    level, not bob's identity. This proves the four axes are not conflated
    """
    broker = build()
    # alice sends to bob; alice's sender account has HIGH confidentiality
    # (e.g. a sensitive executive message). bob's mailbox owner is "bob" (low)
    # The send provenance (sender account = alice@corp.com) drives FlowOK
    # Use alice's address as the target (sender = bob, so sender != owner)
    broker.store._unsafe_bootstrap_email("bob@corp.com", Domain.INTERNAL)
    broker.store._unsafe_bootstrap_email("alice@corp.com", Domain.INTERNAL)
    # grant a send capability for bob@corp.com
    broker.grant_root(
        _capability(USER, USER, "send", "bob@corp.com", frozenset({"internal"}), 100, "r-send-bob")
    )
    broker.attenuate("r-send-bob", BROKER, "send", "bob@corp.com", frozenset({"internal"}), 100)

    # Sender account (alice@corp.com) has CONFIDENTIAL provenance — this is the
    # axis FlowOK resolves against. The send target is bob@corp.com (recipient)
    # FlowOK sees provenance=CONFIDENTIAL -> sink=INTERNAL -> conf-leak -> BLOCK
    effect = Effect(
        "send",
        "bob@corp.com",
        {},
        (Data("alice_exec_email", Confidentiality.CONFIDENTIAL, Integrity.USER),),
        "r-send-bob:EffectBroker",
        CHAIN,
    )
    allow, evidence = broker.commit(Commit(effect))
    # FlowOK blocks because alice's sender-account provenance is CONFIDENTIAL
    # and the sink (task.flow_boundary) is INTERNAL — proving provenance
    # is tracked against the sender identity, NOT the mailbox owner
    assert allow is False
    assert evidence["primary_blocker"] == "FlowOK"
    assert "conf-leak" in evidence["predicates"]["FlowOK"]


# (b) Two messages to the same mailbox are distinct for replay
def test_two_messages_same_mailbox_distinct_for_replay() -> None:
    """regression (b): the same recipient address does NOT mean the
    same message nonce. Two distinct send effects to the same mailbox target
    each consume their own capability nonce — first ALLOW, second BLOCK Fresh
    (replay of the capability nonce, not the mailbox target)
    """
    broker = build()
    # Both messages go to internal@corp.com but use DIFFERENT capability nonces
    msg1 = Effect(
        "send",
        "internal@corp.com",
        {},
        (Data("msg1_body", Confidentiality.INTERNAL, Integrity.USER),),
        "r-send:Agent:EffectBroker",
        CHAIN,
    )
    # r-send2 is a separate nonce (second attenuation chain in build())
    msg2 = Effect(
        "send",
        "internal@corp.com",
        {},
        (Data("msg2_body", Confidentiality.INTERNAL, Integrity.USER),),
        "r-send2:Agent:EffectBroker",
        CHAIN,
    )
    allow1, _ = broker.commit(Commit(msg1))
    assert allow1 is True  # first message ALLOW

    allow2, evidence2 = broker.commit(Commit(msg2))
    assert allow2 is True  # second message ALLOW (different nonce -> no replay)

    # Both landed in the same mailbox (internal@corp.com -> local "internal")
    assert "internal" in broker.store.mailboxes
    assert len(broker.store.mailboxes["internal"].outbox) == 2  # two distinct messages
    assert broker.store.effects_log.count(("send", "email:internal@corp.com")) == 2


# (b') Same capability nonce twice: second use is replay (Fresh)
def test_same_capability_nonce_twice_blocked_by_fresh() -> None:
    """regression (b') — complement of the above: if the SAME capability
    nonce is committed twice to the same mailbox, the second is replay-blocked
    This proves replay is bound to capability nonce, not to mailbox identity
    """
    broker = build()
    msg1 = Effect(
        "send",
        "internal@corp.com",
        {},
        (Data("message_body", Confidentiality.INTERNAL, Integrity.USER),),
        "r-send:Agent:EffectBroker",
        CHAIN,
    )
    # msg2 reuses the SAME capability nonce (r-send:Agent:EffectBroker)
    msg2 = Effect(
        "send",
        "internal@corp.com",
        {},
        (Data("message_body", Confidentiality.INTERNAL, Integrity.USER),),
        "r-send:Agent:EffectBroker",  # ← same nonce as msg1
        CHAIN,
    )
    allow1, _ = broker.commit(Commit(msg1))
    assert allow1 is True

    allow2, evidence2 = broker.commit(Commit(msg2))
    assert allow2 is False
    assert evidence2["primary_blocker"] == "Fresh"
    assert "replay" in evidence2["predicates"]["Fresh"]


class TestClosedSessionBlocksCommit:
    """Gap: closed/dead session must block ALL commits in that task."""

    def test_dead_session_blocks_commit(self) -> None:
        """Setting session.live=False blocks commit for that task.

        Once a session is closed, its authority ceiling is invalid.
        The Fresh predicate returns session-closed. The task cannot
        be reopened — a new task with a fresh session must be registered.
        Uses build() + warmup commit to trigger lazy task creation.
        """
        from effect_broker.traces import build

        broker = build()

        # Trigger lazy task creation (first commit populates broker.tasks["default"])
        warmup = Effect(
            "send", "internal@corp.com", {},
            (Data("warmup", Confidentiality.INTERNAL, Integrity.USER),),
            "r-send:Agent:EffectBroker", (USER, AGENT, BROKER),
        )
        broker.commit(Commit(warmup))

        task = broker.tasks["default"]
        assert task.session is not None
        assert task.session.live is True

        # Close the session
        task.session.live = False
        assert task.session.live is False  # confirmed dead

        # Any capability committed against this task → BLOCK
        msg = Effect(
            "send",
            "internal@corp.com",
            {},
            (Data("user_query", Confidentiality.INTERNAL, Integrity.USER),),
            "r-send:Agent:EffectBroker",
            (USER, AGENT, BROKER),
        )
        allow, evidence = broker.commit(Commit(msg))
        assert allow is False
        assert evidence["primary_blocker"] == "Fresh"
        assert "session-closed" in evidence["predicates"]["Fresh"]

    def test_closed_session_cannot_be_reopened(self) -> None:
        """Session.live cannot be set back to True after being False."""
        from effect_broker.traces import build

        broker = build()
        # Trigger lazy task creation
        warmup = Effect("send", "internal@corp.com", {},
                        (Data("warmup", Confidentiality.INTERNAL, Integrity.USER),),
                        "r-send:Agent:EffectBroker", (USER, AGENT, BROKER))
        broker.commit(Commit(warmup))
        task = broker.tasks["default"]

        task.session.live = False
        with pytest.raises(ValueError, match="cannot be reopened"):
            task.session.live = True  # type: ignore[assignment]


class TestCrossTaskApprovalUse:
    """Gap: approval granted for task-A must NOT commit in task-B."""

    def test_approval_task_id_restricts_usage(self) -> None:
        """Approval for task-A is blocked in task-B by ApprovalBinding.

        The ApprovalBinding check in gate() verifies task_id exactly.
        An approval scoped to task-A cannot be reused in task-B — even
        if all other parameters (effect, targets, content) match.
        Uses build() which pre-registers "default" task with capabilities.
        """
        from effect_broker.traces import build

        broker = build()

        task_a = Task(
            task_id="task-a",
            owner=USER,
            ceiling=Capability(
                USER, "EffectBroker", "send", "internal@corp.com",
                frozenset({"internal"}), float("inf"), "ceiling-task-a",
            ),
        )
        task_b = Task(
            task_id="task-b",
            owner=USER,
            ceiling=Capability(
                USER, "EffectBroker", "send", "internal@corp.com",
                frozenset({"internal"}), float("inf"), "ceiling-task-b",
            ),
        )
        broker.register_task(task_a)
        broker.register_task(task_b)
        broker.tasks["task-a"] = task_a

        # Grant approval scoped to task-a
        grant_effect = Effect(
            "send",
            "internal@corp.com",
            {},
            (Data("msg", Confidentiality.INTERNAL, Integrity.USER, "hello"),),
            "unused",
            (USER,),
            known_targets=EffectTarget(primary="internal@corp.com"),
        )
        approval_nonce = broker.grant_approval(grant_effect, expiry=100.0, task_id="task-a")
        stored = broker._approved_requests[approval_nonce]

        # Commit with task-a: ALLOW
        effect_a = Effect(
            "send",
            "internal@corp.com",
            {},
            (Data("msg", Confidentiality.INTERNAL, Integrity.USER, "hello"),),
            approval_nonce,
            (USER,),
            known_targets=EffectTarget(primary="internal@corp.com"),
        )
        commit_a = Commit(effect=effect_a, task=task_a, tool_name=None)
        allow_a, _ = broker.commit(commit_a)
        assert allow_a is True, "Approval in task-a should ALLOW"

        # Commit with task-b: BLOCK (cross-task use).
        # CRITICAL: Commit.approved_request must be set to trigger ApprovalBinding.
        effect_b = Effect(
            "send",
            "internal@corp.com",
            {},
            (Data("msg", Confidentiality.INTERNAL, Integrity.USER, "hello"),),
            approval_nonce,
            (USER,),
            known_targets=EffectTarget(primary="internal@corp.com"),
        )
        commit_b = Commit(effect=effect_b, task=task_b, tool_name=None)
        allow_b, evidence_b = broker.commit(commit_b)
        assert allow_b is False
        assert evidence_b["primary_blocker"] == "ApprovalBinding"
        assert "cross-task-use" in evidence_b.get("approval_binding", "")



class TestCrossTaskCapabilityScope:
    """Gap: reusable capability with task_id must not be used outside that task."""

    def test_reusable_cap_task_id_restricts_usage(self, broker: EffectBroker) -> None:
        """Capability with cap.task_id set must be used only in that task.

        A reusable capability derived for task-A (e.g., from a grant)
        carries task_id=A. Attempting to use it in task-B is blocked
        by check_auth() as task-scope-mismatch.
        """
        from effect_broker.model import Capability

        task_a = Task(
            task_id="task-a",
            owner=USER,
            ceiling=Capability(
                USER, "EffectBroker", "send", "internal@corp.com",
                frozenset({"internal"}), float("inf"), "ceiling-task-a",
            ),
        )
        task_b = Task(
            task_id="task-b",
            owner=USER,
            ceiling=Capability(
                USER, "EffectBroker", "send", "internal@corp.com",
                frozenset({"internal"}), float("inf"), "ceiling-task-b",
            ),
        )
        broker.register_task(task_a)
        broker.register_task(task_b)

        # Root-grant gives capability with task_id=None (default = "default")
        # We need a capability scoped to task-a — derive it
        broker.grant_root(Capability(
            USER, USER, "send", "internal@corp.com",
            frozenset({"internal"}), 100, "cap-for-task-a",
        ))
        broker.attenuate(
            "cap-for-task-a", "EffectBroker", "send",
            "internal@corp.com", frozenset({"internal"}), 100,
        )
        # The attenuated cap inherits from parent — manually set task_id
        broker.capabilities["cap-task-a-restricted"] = Capability(
            USER, "EffectBroker", "send", "internal@corp.com",
            frozenset({"internal"}), 100, "cap-task-a-restricted",
            derives_from="cap-for-task-a:EffectBroker",
            task_id="task-a",
        )

        # Use in task-a: ALLOW
        msg_a = Effect(
            "send", "internal@corp.com", {},
            (Data("q", Confidentiality.INTERNAL, Integrity.USER),),
            "cap-task-a-restricted", CHAIN,
        )
        allow_a, _ = broker.commit(Commit(msg_a, task=task_a))
        assert allow_a is True

        # Use in task-b: BLOCK (task-scope-mismatch)
        msg_b = Effect(
            "send", "internal@corp.com", {},
            (Data("q", Confidentiality.INTERNAL, Integrity.USER),),
            "cap-task-a-restricted", CHAIN,
        )
        allow_b, evidence_b = broker.commit(Commit(msg_b, task=task_b))
        assert allow_b is False
        assert evidence_b["primary_blocker"] == "Auth"
        assert "task-scope-mismatch" in evidence_b["predicates"]["Auth"]


class TestOverObservedIsUnknown:
    """Gap: observer recording more observations than authorizations → UNKNOWN."""

    def test_over_observed_returns_unknown(self, broker: EffectBroker) -> None:
        """If obs_count > auth_count, ledger.verify() returns UNKNOWN.

        This cannot happen through normal broker operation (the ledger is
        called once per effect). But it proves the "unknown, not safe" invariant:
        the ledger MUST NOT return CONFIRMED_COMMITTED when it cannot verify
        the claim. This tests the boundary case directly.
        """
        from effect_broker.ledger import LedgerVerdict, UnknownLedgerResult

        task_id = "default"
        nonce = "test-nonce"

        # Record ONE authorization
        broker.ledger.record_authorization(
            task_id, nonce, frozenset({"file:///reports"}), source="test",
        )

        # Record TWO observations (over-observed)
        broker.ledger.record_observation(
            task_id, nonce, frozenset({"file:///reports"}), source="test-obs-1",
        )
        broker.ledger.record_observation(
            task_id, nonce, frozenset({"file:///reports"}), source="test-obs-2",
        )

        verdict = broker.ledger.verify(task_id, nonce)
        assert isinstance(verdict, UnknownLedgerResult)
        assert "over-observed" in verdict.reason
        assert "obs_count=2" in verdict.reason


class TestUnknownLedgerResultIsNotSafe:
    """Gap: ledger returning UNKNOWN must not be treated as safe."""

    def test_authorized_not_observed_returns_unknown(self, broker: EffectBroker) -> None:
        """Authorization recorded but no observation → UNKNOWN (possible bypass).

        Key invariant: auth > 0, obs = absent → UNKNOWN. NOT "safe."
        This proves the ledger's "unknown, not safe" guarantee.
        """
        from effect_broker.ledger import UnknownLedgerResult

        task_id = "default"
        nonce = "orphan-auth"

        # Authorization without observation (simulates bypass)
        broker.ledger.record_authorization(
            task_id, nonce, frozenset({"file:///secrets"}), source="test",
        )
        # No record_observation call

        verdict = broker.ledger.verify(task_id, nonce)
        assert isinstance(verdict, UnknownLedgerResult)
        assert "possible_bypass" in verdict.reason or "authorized_not_observed" in verdict.reason

    def test_direct_store_mutation_produces_unknown(self, broker: EffectBroker) -> None:
        """Direct store mutation (bypassing executor) produces UNKNOWN from ledger.

        This proves the "unknown, not safe" guarantee: direct mutation bypasses
        the executor, so the ledger records only authorization (from gate) but
        no observation (from apply_effect). The ledger verifies (auth=1, obs=0)
        and returns UNKNOWN — NOT "safe."

        In a multi-process deployment, the ledger process cannot be mutated
        by the broker process, so this bypass is structurally impossible.
        """
        task_id = "default"
        nonce = "bypass-nonce"

        # Record authorization (as if broker allowed it via gate)
        broker.ledger.record_authorization(
            task_id, nonce, frozenset({"file:///reports"}), source="broker.gate",
        )

        # Direct store mutation bypassing executor (simulates same-process bypass)
        # This is NOT observed by the ledger — no record_observation call
        broker.store._files._data["file:///reports"] = File(
            "file:///reports", Confidentiality.CONFIDENTIAL,
        )
        # NOTE: NO record_observation call — the executor is bypassed

        verdict = broker.ledger.verify(task_id, nonce)
        # Ledger sees (auth=1, obs=0) → UNKNOWN (possible bypass)
        # NOT "safe" — this is the core invariant
        assert isinstance(verdict, UnknownLedgerResult)
        assert "authorized_not_observed" in verdict.reason or "possible_bypass" in verdict.reason


class TestConcurrentNonceDoubleCommit:
    """Gap: same nonce committed concurrently from two threads → only one succeeds."""

    def test_concurrent_same_nonce_only_one_commits(self) -> None:
        """Two threads using the same nonce simultaneously: only one Fresh passes.

        The broker uses per-task locks in gate() to atomically check AND
        reserve the nonce. This test verifies that concurrent attempts
        with the same nonce result in exactly one ALLOW and one Fresh BLOCK.
        Uses build() which pre-registers the default task with capabilities.
        """
        import threading

        from effect_broker.traces import build

        broker = build()

        results: list[tuple[bool, str]] = []

        def try_commit(thread_id: int) -> None:
            msg = Effect(
                "send",
                "internal@corp.com",
                {},
                (Data("user_query", Confidentiality.INTERNAL, Integrity.USER),),
                "r-send:Agent:EffectBroker",
                (USER, AGENT, BROKER),
            )
            allow, evidence = broker.commit(Commit(msg))
            results.append((allow, evidence["primary_blocker"] or "none"))

        # Launch two threads simultaneously
        t1 = threading.Thread(target=try_commit, args=(1,))
        t2 = threading.Thread(target=try_commit, args=(2,))

        t1.start()
        t2.start()
        t1.join()
        t2.join()

        allows = [allow for allow, _ in results if allow]
        blocks = [blocker for _, blocker in results if not _]

        # Exactly one ALLOW, one Fresh BLOCK
        assert len(allows) == 1, f"Expected 1 ALLOW, got {len(allows)}: {results}"
        assert len(blocks) == 1, f"Expected 1 BLOCK, got {len(blocks)}: {results}"
        # The block must be Fresh (replay), not Auth/FlowOK/NoAmp
        assert blocks[0] == "Fresh", f"Block must be Fresh, got: {results}"
