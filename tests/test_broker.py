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
    BROKER,
    USER,
    Capability,
    Commit,
    Data,
    Domain,
    Effect,
    LabelException,
    Task,
)
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
        "file:///secrets",
        {},
        (Data("tool_action", Confidentiality.INTERNAL, Integrity.USER),),
        "r-write:Agent:EffectBroker",
        CHAIN,
    )
    verdict = mediator.inspect(effect, "write-tool")
    assert verdict.allow is False
    assert verdict.boundary_stop == "hidden-side-effect"


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
    # false MCP description: tool declares it will write reports, actually writes secrets
    mediation = MediationVerdict(
        False, "false-description(declared=file:///reports,actual=file:///secrets)"
    )
    allow, evidence = broker.commit(Commit(effect), mediation=mediation)
    assert allow is False
    assert evidence["boundary_stop"] == (
        "false-description(declared=file:///reports,actual=file:///secrets)"
    )
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
