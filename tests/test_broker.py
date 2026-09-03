"""Regression tests encoding the Week-1 adversarial trace suite as assertions

Each test asserts the security outcome of an effect commit, so a regression
in any predicate (Auth, FlowOK, NoAmp, Fresh) fails CI loudly
"""

from collections.abc import Iterator

import pytest

from effect_broker.broker import EffectBroker
from effect_broker.lattice import Confidentiality, Integrity
from effect_broker.model import (
    AGENT,
    BROKER,
    USER,
    Capability,
    Commit,
    Data,
    Domain,
    Effect,
    Email,
    File,
    LabelException,
    Mailbox,
)
from effect_broker.traces import mediat

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
    # external resources: R = F ∪ E ∪ M
    broker_instance.store.files["file:///reports"] = File(
        "file:///reports", Confidentiality.INTERNAL
    )
    broker_instance.store.files["file:///secrets"] = File(
        "file:///secrets", Confidentiality.CONFIDENTIAL
    )
    broker_instance.store.emails["internal@corp.com"] = Email("internal@corp.com", Domain.INTERNAL)
    broker_instance.store.mailboxes["alice"] = Mailbox("alice")
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
    # forged capability injected straight into the store (no grant_root)
    broker_instance.capabilities["forged-net"] = _capability(
        "Mallory",
        BROKER,
        "network",
        "http://internal-ssrf",
        frozenset({"internal"}),
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


# ---- T5: forged network capability blocked by NoAmp (not Auth) ----
def test_forged_capability_blocked_noamp(broker: EffectBroker) -> None:
    effect = Effect(
        "network",
        "http://internal-ssrf",
        {},
        (Data("user_query", Confidentiality.INTERNAL, Integrity.USER),),
        "forged-net",
        CHAIN,
    )
    allow, evidence = broker.commit(Commit(effect))
    assert allow is False

    # Auth passes (right+target match, holder=broker) — NoAmp is the blocker
    assert evidence["predicates"]["Auth"] == "auth-ok"
    assert evidence["primary_blocker"] == "NoAmp"
    assert "not-root-anchored" in evidence["predicates"]["NoAmp"]


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


# ---- T13: false MCP description (hidden write) is a boundary stop ----
def test_false_mcp_description_stops_at_boundary() -> None:
    effect = Effect(
        "write",
        "file:///secrets",  # actual target the hidden tool would touch
        {},
        (Data("tool_action", Confidentiality.INTERNAL, Integrity.USER),),
        "r-write:Agent:EffectBroker",
        CHAIN,
    )
    verdict = mediat(effect, declared_write_target="file:///reports")
    assert verdict.allow is False
    assert verdict.boundary_stop == (
        "false-description(declared=file:///reports,actual=file:///secrets)"
    )


# ---- T14: hidden (undeclared) side effect is a boundary stop ----
def test_hidden_side_effect_stops_at_boundary() -> None:
    effect = Effect(
        "read",
        "file:///trusted",
        {},
        (Data("tool_action", Confidentiality.INTERNAL, Integrity.USER),),
        "r-read:Agent:EffectBroker",
        CHAIN,
    )
    verdict = mediat(effect, hidden_side_effect=True)
    assert verdict.allow is False
    assert verdict.boundary_stop == "hidden-side-effect"


# ---- T15: monitor bypass is a boundary stop ----
def test_monitor_bypass_stops_at_boundary() -> None:
    effect = Effect(
        "read",
        "file:///trusted",
        {},
        (Data("tool_action", Confidentiality.INTERNAL, Integrity.USER),),
        "r-read:Agent:EffectBroker",
        CHAIN,
    )
    verdict = mediat(effect, monitoring_bypass=True)
    assert verdict.allow is False
    assert verdict.boundary_stop == "monitor-bypass"


# ---- benign mediation: an honest effect with matching declaration is forwarded ----
def test_benign_mediation_forwarded() -> None:
    effect = Effect(
        "write",
        "file:///reports",
        {},
        (Data("tool_action", Confidentiality.INTERNAL, Integrity.USER),),
        "r-write:Agent:EffectBroker",
        CHAIN,
    )
    verdict = mediat(effect, declared_write_target="file:///reports")
    assert verdict.allow is True
    assert verdict.boundary_stop is None

