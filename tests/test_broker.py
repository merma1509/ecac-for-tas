"""Regression tests encoding the Week-1 adversarial trace suite as assertions

Each test asserts the security outcome of an effect commit, so a regression
in any predicate (Auth, FlowOK, NoAmp, Fresh) fails CI loudly
"""

from collections.abc import Iterator

import pytest

from effect_broker.broker import EffectBroker
from effect_broker.lattice import Confidentiality, Integrity
from effect_broker.model import AGENT, BROKER, USER, Capability, Data, Effect

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
    return Capability(
        owner, holder, right, target, scope, expiry, nonce, derives_from=derives
        )


@pytest.fixture
def broker() -> Iterator[EffectBroker]:
    broker_instance = EffectBroker()
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
    allow, evidence = broker.commit(effect)
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
    allow, evidence = broker.commit(effect)
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
    allow, evidence = broker.commit(effect)
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
    allow, evidence = broker.commit(effect)
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
    allow, evidence = broker.commit(effect)
    assert allow is False
    
    # Auth passes (right+target match, holder=broker) — NoAmp is the blocker
    assert evidence["predicates"]["Auth"] == "auth-ok"
    assert evidence["primary_blocker"] == "NoAmp"
    assert "not-root-anchored" in evidence["predicates"]["NoAmp"]
