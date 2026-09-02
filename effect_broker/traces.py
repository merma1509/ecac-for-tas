"""Adversarial trace suite for the tiny executable model

Builds root grants + attenuation chains, then runs six traces covering clean
operation and the four predicates (Auth, FlowOK, NoAmp, Fresh)

Every effect commit carries the real delegation chain (User -> Agent -> Broker)
so NoAmp truly reflects the "broker is always in the chain" property that the
early set-based model got wrong
"""

from .broker import EffectBroker
from .lattice import Confidentiality, Integrity
from .model import AGENT, BROKER, USER, Capability, Data, Effect

# Delegation chain: User (root) delegates to Agent, which delegates to Broker
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


def build() -> EffectBroker:
    broker = EffectBroker()

    # ---- root grants (User is the sole trusted root) ----
    broker.grant_root(
        _capability(USER, USER, "send", "internal@corp.com", frozenset({"internal"}), 100, "r-send")
    )
    broker.grant_root(
        _capability(USER, USER, "delete", "file:///reports", frozenset({"internal"}), 100, "r-del")
    )

    # ---- monotonic attenuation chains User -> Agent -> Broker ----
    # (holder must equal owner to delegate: User delegates to Agent, not Agent->Agent)
    # We therefore model User delegating directly to each subsequent holder.
    broker.attenuate("r-send", AGENT, "send", "internal@corp.com", frozenset({"internal"}), 100)
    broker.attenuate(
        "r-send:Agent", BROKER, "send", "internal@corp.com", frozenset({"internal"}), 100
    )
    broker.attenuate("r-del", AGENT, "delete", "file:///reports", frozenset({"internal"}), 100)
    broker.attenuate(
        "r-del:Agent", BROKER, "delete", "file:///reports", frozenset({"internal"}), 100
    )

    # ---- short-expiry chain for the staleness test ----
    broker.grant_root(
        _capability(
            USER, USER, "send", "internal@corp.com", frozenset({"internal"}), 5, "r-send-short"
        )
    )
    broker.attenuate("r-send-short", AGENT, "send", "internal@corp.com", frozenset({"internal"}), 5)
    broker.attenuate(
        "r-send-short:Agent", BROKER, "send", "internal@corp.com", frozenset({"internal"}), 5
    )

    # ---- forged network capability placed in the store WITHOUT going through
    #      grant_root (simulates a tampered/corrupted store or a buggy plugin)
    #      It matches right+target and is held by the broker, so Auth passes —
    #      but it is NOT root-anchored, so NoAmp must reject it at commit
    #      This is the defense-in-depth point of NoAmp
    broker.capabilities["forged-net"] = _capability(
        "Mallory",
        BROKER,
        "network",
        "http://internal-ssrf",
        frozenset({"internal"}),
        100,
        "forged-net",
    )
    return broker


def run_all() -> EffectBroker:
    broker = build()
    traces = [
        (
            "T1 clean send -> ALLOW",
            Effect(
                "send",
                "internal@corp.com",
                {},
                (Data("user_query", Confidentiality.INTERNAL, Integrity.USER),),
                "r-send:Agent:EffectBroker",
                CHAIN,
            ),
        ),
        (
            "T2 injected send -> BLOCK FlowOK",
            Effect(
                "send",
                "internal@corp.com",
                {},
                (Data("web_page", Confidentiality.PUBLIC, Integrity.UNTRUSTED),),
                "r-send:Agent:EffectBroker",
                CHAIN,
            ),
        ),
        (
            "T3 delete wrong-target -> BLOCK Auth",
            Effect(
                "delete",
                "file:///secrets",
                {},
                (Data("user_query", Confidentiality.INTERNAL, Integrity.USER),),
                "r-del:Agent:EffectBroker",
                CHAIN,
            ),
        ),
        (
            "T4 stale/expired -> BLOCK Fresh",
            Effect(
                "send",
                "internal@corp.com",
                {},
                (Data("user_query", Confidentiality.INTERNAL, Integrity.USER),),
                "r-send-short:Agent:EffectBroker",
                CHAIN,
            ),
        ),
        (
            "T5 forged network -> BLOCK NoAmp",
            Effect(
                "network",
                "http://internal-ssrf",
                {},
                (Data("user_query", Confidentiality.INTERNAL, Integrity.USER),),
                "forged-net",
                (USER, AGENT, BROKER),
            ),
        ),
    ]
    broker.logical_time = 10.0  # advance time so T4's short-expiry capability is stale
    for trace_name, effect in traces:
        allow, evidence = broker.commit(effect)
        print(
            f"[{trace_name}] allow={allow}  primary_blocker={evidence['primary_blocker'] or 'none'}"
        )
        for predicate_name, predicate_message in evidence["predicates"].items():
            print(f"    {predicate_name}: {predicate_message}")
        print()
    return broker
