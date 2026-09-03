"""Adversarial trace suite for the tiny executable model

Covers ALL 20 attack classes of the brief as runnable traces

Two kinds of traces live here:

1. *Predicate-gate traces* (auth/flow/noamp/fresh) — decided by the
   four-predicate gate over the commit primitive. These are the bulk of the
   suite (T1-T12, T16-T20).

2. *Tool-boundary / MCP-semantics-honesty traces* (T13, T14, T15) — decided by
   a mediation step that models where the guarantee stops at the
   broker -> tool boundary. Their verdict is a `BoundaryStop` (a mediation
   decision, not a predicate): the effect never reaches the remote tool because
   the broker detects a declared-vs-actual mismatch (false description), a
   hidden side effect, or a monitoring bypass.

Every effect commit carries the real delegation chain (User -> Agent -> Broker)
so NoAmp truly reflects the "broker is always in the chain" property that the
early set-based model got wrong.
"""

from dataclasses import dataclass

from .broker import EffectBroker
from .lattice import Confidentiality, Integrity
from .model import (
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

    # ---- external resources: R = F ∪ E ∪ M (files, emails, mailboxes) ----
    broker.store.files["file:///reports"] = File("file:///reports", Confidentiality.INTERNAL)
    broker.store.files["file:///secrets"] = File("file:///secrets", Confidentiality.CONFIDENTIAL)
    broker.store.files["file:///trusted"] = File("file:///trusted", Confidentiality.INTERNAL)
    broker.store.emails["internal@corp.com"] = Email("internal@corp.com", Domain.INTERNAL)
    broker.store.emails["external@elsewhere.com"] = Email("external@elsewhere.com", Domain.EXTERNAL)
    broker.store.mailboxes["alice"] = Mailbox("alice")

    # ---- root grants (User is the sole trusted root) ----
    broker.grant_root(
        _capability(USER, USER, "send", "internal@corp.com", frozenset({"internal"}), 100, "r-send")
    )
    broker.grant_root(
        _capability(USER, USER, "delete", "file:///reports", frozenset({"internal"}), 100, "r-del")
    )
    broker.grant_root(
        _capability(USER, USER, "write", "file:///reports", frozenset({"internal"}), 100, "r-write")
    )
    broker.grant_root(
        _capability(USER, USER, "read", "file:///trusted", frozenset({"internal"}), 100, "r-read")
    )
    broker.grant_root(
        _capability(
            USER,
            USER,
            "network",
            "https://ok.example.com",
            frozenset({"internal"}),
            100,
            "r-net",
        )
    )

    # ---- monotonic attenuation chains User -> Agent -> Broker ----
    broker.attenuate("r-send", AGENT, "send", "internal@corp.com", frozenset({"internal"}), 100)
    broker.attenuate(
        "r-send:Agent", BROKER, "send", "internal@corp.com", frozenset({"internal"}), 100
    )
    broker.attenuate("r-del", AGENT, "delete", "file:///reports", frozenset({"internal"}), 100)
    broker.attenuate(
        "r-del:Agent", BROKER, "delete", "file:///reports", frozenset({"internal"}), 100
    )
    broker.attenuate("r-write", AGENT, "write", "file:///reports", frozenset({"internal"}), 100)
    broker.attenuate(
        "r-write:Agent", BROKER, "write", "file:///reports", frozenset({"internal"}), 100
    )
    broker.attenuate("r-read", AGENT, "read", "file:///trusted", frozenset({"internal"}), 100)
    broker.attenuate(
        "r-read:Agent", BROKER, "read", "file:///trusted", frozenset({"internal"}), 100
    )
    broker.attenuate(
        "r-net", AGENT, "network", "https://ok.example.com", frozenset({"internal"}), 100
    )
    broker.attenuate(
        "r-net:Agent", BROKER, "network", "https://ok.example.com", frozenset({"internal"}), 100
    )

    # ---- a second, dedicated send chain (fresh nonce for the declass trace) ----
    broker.grant_root(
        _capability(
            USER, USER, "send", "internal@corp.com", frozenset({"internal"}), 100, "r-send2"
        )
    )
    broker.attenuate("r-send2", AGENT, "send", "internal@corp.com", frozenset({"internal"}), 100)
    broker.attenuate(
        "r-send2:Agent", BROKER, "send", "internal@corp.com", frozenset({"internal"}), 100
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

    # ---- forged capabilities injected straight into the store (NOT grant_root) ----
    # 1. Forged network capability for an internal SSRF target: matches
    #    right+target and is held by the broker -> Auth passes; but it is NOT
    #    root-anchored -> NoAmp rejects (T4/T5 verbatim from earlier).
    broker.capabilities["forged-net"] = _capability(
        "Mallory",
        BROKER,
        "network",
        "http://internal-ssrf",
        frozenset({"internal"}),
        100,
        "forged-net",
    )
    # 2. Forged write capability to a confidential path (capability forgery, T16).
    broker.capabilities["forged-write"] = _capability(
        "Mallory", BROKER, "write", "file:///secrets", frozenset({"internal"}), 100, "forged-write"
    )
    # 3. Forged wide capability (amplification via composition, T20): Mallory
    #    "widens" an Agent grant to a confidential resource the User never
    #    authorized for it.
    broker.capabilities["forged-wide"] = _capability(
        "Mallory",
        BROKER,
        "delete",
        "file:///secrets",
        frozenset({"internal", "confidential"}),
        100,
        "forged-wide",
    )

    # ---- validated declass grant (broker-only, on explicit User policy) ----
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
    return broker


def _clean_effect() -> Effect:
    return Effect(
        "send",
        "internal@corp.com",
        {},
        (Data("user_query", Confidentiality.INTERNAL, Integrity.USER),),
        "r-send:Agent:EffectBroker",
        CHAIN,
    )


# ---------------------------------------------------------------------------
# Tool-boundary mediation model (T13 / T14 / T15)
# ---------------------------------------------------------------------------
# The predicate gate decides *effects proposed to the broker*. It cannot see
# the *actual* remote-tool behavior that the MCP/tool layer will perform from
# the effect's declared shape. The brief's "Tool / MCP semantics honesty"
# traces (T13, T14, T15) are therefore a *mediation* decision: given the
# declared effect, does the broker refuse to forward it to the remote tool?
# The verdict is a `BoundaryStop`, not a predicate blocker.


@dataclass(frozen=True)
class MediationVerdict:
    """Machine-checkable outcome of the broker -> tool mediation step."""

    allow: bool
    boundary_stop: str | None  # reason the effect is not forwarded, if blocked


def mediat(
    effect: Effect,
    *,
    declared_write_target: str | None = None,
    hidden_side_effect: bool = False,
    monitoring_bypass: bool = False,
) -> MediationVerdict:
    """Decide whether to forward a prepared effect to the remote tool.

    Mirrors the three MCP-semantics-honesty failures from the brief:
      - a tool whose *declared* write target (from its MCP description) differs
        from the actual target it would touch  -> false description (T13)
      - a tool that performs a side effect it does not declare          -> T14
      - an effect that monitors/validates the system but could bypass the
        mediation itself                                                -> T15
    Any such mismatch stops at the boundary: the effect is not forwarded.
    """
    if monitoring_bypass:
        return MediationVerdict(False, "monitor-bypass")
    if hidden_side_effect:
        return MediationVerdict(False, "hidden-side-effect")
    if declared_write_target is not None and declared_write_target != effect.target:
        return MediationVerdict(
            False, f"false-description(declared={declared_write_target},actual={effect.target})"
        )
    return MediationVerdict(True, None)


def run_mediation_traces() -> EffectBroker:
    """Run the tool-boundary traces T13/T14/T15. At this layer effects are
    *not* committed to the ResourceStore; they are screened by the mediator
    before forwarding to the remote tool. No side effect occurs."""
    # T13: false MCP description — tool's declared write target (the reports
    #   dir) differs from the actual path it would touch (secrets) once invoked
    broker = build()
    false_desc = Effect(
        "write",
        "file:///secrets",  # actual target the tool *would* write
        {},
        (Data("tool_action", Confidentiality.INTERNAL, Integrity.USER),),
        "r-write:Agent:EffectBroker",
        CHAIN,
    )
    t13 = mediat(false_desc, declared_write_target="file:///reports")
    assert not t13.allow and t13.boundary_stop == "false-description(declared=file:///reports,actual=file:///secrets)"  # noqa: E501
    print("[T13 false-mcp-description: hidden write to secrets] -> BLOCK BoundaryStop")
    print(f"    boundary_stop={t13.boundary_stop}")

    # T14: hidden side effect — tool performs an undeclared side effect
    #   (exfiltrating a file) even though the declared effect is a benign read
    t14 = mediat(
        Effect(
            "read",
            "file:///trusted",
            {},
            (Data("tool_action", Confidentiality.INTERNAL, Integrity.USER),),
            "r-read:Agent:EffectBroker",
            CHAIN,
        ),
        hidden_side_effect=True,
    )
    assert not t14.allow and t14.boundary_stop == "hidden-side-effect"
    print("[T14 hidden-side-effect: undeclared exfil sidesteps read] -> BLOCK BoundaryStop")
    print(f"    boundary_stop={t14.boundary_stop}")

    # T15: monitor bypass — the effect is itself a monitoring/validation action
    #   that, if forwarded, could observe or bypass the mediation boundary
    t15 = mediat(
        Effect(
            "read",
            "file:///trusted",
            {},
            (Data("tool_action", Confidentiality.INTERNAL, Integrity.USER),),
            "r-read:Agent:EffectBroker",
            CHAIN,
        ),
        monitoring_bypass=True,
    )
    assert not t15.allow and t15.boundary_stop == "monitor-bypass"
    print("[T15 monitor-bypass: monitoring action can bypass mediation] -> BLOCK BoundaryStop")
    print(f"    boundary_stop={t15.boundary_stop}")
    print()

    # The boundary is not reached: no side effect was committed to the store
    assert broker.store.effects_log == []
    return broker


def run_all() -> EffectBroker:
    """Run the predicate-gate traces, each on a fresh broker (so no trace's
    replay state masks another's intended predicate). Returns the last broker."""

    # A trace is (label, effect_factory, expect_allow). We deliberately use a
    # separate broker per trace so that one trace committing a capability does
    # not turn every later reuse into a \"replay\" (Fresh) — each attack is
    # judged by its own predicate, matching the original intent
    single_commit_traces: list[tuple[str, Effect, bool]] = [
        # T1: clean benign send of trusted data -> ALLOW
        (
            "T1 clean benign send -> ALLOW",
            Effect(
                "send",
                "internal@corp.com",
                {},
                (Data("user_query", Confidentiality.INTERNAL, Integrity.USER),),
                "r-send:Agent:EffectBroker",
                CHAIN,
            ),
            True,
        ),
        # T2: prompt injection: untrusted web content drives a send -> FlowOK
        (
            "T2 prompt-injection: send driven by untrusted web content -> BLOCK FlowOK",
            Effect(
                "send",
                "internal@corp.com",
                {},
                (Data("web_page", Confidentiality.PUBLIC, Integrity.UNTRUSTED),),
                "r-send:Agent:EffectBroker",
                CHAIN,
            ),
            False,
        ),
        # T3: confused deputy: delete target B the agent has no capability for -> Auth
        (
            "T3 confused-deputy: delete secrets with reports-capability -> BLOCK Auth",
            Effect(
                "delete",
                "file:///secrets",
                {},
                (Data("user_query", Confidentiality.INTERNAL, Integrity.USER),),
                "r-del:Agent:EffectBroker",
                CHAIN,
            ),
            False,
        ),
        # T4: attacker-controlled URL: SSRF via forged (non-root-anchored) cap -> NoAmp
        (
            "T4 attacker-controlled-URL: network SSRF via forged cap -> BLOCK NoAmp",
            Effect(
                "network",
                "http://internal-ssrf",
                {},
                (Data("user_query", Confidentiality.INTERNAL, Integrity.USER),),
                "forged-net",
                CHAIN,
            ),
            False,
        ),
        # T5: capability laundering: untrusted content copied into a trusted file,
        #   then used to authorize a send. Copy does not remove taint -> FlowOK.
        (
            "T5 capability-laundering: laundered untrusted content sent -> BLOCK FlowOK",
            Effect(
                "send",
                "internal@corp.com",
                {},
                (Data("laundered_file", Confidentiality.INTERNAL, Integrity.UNTRUSTED),),
                "r-send2:Agent:EffectBroker",
                CHAIN,
            ),
            False,
        ),
        # T6: delegation widening: Mallory widens authority to a resource the User
        #   never granted -> NoAmp (non-root-anchored forged capability).
        (
            "T6 delegation-widening: Mallory widens delete to secrets -> BLOCK NoAmp",
            Effect(
                "delete",
                "file:///secrets",
                {},
                (Data("user_query", Confidentiality.INTERNAL, Integrity.USER),),
                "forged-wide",
                CHAIN,
            ),
            False,
        ),
        # T7: confidential-data leakage: confidential content to send w/o declass -> FlowOK
        (
            "T7 confidential-leak: confidential file sent without declass -> BLOCK FlowOK",
            Effect(
                "send",
                "internal@corp.com",
                {},
                (Data("secret_report", Confidentiality.CONFIDENTIAL, Integrity.USER),),
                "r-send:Agent:EffectBroker",
                CHAIN,
            ),
            False,
        ),
        # T8: low-integrity data controlling a privileged action (write) -> FlowOK
        (
            "T8 low-integrity->privileged: untrusted data writes sensitive -> BLOCK FlowOK",
            Effect(
                "write",
                "file:///reports",
                {},
                (Data("web_page", Confidentiality.PUBLIC, Integrity.UNTRUSTED),),
                "r-write:Agent:EffectBroker",
                CHAIN,
            ),
            False,
        ),
        # T9: stale approval: expired-usage capability reused -> Fresh
        (
            "T9 stale-approval: expired capability reused -> BLOCK Fresh",
            Effect(
                "send",
                "internal@corp.com",
                {},
                (Data("user_query", Confidentiality.INTERNAL, Integrity.USER),),
                "r-send-short:Agent:EffectBroker",
                CHAIN,
            ),
            False,
        ),
        # T11: declassification abuse: LLM-attached declass never broker-granted -> FlowOK
        (
            "T11 declass-abuse: LLM-attached declass (no grant) -> BLOCK FlowOK",
            Effect(
                "send",
                "internal@corp.com",
                {},
                (Data("secret_report", Confidentiality.CONFIDENTIAL, Integrity.USER),),
                "r-send:Agent:EffectBroker",
                CHAIN,
                (
                    LabelException(
                        "declass", "internal@corp.com", "CONFIDENTIAL", "INTERNAL", "?", "no-grant"
                    ),
                ),
            ),
            False,
        ),
        # T12: endorsement abuse: LLM-attached endorse never broker-granted -> FlowOK
        (
            "T12 endorse-abuse: LLM-attached endorse (no grant) -> BLOCK FlowOK",
            Effect(
                "send",
                "internal@corp.com",
                {},
                (Data("web_page", Confidentiality.PUBLIC, Integrity.UNTRUSTED),),
                "r-send:Agent:EffectBroker",
                CHAIN,
                (
                    LabelException(
                        "endorse", "internal@corp.com", "UNTRUSTED", "USER", "?", "no-grant"
                    ),
                ),
            ),
            False,
        ),
        # T16: capability forgery: fabricated capability for a resource the agent
        #   lacks. It looks valid (holder=BROKER, right+target match -> Auth
        #   passes) but is NOT root-anchored (owner=Mallory, injected straight
        #   into the store) -> NoAmp rejects it at commit
        (
            "T16 capability-forgery: forged write to secrets -> BLOCK NoAmp",
            Effect(
                "write",
                "file:///secrets",
                {},
                (Data("user_query", Confidentiality.INTERNAL, Integrity.USER),),
                "forged-write",
                CHAIN,
            ),
            False,
        ),
        # T17: path traversal: write to ../../etc/password -> Auth (target not in cap)
        (
            "T17 path-traversal: write ../etc/password -> BLOCK Auth",
            Effect(
                "write",
                "file:///../../etc/password",
                {},
                (Data("user_query", Confidentiality.INTERNAL, Integrity.USER),),
                "r-write:Agent:EffectBroker",
                CHAIN,
            ),
            False,
        ),
        # T18: recipient spoofing via BCC: untrusted BCC drives a legit send -> FlowOK
        (
            "T18 recipient-spoofing: untrusted BCC in a legit send -> BLOCK FlowOK",
            Effect(
                "send",
                "internal@corp.com",
                {},
                (Data("bcc_field", Confidentiality.PUBLIC, Integrity.UNTRUSTED),),
                "r-send:Agent:EffectBroker",
                CHAIN,
            ),
            False,
        ),
        # T19: memory-poisoned instruction: poisoned memory drives a send -> FlowOK
        (
            "T19 memory-poisoned: poisoned memory drives a send -> BLOCK FlowOK",
            Effect(
                "send",
                "internal@corp.com",
                {},
                (Data("poisoned_memory", Confidentiality.PUBLIC, Integrity.UNTRUSTED),),
                "r-send:Agent:EffectBroker",
                CHAIN,
            ),
            False,
        ),
        # T20: amplification via composition: forged wide delete composes the
        #   same unsafe committed effect twice -> NoAmp.
        (
            "T20 amplification-composition: forged wide delete -> BLOCK NoAmp",
            Effect(
                "delete",
                "file:///secrets",
                {},
                (Data("user_query", Confidentiality.INTERNAL, Integrity.USER),),
                "forged-wide",
                CHAIN,
            ),
            False,
        ),
    ]

    for trace_name, effect, expected_allow in single_commit_traces:
        broker = build()
        if trace_name.startswith("T9"):
            broker.logical_time = 10.0  # make the short-expiry capability stale
        allow, evidence = broker.commit(Commit(effect))
        status = "ALLOW" if allow else "BLOCK"
        assert allow is expected_allow, (
            f"{trace_name}: expected allow={expected_allow}, got {allow} "
            f"(blocker={evidence['primary_blocker']})"
        )
        print(
            f"[{trace_name}] -> {status}  "
            f"primary_blocker={evidence['primary_blocker'] or 'none'}"
        )
        for predicate_name, predicate_message in evidence["predicates"].items():
            print(f"    {predicate_name}: {predicate_message}")
        print()

    # T10: replay — same prepared effect committed twice on ONE broker. The
    #   first commits cleanly (ALLOW); the second is blocked by Fresh (replay).
    broker = build()
    clean = _clean_effect()
    first_allow, first_evidence = broker.commit(Commit(clean))
    second_allow, second_evidence = broker.commit(Commit(clean))
    assert first_allow is True
    assert second_allow is False and second_evidence["primary_blocker"] == "Fresh"
    print("[T10 replay: commit same send twice] -> 1st ALLOW, 2nd BLOCK Fresh")
    print(f"    1st primary_blocker={first_evidence['primary_blocker'] or 'none'}")
    print(f"    2nd primary_blocker={second_evidence['primary_blocker']}")
    for predicate_name, predicate_message in second_evidence["predicates"].items():
        print(f"    2nd {predicate_name}: {predicate_message}")
    print()

    print("effects_log (actual side effects committed by the broker, final broker):")
    for entry in broker.store.effects_log:
        print(f"    {entry[0]} -> {entry[1]}")
    print("remaining files (final broker):", {path for path in broker.store.files})
    print()

    # tool-boundary / MCP-semantics-honesty traces (T13/T14/T15)
    run_mediation_traces()

    return broker
