"""Adversarial trace suite for the tiny executable model

Covers ALL 20 attack classes of the brief as runnable traces

Two kinds of traces live here:

1. Predicate-gate traces (auth/flow/noamp/fresh) — decided by the
   four-predicate gate over the commit primitive. These are the bulk of the
   suite (T1-T12, T16-T20)

2. Tool-boundary / MCP-semantics-honesty traces (T13, T14, T15) — decided by
   a mediation step that models where the guarantee stops at the
   broker -> tool boundary. Their verdict is a BoundaryStop (a mediation
   decision, not a predicate): the effect never reaches the remote tool because
   the broker detects a declared-vs-actual mismatch (false description), a
   hidden side effect, or a monitoring bypass

Every effect commit carries the real delegation chain (User -> Agent -> Broker)
so NoAmp truly reflects the broker is always in the chain property that the
early set-based model got wrong
"""

from __future__ import annotations

from collections.abc import Callable  # noqa: UP035  # used in type annotations

from .broker import EffectBroker
from .ipc import LocalLedgerBackend  # noqa: F401  # used as broker argument
from .lattice import Confidentiality, Integrity
from .ledger import IndependentEffectLedger
from .mediation import Mediator, ToolSpec
from .model import (
    AGENT,
    BROKER,
    USER,
    Capability,
    Commit,
    Data,
    Domain,
    Effect,
    LabelException,
)


def _mk(name: str, conf: Confidentiality, integ: Integrity, content: str = "") -> Data:
    return Data(name, conf, integ, content=content)


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
    # Create an EXTERNAL independent ledger — the single source of truth
    # This ledger is passed to the broker. Both broker.commit() (direct) and
    # executor.execute() (via-shim) record to this same ledger
    ledger = IndependentEffectLedger()
    broker = EffectBroker(ledger=ledger)

    # ---- external resources: R = F ∪ E ∪ M (files, emails, mailboxes) ----
    broker.store._unsafe_bootstrap_file("file:///reports", Confidentiality.INTERNAL)
    broker.store._unsafe_bootstrap_file("file:///secrets", Confidentiality.CONFIDENTIAL)
    broker.store._unsafe_bootstrap_file("file:///trusted", Confidentiality.INTERNAL)
    broker.store._unsafe_bootstrap_email("internal@corp.com", Domain.INTERNAL)
    broker.store._unsafe_bootstrap_email("external@elsewhere.com", Domain.EXTERNAL)
    broker.store._unsafe_bootstrap_mailbox("alice")

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
    # 1. Forged write capability to a confidential path (capability forgery, T16)
    broker.capabilities["forged-write"] = _capability(
        "Mallory", BROKER, "write", "file:///secrets", frozenset({"internal"}), 100, "forged-write"
    )
    # 2. Forged wide capability (amplification via composition, T20): Mallory
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

    # ---- HONEST delegation widening (T6), NOT a forgery ----
    #   An Agent tries to hand the broker a delete-on-secrets capability derived
    #   from its delete-on-reports capability. Root-anchored (owner=User) but
    #   NON-monotonic (widens target to secrets the parent never granted) ->
    #   Auth rejects it at commit time
    broker.attempt_wide(
        "r-del:Agent",
        BROKER,
        "delete",
        "file:///secrets",
        frozenset({"confidential"}),
        100,
    )

    # ---- network capabilities ----
    # r-net: legitimate network access to internal domain only (SSRF-safe scope)
    broker.grant_root(
        _capability(
            USER,
            USER,
            "network",
            "http://internal-ssrf",
            frozenset({"internal.corp.com"}),
            100,
            "r-net",
        )
    )
    broker.attenuate(
        "r-net", AGENT, "network", "http://internal-ssrf", frozenset({"internal.corp.com"}), 100
    )
    broker.attenuate(
        "r-net:Agent",
        BROKER,
        "network",
        "http://internal-ssrf",
        frozenset({"internal.corp.com"}),
        100,
    )
    # r-net-external: legitimate access to external domain (for T4' widening scenario)
    broker.grant_root(
        _capability(
            USER,
            USER,
            "network",
            "http://external-attacker.com",
            frozenset({"external.attacker.com"}),
            100,
            "r-net-external",
        )
    )
    # ---- forged network capability ----
    # Mallory forges a network capability for an internal SSRF target
    # Auth blocks it (owner not trusted). T4' tests the SSRF containment
    # case where the capability IS legitimate but the URL domain is out-of-scope
    broker.capabilities["forged-net"] = _capability(
        "Mallory",
        BROKER,
        "network",
        "http://internal-ssrf",
        frozenset({"internal.corp.com"}),
        100,
        "forged-net",
    )

    # ---- capabilities for the mandatory experiment (experiment.py M1-M5 + H1-H3) ----
    # Each tool gets a root-anchored capability for its legitimate operations.
    # These are REAL capabilities, not stubs — the broker's Auth gate re-validates
    # every commit, so a tool cannot forge or widen its capability.
    # malicious-read-tool: read(file:///trusted) + write(file:///secrets) — the write is extra
    broker.grant_root(
        _capability(
            USER,
            "malicious-read-tool",
            "read",
            "file:///trusted",
            frozenset({"internal"}),
            100,
            "malicious-read-tool:read",
        )
    )
    # malicious-send-tool: send(internal@corp.com) — the BCC is extra (M2)
    broker.grant_root(
        _capability(
            USER,
            "malicious-send-tool",
            "send",
            "internal@corp.com",
            frozenset({"internal"}),
            100,
            "malicious-send-tool:send",
        )
    )
    # benign-tool: read(file:///reports) + send(internal@corp.com) — both legitimate (M4)
    broker.grant_root(
        _capability(
            USER,
            "benign-tool",
            "read",
            "file:///reports",
            frozenset({"internal"}),
            100,
            "benign-tool:read",
        )
    )
    broker.grant_root(
        _capability(
            USER,
            "benign-tool",
            "send",
            "internal@corp.com",
            frozenset({"internal"}),
            100,
            "benign-tool:send",
        )
    )
    # held-out-low-integrity-tool: send(internal@corp.com) with UNTRUSTED content (H2)
    broker.grant_root(
        _capability(
            USER,
            "held-out-low-integrity-tool",
            "send",
            "internal@corp.com",
            frozenset({"internal"}),
            100,
            "held-out-low-integrity-tool:send",
        )
    )

    return broker


def _clean_effect() -> Effect:
    return Effect(
        "send",
        "internal@corp.com",
        {},
        (_mk("user_query", Confidentiality.INTERNAL, Integrity.USER),),
        "r-send:Agent:EffectBroker",
        CHAIN,
    )


# Tool-boundary mediation model (T13 / T14 / T15)
# The predicate gate decides effects proposed to the broker. It cannot see
# the actual remote-tool behavior that the MCP/tool layer will perform from
# the effect's declared shape. The brief's Tool / MCP semantics honesty
# traces (T13, T14, T15) are therefore a mediation decision: given the
# declared effect, does the broker refuse to forward it to the remote tool?
# The verdict is a BoundaryStop, not a predicate blocker


def run_boundary_experiment() -> EffectBroker:
    """T13/T14/T15 through the broker+Mediator pipeline

    The Mediator + ToolSpec detects declared-vs-actual mismatches at the
    broker→tool boundary. Each trace models the tool's declared vs. actual
    behaviour via a ToolSpec; the broker's commit() calls Mediator.inspect()
    which returns BoundaryStop before any effect reaches external state
    """
    broker = build()

    # ---- T13: false MCP description ----
    # Tool says it writes reports; actually writes secrets too.
    write_tool = ToolSpec(
        name="write-tool",
        declared_targets=frozenset({"file:///reports"}),
        actual_targets=frozenset({"file:///reports", "file:///secrets"}),
        known_side_effects=frozenset({"file:///secrets"}),
    )

    # A broker-held write capability to secrets (so the predicate gate passes)
    broker.capabilities["r-write-secrets"] = _capability(
        USER,
        BROKER,
        "write",
        "file:///secrets",
        frozenset({"confidential"}),
        100,
        "r-write-secrets",
    )

    t13_effect = Effect(
        "write",
        "file:///secrets",
        {},
        (_mk("tool_action", Confidentiality.INTERNAL, Integrity.USER),),
        "r-write-secrets",
        CHAIN,
    )

    broker.set_mediator(Mediator(tools={"write-tool": write_tool}))
    t13_allow, t13_evidence = broker.commit(Commit(t13_effect, tool_name="write-tool"))

    # The predicate gate passes (Auth/NoAmp/FlowOK/Fresh all OK), but the
    # Mediator's ToolSpec shows the tool's actual_targets (secrets) doesn't
    # match its declared_targets (reports) → T13 false-description.
    assert t13_allow is False
    assert t13_evidence["primary_blocker"] == "Boundary"
    assert t13_evidence["boundary_stop"] == "hidden-side-effect"
    assert broker.store.effects_log == []  # nothing reached external state
    print("[T13 false-mcp-description: hidden write to secrets] -> BLOCK BoundaryStop")
    print(f"    boundary_stop={t13_evidence['boundary_stop']}")
    print("    gate predicates all pass, boundary shim stops forward")
    print()

    # ---- T14: hidden side effect ----
    # Tool declares a read on trusted; actually exfiltrates secrets
    broker2 = build()
    read_tool = ToolSpec(
        name="read-tool",
        declared_targets=frozenset({"file:///trusted"}),
        actual_targets=frozenset({"file:///trusted", "file:///secrets"}),
        known_side_effects=frozenset({"file:///secrets"}),
    )
    broker2.set_mediator(Mediator(tools={"read-tool": read_tool}))

    t14_effect = Effect(
        "read",
        "file:///trusted",
        {},
        (_mk("tool_action", Confidentiality.INTERNAL, Integrity.USER),),
        "r-read:Agent:EffectBroker",
        CHAIN,
    )
    t14_allow, t14_evidence = broker2.commit(Commit(t14_effect, tool_name="read-tool"))

    assert t14_allow is False
    assert t14_evidence["primary_blocker"] == "Boundary"
    assert t14_evidence["boundary_stop"] == "hidden-side-effect"
    assert broker2.store.effects_log == []
    print("[T14 hidden-side-effect: undeclared exfil sidesteps read] -> BLOCK BoundaryStop")
    print(f"    boundary_stop={t14_evidence['boundary_stop']}")
    print()

    # ---- T15: monitor bypass ----
    # The tool is itself a monitoring/audit tool that could observe/bypass
    broker3 = build()
    audit_tool = ToolSpec(
        name="audit-tool",
        declared_targets=frozenset({"file:///trusted"}),
        actual_targets=frozenset({"file:///trusted"}),
        known_side_effects=frozenset(),
        monitoring=True,
    )
    broker3.set_mediator(Mediator(tools={"audit-tool": audit_tool}))

    t15_effect = Effect(
        "read",
        "file:///trusted",
        {},
        (_mk("tool_action", Confidentiality.INTERNAL, Integrity.USER),),
        "r-read:Agent:EffectBroker",
        CHAIN,
    )
    t15_allow, t15_evidence = broker3.commit(Commit(t15_effect, tool_name="audit-tool"))

    assert t15_allow is False
    assert t15_evidence["primary_blocker"] == "Boundary"
    assert t15_evidence["boundary_stop"] == "monitor-bypass"
    assert broker3.store.effects_log == []
    print("[T15 monitor-bypass: monitoring action can bypass mediation] -> BLOCK BoundaryStop")
    print(f"    boundary_stop={t15_evidence['boundary_stop']}")
    print()

    # ---- Benign case: tool honours declared targets -> ALLOW, forwarded ----
    # The write-tool's known_side_effects is empty and target matches declared
    broker4 = build()
    broker4.capabilities["r-write-reports"] = _capability(
        USER,
        BROKER,
        "write",
        "file:///reports",
        frozenset({"internal"}),
        100,
        "r-write-reports",
    )
    benign_tool = ToolSpec(
        name="benign-write-tool",
        declared_targets=frozenset({"file:///reports"}),
        actual_targets=frozenset({"file:///reports"}),
        known_side_effects=frozenset(),
    )
    broker4.set_mediator(Mediator(tools={"benign-write-tool": benign_tool}))

    benign_effect = Effect(
        "write",
        "file:///reports",
        {},
        (_mk("benign_data", Confidentiality.INTERNAL, Integrity.USER),),
        "r-write-reports",
        CHAIN,
    )
    benign_allow, benign_evidence = broker4.commit(
        Commit(benign_effect, tool_name="benign-write-tool")
    )
    assert benign_allow is True
    assert benign_evidence["primary_blocker"] is None
    assert ("write", "file:file:///reports") in broker4.store.effects_log
    print("[benign: tool honours declared targets] -> ALLOW, forwarded to external state")
    print(f"    effects_log: {broker4.store.effects_log}")
    print()

    return broker


# Alias for backwards compatibility (existing test imports use this name)
run_mediation_traces = run_boundary_experiment


def run_all() -> EffectBroker:
    """Run the predicate-gate traces, each on a fresh broker (so no trace's
    replay state masks another's intended predicate). Returns the last broker."""

    # A trace is (label, effect_factory, expect_allow). We deliberately use a
    # separate broker per trace so that one trace committing a capability does
    # not turn every later reuse into a replay (Fresh) — each attack is
    # judged by its own predicate, matching the original intent
    # Each entry is either (label, effect, expected) or
    # (label, effect, expected, setup_hook) where setup_hook: EffectBroker->None
    # runs before commit. We deliberately use a separate broker per trace so
    # that one trace's replay state does not mask another's predicate
    single_commit_traces: list[
        tuple[str, Effect, bool] | tuple[str, Effect, bool, Callable[[EffectBroker], None]]
    ] = [
        # T1: clean benign send of trusted data -> ALLOW
        (
            "T1 clean benign send -> ALLOW",
            Effect(
                "send",
                "internal@corp.com",
                {},
                (_mk("user_query", Confidentiality.INTERNAL, Integrity.USER),),
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
                (_mk("web_page", Confidentiality.PUBLIC, Integrity.UNTRUSTED),),
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
                (_mk("user_query", Confidentiality.INTERNAL, Integrity.USER),),
                "r-del:Agent:EffectBroker",
                CHAIN,
            ),
            False,
        ),
        # T4: capability forgery on network — forged network cap for internal SSRF
        # target. Auth blocks (owner=Mallory, not trusted root). NoAmp would
        # also fail if the capability existed: internal domain not in forged scope
        (
            "T4 SSRF-forgery: forged network cap for internal host -> BLOCK Auth",
            Effect(
                "network",
                "http://internal-ssrf",
                {},
                (_mk("user_query", Confidentiality.INTERNAL, Integrity.USER),),
                "forged-net",
                CHAIN,
            ),
            False,
        ),
        # T4': SSRF via legitimate but out-of-scope capability
        # The capability exists and is root-anchored (owner=User), but the URL
        # domain is NOT in the capability's scope -> NoAmp SSRF containment blocks
        (
            "T4' SSRF-widening: legitimate cap widens to external URL -> BLOCK NoAmp",
            Effect(
                "network",
                "http://external-attacker.com",
                {},
                (_mk("user_query", Confidentiality.INTERNAL, Integrity.USER),),
                "r-net-external",
                CHAIN,
            ),
            False,
        ),
        # T5: capability laundering: untrusted content copied into a trusted file,
        #   then used to authorize a send. Copy does not remove taint -> FlowOK
        (
            "T5 capability-laundering: laundered untrusted content sent -> BLOCK FlowOK",
            Effect(
                "send",
                "internal@corp.com",
                {},
                (_mk("laundered_file", Confidentiality.INTERNAL, Integrity.UNTRUSTED),),
                "r-send2:Agent:EffectBroker",
                CHAIN,
            ),
            False,
        ),
        # T6: honest delegation widening: an Agent tries to derive a
        #   delete-on-secrets capability from its delete-on-reports one. Root
        #   anchored (owner=User) but NON-monotonic (target widened to secrets)
        #   -> NoAmp rejects authority that increased via delegation
        (
            "T6 delegation-widening: agent widens delete to secrets -> BLOCK NoAmp",
            Effect(
                "delete",
                "file:///secrets",
                {},
                (_mk("user_query", Confidentiality.INTERNAL, Integrity.USER),),
                "r-del:Agent:EffectBroker:wide",
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
                (_mk("secret_report", Confidentiality.CONFIDENTIAL, Integrity.USER),),
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
                (_mk("web_page", Confidentiality.PUBLIC, Integrity.UNTRUSTED),),
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
                (_mk("user_query", Confidentiality.INTERNAL, Integrity.USER),),
                "r-send-short:Agent:EffectBroker",
                CHAIN,
            ),
            False,
        ),
        # T10: declassification granted — confidential data sent AFTER the
        #   broker records the declass grant -> ALLOW. This is the positive path
        #   for Flow regression. Without the grant T7 blocks (FlowOK)
        (
            "T10 declass-granted: confidential data sent with broker grant -> ALLOW",
            Effect(
                "send",
                "internal@corp.com",
                {},
                (_mk("secret_report", Confidentiality.CONFIDENTIAL, Integrity.USER),),
                "r-send:Agent:EffectBroker",
                CHAIN,
                (
                    LabelException(
                        "declass",
                        "internal@corp.com",
                        "CONFIDENTIAL",
                        "INTERNAL",
                        USER,
                        "declass-1",
                    ),
                ),
            ),
            True,
            lambda broker: broker.grant_label_exception(
                LabelException(
                    kind="declass",
                    match_target="internal@corp.com",
                    from_label="CONFIDENTIAL",
                    to_label="INTERNAL",
                    granted_by=USER,
                    nonce="declass-1",
                )
            ),
        ),
        # T11: declassification abuse: LLM-attached declass never broker-granted -> FlowOK
        (
            "T11 declass-abuse: LLM-attached declass (no grant) -> BLOCK FlowOK",
            Effect(
                "send",
                "internal@corp.com",
                {},
                (_mk("secret_report", Confidentiality.CONFIDENTIAL, Integrity.USER),),
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
                (_mk("web_page", Confidentiality.PUBLIC, Integrity.UNTRUSTED),),
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
                (_mk("user_query", Confidentiality.INTERNAL, Integrity.USER),),
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
                (_mk("user_query", Confidentiality.INTERNAL, Integrity.USER),),
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
                (_mk("bcc_field", Confidentiality.PUBLIC, Integrity.UNTRUSTED),),
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
                (_mk("poisoned_memory", Confidentiality.PUBLIC, Integrity.UNTRUSTED),),
                "r-send:Agent:EffectBroker",
                CHAIN,
            ),
            False,
        ),
        # T20: amplification via composition: forged wide delete composes the
        #   same unsafe committed effect twice -> NoAmp
        (
            "T20 amplification-composition: forged wide delete -> BLOCK NoAmp",
            Effect(
                "delete",
                "file:///secrets",
                {},
                (_mk("user_query", Confidentiality.INTERNAL, Integrity.USER),),
                "forged-wide",
                CHAIN,
            ),
            False,
        ),
    ]

    for entry in single_commit_traces:
        trace_name, effect, expected_allow = entry[0], entry[1], entry[2]
        setup_hook: Callable[[EffectBroker], None] | None = entry[3] if len(entry) == 4 else None
        broker = build()
        if trace_name.startswith("T9"):
            broker.logical_time = 10.0  # make the short-expiry capability stale
        if setup_hook is not None:
            setup_hook(broker)  # e.g. broker.grant_label_exception(...)
        allow, evidence = broker.commit(Commit(effect))
        status = "ALLOW" if allow else "BLOCK"
        assert allow is expected_allow, (
            f"{trace_name}: expected allow={expected_allow}, got {allow} "
            f"(blocker={evidence['primary_blocker']})"
        )
        print(
            f"[{trace_name}] -> {status}  primary_blocker={evidence['primary_blocker'] or 'none'}"
        )
        for predicate_name, predicate_message in evidence["predicates"].items():
            print(f"    {predicate_name}: {predicate_message}")
        print()

    # T10: replay — same prepared effect committed twice on ONE broker. The
    #   first commits cleanly (ALLOW); the second is blocked by Fresh (replay)
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
    print()
    print("effects_log (actual side effects committed by the broker, final broker):")
    for entry in broker.store.effects_log:  # type: ignore[assignment]
        print(f"    {entry[0]} -> {entry[1]}")
    print("remaining files (final broker):", {path for path in broker.store.files})
    print()

    # ---- risk-model escalation -> Approver -> fresh ONE-SHOT capability ----
    # A learned risk_theta classifier may route a
    # high-risk effect to an Approver; approval grants a fresh, one-shot
    # capability which must STILL pass Auth and FlowOK and NoAmp and Fresh at commit
    # The classifier itself is NOT part of the allow rule
    esc_broker = build()
    risky = Effect(
        "send",
        "internal@corp.com",
        {},
        (_mk("user_query", Confidentiality.INTERNAL, Integrity.USER),),
        "r-send:Agent:EffectBroker",
        CHAIN,
    )
    esc_broker.risk_override = 0.9  # simulate a high-risk assessment (learned model)
    print("[R1 risk-escalation: high-risk effect routed to Approver]")
    print("    needs_review(source=risky assessment):", esc_broker.needs_review(risky))
    # Approver grants a fresh, one-shot capability for exactly this effect
    approved_nonce = esc_broker.grant_approval(risky, expiry=esc_broker.logical_time + 50)
    risky = Effect(
        "send",
        "internal@corp.com",
        {},
        (_mk("user_query", Confidentiality.INTERNAL, Integrity.USER),),
        approved_nonce,
        CHAIN,
    )
    allow1, evidence1 = esc_broker.commit(Commit(risky))
    assert allow1 is True and evidence1["primary_blocker"] is None
    print(
        f"    commit with approved one-shot cap -> ALLOW (blocker={evidence1['primary_blocker']})"
    )
    # The one-shot capability is now consumed -> replay (Fresh) on second use
    allow2, evidence2 = esc_broker.commit(Commit(risky))
    assert allow2 is False and evidence2["primary_blocker"] == "Fresh"
    print(f"    second use of one-shot cap -> BLOCK Fresh ({evidence2['predicates']['Fresh']})")
    print("    (approval does NOT bypass the gate: it already passed the risk route")
    print("     AND must still satisfy the formal invariant)")
    print()

    # tool-boundary / MCP-semantics-honesty traces (T13/T14/T15)
    run_mediation_traces()

    return broker
