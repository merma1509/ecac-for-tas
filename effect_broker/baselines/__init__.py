"""Baseline comparison module.

Compares ECAC against external systems:
- CaMeL/FIDES: IFC-only
- PACT: Property attestation + capabilities
- ChainCaps: Capability transformations
- Cordon: Commit-time revalidation
- PathAllowlist: path/host allowlist (NOT a sandbox — see its docstring)
- FORGE: Policy DSL
- Allowlist: Tool pattern matching
- ArgProv: Argument provenance
"""

from __future__ import annotations

import warnings

from .mode_allowlist import AllowlistBroker
from .mode_argument_provenance import ArgumentProvenanceBroker
from .mode_camel import CaMeLBroker
from .mode_chaincaps import ChainCapsBroker
from .mode_cordon import CordonBroker
from .mode_ecac import ECACBaselineBroker
from .mode_forge import ForgeBroker
from .mode_os_sandbox import MECHANISMS as OS_SANDBOX_MECHANISMS
from .mode_os_sandbox import NOT_IMPLEMENTED as OS_SANDBOX_OMITS
from .mode_os_sandbox import OSSandboxBroker
from .mode_pact import PACTBroker
from .mode_path_allowlist import PathAllowlistBroker

warnings.filterwarnings("ignore", message="SAME-PROCESS")

__all__ = [
    "CaMeLBroker",
    "PACTBroker",
    "ChainCapsBroker",
    "CordonBroker",
    "PathAllowlistBroker",
    "OSSandboxBroker",
    "ForgeBroker",
    "AllowlistBroker",
    "ArgumentProvenanceBroker",
    "ECACBaselineBroker",
    "COMPARATOR_MECHANISMS",
    "run_comparison",
]


#: Per-comparator statement of what is enforced versus omitted.
COMPARATOR_MECHANISMS: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "ECAC": (
        (
            "Auth: capability nonce + scope",
            "FlowOK: session taint + recorded declass",
            "NoAmp: authority monotonicity (owner != User)",
            "Fresh: nonce lifetime / replay",
            "executor-produced EffectEvidence before COMMITTED",
        ),
        (),
    ),
    "CaMeL": (
        ("IFC: untrusted provenance denied at send/write/network sinks",),
        (
            "session taint (T1 passes)",
            "replay prevention (T4 passes)",
            "capability scope (T5, T10 pass)",
            "delegation-chain verification (T6, T16 pass)",
            "recipient completeness (T3 passes)",
            "content binding (T2, T15 pass)",
        ),
    ),
    "PACT": (
        ("capability scope covers (etype, target)", "provenance recorded for audit"),
        (
            "session taint (T1 passes)",
            "replay prevention (T4 passes)",
            "recipient completeness (T3 passes)",
            "content binding (T2 passes; T9/T15 are blocked only by missing "
            "coverage, not by a content check)",
            "delegation-chain verification (T6/T16 blocked only by missing "
            "coverage, not by chain verification)",
        ),
    ),
    "ChainCaps": (
        (
            "capability scope enforcement",
            "transformation chain consulted (EXPAND widens to `*`, as documented)",
        ),
        (
            "session taint (T1 passes)",
            "replay prevention (T4, T9 pass)",
            "recipient completeness (T3 passes)",
            "content binding (T2, T15 pass)",
        ),
    ),
    "Cordon": (
        ("proposal revalidation: expiry enforced (T9 blocked)", "proposal target/etype match"),
        (
            "session taint (T1 passes)",
            "provenance / IFC (T7 passes)",
            "recipient completeness (T3 passes)",
            "replay prevention (T4 passes: no proposal to revalidate)",
            "content binding (T2, T15 pass)",
        ),
    ),
    "FORGE": (
        ("deny rule in a policy DSL (effect-type + target regex), real decision",),
        (
            "capability scope",
            "session taint",
            "replay prevention",
            "no policy for an effect type ⇒ default allow",
        ),
    ),
    "Allowlist": (
        ("tool-name + target-prefix pattern match",),
        ("everything else — the weakest baseline by design",),
    ),
    "ArgProv": (
        ("argument provenance chain checked", "untrusted provenance denies"),
        (
            "capability nonce / scope (T4, T9, T10 pass)",
            "session taint (T1, T18 pass)",
            "recipient completeness (T3 passes)",
            "content binding (T2, T15 pass)",
        ),
    ),
    "PathAllowlist": (
        ("target-path prefix allowlist (string compare)", "target-host allowlist"),
        (
            "syscall filtering (seccomp)",
            "kernel-enforced path confinement (Landlock/SELinux/seatbelt)",
            "capability system",
            "IFC / session taint",
            "recipient (BCC) scoping",
            "replay prevention",
        ),
    ),
    # The real thing: the kernel enforces this one. Entries are taken from the
    # module itself so the table cannot drift from the code that runs.
    "OS_Sandbox": (OS_SANDBOX_MECHANISMS, OS_SANDBOX_OMITS),
}


def run_comparison() -> dict[str, list[dict]]:
    """Run all baselines against adversarial traces."""
    from .traces import ADVERSARIAL_TRACES

    baselines = {
        "ECAC": ECACBaselineBroker(),
        "CaMeL": CaMeLBroker(),
        "PACT": PACTBroker(),
        "ChainCaps": ChainCapsBroker(),
        "Cordon": CordonBroker(),
        "PathAllowlist": PathAllowlistBroker(),
        "OS_Sandbox": OSSandboxBroker(),
        "FORGE": ForgeBroker(),
        "Allowlist": AllowlistBroker(),
        "ArgProv": ArgumentProvenanceBroker(),
    }

    def setup_baseline(broker, baseline_name):
        """Give each comparator the authority a real deployment would have.

        A comparator denied everything because it was handed no capabilities
        would "block" all 20 traces for the wrong reason, and the comparison
        would measure the setup rather than the mechanism. Each baseline below
        is provisioned with the SAME authority ECAC receives — the internal
        domains, the benign targets — so what each blocks is a property of its
        check, not of a missing grant.
        """
        if baseline_name == "PACT":
            # PACT: capabilities cover the legitimate/internal targets only.
            # No grant for external domains, secrets, or metadata endpoints —
            # a real deployment would not issue those either.
            for right, target in (
                ("send", "mailto:internal@corp.com"),
                ("send", "mailto:hr@corp.com"),
                ("write", "file:///audit_test.txt"),
                ("write", "file:///safe.txt"),
            ):
                broker.grant("tool_write", right, target)
                broker.grant("r-send:Agent", right, target)
                broker.grant("approval-send-hr", right, target)
                broker.grant("tool_email", right, target)

        elif baseline_name == "ChainCaps":
            from .mode_chaincaps import Capability, Transformation

            # A NARROW capability scoped to the internal domain.
            narrow = Capability(
                holder="Agent",
                right="*",
                target="internal",
                scope=frozenset({"mailto:internal@corp.com", "file:///audit_test.txt"}),
                transformations=(Transformation.NARROW.value,),
            )
            for nonce in ("r-send:Agent", "tool_write", "approval-send-hr"):
                broker.register_capability(narrow, nonce)

        elif baseline_name == "Cordon":
            import time

            from .mode_cordon import CordonProposal

            now = time.time()
            # A fresh proposal for the benign target, plus an EXPIRED one for
            # the stale-approval trace (T9) — that trace names its own nonce.
            broker.add_proposal(
                "r-send:Agent",
                CordonProposal(
                    etype="send",
                    target="mailto:internal@corp.com",
                    holder="Agent",
                    expires_at=now + 3600,
                ),
            )
            broker.add_proposal(
                "old-proposal-nonce",
                CordonProposal(
                    etype="send",
                    target="mailto:internal@corp.com",
                    holder="Agent",
                    expires_at=now - 3600,  # expired
                ),
            )
            broker.add_proposal(
                "tool_write",
                CordonProposal(
                    etype="write",
                    target="file:///audit_test.txt",
                    holder="Agent",
                    expires_at=now + 3600,
                ),
            )

    results = {name: [] for name in baselines}

    try:
        for trace in ADVERSARIAL_TRACES:
            effect = trace["effect"]
            task_id = trace["task_id"]
            name = trace["name"]

            for baseline_name, broker in baselines.items():
                if baseline_name != "ECAC":
                    setup_baseline(broker, baseline_name)

                blocked, evidence = broker.commit_effect(effect, task_id=task_id)
                results[baseline_name].append(
                    {
                        "name": name,
                        "blocked": not blocked,  # True = blocked (allowed = False)
                        "reason": evidence.get("reason", ""),
                        "policy": evidence.get("policy", ""),
                    }
                )
    finally:
        # The sandbox comparator owns a temporary fixture; without this the
        # comparison table leaks a directory per call, and `run_comparison()`
        # is called by several tests.
        sandbox_broker = baselines.get("OS_Sandbox")
        close = getattr(sandbox_broker, "close", None)
        if callable(close):
            close()

    return results


