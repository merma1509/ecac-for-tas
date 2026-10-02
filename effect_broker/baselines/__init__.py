"""Baseline comparison module.

Compares ECAC against external systems:
- CaMeL/FIDES: IFC-only
- PACT: Property attestation + capabilities
- ChainCaps: Capability transformations
- Cordon: Commit-time revalidation
- FORGE: Policy DSL
- Allowlist: Tool pattern matching
- ArgProv: Argument provenance
"""

from __future__ import annotations

import warnings

warnings.filterwarnings("ignore", message="SAME-PROCESS")

from .mode_allowlist import AllowlistBroker
from .mode_argument_provenance import ArgumentProvenanceBroker
from .mode_camel import CaMeLBroker
from .mode_chaincaps import ChainCapsBroker
from .mode_cordon import CordonBroker
from .mode_ecac import ECACBaselineBroker
from .mode_forge import ForgeBroker
from .mode_pact import PACTBroker

__all__ = [
    "CaMeLBroker",
    "PACTBroker",
    "ChainCapsBroker",
    "CordonBroker",
    "ForgeBroker",
    "AllowlistBroker",
    "ArgumentProvenanceBroker",
    "ECACBaselineBroker",
    "run_comparison",
]


def run_comparison() -> dict[str, list[dict]]:
    """Run all baselines against adversarial traces."""
    from .traces import ADVERSARIAL_TRACES

    baselines = {
        "ECAC": ECACBaselineBroker(),
        "CaMeL": CaMeLBroker(),
        "PACT": PACTBroker(),
        "ChainCaps": ChainCapsBroker(),
        "Cordon": CordonBroker(),
        "FORGE": ForgeBroker(),
        "Allowlist": AllowlistBroker(),
        "ArgProv": ArgumentProvenanceBroker(),
    }

    def setup_baseline(broker, baseline_name):
        """Setup capabilities for each baseline."""
        if baseline_name == "ECAC":
            from effect_broker.baselines.traces import _capability
            from effect_broker.model import AGENT, USER

            broker.broker.grant_root(
                _capability(
                    USER,
                    USER,
                    "write",
                    "file:///test.txt",
                    frozenset({"file:///test.txt"}),
                    100,
                    "r-write",
                )
            )
            broker.broker.attenuate(
                "r-write", AGENT, "write", "file:///test.txt", frozenset({"file:///test.txt"}), 100
            )
        elif baseline_name in (
            "CaMeL",
            "PACT",
            "ChainCaps",
            "Cordon",
            "FORGE",
            "Allowlist",
            "ArgProv",
        ):
            pass  # Baselines don't need setup

    results = {name: [] for name in baselines}

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

    return results
