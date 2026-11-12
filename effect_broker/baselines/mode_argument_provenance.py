"""ArgProv-style argument provenance tracking.

What ArgProv provides:
- Tracks provenance of arguments (where did this value come from?)
- Verifies integrity of argument chain
- No capabilities

What ECAC adds:
- Capability system with attenuation
- Session taint propagation
- Independent ledger
- Four-predicate gate
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from effect_broker.model import Effect

from effect_broker.lattice import Integrity


@dataclass
class ProvenanceNode:
    """ArgProv-style provenance data point."""

    source: str  # "user-input", "file-read", "env-var", "tool-output"
    value_hash: str  # Hash of the actual value
    integrity: Integrity = Integrity.USER


class ArgumentProvenanceBroker:
    """
    ArgProv-style broker: tracks argument provenance without capabilities.

    Key difference from ECAC:
    - Tracks argument lineage (where values come from)
    - No capability system
    - Relies on argument provenance, not authorization

    WEAKNESSES (these bypass ArgProv but not ECAC):
    - No capability nonce verification
    - No scope checking
    - No session taint
    - No attenuation
    """

    def __init__(self):
        self.provenance: dict[str, ProvenanceNode] = {}

    def record_provenance(self, arg_name: str, source: str, value_hash: str):
        """Record provenance of an argument."""
        self.provenance[arg_name] = ProvenanceNode(
            source=source,
            value_hash=value_hash,
            integrity=Integrity.USER,
        )

    def commit_effect(self, effect: Effect, task_id: str = "default") -> tuple[bool, dict]:
        """Deny when an argument's provenance chain is broken or untrusted.

        ArgProv's mechanism: every argument carries where it came from, and the
        effect is refused if any argument traces to an untrusted source without
        an endorsement. This is a real check with a real deny path — before it,
        `commit_effect` returned True unconditionally.

        Deliberately absent (each is a trace this comparator does not block):

        - **No capability nonce check**: T4, T9, T10 pass (any nonce accepted).
        - **No scope check**: T5, T11, T12 pass (any target allowed).
        - **No session taint**: T1, T18 pass.
        - **No recipient completeness**: T3 passes.
        - **No content binding**: T2, T15 pass.
        """
        # Broken chain: a recorded argument whose source is unknown.
        known_sources = {"user-input", "file-read", "env-var", "tool-output"}
        for arg_name, node in self.provenance.items():
            if node.source not in known_sources:
                return False, {
                    "blocker": "Provenance",
                    "reason": (
                        f"ArgProv: unknown provenance source {node.source!r} for {arg_name!r}"
                    ),
                    "policy": "ArgProv",
                }

        # Untrusted value reaching the effect: the chain is valid but the source
        # is untrusted and unendorsed.
        for datum in effect.provenance:
            if datum.integrity == Integrity.UNTRUSTED:
                return False, {
                    "blocker": "Provenance",
                    "reason": (f"ArgProv: argument {datum.name!r} comes from an untrusted source"),
                    "policy": "ArgProv",
                }

        return True, {
            "blocker": None,
            "reason": "ArgProv: provenance OK",
            "policy": "ArgProv",
        }
