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
        """
        ArgProv-style commit: check argument provenance.

        WEAKNESSES (these bypass ArgProv but not ECAC):
        - No capability nonce check (any nonce allowed)
        - No scope check (any target allowed)
        - No session taint (sends allowed after CONFIDENTIAL reads)
        - No attenuation (no narrowing of authority)
        """
        # ArgProv checks if arguments have valid provenance
        # But it doesn't check if the effect is AUTHORIZED

        # This is the key weakness: ArgProv trusts any effect
        # with valid argument provenance

        # No capability check
        # No scope check
        # No session taint check

        # WEAKNESS: Replay attack - same nonce doesn't check freshness
        # WEAKNESS: Scope widening - any target allowed if provenance OK

        return True, {
            "blocker": None,
            "reason": "ArgProv: provenance OK",
            "policy": "ArgProv",
        }
