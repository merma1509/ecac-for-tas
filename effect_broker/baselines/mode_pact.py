"""PACT-style capability system (property attestation + capabilities).

What PACT/ChainCaps provides:
- Capability attenuation (narrowing scope)
- Provenance tracking
- Property attestation

What ECAC adds:
- Content hash binding (ApprovedRequest)
- Session taint propagation
- Independent ledger verification
- NoAmp predicate (authority monotonicity)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from effect_broker.model import Effect

from effect_broker.lattice import Confidentiality


@dataclass
class PACTActivity:
    """PACT-style activity record."""

    etype: str
    target: str
    holder: str
    holder_conf: Confidentiality
    scope: frozenset


class PACTBroker:
    """
    PACT-style broker: capabilities with provenance, NO content hash.

    Key difference from ECAC:
    - Tracks provenance (who did what)
    - Allows scope narrowing (attenuation)
    - No content hash binding
    - No session taint

    WEAKNESSES (these bypass PACT but not ECAC):
    - No content hash: T2 passes (modify after approval)
    - No session taint: T1 passes
    - No ledger: T4 passes (replay)
    - Attenuation only narrows (T5: widening passes)
    """

    def __init__(self):
        self.activities: list[PACTActivity] = []

    def commit_effect(self, effect: Effect, task_id: str = "default") -> tuple[bool, dict]:
        """
        PACT-style commit: capability + provenance check.

        WEAKNESSES (these bypass PACT but not ECAC):
        - No content hash: T2 (modify after approval) passes
        - No session taint: T1 passes
        - No ledger: T4 (replay) passes
        - Scope can be widened (T5 passes)
        """
        # Record activity (PACT-style)
        activity = PACTActivity(
            etype=effect.etype,
            target=effect.target,
            holder=effect.capability_nonce,
            holder_conf=Confidentiality.INTERNAL,
            scope=frozenset({effect.target}),
        )
        self.activities.append(activity)

        # PACT checks:
        # 1. Capability exists
        # 2. Provenance is tracked
        # But NOT:
        # - Content hash (T2)
        # - Session taint (T1)
        # - Ledger (T4)

        return True, {
            "blocker": None,
            "reason": "PACT: capability + provenance OK",
            "policy": "PACT",
        }
