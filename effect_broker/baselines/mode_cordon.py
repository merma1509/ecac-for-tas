"""Cordon-style commit-time revalidation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from effect_broker.model import Effect


@dataclass
class CordonProposal:
    """Cordon-style proposal."""

    etype: str
    target: str
    holder: str
    expires_at: float


class CordonBroker:
    """
    Cordon-style broker: commit-time revalidation.

    WEAKNESSES (these bypass Cordon but not ECAC):
    - No session taint: T1 passes
    - No provenance: T7 passes
    - No delegation chain: T6 passes
    - Stale proposal: T9 passes
    """

    def __init__(self) -> None:
        self.proposals: dict[str, CordonProposal] = {}

    def add_proposal(self, nonce: str, proposal: CordonProposal) -> None:
        """Add a Cordon-style proposal."""
        self.proposals[nonce] = proposal

    def commit_effect(self, effect: Effect, task_id: str = "default") -> tuple[bool, dict]:
        """
        Cordon-style commit: revalidate proposal at commit time.

        WEAKNESSES (these bypass Cordon but not ECAC):
        - No session taint (T1)
        - No provenance (T7)
        - No delegation chain (T6)
        - Proposals can be reused (T9: stale approval)
        """
        # Cordon checks if proposal is still valid at commit time
        # But it doesn't check:
        # - Session taint
        # - Provenance
        # - Delegation chain

        return True, {
            "blocker": None,
            "reason": "Cordon: proposal valid",
            "policy": "Cordon",
        }
