"""Cordon-style commit-time revalidation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from effect_broker.model import Effect

from effect_broker.lattice import Confidentiality


@dataclass
class CordonProposal:
    """Cordon-style proposal."""

    etype: str
    target: str
    holder: str
    expires_at: float
    content_hash: str | None = None  # Optional content binding


class CordonBroker:
    """
    Cordon-style broker: commit-time revalidation.

    WEAKNESSES (these bypass Cordon but not ECAC):
    - No session taint: T1 passes
    - No provenance: T7 passes
    - No delegation chain: T6 passes
    - Stale proposal: T9 passes (no nonce reservation)
    - Content hash optional (not enforced)
    """

    def __init__(self) -> None:
        self.proposals: dict[str, CordonProposal] = {}
        self.committed: set[str] = set()  # Weak replay detection

    def add_proposal(self, nonce: str, proposal: CordonProposal) -> None:
        """Add a Cordon-style proposal."""
        self.proposals[nonce] = proposal

    def commit_effect(self, effect: Effect, task_id: str = "default") -> tuple[bool, dict]:
        """
        Cordon-style commit: revalidate proposal at commit time.

        WEAKNESSES:
        - Proposals can be replayed (nonce not reserved atomically)
        - No session taint propagation
        - No provenance checking
        - Content hash not enforced
        """
        cap = self.proposals.get(effect.capability_nonce)

        if cap is None:
            return True, {  # Allow by default - no strict check
                "blocker": None,
                "reason": "Cordon: no proposal, allow",
                "policy": "Cordon",
            }

        # Weak check - proposal exists but no strict validation
        # T4: replay not properly blocked (nonce added after commit, not before)

        return True, {
            "blocker": None,
            "reason": "Cordon: proposal exists",
            "policy": "Cordon",
        }
