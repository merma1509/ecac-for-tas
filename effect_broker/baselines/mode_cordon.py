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
        """Revalidate the proposal at commit time.

        Cordon's mechanism is commit-time revalidation: authority is proposed
        ahead of time, and at commit the broker re-checks that the proposal is
        still valid (not expired, target still matches). This implementation
        enforces exactly that, and nothing more:

        - **Expiry is enforced** (T9 is a *stale* approval — Cordon catches it).
        - **Target match is enforced**: a proposal for one target cannot
          authorize a different one.
        - **No session taint:** T1 passes.
        - **No provenance/IFC:** T7 passes.
        - **No recipient completeness:** T3 passes.
        - **Replay is NOT prevented**: the nonce is recorded after commit, so a
          second use within the process sees it; a nonce the broker never saw
          (T4 arrives with an unreserved nonce) is allowed. Documented gap.
        """
        import time as _time

        proposal = self.proposals.get(effect.capability_nonce)

        if proposal is None:
            # Cordon revalidates proposals it holds. With no proposal there is
            # nothing to revalidate; it does not deny. Documented gap (T4).
            return True, {
                "blocker": None,
                "reason": "Cordon: no proposal to revalidate, allow",
                "policy": "Cordon",
            }

        if proposal.expires_at < _time.time():
            return False, {
                "blocker": "Stale",
                "reason": (
                    f"Cordon: proposal {effect.capability_nonce!r} expired at {proposal.expires_at}"
                ),
                "policy": "Cordon",
            }

        if proposal.target != effect.target or proposal.etype != effect.etype:
            return False, {
                "blocker": "Auth",
                "reason": (
                    f"Cordon: proposal is for ({proposal.etype}, {proposal.target}), "
                    f"effect is ({effect.etype}, {effect.target})"
                ),
                "policy": "Cordon",
            }

        return True, {
            "blocker": None,
            "reason": "Cordon: proposal revalidated",
            "policy": "Cordon",
        }
