"""ChainCaps-style capability system with transformation chains."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from effect_broker.model import Effect


class Transformation(Enum):
    """ChainCaps transformation types."""

    NARROW = "narrow"
    EXPAND = "expand"  # DANGEROUS: allows scope widening!
    COPY = "copy"
    TRANSFORM = "transform"


@dataclass
class Capability:
    """ChainCaps-style capability with transformation chain."""

    holder: str
    right: str
    target: str
    scope: frozenset[str]
    transformations: tuple[str, ...] = field(default_factory=tuple)
    origin: str | None = None

    def can_send_to(self, target: str) -> bool:
        if self.right not in ("send", "*"):
            return False
        for s in self.scope:
            if target.startswith(s) or s == "*":
                return True
        return False

    def apply_transform(self, transformation: str) -> Capability:
        """Apply transformation to create new capability."""
        if transformation == Transformation.EXPAND.value:
            # VULNERABILITY: EXPAND widens scope!
            return Capability(
                holder=self.holder,
                right=self.right,
                target=self.target,
                scope=frozenset({"*"}),  # Wildcard scope!
                transformations=(*self.transformations, transformation),
                origin=self.target,
            )
        elif transformation == Transformation.NARROW.value:
            return Capability(
                holder=self.holder,
                right=self.right,
                target=self.target,
                scope=self.scope,
                transformations=(*self.transformations, transformation),
                origin=self.origin,
            )
        return self


class ChainCapsBroker:
    """
    ChainCaps-style broker: capabilities with transformation chains.

    WEAKNESSES (vs ECAC):
    - Transformation EXPAND allows scope widening!
    - No session taint propagation
    - No independent ledger
    - No content hash binding
    - No revocation/replay prevention
    """

    def __init__(self) -> None:
        self.capabilities: dict[str, Capability] = {}
        self._nonce_counter = 0
        self.used_nonces: set[str] = set()

    def register_capability(self, cap: Capability, nonce: str) -> None:
        """Register a capability."""
        self.capabilities[nonce] = cap

    def commit_effect(self, effect: Effect, task_id: str = "default") -> tuple[bool, dict]:
        """
        ChainCaps-style commit: check capability + verify transformation chain.

        VULNERABILITY DEMONSTRATION (T6: delegation widening):
        - EXPAND transformation allows scope widening to wildcard "*"
        - No monotonicity check on scope narrowing
        - No session taint propagation
        - No content hash binding
        - Replay detection is WEAK (nonce not checked before use)
        """
        cap = self.capabilities.get(effect.capability_nonce)

        if cap is None:
            return True, {  # Allow anyway - no strict capability check
                "blocker": None,
                "reason": "ChainCaps: no cap, allow by default",
                "policy": "ChainCaps",
            }

        # Check transformation chain for EXPAND (scope widening)
        if Transformation.EXPAND.value in cap.transformations:
            # VULNERABILITY: EXPAND allows ANY target!
            # This is T6: delegation widening attack
            pass

        # WEAK replay check - nonce not blocked after use
        # T4: replay passes because nonce not in used set

        return True, {
            "blocker": None,
            "reason": f"ChainCaps: cap valid (transforms={cap.transformations})",
            "policy": "ChainCaps",
        }
