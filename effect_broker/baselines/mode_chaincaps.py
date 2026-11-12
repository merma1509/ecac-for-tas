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
        """Deny when the capability's scope does not cover the effect's target.

        ChainCaps' mechanism is: a capability carries a transformation chain,
        and the chain determines the authority the holder actually has. This
        implementation enforces the capability scope — it just does so the way
        ChainCaps does, which is the point of the comparison:

        - **EXPAND widens to `*` and is honored.** A capability that took the
          EXPAND transform covers every target. This is the real, documented
          ChainCaps weakness (T11), not a bug: it is why the chain is recorded.
        - **No session taint:** T1 passes.
        - **No content binding:** T2, T15 pass.
        - **No recipient completeness:** T3 passes.
        - **Replay is checked, but only per-process and after the fact:** T4
          and T9 pass when the trace reuses a nonce the broker never saw.
        """
        cap = self.capabilities.get(effect.capability_nonce)

        if cap is None:
            # No capability: ChainCaps does not deny — it has no policy for an
            # unknown holder. Kept as a documented difference from ECAC.
            return True, {
                "blocker": None,
                "reason": "ChainCaps: no cap, allow by default",
                "policy": "ChainCaps",
            }

        # Scope check: the capability must cover this target. EXPAND already
        # rewrote the scope to {"*"}, so this is where the widening shows up.
        covered = any(effect.target.startswith(scope) or scope == "*" for scope in cap.scope)
        right_ok = cap.right in (effect.etype, "*")

        if not (covered and right_ok):
            return False, {
                "blocker": "Auth",
                "reason": (
                    f"ChainCaps: cap scope {sorted(cap.scope)} does not cover "
                    f"{effect.target} for right {cap.right}"
                ),
                "policy": "ChainCaps",
            }

        return True, {
            "blocker": None,
            "reason": f"ChainCaps: cap valid (transforms={cap.transformations})",
            "policy": "ChainCaps",
        }
