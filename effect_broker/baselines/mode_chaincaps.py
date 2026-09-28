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
    EXPAND = "expand"
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


class ChainCapsBroker:
    """
    ChainCaps-style broker: capabilities with transformation chains.

    WEAKNESSES (vs ECAC):
    - Transformation EXPAND allows scope widening!
    - No session taint propagation
    - No independent ledger
    - No content hash binding
    """

    def __init__(self) -> None:
        self.capabilities: dict[str, Capability] = {}
        self._nonce_counter = 0

    def commit_effect(self, effect: Effect, task_id: str = "default") -> tuple[bool, dict]:
        """
        ChainCaps-style commit: check capability + verify transformation chain.

        WEAKNESSES (these bypass ChainCaps but not ECAC):
        - EXPAND transformation allows scope widening!
        - No session taint: T1 passes
        - No content hash: T2 passes
        - No ledger: replay detection is weak
        """
        # ChainCaps allows any capability with transformation chain
        # No freshness check
        # No session taint
        # No ledger

        return True, {
            "blocker": None,
            "reason": "ChainCaps: authorized",
            "policy": "ChainCaps",
        }
