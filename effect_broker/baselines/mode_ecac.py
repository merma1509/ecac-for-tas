"""ECAC baseline - the actual ECAC implementation.

This is the real ECAC broker for comparison.
It demonstrates what the full four-predicate gate achieves.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from effect_broker.broker import EffectBroker

from effect_broker.traces import build


class ECACBaselineBroker:
    """
    ECAC: the actual implementation for comparison.

    Provides:
    - Four-predicate gate: Auth + FlowOK + NoAmp + Fresh
    - Session taint propagation
    - Capability nonce with replay prevention
    - Ledger-based audit trail
    - Content hash binding (ApprovedRequest)

    BLOCKS ALL TRACES because of complete coverage.
    """

    def __init__(self):
        self.broker: EffectBroker = build()

    def commit_effect(self, effect, task_id: str = "default") -> tuple[bool, dict]:
        """
        ECAC-style commit: four-predicate gate.

        This is the actual ECAC implementation.
        """
        task = self.broker.tasks.get(task_id)
        if not task:
            task = self.broker.tasks.get("default")

        return self.broker.commit_effect(effect, task=task)
