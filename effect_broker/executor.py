"""Isolated executor for tool/shim-motivated effects

ARCHITECTURE:
  ┌─────────────────────────────────────────────────────────────┐
  │  IndependentEffectLedger                                    │
  │  - Created EXTERNALLY (not by broker or executor)            │
  │  - Passed to both broker and executor                       │
  │  - Records authorization events (from broker.gate)           │
  │  - Records observation events (from executor + store)        │
  │  - Makes UNAMBIGUOUS verdicts: COMMITTED/BLOCKED/UNKNOWN    │
  └─────────────────────────────────────────────────────────────┘
                       ↑                    ↑
              broker.gate()          executor.apply()
                   │                        │
                   └──────────┬─────────────┘
                              ↓
                   IndependentEffectLedger

MUTATION PATHS:
  There are TWO paths to external state mutation — both mediated equally:
    1. broker.commit()  — direct path (no shim/executor)
    2. executor.execute() — via-shim path (executor calls gate, then apply_effect)
  Both paths write to the SAME IndependentEffectLedger. The executor is NOT
  the sole caller of _apply_effect; it is the isolation mechanism for tool/shim
  calls. Direct calls (e.g., from a REPL or test) use broker.commit().

THREAD SAFETY: broker.gate() uses per-task locks to atomically check AND reserve
the nonce for Fresh. This prevents double-commit with the same nonce under
concurrency (two threads could both read used=∅ before either reserves).
If gate() fails after reservation, the nonce is rolled back.

SAME-PROCESS LIMITATION: In this model, direct store mutation
(broker.store._files._data[...]=...) is still possible and untracked.
The ledger returns "unknown" (not "safe") for any effect it cannot confirm.
The same-process limitation is documented in restricted_store.py.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .broker import EffectBroker, Evidence
    from .ledger import IndependentEffectLedger
    from .model import Commit, Effect, EffectTarget, Task  # noqa: F401


@dataclass
class IsolatedExecutor:
    """Execute effects through the broker gate with independent ledger observation.

    ARCHITECTURE:
      tool -> shim -> executor.execute()
                    ↓
              broker.gate(commit)   ← evaluates predicates (read-only)
                    ↓
              executor.apply_effect() -> broker._apply_effect()
              executor._ledger.record_authorization()
              executor._ledger.record_observation()

    This class provides the isolation mechanism for tool/shim-motivated effects.
    The executor is NOT the sole path to _apply_effect — broker.commit() also
    calls _apply_effect() directly (the direct path). Both paths record to
    the same external ledger so verify_complete_mediation() works from both.

    The executor is the _isolation mechanism_ for tool/shim calls: it ensures
    that all tool-motivated effects go through the gate before mutation, and
    that the independent ledger observes both authorization and observation
    from a path separate from the broker's direct commit().

    In the current same-process model, direct store mutation bypass is
    still possible and untracked. The ledger returns "unknown" for any
    effect it cannot confirm — this is the "unknown, not safe" guarantee.
    """

    broker: EffectBroker
    task_id: str = "default"
    # The executor uses the broker's ledger (shared with broker.commit path).
    # Both paths record to the same external ledger — this is the key to
    # "unknown, not safe": the ledger is the single source of truth,
    # independent of how the effect reached the gate.
    _ledger: IndependentEffectLedger | None = field(default=None, repr=False)
    _execution_count: int = field(default=0, repr=False)

    @property
    def ledger(self) -> IndependentEffectLedger:
        """Get the ledger. Uses broker.ledger if executor has no own ledger."""
        if self._ledger is not None:
            return self._ledger
        return self.broker.ledger

    def execute(self, commit: Commit) -> tuple[bool, Evidence]:
        """Execute a committed effect through the isolated executor.

        Two-phase pattern:
          1. broker.gate(commit) — evaluates predicates (read-only, atomic Fresh)
          2. executor.apply_effect() — mutates state (on can_apply=True)

        The atomic Fresh check in gate() prevents double-commit with the same
        nonce under concurrency: only one thread can reserve a given nonce;
        others block until the reservation is confirmed (apply) or rolled back
        (failed gate). See broker._atomic_fresh_check() for details.

        Authorization + observation recorded to the independent ledger (shared
        with broker.commit path). Returns (allow, evidence) from broker gate.
        """
        self._execution_count += 1
        effect = commit.effect
        nonce = effect.capability_nonce

        # Determine authorized targets (complete set: primary + BCC)
        # CRITICAL: use canonical complete_targets() — same source as broker.commit
        # and grant_approval. Never re-extract from metadata independently.
        authorized_targets = effect.complete_targets()

        # Phase 1: gate evaluation (read-only)
        gate_result = self.broker.gate(commit)
        allow = gate_result.allow
        evidence = gate_result.evidence

        # Record authorization in the independent ledger
        # (same ledger as broker.commit — both paths record here)
        actual_task_id = gate_result.task.task_id
        self.ledger.record_authorization(
            actual_task_id, nonce, authorized_targets, source="executor.execute"
        )

        if allow:
            # Phase 2: apply state mutation (sole mutation point)
            self.apply_effect(gate_result.effect, gate_result.task)

            # Record observation AFTER apply_effect() wrote to identity_log
            identity_entries = self.broker.store.identity_log
            if identity_entries:
                last_entry = identity_entries[-1]
                self.ledger.record_observation(
                    actual_task_id, nonce, last_entry, source="executor.apply"
                )
        else:
            # BLOCKed effect: record explicit blocked observation.
            # auth > 0, obs = frozenset() -> CONFIRMED_BLOCKED (ledger saw attempt)
            # This is distinct from no observation record -> UNKNOWN (possible bypass).
            self.ledger.record_observation(
                actual_task_id, nonce, None, source="executor.execute:BLOCKED"
            )

        return allow, evidence

    def apply_effect(self, effect: Effect, task: Task) -> None:
        """Apply an effect to external state. THIS is the sole mutation point."""
        self.broker._apply_effect(effect, task)

    def verify_mediation(self) -> list[str]:
        """Verify complete mediation. Delegates to the independent ledger."""
        return self.broker.verify_complete_mediation()

def make_content_hash(provenance: tuple[object, ...]) -> str:
    """Compute a stable hash of provenance data for immutable request binding."""
    from .model import Data

    items: list[tuple[str, str, str] | tuple[str]] = []
    for d in provenance:
        if isinstance(d, Data):
            items.append((d.name, d.confidentiality.name, d.integrity.name))
        else:
            items.append((str(d),))
    return sha256(str(items).encode()).hexdigest()[:16]
