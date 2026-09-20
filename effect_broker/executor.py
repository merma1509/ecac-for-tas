"""Isolated executor — the SOLE path to external state mutation.

ARCHITECTURE (single-path refactor):
  ┌─────────────────────────────────────────────────────────────┐
  │  IndependentEffectLedger  (EXTERNAL, single source of truth)  │
  │  - Created outside broker + executor                         │
  │  - Records authorization (from broker.gate)                 │
  │  - Records observation (from executor apply)                │
  │  - Makes UNAMBIGUOUS verdicts: COMMITTED / BLOCKED / UNKNOWN │
  └─────────────────────────────────────────────────────────────┘
                               ↑
                    broker.gate(commit)  ← read-only predicate gate
                               ↓
                    executor.apply_effect()  ← SOLE MUTATION POINT
                               ↓
                    IndependentEffectLedger.record_observation()

  ALL effects — direct broker.commit() calls AND tool/shim calls — go
  through the SAME execution path: executor.execute(). The executor is the
  ONLY component that calls broker._apply_effect(). There is no other path.

  For same-process deployment (test/dev): broker._default_executor is set
  automatically. broker.commit() delegates to it. Direct callers (tests, REPL)
  use broker.commit() which routes through the shared executor, so the ledger
  observes both authorization and observation from the same logical path.

  Thread safety: broker.gate() uses per-task locks to atomically check AND
  reserve the nonce for Fresh. This prevents double-commit with the same nonce
  under concurrency.

  SAME-PROCESS LIMITATION: In this model, direct store mutation
  (broker.store._files._data[...]=...) bypasses the executor and returns
  "unknown" from the ledger — NOT "safe." The ledger cannot distinguish
  direct bypass from broker-blocked. This is the documented "unknown, not safe"
  guarantee and is resolved by process isolation in production.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .mediation import MediationVerdict

if TYPE_CHECKING:
    from .broker import EffectBroker, Evidence
    from .ledger import IndependentEffectLedger
    from .model import Commit, Effect, Task


@dataclass
class IsolatedExecutor:
    """The SOLE path to external state mutation.

    Every effect — whether from a tool/shim call or a direct REPL command —
    goes through executor.execute(). The executor:
      1. Calls broker.gate() (read-only predicate evaluation + atomic Fresh)
      2. On allow: calls _apply_effect() (SOLE external state mutation)
         and records to the independent ledger
      3. On block: records BLOCKED observation to the ledger

    There is NO other path to _apply_effect(). broker.commit() is an alias
    that routes through the executor's execute() method. The executor is
    instantiated once per broker (broker._default_executor) and shared for
    all commit operations.

    Key properties:
      - execute() is reentrant: the executor can be shared across threads
        because gate() uses per-task locks for atomic Fresh checks.
      - apply_effect() is the ONLY mutation point. Every state change
        goes through it → every state change is recorded in identity_log.
      - The ledger observes authorization from gate() and observation from
        apply_effect(). The SAME path is observed for both.

    SAME-PROCESS LIMITATION: This class cannot prevent direct store mutation
    (broker.store._files._data[...]=X). The ledger returns "unknown" for
    unverifiable effects — this is the correct safe behavior.
    """

    broker: EffectBroker
    task_id: str = "default"
    # Ledger for authorization + observation recording
    # Set automatically by the broker on __init__ to the broker's ledger
    _ledger: IndependentEffectLedger | None = field(default=None, repr=False)
    _execution_count: int = field(default=0, repr=False)

    def _set_ledger(self, ledger: IndependentEffectLedger) -> None:
        """Called by broker to inject the shared ledger. Internal use only."""
        self._ledger = ledger

    @property
    def ledger(self) -> IndependentEffectLedger:
        """The independent ledger for this executor.

        Uses the broker's shared ledger so that all execution paths
        (direct broker.commit + shim via executor) record to the same ledger
        """
        if self._ledger is not None:
            return self._ledger
        return self.broker.ledger

    def execute(
        self,
        commit: Commit,
        mediation: MediationVerdict | None = None,
    ) -> tuple[bool, Evidence]:
        """Execute a committed effect through the sole mutation path.

        This is the ONLY path to external state mutation. Every effect —
        tool/shim call or direct REPL command — goes through here.

        Two-phase pattern:
          1. broker.gate(commit) — evaluates predicates (read-only, atomic Fresh)
          2. apply_effect() — mutates state ONLY on allow (sole mutation point)

        Authorization and observation are recorded to the SAME ledger entry,
        so the ledger observes the complete lifecycle through one path.

        Args:
            commit: the prepared effect with commit metadata
            mediation: optional pre-built boundary mediation verdict
                (passed through to gate() for conditioned mediation testing)
        """
        self._execution_count += 1
        effect = commit.effect
        nonce = effect.capability_nonce

        # Canonical authorized targets (complete set: primary + BCC recipients).
        # CRITICAL: use complete_targets() — the same source used by broker.gate()
        # and grant_approval(). Never re-extract from metadata independently.
        authorized_targets = effect.complete_targets()

        # Phase 1: gate evaluation (read-only predicates, atomic Fresh check)
        gate_result = self.broker.gate(commit, mediation=mediation)
        allow = gate_result.allow
        evidence = gate_result.evidence

        # Record authorization — ledger observes gate decision
        actual_task_id = gate_result.task.task_id
        self.ledger.record_authorization(
            actual_task_id, nonce, authorized_targets, source="executor.execute"
        )

        if allow:
            # Phase 2: SOLE MUTATION POINT — external state changes ONLY here.
            # Every effect that the ledger confirmed as authorized reaches state
            # through this call. There is no other mutation path.
            self.apply_effect(gate_result.effect, gate_result.task)

            # Record observation — ledger sees the state change
            identity_entries = self.broker.store.identity_log
            if identity_entries:
                last_entry = identity_entries[-1]
                self.ledger.record_observation(
                    actual_task_id, nonce, last_entry, source="executor.apply"
                )
        else:
            # BLOCKed effect: explicit observation that the gate rejected it.
            # auth > 0 + obs = None with BLOCKED source → CONFIRMED_BLOCKED.
            # Without this record, the same (auth > 0, obs = absent) would be
            # UNKNOWN — indistinguishable from a direct mutation bypass.
            self.ledger.record_observation(
                actual_task_id, nonce, None, source="executor.execute:BLOCKED"
            )

        return allow, evidence

    def apply_effect(self, effect: Effect, task: Task) -> None:
        """Apply an effect to external state. THIS is the SOLE mutation point.

        Called ONLY after broker.gate() has returned allow=True. This is the
        ONLY path through which any effect reaches external state. Every call
        is recorded in identity_log, enabling the ledger to verify complete
        mediation.

        There is no other call site for _apply_effect() in the broker — the
        direct broker.commit() path also routes through here.
        """
        self.broker._apply_effect(effect, task)

    def verify_mediation(self) -> list[str]:
        """Verify complete mediation. Delegates to the independent ledger."""
        return self.broker.verify_complete_mediation()



