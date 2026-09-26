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
from typing import TYPE_CHECKING, Any

from .mediation import MediationVerdict

if TYPE_CHECKING:
    from .broker import EffectBroker, Evidence
    from .executor_ipc import ProcessExecutorClient
    from .executor_subprocess import ExecutorProcessHandle
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


@dataclass
class SubprocessExecutor:
    """Multi-process executor: gate() in broker process, apply_effect() in subprocess.

    PHASE 1 (broker process):
      - broker.gate(commit) evaluates Auth ∧ FlowOK ∧ NoAmp ∧ Fresh
      - No state mutation here; this is the read-only authorization decision

    PHASE 2 (subprocess):
      - ProcessExecutorClient.execute(effect_dict) sends the effect over IPC
      - IsolatedStore.apply_effect() mutates the subprocess's own store
      - subprocess returns observed_targets (actual resources changed)

    PHASE 3 (broker process, back):
      - Record authorization (from gate) to the independent ledger
      - Record observation (from subprocess response) to the independent ledger

    KEY PROPERTIES:
      - The broker NEVER holds a reference to the subprocess store.
        All state reads go through IPC (via broker.observer).
      - Direct store mutation (broker.store._files._data=...) is IMPOSSIBLE
        in multi-process mode — the broker process has no access.
      - The ledger's observation comes from the subprocess's IPC response,
        NOT from the broker's own report.
      - execute() is reentrant: gate() uses per-task locks for atomic Fresh.

    USAGE:
        broker = EffectBroker(mode="multi-process", ...)
        broker.commit(commit)  # routes through SubprocessExecutor
        broker.observer.verify_all(...)  # IPC reads of subprocess store
        broker.shutdown()  # clean subprocess termination
    """

    broker: EffectBroker
    task_id: str = "subprocess"
    _ledger: IndependentEffectLedger | None = None
    _client: ProcessExecutorClient | None = None
    _process_handle: ExecutorProcessHandle | None = None
    _execution_count: int = 0

    def _set_ledger(self, ledger: IndependentEffectLedger) -> None:
        """Called by broker to inject the shared ledger."""
        self._ledger = ledger

    def _set_client(self, client: ProcessExecutorClient) -> None:
        """Called by broker to inject the IPC client after subprocess starts."""
        self._client = client

    def _set_process_handle(self, handle: ExecutorProcessHandle) -> None:
        """Called by broker to store the process handle for shutdown."""
        self._process_handle = handle

    @property
    def ledger(self) -> IndependentEffectLedger:
        return self._ledger if self._ledger is not None else self.broker.ledger

    def bootstrap_store(
        self,
        files: list[dict[str, str]] | None = None,
        emails: list[dict[str, str]] | None = None,
        mailboxes: list[str] | None = None,
    ) -> None:
        """Bootstrap the subprocess store with initial resources.

        MUST be called BEFORE any execute() calls. This transfers the
        broker's resource definitions (F ∪ E ∪ M) into the subprocess.

        Args:
            files: list of {"path": "...", "sensitivity": "PUBLIC|INTERNAL|CONFIDENTIAL|..."}
            emails: list of {"address": "...", "domain": "INTERNAL|EXTERNAL"}
            mailboxes: list of mailbox usernames
        """
        if self._client is None:
            raise RuntimeError("SubprocessExecutor not bootstrapped: no IPC client")
        self._client.bootstrap(files=files, emails=emails, mailboxes=mailboxes)

    def execute(
        self,
        commit: Commit,
        mediation: MediationVerdict | None = None,
    ) -> tuple[bool, Evidence]:
        """Execute through the multi-process isolation path.

        Atomic commit protocol (session sync fix):
          1. gate() in broker process (read-only predicates, atomic Fresh in A)
          2. APPLY_COMMIT IPC → subprocess: Fresh check + nonce reserve + apply_effect
          3. Sync session_update (B→A): taint, used nonces, logical_time
          4. Record authorization + observation to the independent ledger

        The key fix: session state is now synchronized both ways:
        - A→B: session snapshot at gate time (used, revoked, taint, logical_time)
        - B→A: session_update after apply (updated used, taint, logical_time)
        """
        self._execution_count += 1
        effect = commit.effect
        nonce = effect.capability_nonce
        authorized_targets = effect.complete_targets()

        # Phase 1: gate evaluation (read-only, in broker process)
        # CRITICAL: reserve_nonce=False because the subprocess handles
        # nonce reservation via APPLY_COMMIT protocol. This ensures the
        # nonce is NOT reserved in A's session before IPC round-trip,
        # preventing false replay detection in B.
        gate_result = self.broker.gate(commit, mediation=mediation, reserve_nonce=False)
        allow = gate_result.allow
        evidence = gate_result.evidence

        # Record authorization — ledger observes gate decision
        actual_task_id = gate_result.task.task_id
        self.ledger.record_authorization(
            actual_task_id, nonce, authorized_targets, source="subprocess.gate"
        )

        if allow:
            # Phase 2: Atomic commit in subprocess with session sync
            if self._client is None:
                raise RuntimeError("SubprocessExecutor: no IPC client available")

            task = gate_result.task
            session = task.session

            # Build A's session snapshot at gate time
            from .executor_ipc import effect_to_dict, session_state_to_dict

            session_snapshot = session_state_to_dict(session) if session else {}
            effect_dict = effect_to_dict(effect)

            # APPLY_COMMIT: Fresh check + nonce reserve + apply_effect in B
            # B returns session_update with updated state (taint, used, logical_time)
            resp = self._client.apply_commit(
                effect_dict=effect_dict,
                task_id=task.task_id,
                session_snapshot=session_snapshot,
                reserve_nonce=True,
            )

            if resp.get("status") == "ok":
                # Sync B→A: update A's session with B's changes
                self._sync_session_from_subprocess(task, resp.get("session_update", {}))

                # Phase 3: record observation from subprocess's response
                obs_targets = frozenset(resp.get("observed_targets", []))
                identity_entry = resp.get("identity_entry", obs_targets)
                self.ledger.record_observation(
                    actual_task_id, nonce, identity_entry, source="subprocess.apply"
                )
            elif resp.get("status") == "blocked":
                # Fresh check in B detected replay/revoked — block the commit
                # This should be rare since A already checked Fresh, but provides
                # defense-in-depth for process isolation scenarios.
                allow = False
                evidence = dict(evidence)  # type: ignore[assignment]
                evidence["allow"] = False
                evidence["primary_blocker"] = resp.get("blocker", "Fresh")
                evidence["block_reason"] = resp.get("reason", "unknown")
                self.ledger.record_observation(
                    actual_task_id, nonce, None, source="subprocess.apply:BLOCKED"
                )
            else:
                # Error in subprocess — propagate to caller
                raise RuntimeError(f"Apply commit failed: {resp.get('reason')}")

        else:
            # BLOCKED: record explicit blocked observation
            self.ledger.record_observation(
                actual_task_id, nonce, None, source="subprocess.gate:BLOCKED"
            )

        return allow, evidence

    def _sync_session_from_subprocess(
        self,
        task: Task,
        update: dict[str, Any],
    ) -> None:
        """Sync session state from subprocess (B) back to broker (A).

        This implements B→A sync for the atomic commit protocol:
        - used: updated set of reserved nonces
        - tainted: session taint from reading CONFIDENTIAL data
        - logical_time: updated logical clock

        Args:
            task: The task whose session to update
            update: session_update dict from subprocess response
        """
        if task.session is None:
            return

        # Sync used nonces
        if "used" in update:
            task.session.used = set(update["used"])

        # Sync logical time
        if "logical_time" in update:
            task.session.logical_time = update["logical_time"]

        # Sync taint state (critical for FlowOK in subsequent commits)
        if update.get("tainted"):
            task.session.taint_for_send(update.get("_taint_reason", "read-confidential"))
            # Note: taint doesn't get cleared — once tainted, always tainted
            # until broker records explicit declass exception

    def apply_effect(self, effect: Effect, task: Task) -> None:
        """NOT USED in multi-process mode.

        In multi-process mode, apply_effect() is called ONLY by the subprocess's
        IsolatedStore. The broker calls execute() which routes through IPC.
        This method raises NotImplementedError to catch any accidental misuse.
        """
        raise NotImplementedError(
            "SubprocessExecutor.apply_effect() should not be called directly. "
            "Use execute() which routes through IPC."
        )

    def verify_mediation(self) -> list[str]:
        """Verify complete mediation. Delegates to the independent ledger."""
        return self.broker.verify_complete_mediation()

    def shutdown(self) -> None:
        """Cleanly terminate the executor subprocess.

        Sends SHUTDOWN via IPC, then kills the process handle.
        Safe to call multiple times.
        """
        if self._client is not None:
            try:
                self._client.shutdown()
            except Exception:
                pass  # best-effort: process may already be dead
        if self._process_handle is not None:
            self._process_handle.stop()
        self._client = None
        self._process_handle = None
