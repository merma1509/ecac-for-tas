"""Isolated executor — the SOLE path to external state mutation.

ARCHITECTURE (single-path refactor):
  ┌────────────────────────────────────────────────────────────────┐
  │  IndependentEffectLedger  (EXTERNAL, single source of truth)   │
  │  - Created outside broker + executor                           │
  │  - Records authorization (from broker.gate)                    │
  │  - Records observation (from executor apply)                   │
  │  - Makes UNAMBIGUOUS verdicts: COMMITTED / BLOCKED / UNKNOWN   │
  └────────────────────────────────────────────────────────────────┘
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

import hashlib
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from .mediation import MediationVerdict

if TYPE_CHECKING:
    from .broker import EffectBroker, Evidence
    from .executor_ipc import ProcessExecutorClient
    from .executor_subprocess import ExecutorProcessHandle
    from .ledger import IndependentEffectLedger
    from .model import Commit, Effect, Task


# ---- Content binding verification (same-process gate↔execute coupling) ----
# This mirrors executor_subprocess._verify_content_binding() for multi-process mode.
# The same-process shim (RealFileShim) computes authorized_content_hash BEFORE
# broker.commit() and stores it in Commit.authorized_content_hash.
# This function verifies the hash matches before allowing apply_effect().


def _verify_content_binding(
    effect: Effect, authorized_content_hash: str | None
) -> tuple[bool, str]:
    """Verify effect content matches the authorized hash.

    This closes the same-process gate↔execute coupling gap.

    Without this fix (same-process):
      1. RealFileShim.compute hash(content_A) and calls broker.commit(effect_A)
      2. broker.gate() evaluates predicates on effect_A
      3. ALLOW: executor.apply_effect(effect_A) → but subprocess could write content_B

    WITH this fix (same-process):
      1. RealFileShim computes hash(content_A) and passes authorized_content_hash=hash_A
         in Commit.authorized_content_hash
      2. broker.gate() evaluates predicates on effect_A (hash_A from content)
      3. ALLOW: executor.execute() calls _verify_content_binding(effect_A, hash_A)
      4. Compares hash(effect_A.metadata.content) == hash_A → MATCH
      5. Only then calls apply_effect(effect_A)
      6. Same-process writes content_A (from effect.metadata, not modified)

    For read/delete effects, authorized_content_hash is None → verification skipped.

    Returns: (verified: bool, reason: str)
    """
    if authorized_content_hash is None:
        # No content binding required (read/delete/effects without mutable content)
        return True, "no-content-binding"

    # Compute hash from actual effect content (matches _compute_effect_content_hash)
    actual_hash = effect.compute_content_hash()
    if actual_hash is None:
        return False, "content-binding-effect-without-hashable-content"

    if actual_hash != authorized_content_hash:
        return False, (
            f"content-hash-mismatch: "
            f"expected={authorized_content_hash[:32]}..., "
            f"got={actual_hash[:32]}..."
        )

    return True, "content-binding-verified"


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
            # Content binding verification (gate↔execute coupling).
            # RealFileShim computes authorized_content_hash BEFORE broker.commit()
            # and stores it in Commit.authorized_content_hash. The executor verifies
            # it BEFORE apply_effect() — so the content actually written matches
            # what was authorized. This mirrors subprocess._verify_content_binding()
            # for multi-process mode and closes the same-process coupling gap.
            verified, reason = _verify_content_binding(
                gate_result.effect, commit.authorized_content_hash
            )
            if not verified:
                # Content was modified after gate authorization — BLOCK.
                # Roll back any nonce reservation made during gate.
                self.broker._release_fresh_reservation(gate_result.effect, gate_result.task)
                # Record explicit blocked observation.
                self.ledger.record_observation(
                    actual_task_id, nonce, None, source="executor.execute:BLOCKED"
                )
                return False, {
                    "allow": False,
                    "primary_blocker": "ContentBinding",
                    "predicates": {**evidence.get("predicates", {}), "ContentBinding": reason},
                    "content_binding_block": True,
                    "boundary_stop": None,
                    "approval_binding": evidence.get("approval_binding"),
                }

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

    SUBCONCESS ISOLATION SCOPE (IMPORTANT — what IS and IS NOT confined):
      The subprocess has THREE layers of active confinement:

      LAYER 1 — Import blocking (builtins.__import__ hook):
        - BLOCKED: exec, eval, compile, pickle, marshal, shelve
        - BLOCKED: requests, aiohttp, httpx, websockets (dangerous network packages)
        - Prevents dynamic code generation and remote code execution via network

      LAYER 2 — Filesystem confinement (restricted-open wrapper on os.open):
        - Write ONLY: /tmp, /var/tmp, /dev/shm (sandboxed temp directories)
        - Read: /tmp, /var/tmp, /dev, /etc, /usr, /bin, /sbin, /home
        - Any path outside allowed dirs → PermissionError

      LAYER 3a — Landlock sandbox (Linux 5.13+):
        - Kernel-enforced filesystem restrictions, applied before any Python runs
        - Defense-in-depth: cannot be bypassed from Python

      LAYER 3b — Seccomp BPF filter (Linux kernel-level):
        - BLOCKED: socket(), connect(), accept(), execve(), clone(), ptrace()
        - ALLOWED: read, write, open, close, stat, socketpair(AF_UNIX IPC only)
        - Enforced by the Linux kernel — cannot be bypassed from Python

      WHAT THIS MEANS (confirmed):
        ✓ Broker's file/SMTP I/O via RealFileShim/RealEmailShim IS confined
        ✓ Dynamic code execution (eval/compile/pickle) IS blocked by Layer 1
        ✓ Arbitrary network connections ARE blocked by seccomp (Layer 3b)
        ✓ Filesystem writes OUTSIDE /tmp ARE blocked by restricted-open (Layer 2)
        ✓ Content hash binding (HMAC-signed IPC) prevents gate→execute coupling gap

      REMAINING GAP (documented limitation, Option A fixes this):
        The subprocess still has access to standard library: os, smtplib, imaplib,
        pathlib, threading, etc. A compromised subprocess could:
          1. Use smtplib to connect to ANY SMTP server (not just the configured one)
          2. Read ANY file in allowed read directories (/etc, /home, etc.)
          3. Spawn threads (but no new processes — seccomp blocks clone/execve)
          4. Use imaplib for any IMAP connection (not just configured server)

        To FULLY confine arbitrary tool code (Option A — recommended):
          1. Run tool in a SEPARATE subprocess with its own broker/shim
          2. Tool's effects go through tool's own broker → outer broker via IPC
          3. Outer broker verifies via nested composition protocol
          This gives two independent broker instances, each with full sandboxing.

        Option B (OS sandbox): seccomp profiles, namespace containers, chroot
          → requires root/capabilities beyond Python's reach

        Option C (Language taint): PACT/CaMeL/FIDES runtime instrumentation
          → requires instrumentation of the tool's language runtime

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
        # reserve_nonce=False because the subprocess handles
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

            # Compute approved_content_hash for atomic commit verification.
            # Prefer the shim-computed hash from Commit (same-process path).
            # Fall back to re-computing from metadata for compatibility.
            approved_content_hash: str | None = commit.authorized_content_hash
            if approved_content_hash is None:
                # Fallback: re-compute from effect metadata
                metadata = effect.metadata or {}
                content_raw = metadata.get("content", "")
                if isinstance(content_raw, bytes) and content_raw:
                    approved_content_hash = hashlib.sha256(content_raw).hexdigest()
                elif isinstance(content_raw, str) and content_raw:
                    approved_content_hash = hashlib.sha256(
                        content_raw.encode("utf-8")
                    ).hexdigest()
                elif "content_b64" in metadata:
                    import base64

                    try:
                        b64_str = metadata["content_b64"]
                        decoded = base64.b64decode(b64_str)  # type: ignore[arg-type]
                        approved_content_hash = hashlib.sha256(decoded).hexdigest()
                    except Exception:
                        pass  # Invalid base64 — skip hash binding

            # APPLY_COMMIT: Fresh check + content_hash verify + apply_effect in B
            # B returns session_update with updated state (taint, used, logical_time)
            resp = self._client.apply_commit(
                effect_dict=effect_dict,
                task_id=task.task_id,
                session_snapshot=session_snapshot,
                reserve_nonce=True,
                approved_content_hash=approved_content_hash,
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
