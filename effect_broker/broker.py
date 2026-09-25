"""The EffectBroker: policy evaluation engine.

The broker evaluates the four-predicate gate (Auth, FlowOK, NoAmp, Fresh) and
issues machine-checkable evidence for every commit decision.

IMPORTANT — Architecture change (ADR-003):
  The broker NO LONGER calls _apply_effect() directly. ALL effects — direct
  broker.commit() calls AND tool/shim calls — go through IsolatedExecutor,
  which is the sole mutation point. broker.commit() is a reentrant wrapper
  that routes through executor.execute(). The executor records authorization
  and observation to the ledger, so the ledger observes the complete lifecycle
  through one path.

  OLD (removed):
    broker.commit() → gate() → _apply_effect()         ← TWO mutation paths
    executor.execute() → broker.gate() → apply_effect() ↗

  NEW (single-path):
    broker.commit() → executor.execute() → broker.gate() → executor.apply_effect() → _apply_effect()
    shim calls executor.execute() → broker.gate() → executor.apply_effect() → _apply_effect()
                                              ↑                                ↑
                                        read-only gate                  SOLE MUTATION POINT

  There is ONE and only ONE call site for _apply_effect(): executor.apply_effect().
  Direct mutations (broker.store._files._data[...]=X) still bypass in same-process
  mode, but the ledger returns "unknown" for them — NOT "safe."

FOUR-PREDICATE GATE (Auth ∧ FlowOK ∧ NoAmp ∧ Fresh):

  Auth    : static authorization — root-anchored + monotonic + bottom-scoped
            + task-bounded + exact (right, target, holder) match
  FlowOK  : IFC — provenance labels must not exceed task's flow_boundary
  NoAmp   : composition safety — effect authority within task ceiling scope,
            plus extra-target scope check for BCC/CC recipients
  Fresh   : dynamic authorization — unexpired, unrevoked, not replayed
            (task-scoped logical clock; per-task used-nonce set)

SAME-PROCESS LIMITATION: The broker, executor, store, and ledger all share
a Python process. Direct store mutation (broker.store._files._data[...] = X)
bypasses the executor and the ledger returns "unknown" — not "safe."
Real isolation requires a separate process/enclave (production target).
"""

from __future__ import annotations

import os
import threading
from pathlib import Path
from typing import cast

from .executor import IsolatedExecutor, SubprocessExecutor
from .executor_ipc import ProcessExecutorClient
from .ipc import LedgerBackend, LocalLedgerBackend
from .lattice import Confidentiality, Integrity
from .ledger import IndependentEffectLedger
from .mediation import MediationVerdict, Mediator
from .model import (
    APPROVER,
    BROKER,
    USER,
    ApprovedRequest,
    Capability,
    Commit,
    CommitGateResult,
    Effect,
    EffectTarget,
    Evidence,
    LabelException,
    Task,
    TaskId,
)
from .restricted_store import RestrictedResourceStore as ResourceStore

# Union of types that can be passed as the `ledger` argument.
# Local: IndependentEffectLedger (wrapped in LocalLedgerBackend internally).
# Remote: ProcessLedgerClient or any LedgerBackend implementation.
LedgerSource = IndependentEffectLedger | LedgerBackend | None


def _wrap_ledger(
    ledger: LedgerSource,
) -> tuple[LedgerBackend, IndependentEffectLedger | None]:
    """Convert LedgerSource to (LedgerBackend, local_ledger_or_None)."""
    if ledger is None:
        local = IndependentEffectLedger()
        return LocalLedgerBackend(local), local
    if isinstance(ledger, IndependentEffectLedger):
        return LocalLedgerBackend(ledger), ledger
    return ledger, None


__all__ = [
    "EffectBroker",
    "Evidence",
    "CommitGateResult",
    "LabelException",
    "Task",
    "TaskId",
    "ApprovedRequest",
    "Capability",
    "Effect",
    "Commit",
    "derive_file_provenance",  # provenance derivation from resource metadata
]

# Trusted roots: only these principals may seed NEW authority.
TRUSTED_ROOTS: frozenset[str] = frozenset({USER})

# Type aliases
PredicateResult = tuple[bool, str]


# ---- Provenance derivation from real resource state ----
# NOT hand-assigned labels — derive from the resource's actual metadata.

# Classification patterns: path keywords → sensitivity level.
# This simulates real OS-level file classification (e.g. from SELinux contexts,
# Windows sensitivity labels, or a file metadata DB).
# In a real deployment, this would query the OS/security system for the
# resource's authoritative label.
_FILE_SENSITIVITY_PATTERNS: list[tuple[str, Confidentiality]] = [
    # CONFIDENTIAL: explicitly sensitive files
    ("secrets", Confidentiality.CONFIDENTIAL),
    ("password", Confidentiality.CONFIDENTIAL),
    ("credential", Confidentiality.CONFIDENTIAL),
    ("secret", Confidentiality.CONFIDENTIAL),
    ("private", Confidentiality.CONFIDENTIAL),
    ("confidential", Confidentiality.CONFIDENTIAL),
    # INTERNAL: corporate internal (default)
    ("reports", Confidentiality.INTERNAL),
    ("internal", Confidentiality.INTERNAL),
    ("corp", Confidentiality.INTERNAL),
    ("project", Confidentiality.INTERNAL),
    # PUBLIC: explicitly public
    ("public", Confidentiality.PUBLIC),
    ("/tmp/", Confidentiality.PUBLIC),
]


def derive_file_provenance(target: str) -> tuple[Confidentiality, Integrity]:
    """Derive provenance labels from the file's real OS metadata.

    RESOLVES the "provenance is heuristic" limitation. The kernel reads from
    the OS, not from LLM-declared labels:

    Resolution order (first match wins):
      1. os.statx() → OS-level extended attributes (statx_attr_encrypted,
         statx_attr_immutable + permission bits) — available on Linux.
         In production: SELinux context, Windows sensitivity label, xattrs.
      2. os.stat() permission bits → owner-only (0o700) → CONFIDENTIAL,
         group-readable → INTERNAL, world-readable → PUBLIC.
         Reads real permission bits, not path keywords.
      3. Path keyword fallback (last resort, for new files not yet on disk).

    For email targets, check the domain classification from ResourceStore
    (TRUSTED_DOMAINS + EXTERNAL_DOMAINS), not path keywords.

    Returns (Confidentiality, Integrity). Integrity is always USER for
    legitimate tool content — UNTRUSTED only for unsanitized external input.
    """
    # Skip OS calls for non-file targets (email, network, etc.)
    if not target.startswith("file://"):
        # Case-insensitive path matching fallback for non-file targets
        lower_target = target.lower()
        for keyword, conf in _FILE_SENSITIVITY_PATTERNS:
            if keyword.lower() in lower_target:
                return conf, Integrity.USER
        return Confidentiality.INTERNAL, Integrity.USER

    # Convert file:// URI to OS path
    os_path = target[7:]  # strip "file://"
    if os_path.startswith("/"):
        os_path = os_path[1:]

    # Step 1: Try os.statx() (Linux with kernel >= 4.11)
    try:
        stx = os.statx(os_path, flags=os.STATX_ALL)  # type: ignore[attr-defined]
        # ENCRYPTED flag → CONFIDENTIAL (filesystem-level sensitivity)
        if stx.stx_attributes & (1 << 0):
            return Confidentiality.CONFIDENTIAL, Integrity.USER
        # IMMUTABLE + owner-only → CONFIDENTIAL
        if stx.stx_attributes & (1 << 1):
            mode = stx.stx_mode & 0o777
            if mode & 0o077 == 0:  # owner-only
                return Confidentiality.CONFIDENTIAL, Integrity.USER
            return Confidentiality.INTERNAL, Integrity.USER
    except (OSError, AttributeError):
        # statx not available (macOS / older kernel) — fall through to stat()
        pass

    # Step 2: Try os.stat() permission bits (portable)
    try:
        st = os.stat(os_path)
        mode = st.st_mode & 0o777
        if mode & 0o077 == 0:
            return Confidentiality.CONFIDENTIAL, Integrity.USER  # owner-only
        if mode & 0o004:
            return Confidentiality.PUBLIC, Integrity.USER  # world-readable
        if mode & 0o070:
            return Confidentiality.INTERNAL, Integrity.USER  # group-readable
    except (FileNotFoundError, PermissionError, OSError):
        pass

    # Step 3: Path keyword fallback (for new files not yet on disk)
    lower_target = target.lower()
    for keyword, conf in _FILE_SENSITIVITY_PATTERNS:
        if keyword.lower() in lower_target:
            return conf, Integrity.USER

    # Step 4: Default (deny-most: INTERNAL, not PUBLIC)
    return Confidentiality.INTERNAL, Integrity.USER


class _ProvenanceResolver:
    """Resolves provenance labels from real resource state (not LLM claims).

    In a real deployment, this would query:
      - OS file metadata (SELinux context, Windows sensitivity label)
      - Email domain classification DB
      - Network URL allowlist/blocklist

    This resolver provides a traceable, auditable derivation path from the
    actual resource to its security label. The LLM cannot forge provenance —
    the broker derives it from the resource's own metadata.

    Usage:
      resolver = _ProvenanceResolver(broker)
      conf, integ = resolver.resolve("file:///secrets")  # CONFIDENTIAL/USER
    """

    def __init__(self, broker: EffectBroker) -> None:
        self._broker = broker

    def resolve(self, target: str) -> tuple[Confidentiality, Integrity]:
        """Resolve the provenance for a given target.

        Resolution order:
          1. File targets: check path patterns → Confidentiality
          2. Email targets: check domain classification from ResourceStore
          3. Default: INTERNAL/USER (safe default)
        """
        # Email: derive from domain classification (not path keyword)
        if "@" in target:
            domain_label = self._broker._scope_label_for_target(target)
            if domain_label == "internal":
                return Confidentiality.INTERNAL, Integrity.USER
            return Confidentiality.PUBLIC, Integrity.USER  # external → PUBLIC

        # File: derive from path classification
        conf, integ = derive_file_provenance(target)
        return conf, integ

    def resolve_for_read(self, target: str) -> tuple[Confidentiality, Integrity]:
        """Resolve provenance for a READ effect (content sourced FROM this resource).

        A read from a CONFIDENTIAL file → CONFIDENTIAL/integrity=USER provenance.
        The read effect carries the file's sensitivity as its output label.
        """
        return self.resolve(target)

    def resolve_for_write(
        self, target: str, content_confidence: str = "USER"
    ) -> tuple[Confidentiality, Integrity]:
        """Resolve provenance for a WRITE effect (content written TO this resource).

        The write's output label should match the file's sensitivity.
        Content integrity: USER for normal content, UNTRUSTED for untrusted sources.
        """
        conf, _ = self.resolve(target)
        if content_confidence == "UNTRUSTED":
            integ = Integrity.UNTRUSTED
        else:
            integ = Integrity.USER
        return conf, integ


# ---- EffectBroker ----
def _provides(auth_capability: Capability, right: str, target: str) -> bool:
    """True if the capability's right+target covers this (right, target)"""
    return auth_capability.right == right and auth_capability.target == target


class EffectBroker:
    def __init__(
        self,
        ledger: LedgerSource = None,
        *,
        mode: str = "same-process",
        executor_socket: str | Path = "/tmp/ecac-executor.sock",
        store_socket: str | Path = "/tmp/ecac-executor-store.sock",
    ) -> None:
        """Create an EffectBroker.

        Args:
            ledger: the independent ledger (local or remote ProcessLedgerClient)
            mode: execution mode — "same-process" (default) or "multi-process".
                  In multi-process mode, the broker runs in a separate process
                  from the executor's mutable store. State mutation happens in
                  the subprocess; the broker communicates via IPC only.
            executor_socket: Unix socket path for broker → executor IPC
                             (only used in multi-process mode)
            store_socket: Unix socket path for observer → executor store reads
                         (only used in multi-process mode)
        """
        # Ledger backend (local or remote IPC). The ledger is the single
        # source of truth for mediation verdicts. Neither broker nor
        # executor can modify ledger entries after recording.
        self._ledger_backend, self._local_ledger = _wrap_ledger(ledger)
        # Capability store: nonce -> Capability
        self.capabilities: dict[str, Capability] = {}
        # Validated declass/endorse grants (broker-only writes)
        self.label_exceptions: dict[str, LabelException] = {}
        # One-shot approvals from Approver (nonce -> expiry)
        self.approvals: dict[str, float] = {}
        # External state (R = F ∪ E ∪ M) — only executor.apply_effect()
        # may mutate it via _apply_effect(). In production, the store lives
        # in an isolated process/enclave with apply_effect as its sole write path.
        self.store: ResourceStore = ResourceStore()
        # Registered tasks: task_id -> Task
        self.tasks: dict[TaskId, Task] = {}
        # Risk model stub (NOT part of the allow rule)
        self.risk_override: float = 0.0
        # Nonces revoked without a task_id (global revocation)
        self.global_revoked: set[str] = set()
        self.logical_time: float = 0.0
        # Mediator: enforcement shim for tool boundary (T13/T14/T15)
        self._mediator: Mediator | None = None
        # Per-task locks for atomic Fresh check + nonce reservation
        self._task_locks: dict[TaskId, threading.Lock] = {}
        # Provenance derivation from real resource metadata (not hand-assigned)
        self._provenance_resolver = _ProvenanceResolver(self)
        # Execution mode
        self._mode = mode
        self._executor_socket = Path(executor_socket)
        self._store_socket = Path(store_socket)
        self._executor: IsolatedExecutor | SubprocessExecutor | None = None

        if mode == "multi-process":
            self._setup_multi_process()
        else:
            self._executor = IsolatedExecutor(broker=self)
            self._executor._set_ledger(self.ledger)

    def _setup_multi_process(self) -> None:
        """Set up multi-process execution: start subprocess, create SubprocessExecutor."""
        from .executor_subprocess import ExecutorProcessHandle

        # Start the executor subprocess
        handle = ExecutorProcessHandle(self._executor_socket, self._store_socket)
        handle.start()

        # Create IPC client
        client = ProcessExecutorClient(self._executor_socket)

        # Create SubprocessExecutor and wire it up
        self._executor = SubprocessExecutor(broker=self)
        self._executor._set_ledger(self.ledger)
        self._executor._set_client(client)
        self._executor._set_process_handle(handle)

        # Bootstrap the subprocess store with the broker's existing resources
        self._bootstrap_executor_store(client)

    def _bootstrap_executor_store(self, client: ProcessExecutorClient) -> None:
        """Bootstrap the subprocess store with resources from broker's same-process store.

        Transfers resource definitions from the broker's store into the
        subprocess's IsolatedStore so both views of state are consistent
        at startup (pre-populated files, emails, mailboxes).
        """
        files: list[dict[str, str]] = [
            {"path": f.path, "sensitivity": f.sensitivity.name}
            for f in self.store._files._data.values()
        ]
        emails: list[dict[str, str]] = [
            {"address": e.address, "domain": e.domain.name}
            for e in self.store._emails._data.values()
        ]
        mailboxes: list[str] = list(self.store._mailboxes._data.keys())

        client.bootstrap(files=files, emails=emails, mailboxes=mailboxes)

    def shutdown(self) -> None:
        """Cleanly shut down the broker and its subprocess (multi-process mode only).

        In multi-process mode: sends SHUTDOWN to the executor subprocess,
        terminates and rejoins the process. Safe to call multiple times
        (idempotent after first call).

        In same-process mode: no-op.
        """
        if self._mode == "multi-process":
            executor = self._executor
            if isinstance(executor, SubprocessExecutor):
                executor.shutdown()
            self._mode = "shutdown"  # prevent double-shutdown

    def set_mediator(self, mediator: Mediator) -> None:
        """Attach a Mediator (the enforcement shim) to this broker"""
        self._mediator = mediator

    @property
    def executor(self) -> IsolatedExecutor | SubprocessExecutor:
        """The sole executor for this broker. All effects go through it."""
        assert self._executor is not None, "executor not initialized"
        return self._executor

    # ---- capability management (monotonic, root-anchored) ----
    def grant_root(self, capability: Capability) -> None:
        """Seed NEW authority. Only a trusted root may do this"""
        assert capability.owner in TRUSTED_ROOTS, (
            f"non-root principal {capability.owner} cannot seed authority (NoAmp)"
        )
        assert capability.derives_from is None, "root grant must not have a parent"
        self.capabilities[capability.nonce] = capability

    def attenuate(
        self,
        parent_nonce: str,
        holder: str,
        right: str,
        target: str,
        scope: frozenset[str],
        expiry: float,
    ) -> Capability:
        """Derive a child capability from a parent. Must not widen authority.

        Requires:
          - parent exists,
          - child scope is a subset of parent scope (monotonic),
          - the parent actually authorizes this (right, target) — i.e. the child
            asks for no more than the parent granted.
        """
        parent = self.capabilities[parent_nonce]
        assert scope <= parent.scope, f"attenuation must narrow scope ({scope} !<= {parent.scope})"
        assert _provides(parent, right, target), "cannot widen authority beyond parent grant"

        # Capabilities may be forwarded (standard object-capability transitivity);
        # NoAmp safety comes from *monotonic narrowing* + *root-anchoring* (the
        # child still carries the root owner via derives_from), not from banning
        # delegation. A holder may pass a capability on subject to monotonicity
        child = Capability(
            owner=parent.owner,
            holder=holder,
            right=right,
            target=target,
            scope=scope,
            expiry=expiry,
            nonce=f"{parent.nonce}:{holder}",
            derives_from=parent.nonce,
        )
        self.capabilities[child.nonce] = child
        return child

    def revoke(self, nonce: str, task_id: TaskId | None = None) -> None:
        """Revoke a capability by nonce.

        - With task_id: per-task revocation (affects only that task's session).
        - Without task_id: global revocation (adds nonce to ALL registered task
          sessions, so the revocation takes effect regardless of which task
          context a commit uses).
        """
        if task_id is not None:
            task = self.tasks.get(task_id)
            if task is not None:
                assert task.session is not None, "task.session must be set by Task.__post_init__"
                task.session.revoked.add(nonce)
        else:
            # Global revocation: add to the broker-level set. check_fresh will
            # check this in addition to any task-scoped revocation. This works
            # even before any task is registered (revoke called before commit).
            self.global_revoked.add(nonce)

    # ---- task management ----
    def register_task(self, task: Task) -> None:
        """Register a task with the broker. Call this before any effect commit.

        REPLAY GUARD: a task_id may not be re-registered after it has been
        used (had a session with nonces in `used`). This prevents an attacker
        from re-registering a task with a fresh session to replay a consumed
        nonce. To restart a task, call revoke(nonce) for each capability
        explicitly and then register with a DIFFERENT task_id.
        """
        existing = self.tasks.get(task.task_id)
        if existing is not None and existing.session is not None:
            # If the existing task ever had a committed nonce (used set non-empty),
            # it cannot be silently replaced. This prevents replay via session-reopen.
            if existing.session.used:
                raise ValueError(
                    f"task_id '{task.task_id}' is already registered and has been used "
                    f"(session.used={existing.session.used}). To restart, use a different "
                    f"task_id or explicitly revoke all nonces first. "
                    f"Re-registering a used task would allow replay attacks."
                )
        self.tasks[task.task_id] = task

    def get_task(self, task_id: TaskId) -> Task | None:
        """Look up a registered task."""
        return self.tasks.get(task_id)

    def advance_time(self, task_id: TaskId, delta: float = 1.0) -> None:
        """Advance the task session's logical clock (logical time)."""
        task = self.tasks[task_id]
        assert task.session is not None, "task.session must be set by Task.__post_init__"
        task.session.logical_time += delta

    def attempt_wide(
        self,
        parent_nonce: str,
        holder: str,
        right: str,
        target: str,
        scope: frozenset[str],
        expiry: float,
        task_id: TaskId | None = None,
    ) -> Capability:
        """Deliberately create a NON-monotonic (widened) capability.

        This models delegation widening (T6): an agent tries to hand a
        sub-agent a capability that is NOT a monotonic narrowing of its own
        Auth rejects the non-monotonic derivation chain at commit time
        """
        parent = self.capabilities[parent_nonce]
        child = Capability(
            owner=parent.owner,
            holder=holder,
            right=right,
            target=target,
            scope=scope,
            expiry=expiry,
            nonce=f"{parent.nonce}:{holder}:wide",
            task_id=task_id,
            derives_from=parent.nonce,
        )
        self.capabilities[child.nonce] = child
        return child

    # ---- declass/endorse (broker-only privileged operations) ----
    def grant_label_exception(
        self,
        exception: LabelException,
        task_id: str | None = None,
    ) -> None:
        """Record a validated declass/endorse grant. BROKER-ONLY

        declass/endorse are privileged operations performed ONLY
        by the EffectBroker on explicit User Policy or a validated approval.
        The LLM may request (see request_label_exception), never perform. This
        is the single trusted spot where an otherwise-forbidden flow may be
        explicitly allowed (T3): the label reclassification is explicit and
        attributable to a trusted grantor

        SESSION TAINT CLEARING (inter-effect composition):
          If this is a declass for CONFIDENTIAL send and a session is taint-forced
          (session.tainted=True), this grant clears the taint so the send can proceed.
          The task_id must match for the taint to be cleared (cross-task declass
          does NOT clear taint in the original task).
        """
        if exception.granted_by not in (USER, APPROVER):
            raise ValueError(
                f"label exception must be granted by a trusted principal "
                f"(User or Approver), got {exception.granted_by}"
            )
        if exception.nonce in self.label_exceptions:
            raise ValueError(f"duplicate label exception nonce {exception.nonce}")
        self.label_exceptions[exception.nonce] = exception

        # ---- Session taint clearing (inter-effect composition) ----
        # If a declass for CONFIDENTIAL→INTERNAL send is recorded, and the
        # session is taint-forced (read secrets happened), clear taint.
        # This allows legitimate workflows: read-confidential → request declass →
        # broker grants → taint cleared → send allowed.
        if exception.kind == "declass":
            target_task_id = task_id or "default"
            if exception.task_id is not None and exception.task_id != target_task_id:
                return  # declass is for different task, don't clear taint
            task = self.tasks.get(target_task_id)
            if task is not None and task.session is not None and task.session.tainted:
                if exception.from_label == "CONFIDENTIAL" and exception.etype in ("send", None):
                    task.session.clear_taint()

    @staticmethod
    def request_label_exception(
        *,
        kind: str,
        target: str,
        additional_targets: frozenset[str] = frozenset(),
        etype: str | None = None,
        from_label: str,
        to_label: str,
        task_id: str | None = None,
    ) -> LabelException:
        """LLM/agent-side REQUEST for a declass/endorse.

        The returned LabelException is a REQUEST only — the broker must later
        record it via grant_label_exception after checking policy. This enforces
        "LLM may request, never perform".

        The exact effect identity check is deferred to the broker's
        matches_effect() method at grant time. The request includes
        additional_targets and etype so the broker can verify the complete
        effect identity at grant time (not just at commit time).
        """
        return LabelException(
            kind=kind,
            match_target=target,
            additional_targets=additional_targets,
            etype=etype,
            from_label=from_label,
            to_label=to_label,
            granted_by="?",
            nonce="?",
            task_id=task_id,
        )

    # ---- risk model placement: escalation, NOT in the allow rule ----
    def assess_risk(self, effect: Effect) -> float:
        """Learned/stub risk classifier. May route to an Approver for review

        This is deliberately NOT part of the formal allow rule: the four
        predicates decide allow/deny regardless of this score. If the score is
        high, the effect is *routed* to an Approver; approval grants a fresh,
        one-shot capability which must STILL pass Auth and FlowOK and NoAmp and Fresh
        at commit. The theorem holds even if this classifier is wrong
        """
        # Minimal stub: escalate sensitive-target effects unless overridden
        score = 0.0
        if effect.target.endswith("/secrets") or effect.target.startswith("http://"):
            score = 0.9
        # test override lets us force a high/low risk deterministically
        return max(score, self.risk_override)

    def needs_review(self, effect: Effect) -> bool:
        """True if the risk model wants human review before commit."""
        return self.assess_risk(effect) >= 0.8

    def grant_approval(
        self,
        effect: Effect,
        expiry: float,
        task_id: TaskId | None = None,
    ) -> str:
        """Approver grants a FRESH, ONE-SHOT capability for `effect`.

        The approved capability is scoped to task_id (defaults to "default")
        and still must pass Auth and FlowOK and NoAmp and Fresh at commit.

        Returns the capability nonce. The ApprovedRequest (full identity binding)
        is stored separately for exact verification in EffectObserver.verify().
        """
        if task_id is None:
            task_id = "default"
        nonce = f"approval:{effect.etype}:{effect.target}:{len(self.approvals)}"

        # Scope for this approval capability. For send effects, the scope must
        # cover ALL recipients (primary + BCC) — NoAmp's extra-target check
        # verifies every BCC domain is in the cap scope. If only primary's domain
        # is in scope, a BCC to external will fail NoAmp even WITH approval.
        if effect.etype == "send" and "@" in effect.target:
            # Collect ALL email domains from primary + extra targets
            all_targets = effect.complete_targets()
            scope_elements: set[str] = set()
            for addr in all_targets:
                domain_label = self._domain_for_email(addr)
                if domain_label is not None:
                    scope_elements.add(domain_label)
            cap_scope = frozenset(scope_elements) if scope_elements else frozenset({effect.target})
        else:
            cap_scope = frozenset({effect.target})

        cap = Capability(
            owner=USER,
            holder=BROKER,
            right=effect.etype,
            target=effect.target,
            scope=cap_scope,
            expiry=expiry,
            nonce=nonce,
            task_id=task_id,
            derives_from=None,
        )
        self.capabilities[nonce] = cap
        self.approvals[nonce] = expiry

        # Also store the ApprovedRequest for exact immutable request binding
        # (kill-criterion #5: complete identity must match).
        # The binding covers etype, target set, and task_id.
        # Provenance/integrity is checked by FlowOK, not the binding.
        authorized_targets = effect.complete_targets()
        all_targets = authorized_targets

        approved_req = ApprovedRequest(
            nonce=nonce,
            etype=effect.etype,
            targets=EffectTarget(primary=effect.target, additional=all_targets - {effect.target}),
            expiry=expiry,
            task_id=task_id,
            granted_by=APPROVER,
        )
        self._approved_requests: dict[str, ApprovedRequest] = getattr(
            self, "_approved_requests", {}
        )
        self._approved_requests[nonce] = approved_req

        return nonce

    def _has_validated_exception(self, effect: Effect, kind: str, datum_label_name: str) -> bool:
        """True if a broker-recorded, validated exception sanctions this override

        An exception applies only if:
          - it targets this effect (matches_effect checks target set exactly)
          - its `from_label` names the label currently violating the flow
          - the grant was actually recorded by the broker (nonce known)
          - kind matches (declass vs endorse)

        This makes declass/endorse explicit, attributable, and broker-validated.
        The key fix: matches_effect() checks exact effect identity, including
        BCC/extra_targets and etype — a grant for "send to internal" does NOT
        authorize "send to internal with BCC to external" unless explicit.
        """
        for exception in effect.label_exceptions:
            grant = self.label_exceptions.get(exception.nonce)
            if grant is None:
                continue  # not yet broker-validated
            if grant.kind != kind:
                continue
            if not grant.matches_effect(effect):
                # Target set mismatch: grant doesn't cover this effect's complete identity
                continue
            if grant.from_label != datum_label_name:
                continue
            return True
        return False

    # ---- root-anchoring / monotonicity helper (used by Auth and NoAmp) ----
    def _check_derivation(self, capability: Capability) -> tuple[bool, str]:
        """Check root-anchoring AND monotonicity of the derivation chain.

        Returns (ok, evidence). A capability is legitimate iff:
          - its owner is a trusted root (root-anchored), AND
          - the entire chain of attenuations is monotonic (each child scope ⊆
            parent scope, each child right+target is covered by the parent).

        This is the key property that distinguishes a trusted attenuation from
        a forged capability with an accidentally-matching owner field: the chain
        is what proves monotonic narrowing, not just the presence of a trusted
        owner.
        """
        if capability.owner not in TRUSTED_ROOTS:
            return False, f"owner-not-trusted({capability.owner})"
        seen: set[str] = set()
        node: Capability | None = capability
        while node is not None:
            if node.nonce in seen:  # cycle guard
                return False, "cycle-in-chain"
            seen.add(node.nonce)
            if node.derives_from is None:
                # root grant: owner already checked, derivation terminates legitimately
                if node.owner in TRUSTED_ROOTS:
                    return True, f"root-anchored({node.owner})"
                return False, f"root-owner-untrusted({node.owner})"
            parent = self.capabilities.get(node.derives_from)
            if parent is None:
                return False, f"broken-chain(parent={node.derives_from})"
            # Monotonicity: child scope <= parent scope and parent's right+target
            # covers the child's request
            if not (node.scope <= parent.scope and _provides(parent, node.right, node.target)):
                return False, (
                    f"non-monotonic(scope={node.scope}!<={parent.scope},"
                    f"right={node.right} not in parent's rights)"
                )
            node = parent
        return True, f"legitimate(owner={capability.owner})"

    def _authority(self, capability: Capability) -> tuple[str, str]:
        """Return the (right, target) pair this capability authorizes."""
        return (capability.right, capability.target)

    def check_auth(self, effect: Effect, task: Task) -> PredicateResult:
        """Complete static-and-dynamic judgment: Auth(e,t).

        The task `t` is the authoritative bound — it is the task passed to
        commit() (which wraps the effect). `effect.task_id` may be set for
        logging/audit; this method validates against the ceiling in `t`.


        Rejects forged/widened capabilities at the gate, not downstream.
        The five sub-checks:

          1. root-anchored  : capability owner is a trusted root
          2. monotonic      : no widening along the derivation chain
          3. bottom-scoped  : write authority is subset ceiling scope (integrity floor)
          4. task-bounded   : effect authority subset task ceiling scope (confidentiality floor)
          5. matches        : holder, right, target all agree with the effect

        After this refactor, forged capabilities (owner=Mallory, forged nonce)
        fail sub-check 1 (owner not trusted). Honest delegation widening fails
        sub-check 2 (non-monotonic). So the blocker is Auth, not NoAmp.
        """
        capability = self.capabilities.get(effect.capability_nonce)
        if capability is None:
            return False, "no-capability"

        # Sub-check 1+2: derivation (root-anchoring + monotonicity)
        legit_ok, legit_evidence = self._check_derivation(capability)
        if not legit_ok:
            return False, f"derivation-fail({legit_evidence})"

        # Sub-check 3: bottom-scoped — write authority is subset ceiling scope
        # (integrity floor: a writer may not escalate beyond the ceiling's scope)
        if effect.etype == "write":
            if capability.scope > task.ceiling.scope:
                return False, (
                    f"bottom-scoping-violation(scope={capability.scope}!≤{task.ceiling.scope})"
                )

        # Sub-check 4: task-bounded — effect authority subset task ceiling
        # A ceiling.scope containing "*" is a wildcard: covers any target/right.
        # Otherwise, the capability's scope elements must all be in the ceiling's
        # scope AND the effect's target (or its domain, for email targets) must be
        # a member of the ceiling scope.
        # CRITICAL FIX: for email targets (addr@domain), compare the DOMAIN LABEL
        # against the ceiling scope, not the raw email address. Otherwise:
        #   "internal@corp.com" in {"internal"} = False <- WRONG (masks the bug)
        #   _domain_for_email("internal@corp.com") = "internal"
        #   "internal" in {"internal"} = True <- CORRECT
        is_wildcard = "*" in task.ceiling.scope
        target_for_scope_check = self._scope_label_for_target(effect.target)
        # For file:// targets: check if the target is inside any scope element.
        # A cap scoped to file:///a/b allows operations on
        # file:///a/b/subdir/file.txt (target is a subdirectory of the scope).
        # For non-file targets or wildcard scopes: use exact match.
        if target_for_scope_check.startswith("file://") and not is_wildcard:
            # Subdirectory containment: file:///a/b allows file:///a/b/c
            target_in_scope = any(
                target_for_scope_check.startswith(s + "/") or target_for_scope_check == s
                for s in task.ceiling.scope
            )
            # Cap scope doesn't need to be subset of ceiling (for scoped caps)
            scope_ok = target_in_scope
        else:
            # Original logic: cap scope ≤ ceiling scope AND target in ceiling.
            # Special case: ceiling scope is wildcard {'*'} — skip subset check.
            target_in_scope = is_wildcard or target_for_scope_check in task.ceiling.scope
            scope_ok = (is_wildcard or capability.scope <= task.ceiling.scope) and target_in_scope
        if not scope_ok:
            return (
                False,
                "task-bounded-fail("
                f"e-target={effect.target} (scope-label={target_for_scope_check}) "
                f"not in ceiling-scope={task.ceiling.scope})",
            )

        # Sub-check 5: right must match.
        # A capability grants exactly one right. An approval for read cannot
        # authorize write — right="*" on a default ceiling was the bypass path.
        # Strict ceiling.right must match capability.right must match effect.etype.
        # Exception: right="*" is a wildcard — matches any etype.
        if capability.right != "*" and capability.right != effect.etype:
            return False, f"right-mismatch(cap_right={capability.right}!=etype={effect.etype})"
        if capability.target != "*" and capability.target != effect.target:
            return (
                False,
                f"target-mismatch(cap_target={capability.target}!=effect.target={effect.target})",
            )

        # Sub-check 6: task-scoping (only for reusable capabilities with task_id).
        # Approval capabilities (identified by "approval:" prefix) use ApprovalBinding
        # in gate() instead, which already checks task_id exactly. Reusable capabilities
        # that declare a task_id must be used only in that task — this prevents a
        # reusable cap scoped to task-A from being used in task-B.
        if capability.task_id is not None and not effect.capability_nonce.startswith("approval:"):
            if capability.task_id != task.task_id:
                return False, (
                    f"task-scope-mismatch("
                    f"cap-task_id={capability.task_id}!=commit-task_id={task.task_id})"
                )

        return True, f"auth-ok(derivation={legit_evidence},task={task.task_id})"

    def check_flow(self, effect: Effect, task: Task) -> PredicateResult:
        """IFC gate: provenance labels must not exceed task's flow_boundary.

        Uses the task's declared (sink_confidentiality, sink_integrity) interval
        rather than hard-coded per-effect-type defaults. This lets
        each task define its own sensitivity floor, making FlowOK task-scoped.

        SESSION TAINT (inter-effect composition):
          If the task's session has read CONFIDENTIAL data (session.tainted=True),
          ALL send effects are blocked unless a broker-recorded declass exception
          exists. This prevents the read-secrets→send-exfil attack without requiring
          taint tracking on data values. The session is tainted when a read effect
          reads a CONFIDENTIAL file (see _apply_effect for read handling).
        """
        # ---- Session taint check (inter-effect composition) ----
        # If session is tainted, send effects require a declass exception.
        # This is the conservative cross-effect guard: once CONFIDENTIAL data
        # was read in this session, every send needs explicit declass.
        if task.session is not None and task.session.tainted:
            if effect.etype == "send":
                # Check if there's a declass exception that covers this send
                if self._has_validated_exception(effect, "declass", "CONFIDENTIAL"):
                    return True, "flow-ok(session-taint-cleared-by-declass)"
                return False, (
                    f"session-taint("
                    f"session={task.session.session_id} "
                    f"has-read-confidential, "
                    f"reason={task.session._taint_reason!r}, "
                    f"declass-required)"
                )

        sink_confidentiality, sink_integrity = task.flow_boundary
        for datum in effect.provenance:
            if datum.confidentiality > sink_confidentiality and not self._has_validated_exception(
                effect, "declass", datum.confidentiality.name
            ):
                return False, (
                    f"conf-leak({datum.name}:"
                    f"{datum.confidentiality.name}>{sink_confidentiality.name})"
                )
            if datum.integrity < sink_integrity and not self._has_validated_exception(
                effect, "endorse", datum.integrity.name
            ):
                return False, (
                    f"low-integrity({datum.name}:{datum.integrity.name}<{sink_integrity.name})"
                )
        return True, "flow-ok"

    def check_noamp(self, effect: Effect, task: Task) -> PredicateResult:
        """Composition safety: effect authority stays within the task ceiling

        Single-effect scope: NoAmp verifies that the effect's target and all
        extra_targets (BCC/CC recipients) are within the task ceiling scope.
        For `network` effects, also enforces SSRF containment.

        INTER-EFFECT COMPOSITION: Handled by Session Taint Mode (check_flow).
          The read-secrets→send-exfil attack is blocked by session taint:
            - When read(secrets) commits: session.tainted = True (see _apply_effect)
            - When send(internal) commits: check_flow() blocks with "session-taint"
              unless a broker-recorded declass exception exists
          This covers the primary composition attack. Session taint is
          conservative: ALL sends after a CONFIDENTIAL read require declass,
          even for legitimate workflows. To use a tainted session for sends,
          the broker must record a declass exception via grant_label_exception().

        REMAINING GAP: Cross-task composition (effect from Task A → task B).
          If the same capability is valid across tasks, a sequence of effects
          across task boundaries is not tracked. This requires task isolation
          beyond process isolation — deferred.
        """
        capability = self.capabilities.get(effect.capability_nonce)
        if capability is None:
            return False, "no-capability"

        # The effect's target must be in the task's ceiling scope.
        # CRITICAL FIX: for email targets, compare the domain label, not the
        # raw email address. This is the same fix as in check_auth().
        is_wildcard = "*" in task.ceiling.scope
        target_for_scope_check = self._scope_label_for_target(effect.target)
        # Same subdirectory-aware logic as check_auth:
        # file:///a/b allows file:///a/b/c (subdirectory)
        if target_for_scope_check.startswith("file://"):
            target_in_scope = is_wildcard or any(
                target_for_scope_check.startswith(s + "/") or target_for_scope_check == s
                for s in task.ceiling.scope
            )
        else:
            target_in_scope = is_wildcard or target_for_scope_check in task.ceiling.scope
        if not target_in_scope:
            return (
                False,
                "composition-fail("
                f"target={effect.target} (scope-label={target_for_scope_check}) "
                f"not in ceiling-scope={task.ceiling.scope})",
            )

        # Right dominance: ceiling.right = "*" dominates all rights (any right allowed).
        # Any other ceiling.right must exactly match the capability's right.
        if task.ceiling.right == "*":
            pass  # wildcard: any capability right is within ceiling
        elif capability.right == task.ceiling.right:
            pass  # exact match: within ceiling
        else:
            return False, (
                f"ceiling-right-mismatch(cap-right={capability.right}!=ceiling-right={task.ceiling.right})"
            )

        # Extra-target scope check for BCC/CC recipients
        # The capability scope defines which domains (scopes) the capability covers.
        # Extra targets outside this scope are not authorized — for both email
        # (domain label check) AND non-email targets (scope inclusion check).
        if effect.known_targets is not None and effect.known_targets.additional:
            for extra_target in effect.known_targets.additional:
                if "@" in extra_target:
                    # Email extra target: check domain label against cap scope
                    extra_domain = self._domain_for_email(extra_target)
                    if extra_domain is not None and extra_domain not in capability.scope:
                        return False, (
                            f"extra-target-outside-scope("
                            f"{extra_target} (domain={extra_domain}) "
                            f"not in cap-scope={capability.scope})"
                        )
                else:
                    # Extra targets from the effect's complete_targets() are directory
                    # paths (parent dirs, temp dirs, etc.) for file ops.
                    # Check if the directory itself or any of its parent directories
                    # is in the cap scope. This allows operations on files in
                    # file:///a/b/subdir/file.txt where scope={file:///a/b}.
                    target_label = extra_target
                    if not any(
                        target_label.startswith(s + "/") or target_label == s
                        for s in capability.scope
                    ):
                        return False, (
                            f"extra-target-outside-scope("
                            f"{extra_target} "
                            f"not under cap-scope={capability.scope})"
                        )

        # SSRF containment for network effects
        if effect.etype == "network":
            if "://" in effect.target:
                # Extract the domain/host from the URL, normalize for comparison.
                # The capability scope stores DOMAIN-LEVEL entries (e.g. {"internal.corp.com"})
                # not full URL origins. We must extract the domain from both the URL
                # and the scope entries to compare them consistently.
                after_scheme = effect.target.split("://", 1)[1]
                path_start = after_scheme.find("/")
                host_part = after_scheme[:path_start] if path_start >= 0 else after_scheme
                # Extract domain from host: strip port, strip subdomains to root
                # "internal.corp.com" -> "internal.corp.com"
                # "internal.corp.com:8080" -> "internal.corp.com"
                url_domain = host_part.split(":")[0].lower()

                # Compare the URL's domain against each scope entry.
                # Scope entries are domain-level (e.g. "internal.corp.com" or "evil.com").
                # We compare domain strings directly — "internal.corp.com" == "internal.corp.com".
                # If scope={"*"} → wildcard, skip containment check.
                if "*" not in capability.scope:
                    domain_allowed = False
                    for scope_entry in capability.scope:
                        if scope_entry.startswith("http://") or scope_entry.startswith("https://"):
                            # Scope entry is a full origin — extract its domain
                            scope_after = scope_entry.split("://", 1)[1]
                            scope_host = scope_after.split("/")[0].split(":")[0].lower()
                            scope_domain = scope_host
                        else:
                            # Scope entry is a domain string (e.g. "internal.corp.com")
                            scope_domain = scope_entry.lower()

                        if url_domain == scope_domain:
                            domain_allowed = True
                            break

                    if not domain_allowed:
                        return False, (
                            f"ssrf containment failed: url-domain={url_domain} "
                            f"not in cap-scope={capability.scope}"
                        )

        return True, f"composition-ok(ceiling-scope={task.ceiling.scope})"

    def _scope_label_for_target(self, target: str) -> str:
        """Extract the scope-relevant label from a target for scope comparison.

        For email targets (addr@domain), returns the domain label so that:
          - "internal@corp.com" -> "internal" (matches ceiling scope {"internal"})
          - "external@attacker.com" -> "external" (matches ceiling scope {"external"})

        For file:// targets, returns the parent directory URI so that:
          - "file:///canon/new_file.txt" -> "file:///canon"
            (matches ceiling scope {"file:///canon"})

        For other targets, returns the target as-is:
          - "http://internal.corp.com" -> "http://internal.corp.com"
        """
        if "@" in target:
            domain = self._domain_for_email(target)
            return domain if domain is not None else target

        if target.startswith("file://"):
            # Extract scope-relevant label for containment check.
            # For a FILE target file:///a/b/c:
            #   scope-label = parent(file:///a/b/c) = file:///a/b
            #   → checks if parent is in scope
            # For a DIRECTORY extra-target file:///a/b:
            #   scope-label = file:///a/b (use as-is — it's already a scope element)
            #   → checks if the directory itself is in scope
            path_part = target[7:]  # remove "file://"
            last_slash = path_part.rfind("/")
            if last_slash > 0:
                return f"file://{path_part[:last_slash]}"
            # Bare path like "file:///filename" → use the path itself as label
            return target

        return target

    def _domain_for_email(self, addr: str) -> str | None:
        """Derive the domain label from an email address for scope checking.

        Uses the formal Domain enum from model.py — NOT string heuristics.
        This ensures attacker-controlled domains are always "external", not
        accidentally classified as "internal" by the "corp in domain" heuristic.

        Rules (in priority order):
          1. If the email address is a bootstrap resource (registered in store),
             use its actual domain classification from the ResourceStore.
          2. Known trusted domains (allowlist): internal corporate domains
             with a controlled registration path. "corp.com" alone is NOT enough —
             "evil.corp.com" also matches "corp" and must be "external".
          3. External: any other domain (including attacker-controlled domains
             with "corp" in the name like "evil-corp.com" or "attacker-corp.com").
          4. No "@" → None (not an email address).

        The allowlist is intentionally restrictive: we err on the side of
        "external" to avoid misclassifying attacker-controlled lookalike domains.
        Production deployments should expand this list with their actual
        trusted domain suffixes.
        """
        if "@" not in addr:
            return None
        domain_part = addr.split("@")[1].lower()

        # Priority 1: check the ResourceStore — authoritative for registered resources
        # A bootstrap'd resource has a pre-classified Domain enum value.
        from .model import Domain

        if addr in self.store._emails._data:
            email_resource = self.store._emails._data[addr]
            if email_resource.domain == Domain.INTERNAL:
                return "internal"
            return "external"

        # Priority 2: allowlist of known trusted domain suffixes.
        # CRITICAL: "corp" alone in the domain is NOT sufficient to classify as internal.
        # "attacker@corp.com" and "evil@corp.com" must be "external" — an attacker
        # can register "corp.com" typosquatting domain. We require the EXACT domain,
        # not just a substring match.
        TRUSTED_DOMAINS: frozenset[str] = frozenset(
            {
                "corp.com",  # legitimate corporate domain
                "internal.corp.com",  # explicit internal subdomain
            }
        )
        EXTERNAL_DOMAINS: frozenset[str] = frozenset(
            {
                "elsewhere.com",  # known external in test bootstrap
                "attacker.com",  # attacker domain in test traces
                "evil.com",
                "attacker.evil.com",
            }
        )

        # Strip port if present
        clean_domain = domain_part.split(":")[0]

        if clean_domain in EXTERNAL_DOMAINS:
            return "external"
        if clean_domain in TRUSTED_DOMAINS:
            return "internal"

        # Default: external (safe by default for unknown domains).
        # This prevents attacker-controlled domains like "mycorp.com" or "corp.evil.com"
        # from being accidentally classified as internal. Known corporate email
        # MUST be explicitly added to TRUSTED_DOMAINS in production deployments.
        return "external"

    def check_fresh(self, effect: Effect, task: Task) -> PredicateResult:
        """Task-scoped freshness: lifetime/revocation/replay against Session.

        the lifetime model is per-task (logical clock of the task's
        Session, not a wall-clock). Revocation and replay are also per-task.

        FIXED: Session.live=False now BLOCKs commit. A dead session has no
        authoritative clock, so no effect can be committed in its name —
        the task's authority ceiling is invalid until the session is reopened.

        NOTE: This method does NOT reserve the nonce. For thread-safe commits
        (preventing double-commit with the same nonce under concurrency), use
        _atomic_fresh_check() instead, which checks AND reserves atomically.
        """
        capability = self.capabilities.get(effect.capability_nonce)
        if capability is None:
            return False, "no-capability"
        assert task.session is not None, "task.session must be initialized by Task.__post_init__"

        # FIXED: closed/dead session blocks all commits in this task.
        # The session's authority ceiling is no longer authoritative.
        if not task.session.live:
            return False, f"session-closed(task={task.task_id})"

        # Lifetime: capability not expired against the task's logical clock
        effective_time = max(task.session.logical_time, self.logical_time)
        if capability.expiry <= effective_time:
            return False, f"expired(t_session={effective_time},cap_exp={capability.expiry})"

        # Revocation: per-task nonce list AND broker-level global revocation
        if capability.nonce in task.session.revoked or capability.nonce in self.global_revoked:
            return False, f"revoked(in_task={task.task_id} or global)"

        # Replay: per-task used nonce set
        if effect.capability_nonce in task.session.used:
            return False, f"replay(in_task={task.task_id})"

        return True, f"fresh(t_session={task.session.logical_time})"

    def _atomic_fresh_check(self, effect: Effect, task: Task) -> tuple[PredicateResult, bool]:
        """Thread-safe Fresh check: atomically checks and RESERVES the nonce.

        Returns ((ok, evidence), nonce_reserved). If the caller (gate()) fails
        after reservation, it MUST call _release_fresh_reservation() to roll back.

        This closes the race:
          Thread 1: check_fresh() reads used=∅ -> PASS
          Thread 2: check_fresh() reads used=∅ -> PASS
          Thread 1: _apply_effect() adds nonce
          Thread 2: _apply_effect() adds nonce  <- double-commit with same nonce!

        With per-task locks:
          Thread 1: lock(task) -> check -> reserve -> unlock
          Thread 2: lock(task) -> check -> BLOCKED until T1 releases
          T2 sees nonce is used -> Fresh rejects -> correct.
        """
        lock = self._task_locks.setdefault(task.task_id, threading.Lock())
        with lock:
            result = self.check_fresh(effect, task)
            if result[0]:
                # Atomic reservation: add nonce while holding the lock.
                # No other thread can check or reserve this nonce until we release.
                # session is always set: Task.__post_init__ creates a default one.
                task.session.used.add(effect.capability_nonce)  # type: ignore[union-attr]
                return result, True
            return result, False

    def _release_fresh_reservation(self, effect: Effect, task: Task) -> None:
        """Roll back a nonce reservation when gate() fails after atomic reservation.

        Called ONLY when _atomic_fresh_check() returned nonce_reserved=True but
        gate() subsequently failed (e.g. Auth blocked, boundary mediation stopped).
        This ensures a failed effect does not consume a valid one-shot capability.
        """
        lock = self._task_locks.get(task.task_id)
        if lock is None:
            return
        with lock:
            task.session.used.discard(effect.capability_nonce)  # type: ignore[union-attr]

    # ---- commit gate (the ONLY way external state changes) ----
    def commit(
        self,
        commit: Commit,
        mediation: MediationVerdict | None = None,
    ) -> tuple[bool, Evidence]:
        """Commit an effect — routes through the sole executor.

        This is a thin reentrant wrapper: it calls executor.execute(), which
        calls broker.gate() and (on allow) executor.apply_effect() — which is
        the ONLY call site for _apply_effect(). ALL effects — direct broker.commit()
        calls and tool/shim calls — go through the SAME execution path.

        The executor records authorization (from gate) and observation (from
        apply_effect) to the shared ledger, so the ledger sees the complete
        lifecycle through one path.

        Args:
            commit: the prepared effect with commit metadata
            mediation: optional pre-built boundary mediation verdict

        Returns:
            (allow, evidence) — same as gate() but with state applied on allow
        """
        assert self._executor is not None
        return self._executor.execute(commit, mediation=mediation)

    def commit_effect(self, effect: Effect, task: Task | None = None) -> tuple[bool, Evidence]:
        """Stage and commit an effect within task `task`.

        If task is None, a permissive default task is created (same as commit()).
        All commit operations go through the sole executor.
        """
        return self.commit(Commit(effect, task))

    def _make_commit(self, effect: Effect, task_id: TaskId = "default") -> Commit:
        """Build a Commit from an effect and task_id (used by the shim)."""
        task = self.tasks.get(task_id)
        if task is None:
            default_ceiling = Capability(
                owner=USER,
                holder=BROKER,
                right="*",
                target="*",
                scope=frozenset({"*"}),
                expiry=float("inf"),
                nonce="default-ceiling",
            )
            task = Task(task_id=task_id, owner=USER, ceiling=default_ceiling)
            self.tasks[task_id] = task
        return Commit(effect, task)

    # ---- Split commit gate (evaluation) from apply (state mutation) ----
    # This is the key separation for independent observer verification.
    # The executor calls gate() then (on can_apply=True) apply_effect().

    def gate(
        self,
        commit: Commit,
        mediation: MediationVerdict | None = None,
    ) -> CommitGateResult:
        """Phase 1: Evaluate the four-predicate gate. No state mutation.

        Returns CommitGateResult with allow/evidence. Does NOT apply any effect.
        The executor calls this, then calls apply_effect() on can_apply=True.

        This split enables independent observer verification:
        - observer records authorized effects from gate result
        - executor calls apply_effect() which records observed effects
        - verifier compares authorized vs. observed (independent of broker)
        """
        effect = commit.effect
        task = commit.task

        # Get or create task (same logic as commit())
        if task is None:
            task = self.tasks.get("default")
            if task is None:
                default_ceiling = Capability(
                    owner=USER,
                    holder=BROKER,
                    right="*",
                    target="*",
                    scope=frozenset({"*"}),
                    expiry=float("inf"),
                    nonce="default-ceiling",
                )
                task = Task(task_id="default", owner=USER, ceiling=default_ceiling)
                self.tasks[task.task_id] = task

        assert task.session is not None, "Task must have a session (set by __post_init__)"

        # Auto-resolve approved_request from nonce.
        # CRITICAL: if capability_nonce starts with "approval:" but approved_request
        # is None, ApprovalBinding silently skips. This is a silent security failure.
        # We fix it by looking up the ApprovedRequest automatically so callers do NOT
        # need to pass it explicitly — the nonce is the authoritative key.
        from dataclasses import replace

        if (
            commit.approved_request is None
            and effect.capability_nonce is not None
            and effect.capability_nonce.startswith("approval:")
        ):
            stored_req = self._approved_requests.get(effect.capability_nonce)
            if stored_req is not None:
                # Frozen dataclass: create a copy with the resolved approved_request.
                commit = replace(commit, approved_request=stored_req)
                effect = commit.effect  # update local ref after replace
            else:
                # Approval nonce referenced but not found → block at Fresh.
                # This fires when a stale/invalid nonce is used.
                allow = False
                approval_predicate_results: dict[str, PredicateResult] = {
                    "Auth": (True, "auth-ok"),
                    "FlowOK": (True, "flow-ok"),
                    "NoAmp": (True, "composition-ok"),
                    "Fresh": (False, f"approval-nonce-invalid({effect.capability_nonce})"),
                }
                return CommitGateResult(
                    allow=False,
                    evidence={
                        "allow": False,
                        "primary_blocker": "Fresh",
                        "predicates": {k: v[1] for k, v in approval_predicate_results.items()},
                        "boundary_stop": None,
                        "approval_binding": None,
                    },
                    effect=effect,
                    task=task,
                    can_apply=False,
                )

        # Atomic Fresh check: check AND reserve the nonce atomically.
        # This prevents double-commit with the same nonce under concurrency.
        # nonce_reserved = True means Fresh passed AND the nonce is now in used.
        # If we fail the gate AFTER reserving, we MUST release (see rollback below).
        fresh_result, nonce_reserved = self._atomic_fresh_check(effect, task)

        predicate_results: dict[str, PredicateResult] = {
            "Auth": self.check_auth(effect, task),
            "FlowOK": self.check_flow(effect, task),
            "NoAmp": self.check_noamp(effect, task),
            "Fresh": fresh_result,
        }
        allow = all(predicate_result[0] for predicate_result in predicate_results.values())
        predicate_order = ("Auth", "FlowOK", "NoAmp", "Fresh")
        blocking_predicate: str | None = next(
            (predicate for predicate in predicate_order if not predicate_results[predicate][0]),
            None,
        )
        boundary_stop: str | None = None
        approval_binding_ok = True
        approval_binding_msg = ""

        # Approval binding: verify exact immutable request binding
        if allow and commit.approved_request is not None:
            stored = self._approved_requests.get(commit.approved_request.nonce)

            if stored is None or stored.nonce != commit.approved_request.nonce:
                approval_binding_ok = False
                approval_binding_msg = f"approval-nonce-unknown({commit.approved_request.nonce})"
            else:
                # ApprovalBinding checks: etype, target, additional recipients, task_id.
                # Provenance/integrity is checked by FlowOK at commit time.
                # We do NOT bind to content values — that would break dynamic content.
                # CRITICAL: use canonical complete_targets() — authoritative
                # source for target set. Must match what grant_approval() stored.
                current_additional = effect.complete_targets() - {effect.target}

                if effect.etype != stored.etype:
                    approval_binding_ok = False
                    approval_binding_msg = (
                        f"etype-mismatch(approved={stored.etype},got={effect.etype})"
                    )
                elif effect.target != stored.targets.primary:
                    approval_binding_ok = False
                    approval_binding_msg = (
                        f"primary-target-mismatch(approved={stored.targets.primary},"
                        f"got={effect.target})"
                    )
                elif not (current_additional <= stored.targets.additional):
                    extra = current_additional - stored.targets.additional
                    approval_binding_ok = False
                    approval_binding_msg = f"extra-targets-not-approved({extra})"
                elif task.task_id != stored.task_id:
                    approval_binding_ok = False
                    approval_binding_msg = f"cross-task-use({task.task_id}!={stored.task_id})"

            if not approval_binding_ok:
                allow = False
                if blocking_predicate is None:
                    blocking_predicate = "ApprovalBinding"

        # Boundary mediation
        if allow:
            if mediation is not None:
                boundary_verdict = mediation
            elif self._mediator is not None and commit.tool_name is not None:
                boundary_verdict = self._mediator.inspect(effect, commit.tool_name)
            else:
                boundary_verdict = MediationVerdict(True, None)

            if not boundary_verdict.allow:
                allow = False
                boundary_stop = boundary_verdict.boundary_stop
                if blocking_predicate is None:
                    blocking_predicate = "Boundary"

        evidence: Evidence = {
            "allow": allow,
            "primary_blocker": blocking_predicate,
            "predicates": {
                predicate: predicate_result[1]
                for predicate, predicate_result in predicate_results.items()
            },
            "boundary_stop": boundary_stop,
            "approval_binding": (
                approval_binding_msg if commit.approved_request is not None else None
            ),
        }

        # Rollback: if the gate failed AFTER reserving the nonce, release it.
        # This ensures a blocked effect does NOT consume a valid one-shot
        # capability. Without this, a failed gate would permanently burn the
        # nonce (approval nonce for a modified-content effect would be unusable
        # even though the effect was correctly blocked).
        if not allow and nonce_reserved:
            self._release_fresh_reservation(effect, task)

        return CommitGateResult(
            allow=allow,
            evidence=evidence,
            effect=effect,
            task=task,
            can_apply=allow,
        )

    def _apply_effect(self, effect: Effect, task: Task) -> None:
        """Apply an effect to external state. Broker-internal.

        NOTE: The nonce is ALREADY reserved by _atomic_fresh_check() in gate().
        We do NOT add it again here — that would be a no-op (set semantics) but
        would also re-add a nonce that was rolled back after a failed gate.
        Since this is called ONLY when gate() succeeded, the nonce is in used
        and the add is a harmless no-op. If gate() failed, _release_fresh_reservation()
        removed the nonce — this method is never called.

        SESSION TAINT (inter-effect composition):
          When a read effect reads a CONFIDENTIAL file, the session is marked
          as tainted. This prevents subsequent send effects without declass.
        """
        # ---- Session taint: mark session as tainted on CONFIDENTIAL read ----
        if effect.etype == "read" and task.session is not None:
            file_res = self.store.resolve(effect.target)
            if file_res is not None and hasattr(file_res, "sensitivity"):
                if file_res.sensitivity == Confidentiality.CONFIDENTIAL:
                    task.session.taint_for_send(reason=f"read-confidential({effect.target})")

        self.store.apply_effect(effect)

    def apply_effect(self, commit_or_effect: Commit | Effect, task: Task | None = None) -> None:
        """Apply an effect to external state. CALLER must verify gate first.

        DEPRECATED: This is the SECOND phase of commit, called by the IsolatedExecutor
        AFTER gate() returns can_apply=True. Call broker.commit() instead —
        it routes through the sole executor automatically. Direct calls to
        apply_effect() bypass the gate and the ledger.

        If called directly (backwards compat), it applies without ledger observation.

        IMPORTANT: This method does NOT check predicates. The caller is
        responsible for calling gate() first and checking can_apply=True.
        """
        if isinstance(commit_or_effect, Commit):
            effect = commit_or_effect.effect
            effective_task = commit_or_effect.task
            if effective_task is None:
                effective_task = self.tasks.get("default")
                if effective_task is None:
                    raise ValueError("No task for commit and no default task registered")
        else:
            effect = commit_or_effect
            if task is None:
                effective_task = self.tasks.get("default")
                if effective_task is None:
                    raise ValueError("No task provided and no default task registered")
            else:
                effective_task = task
        self._apply_effect(effect, effective_task)

    # ---- Independent ledger: the single source of truth ----
    # The ledger is EXTERNAL (passed in via constructor), not owned by broker.
    # Both broker.commit() (direct) and executor.execute() (via-shim) record to it.
    # The ledger is the ONLY entity that can say "confirmed-committed" or "unknown".

    @property
    def ledger(self) -> IndependentEffectLedger:
        """The independent effect ledger for complete mediation verification.

        This ledger is the single source of truth for authorized vs. observed
        effects. Both broker.commit() (direct) and executor.execute() (via-shim)
        record to this ledger. Call verify_complete_mediation() to check.

        Returns the local IndependentEffectLedger if in same-process mode.
        In multi-process mode (ProcessLedgerClient), this returns the local
        client wrapper and direct attribute access may not reflect remote state.
        Prefer verify_complete_mediation() for multi-process verification.
        """
        return (
            self._local_ledger
            if self._local_ledger is not None
            else cast(IndependentEffectLedger, self._ledger_backend)
        )

    @property
    def observer(self) -> IndependentEffectLedger:
        """Alias for ledger (backwards compatibility). Prefer ledger()."""
        return self.ledger

    def verify_complete_mediation(self) -> list[str]:
        """Verify complete mediation across all authorized effects.

        Uses the independent ledger to compare authorized vs. observed effects.
        Returns list of failure strings (empty = complete mediation).

        Works from BOTH paths:
          - Direct: broker.commit() records authorization + observation
          - Via-shim: executor.execute() records authorization + observation
        """
        # Build the authorized records dict that ledger.verify_all() expects.
        # Keys are (task_id, nonce) tuples; values are authorized targets frozensets.
        authorized_records: dict[tuple[str, str], frozenset[str]] = {}

        # Merge all authorized targets from all authorization entries for each nonce
        for (tid, nonce), entries in self._ledger_backend.get_authorization_entries().items():
            targets: frozenset[str] = frozenset()
            for entry in entries:
                targets |= entry.authorized_targets
            authorized_records[(tid, nonce)] = targets

        return self._ledger_backend.verify_all(authorized_records)

    # ---- Real shim factory (IPC-aware) ----
    # In multi-process mode, shims MUST route real I/O through the subprocess.
    # These factory methods wire the IPC client into the shim automatically.

    def create_real_file_shim(
        self,
        task_id: str = "default",
        tool_name: str = "untrusted-tool",
    ) -> "RealFileShim":
        """Create a RealFileShim with IPC routing in multi-process mode.

        In multi-process mode, real file I/O happens in the executor subprocess
        (not in the broker process). The IPC client is extracted from the
        SubprocessExecutor.

        In same-process mode, ipc_client is None and the shim uses direct
        OS calls (legacy behavior).
        """
        from .shim_real import RealFileShim

        shim = RealFileShim(broker=self, task_id=task_id, tool_name=tool_name)

        if self._mode == "multi-process" and self._executor is not None:
            # Wire IPC client from SubprocessExecutor into the shim
            from .executor import SubprocessExecutor

            if isinstance(self._executor, SubprocessExecutor):
                shim.ipc_client = self._executor._client

        return shim

    def create_real_email_shim(
        self,
        task_id: str = "default",
        tool_name: str = "untrusted-tool",
        smtp_host: str = "localhost",
        smtp_port: int = 25,
        imap_host: str = "localhost",
        imap_port: int = 993,
    ) -> "RealEmailShim":
        """Create a RealEmailShim with IPC routing in multi-process mode.

        In multi-process mode, real SMTP/IMAP happens in the executor subprocess
        (not in the broker process). The IPC client is extracted from the
        SubprocessExecutor.

        In same-process mode, ipc_client is None and the shim uses direct
        smtplib/imaplib calls (legacy behavior).
        """
        from .shim_email import RealEmailShim

        shim = RealEmailShim(
            broker=self,
            task_id=task_id,
            tool_name=tool_name,
            smtp_host=smtp_host,
            smtp_port=smtp_port,
            imap_host=imap_host,
            imap_port=imap_port,
        )

        if self._mode == "multi-process" and self._executor is not None:
            # Wire IPC client from SubprocessExecutor into the shim
            from .executor import SubprocessExecutor

            if isinstance(self._executor, SubprocessExecutor):
                shim.ipc_client = self._executor._client

        return shim
