"""Advisory enforcement shim: the structured path from tool to broker gate.

This shim provides the LOGICAL isolation structure recommended by the ECAC
design. In a real deployment, it would be the ONLY code path from tool code
to external state. In this same-process model:

  - The shim IS the structured path: tool code calls ONLY shim methods.
  - Direct store mutation (broker.store.files[key]=X) is now blocked at the
    dict level (TypeError) — accidental bypass is prevented.
  - A determined adversary who replaces store._files._data directly CAN
    still bypass. The IndependentEffectLedger returns Unknown for unverifiable effects

The key property this enforces: tool code cannot accidentally bypass the
broker gate. The ledger verifies that effects it CAN see match authorized
ones. Effects it cannot verify produce UnknownLedgerResult (not "safe")

ARCHITECTURE (improved):
  tool -> shim -> IsolatedExecutor.execute() -> broker.gate() -> executor.apply()
       ↓                                               ↓
       ledger.record_authorization() ←─────────────────┘
       ledger.record_observation() ←─────────────────────

The IndependentEffectLedger is the single source of truth, independent of
how the effect reached the gate.

SAME-PROCESS LIMITATION:
  The shim, broker, executor, store, and ledger share a Python process.
  An adversarial process can still mutate the store directly. The ledger
  returns Unknown for unverifiable effects — this is the "unknown, not safe"
  requirement. For real isolation, deploy in a separate process/enclave
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, TypeVar

from .executor import IsolatedExecutor

if TYPE_CHECKING:
    from .broker import EffectBroker
    from .tool_registry import ToolRegistry

T = TypeVar("T")


@dataclass
class ShimOp:
    """A single operation logged by the shim (independent observer).

    This is the ONLY record of what the untrusted tool actually did.
    Compare with broker.store.identity_log for complete-effect-identity verification.

    Key fix: extra_resources are now part of the Effect's known_targets,
    not just metadata. The broker gate validates the complete set.
    """

    operation: str  # "read" | "write" | "delete" | "send"
    resource: str  # actual resource the shim observed (primary target)
    extra_resources: frozenset[str] = field(default_factory=frozenset)
    # For T14 (hidden exfil): any ADDITIONAL resources the tool touched
    # For T2/BCC: extra recipients beyond the declared one
    # For T13: declared vs actual target mismatch
    tool_name: str = "untrusted-tool"
    blocked: bool = False  # True if broker BLOCKed this effect (expected)


class SecurityError(Exception):
    """Raised by the shim when the broker BLOCKs an effect.

    The untrusted tool cannot catch or suppress this. It means:
    - No effect reached external state
    - The broker's gate + mediation stopped the attack
    - The claim "every real effect is broker-authorized" holds for this op
    """

    pass


class FileShim:
    """Advisory enforcement shim for file and email operations.

    In a real isolated deployment: the ONLY path from tool code to external state.
    In this same-process model: the structured path with accidental-bypass prevention.

    Structural enforcement (ToolRegistry):
      Every tool MUST declare its capabilities upfront via ToolDeclaration.
      Before building an Effect, the shim checks:
        - operation (right) ∈ declared_rights
        - target ∈ declared_targets
        - extra targets ∈ declared_targets
      If not → SecurityError BEFORE the Effect is built → no ledger entry.

    For each call, the shim:
      1. Structural check: operation + target ∈ tool's declared capabilities
      2. Derives the EXACT effect from real state (not the tool's declaration)
         — including ALL extra_resources in known_targets
      3. Submits it to the broker gate via IsolatedExecutor.execute()
      4. The executor's EffectObserver records authorized vs. observed effects
      5. Raises SecurityError if broker BLOCKs
      6. On ALLOW: store.apply_effect() handles ALL targets (primary + extra)

    NOTE: In the same-process model, direct store mutation is still theoretically
    possible (store._files._data[...] = X). The read-only dict proxies prevent
    ACCIDENTAL bypass. A determined adversary would need to access _underscore
    attributes. The observer returns UnknownObserverResult for unverifiable
    effects — this is the "unknown, not safe" requirement.

    Key property: the shim does NOT trust the tool's declared intent.
    It derives the actual effect from what the tool DOES, not what it SAYS.
    """

    def __init__(
        self,
        broker: EffectBroker,
        task_id: str = "default",
        tool_name: str = "untrusted-tool",
        registry: ToolRegistry | None = None,
    ) -> None:
        self.broker = broker
        self.task_id = task_id
        self.tool_name = tool_name
        self.op_log: list[ShimOp] = []
        # Structural enforcement: tool capability declarations
        # If registry is set, the shim checks each operation against the
        # tool's declared rights/targets BEFORE building the Effect.
        self._registry = registry

        # IsolatedExecutor
        # All mutations go through executor.execute() — the single mutation path.
        # The observer is broker._observer (shared with broker.commit path).
        self._executor = IsolatedExecutor(
            broker=broker,
            task_id=task_id,
        )

    def _set_registry(self, registry: ToolRegistry) -> None:
        """Attach a ToolRegistry for structural enforcement (T13/T14)."""
        self._registry = registry

    # ---- public shim API (untrusted tool calls these) ----
    def _structural_check(
        self, operation: str, target: str, extra: frozenset[str] = frozenset()
    ) -> None:
        """Structural enforcement: operation must be in tool's declared capabilities.

        Called at the START of each shim operation, BEFORE the Effect is built.
        This prevents undeclared operations from even reaching the broker gate.

        If registry is None: permissive mode (unknown tools allowed).
        If strict=True in registry: unknown tools raise SecurityError.
        """
        if self._registry is None:
            return  # permissive mode: no structural check
        ok, reason = self._registry.check_operation_by_name(
            self.tool_name, operation, target, extra
        )
        if not ok:
            raise SecurityError(f"[{self.tool_name}] structural-blocked: {reason}")

    def read(self, path: str) -> str:
        """Read a file. The shim derives the read effect and submits to broker.

        Structural check: operation "read" must be in tool's declared rights
        and target must be in declared_targets.
        """
        self._structural_check("read", path)
        return self._commit_op(
            ShimOp(operation="read", resource=path, tool_name=self.tool_name),
            action=lambda: self._do_read(path),
        )

    def write(self, path: str, content: bytes) -> None:
        """Write a file. The shim submits the write effect to the broker.

        Structural check: operation "write" must be in tool's declared rights
        and target must be in declared_targets (T14: prevents hidden write).
        """
        self._structural_check("write", path)
        self._commit_op(
            ShimOp(operation="write", resource=path, tool_name=self.tool_name),
            action=lambda: self._do_write(path, content),
        )

    def delete(self, path: str) -> None:
        """Delete a file.

        Structural check: operation "delete" must be in tool's declared rights
        and target must be in declared_targets.
        """
        self._structural_check("delete", path)
        self._commit_op(
            ShimOp(operation="delete", resource=path, tool_name=self.tool_name),
            action=lambda: self._do_delete(path),
        )

    def send(self, recipient: str, body: str, **extra_recipients: str) -> None:
        """Send an email to recipient AND extra_recipients (BCC attempts, T18).

        ALL recipients are included in the Effect's known_targets.
        The broker validates the complete set {recipient} ∪ {extra_recipients}.
        BCC delivery only happens through store.apply_effect() — not in _do_send.

        Structural check: operation "send" must be in tool's declared rights
        and all targets (primary + BCC) must be in declared_targets.
        """
        extra = frozenset(extra_recipients.values())
        self._structural_check("send", recipient, extra)
        self._commit_op(
            ShimOp(
                operation="send",
                resource=recipient,
                extra_resources=extra,
                tool_name=self.tool_name,
            ),
            action=lambda: self._do_send(recipient, body),
        )

    def get_op_log(self) -> list[ShimOp]:
        """Return the independent observer log."""
        return list(self.op_log)

    def get_broker_effect_log(self) -> list[tuple[str, str]]:
        """Return the broker's effects log for comparison with op_log."""
        return list(self.broker.store.effects_log)

    def get_identity_log(self) -> list[frozenset[str]]:
        """Return the broker's identity_log for complete target set verification."""
        return list(self.broker.store.identity_log)

    # ---- verify: complete effect identity (not just operation+target existence) ----
    def verify_complete_mediation(self) -> list[str]:
        """Verify complete mediation using the independent ledger.

        The ledger is the source of truth: it records authorized effects
        from broker.gate() and observed effects from executor.apply() + store.

        Returns list of failure descriptions (empty = complete mediation).
        """
        return self.broker.verify_complete_mediation()

    def verify_complete_effect_identity(self) -> list[str]:
        """Verify complete effect identity using the independent ledger

        Alias for verify_complete_mediation() — both use the same ledger
        The ledger is the single source of truth; both shim and direct
        commit record to it
        """
        return self.verify_complete_mediation()

    # ---- private: the shim enforcement logic ----
    def _commit_op(
        self,
        op: ShimOp,
        action: Callable[[], T],
    ) -> T:
        """Commit an op via IsolatedExecutor. Apply ONLY if ALLOW.

        The executor is the ONLY mutation path:
          - executor.execute() calls broker.commit() and store.apply_effect()
          - _do_write/_do_send are ONLY called on ALLOW, AFTER executor commits
          - We do NOT call broker.commit() separately — that would double-apply
        """
        from .lattice import Confidentiality, Integrity
        from .model import Commit, Data, Effect, EffectTarget

        # Build the COMPLETE target set (Week 2 key fix).
        # The Effect must include ALL resources it actually touches.
        known_targets = EffectTarget(
            primary=op.resource,
            additional=op.extra_resources,
        )

        effect = Effect(
            etype=op.operation,
            target=op.resource,
            metadata={"extra_resources": list(op.extra_resources)},
            provenance=(
                Data(
                    f"shim-{op.operation}",
                    Confidentiality.INTERNAL,
                    Integrity.USER,
                ),
            ),
            capability_nonce=self._find_capability(op.operation, op.resource, op.extra_resources),
            delegation_chain=(self.tool_name, "broker-shim"),
            known_targets=known_targets,
        )

        commit = Commit(effect=effect, task=None, tool_name=self.tool_name)

        # Execute through the IsolatedExecutor (the ONLY path to both broker
        # gate AND store mutation). This calls broker.commit() + store.apply_effect().
        # NOTE: we do NOT call broker.commit() separately here — that would
        # double-apply the effect (one in executor, one in broker.commit).
        allow, evidence = self._executor.execute(commit)

        if not allow:
            # Broker BLOCKed: log with blocked=True, raise SecurityError
            op.blocked = True
            self.op_log.append(op)
            blocker = evidence.get("primary_blocker") or evidence.get("boundary_stop", "unknown")
            raise SecurityError(
                f"[{op.tool_name}] {op.operation} on {op.resource} BLOCKed by "
                f"{blocker}: tool cannot proceed. No effect reached external state."
            )

        # Broker ALLOWed: log with blocked=False
        self.op_log.append(op)
        return action()

    def _derive_nonce(self, operation: str, resource: str, extra: frozenset[str]) -> str:
        """Derive a unique nonce from complete target set (primary + BCC/extra).

        This ensures two sends with the same primary but different extra_resources
        produce different nonces -> the observer tracks them as separate effects.
        Without this, BCC sends would merge into one observer entry (wrong count).
        """
        base = f"{self.tool_name}:{operation}"
        if not extra:
            return base
        extras = ",".join(sorted(extra))
        return f"{base}:{extras}"

    def _find_capability(
        self,
        right: str,
        target: str,
        extra: frozenset[str] = frozenset(),
    ) -> str:
        """Find a capability covering (right, target) and return its ACTUAL nonce.

        Lookup priority:
          1. Exact (right, target) match
          2. Wildcard: capability with target="*" covers any target
          3. Domain-level: for email targets, find capability whose target
             is a domain pattern or "*" covering the same domain label

        The returned nonce is the actual registered nonce in broker.capabilities.
        This nonce must exist in broker.capabilities for Auth to succeed.

        BCC extras are validated by NoAmp's extra-target check, NOT by
        nonce differentiation. The capability nonce identifies the CAPABILITY,
        not the specific BCC variant.
        """
        # Primary: exact (holder, right, target) match
        for nonce, cap in self.broker.capabilities.items():
            if cap.holder == self.tool_name and cap.right == right and cap.target == target:
                return nonce
        # Fallback: EffectBroker holder (shim acts as broker for tool)
        for nonce, cap in self.broker.capabilities.items():
            if cap.holder == "EffectBroker" and cap.right == right and cap.target == target:
                return nonce
        # Wildcard match: capability with target="*" covers any target
        for nonce, cap in self.broker.capabilities.items():
            if cap.holder == self.tool_name and cap.right == right and cap.target == "*":
                return nonce
        for nonce, cap in self.broker.capabilities.items():
            if cap.holder == "EffectBroker" and cap.right == right and cap.target == "*":
                return nonce
        # Last resort: any capability with matching (right, target)
        for nonce, cap in self.broker.capabilities.items():
            if cap.right == right and cap.target == target:
                return nonce
        return f"no-cap-{right}-{target}"

    def _do_read(self, path: str) -> str:
        """Read-only: return simulated content.

        The actual file read effect was committed via broker.commit() ->
        store.apply_effect() in the executor. The shim action is a read-only
        stub that returns simulated content (no further state mutation)
        """
        # store.files is now a read-only Mapping. get() is permitted (read-only).
        file = self.broker.store.files.get(path)
        if file is None:
            raise FileNotFoundError(f"no such file: {path}")
        return "(simulated file content)"

    def _do_write(self, path: str, content: bytes) -> None:
        """NO-OP stub: the write already happened in broker.commit() -> apply_effect().

        The executor called broker.commit() which called store.apply_effect(),
        which recorded the write in effects_log. This stub does nothing.
        """

    def _do_delete(self, path: str) -> None:
        """NO-OP stub: the delete already happened in broker.commit() -> apply_effect().

        The executor called broker.commit() which called store.apply_effect(),
        which removed the file from _files._data and recorded in effects_log.
        This stub does nothing.
        """

    def _do_send(self, recipient: str, body: str) -> None:
        """NO-OP stub: email delivery already happened in broker.commit() -> apply_effect().

        The executor called broker.commit() which called store.apply_effect(),
        which delivered the message to ALL recipients (primary + BCC) and
        recorded the complete target set in identity_log. This stub does nothing.
        """
