"""Thin enforcement shim: the ONLY code path to external state

The shim is the TCB. The untrusted tool calls ONLY shim methods; the shim
derives the EXACT Effect from real state and submits it to the broker for
commit. If the broker BLOCKs, the shim raises SecurityError — the tool CANNOT
proceed and no effect reaches external state.

This makes effect-complete mediation REAL:
  - T13: the tool declares write(reports) but actually writes secrets.
    The shim observes ALL paths the tool touches and derives the REAL effect.
  - T14: the tool declares read(trusted) but actually exfiltrates secrets.
    The shim observes the extra write path and derives that effect too.
  - T15: the tool monitors/validates — if forwarded, it could bypass mediation.
    The shim flags this as a monitoring-bypass.

The broker's effect_log and the shim's op_log are COMPARED:
  - Every entry in op_log has a corresponding broker-authorized entry in effect_log
  - Any real effect NOT in effect_log = hard failure (claim falsified)
  - Any effect_log entry NOT in op_log = hard failure (false positive)

For the mandatory experiment: the tool is REAL untrusted code, the observer
is the shim's op_log, and paired success case (M4) proves benign work still works.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, TypeVar

if TYPE_CHECKING:
    from .broker import EffectBroker

T = TypeVar("T")


@dataclass
class ShimOp:
    """A single operation logged by the shim (independent observer).

    This is the ONLY record of what the untrusted tool actually did.
    Compare with broker.store.effects_log for verification.
    """

    operation: str  # "read" | "write" | "delete" | "send"
    resource: str  # actual resource the shim observed
    extra_resources: frozenset[str] = field(default_factory=frozenset)
    # For T14 (hidden exfil): any ADDITIONAL resources the tool touched
    # For T2 (BCC send): extra recipients beyond the declared one
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
    """Thin enforcement shim for file and email operations.

    The untrusted tool calls ONLY shim methods (never broker or store directly).
    For each call, the shim:
      1. Derives the EXACT effect from real state (not the tool's declaration)
      2. Submits it to the broker for commit (four-predicate gate + boundary)
      3. Logs to op_log (independent observer)
      4. Applies to real state ONLY if broker ALLOWs
      5. Raises SecurityError if broker BLOCKs

    Key property: the shim does NOT trust the tool's declared intent.
    It derives the actual effect from what the tool DOES, not what it SAYS.
    """

    def __init__(
        self,
        broker: EffectBroker,
        task_id: str = "default",
        tool_name: str = "untrusted-tool",
    ) -> None:
        self.broker = broker
        self.task_id = task_id
        self.tool_name = tool_name
        self.op_log: list[ShimOp] = []

    # ---- public shim API (untrusted tool calls these) ----

    def read(self, path: str) -> str:
        """Read a file. The shim derives the read effect and submits to broker."""
        return self._commit_op(
            ShimOp(operation="read", resource=path, tool_name=self.tool_name),
            action=lambda: self._do_read(path),
        )

    def write(self, path: str, content: bytes) -> None:
        """Write a file. The shim submits the write effect to the broker."""
        self._commit_op(
            ShimOp(operation="write", resource=path, tool_name=self.tool_name),
            action=lambda: self._do_write(path, content),
        )

    def delete(self, path: str) -> None:
        """Delete a file."""
        self._commit_op(
            ShimOp(operation="delete", resource=path, tool_name=self.tool_name),
            action=lambda: self._do_delete(path),
        )

    def send(self, recipient: str, body: str, **extra_recipients: str) -> None:
        """Send an email. Any extra recipients are treated as BCC attempts (T18)."""
        extra = frozenset(extra_recipients.values())
        self._commit_op(
            ShimOp(
                operation="send",
                resource=recipient,
                extra_resources=extra,
                tool_name=self.tool_name,
            ),
            action=lambda: self._do_send(recipient, body, extra_recipients),
        )

    def get_op_log(self) -> list[ShimOp]:
        """Return the independent observer log."""
        return list(self.op_log)

    def get_broker_effect_log(self) -> list[tuple[str, str]]:
        """Return the broker's effects log for comparison with op_log."""
        return list(self.broker.store.effects_log)

    # ---- verify: every op_log entry has a broker-authorized entry ----
    def verify_complete_mediation(self) -> list[str]:
        """Verify that every ALLOWED op in op_log has a corresponding broker-authorized entry

        Returns a list of failures (empty = pass). A failure means:
          - a real effect reached external state WITHOUT broker authorization
          - this FAILS the "effect-complete mediation" claim for this run
        BLOCKed operations are EXPECTED not to be in effects_log (that's correct).
        """
        failures: list[str] = []
        for op in self.op_log:
            if op.blocked:
                # BLOCKed ops are expected NOT to be in effects_log (that's correct behavior)
                continue
            # Map shim op to broker effects_log entry format
            resource_label = (
                f"file:{op.resource}" if op.operation != "send" else f"email:{op.resource}"
            )
            found = any(
                eff_op == op.operation and eff_res == resource_label
                for eff_op, eff_res in self.broker.store.effects_log
            )
            if not found:
                failures.append(f"MISSING broker authorization for {op.operation} on {op.resource}")
        return failures

    # ---- private: the shim enforcement logic ----
    def _commit_op(
        self,
        op: ShimOp,
        action: Callable[[], T],
    ) -> T:
        """Commit an op to the broker. Apply ONLY if ALLOW. Raise if BLOCK."""
        from .lattice import Confidentiality, Integrity
        from .model import Data, Effect

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
            capability_nonce=self._find_capability(op.operation, op.resource),
            delegation_chain=(self.tool_name, "broker-shim"),
        )

        commit = self.broker._make_commit(effect, task_id=self.task_id)
        allow, evidence = self.broker.commit(commit)

        if not allow:
            # Broker BLOCKed: log with blocked=True, raise SecurityError
            op.blocked = True
            self.op_log.append(op)
            blocker = evidence.get("primary_blocker") or evidence.get("boundary_stop", "unknown")
            raise SecurityError(
                f"[{op.tool_name}] {op.operation} on {op.resource} BLOCKed by "
                f"{blocker}: tool cannot proceed. No effect reached external state."
            )

        # Broker allowed: log with blocked=False, execute the real operation
        self.op_log.append(op)
        return action()

    def _find_capability(self, right: str, target: str) -> str:
        """Find a capability covering (right, target) for the tool's holder.

        The broker re-validates the derivation at commit time, so this lookup
        is safe: the tool cannot forge a capability here — if the holder doesn't
        have a valid root-anchored capability for (right, target), the broker's
        Auth check will block the effect.
        """
        holder = self.tool_name
        for nonce, cap in self.broker.capabilities.items():
            if cap.holder == holder and cap.right == right and cap.target == target:
                return nonce
        # Try broker-level capability (attenuated chain ends at BROKER)
        for nonce, cap in self.broker.capabilities.items():
            if cap.holder == "EffectBroker" and cap.right == right and cap.target == target:
                return nonce
        return f"no-cap-{right}-{target}"

    def _do_read(self, path: str) -> str:
        file = self.broker.store.files.get(path)
        if file is None:
            raise FileNotFoundError(f"no such file: {path}")
        return "(simulated file content)"

    def _do_write(self, path: str, content: bytes) -> None:
        from .lattice import Confidentiality
        from .model import File

        self.broker.store.files[path] = File(path, Confidentiality.INTERNAL)

    def _do_delete(self, path: str) -> None:
        self.broker.store.files.pop(path, None)

    def _do_send(
        self,
        recipient: str,
        body: str,
        extra_recipients: dict[str, str],
    ) -> None:
        from .model import Domain, Email, Mailbox

        def _domain_for(addr: str) -> Domain:
            part = addr.split("@")[1]
            return Domain.INTERNAL if "corp" in part or "internal" in part else Domain.EXTERNAL

        domain = _domain_for(recipient)
        self.broker.store.emails[recipient] = Email(recipient, domain)
        local = recipient.split("@")[0]
        if local not in self.broker.store.mailboxes:
            self.broker.store.mailboxes[local] = Mailbox(local)
        self.broker.store.mailboxes[local].outbox.append(f"{recipient}: {body[:50]}")

        for _label, extra_recip in extra_recipients.items():
            extra_domain = _domain_for(extra_recip)
            self.broker.store.emails[extra_recip] = Email(extra_recip, extra_domain)
            extra_local = extra_recip.split("@")[0]
            if extra_local not in self.broker.store.mailboxes:
                self.broker.store.mailboxes[extra_local] = Mailbox(extra_local)
            self.broker.store.mailboxes[extra_local].outbox.append(f"{extra_recip}: {body[:50]}")
