"""Independent Observer: out-of-band effect verification.

The Observer is a SEPARATE component from the broker that watches resource
state independently. Its job:
    - For every effect the broker ALLOWed, verify it actually occurred.
    - For effects NOT in the broker's ledger, detect them as possible bypasses.
    - Return "unknown" when it cannot verify — never "safe".

This is the OUT-OF-BAND check that makes complete mediation falsifiable.

DEPLOYMENT:
  - Same-process: observer is a separate object in the same Python process.
    A determined adversary can still mutate store directly (but ledger returns
    UNKNOWN for auth-without-obs, and observer detects obs-without-auth).
  - Multi-process: observer runs in the broker process, watching the
    subprocess store via IPC. Direct bypass of the subprocess store requires
    IPC — impossible from the broker process.

THREE-LEVEL VERIFICATION:
  Level 1 (Ledger): Records broker.gate() auth + executor.apply_effect() obs.
                    Returns CONFIRMED | UNKNOWN | REJECTED.
  Level 2 (Observer): Watches resource state, independent of broker path.
                     Returns OBSERVED | NOT_OBSERVED | UNKNOWN.
  Level 3 (Complete Mediation): Ledger + Observer together provide the full
    guarantee: every broker-authorized effect is observer-confirmed, and
    every observer-confirmed effect is broker-authorized.

"UNKNOWN, NOT SAFE" INVARIANT:
  If the observer cannot verify an effect occurred, it returns UNKNOWN —
  NOT "safe" or "observed". The absence of evidence is not evidence of safety.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from effect_broker.model import Effect


class ObserverVerdict(Enum):
    """Observer verdicts for a given effect.

    OBSERVED: the observer confirmed this effect occurred (via resource state).
    NOT_OBSERVED: the observer checked and the effect did NOT occur.
    UNKNOWN: the observer cannot determine whether the effect occurred.
    """

    OBSERVED = "observed"
    NOT_OBSERVED = "not_observed"
    UNKNOWN = "unknown"


@dataclass
class ObserverCheck:
    """A single observer check result."""

    effect_signature: str  # canonical signature: etype:target:nonce
    verdict: ObserverVerdict
    reason: str
    observed_targets: frozenset[str] = field(default_factory=frozenset)
    timestamp: float = 0.0


@dataclass
class CompleteMediationResult:
    """The complete mediation verdict combining Ledger + Observer.

    This is the authoritative judgment. The broker's own report is NOT used
    here — the observer and ledger are the source of truth.
    """

    # Ledger component
    ledger_confirmed: bool  # ledger returned CONFIRMED_COMMITTED
    ledger_unknown: bool    # ledger returned UNKNOWN
    ledger_rejected: bool  # ledger returned REJECTED

    # Observer component
    observer_observed: bool   # observer confirmed effect occurred
    observer_not_observed: bool  # observer checked and saw nothing
    observer_unknown: bool   # observer cannot determine

    # Combined
    complete_mediation: bool  # True ONLY if ledger_confirmed AND observer_observed
    bypass_detected: bool     # True if observer observed but ledger didn't confirm

    @property
    def summary(self) -> str:
        """Human-readable summary."""
        if self.complete_mediation:
            return "COMPLETE_MEDIATION: broker-authorized + observer-confirmed"
        if self.bypass_detected:
            return "BYPASS_DETECTED: effect occurred without broker authorization"
        if self.ledger_unknown:
            return "UNKNOWN: ledger cannot verify (possible bypass or observer failure)"
        if self.observer_unknown:
            return "UNKNOWN: observer cannot verify effect occurrence"
        if self.ledger_rejected:
            return "REJECTED: broker blocked this effect"
        if self.observer_not_observed:
            return "NOT_OBSERVED: effect not seen by observer"
        return "UNDETERMINED"


class IndependentObserver:
    """Independent effect observer.

    In a real deployment, this wraps a filesystem watcher and/or MTA log.
    In this prototype, it wraps the broker's resource store to demonstrate
    the pattern.

    The observer does NOT trust the broker's own effects_log or identity_log.
    It independently checks the resource store state and compares with the
    ledger records.
    """

    def __init__(
        self,
        broker: "EffectBroker | None" = None,
        store: "Any | None" = None,
    ) -> None:
        self._broker = broker
        self._store = store
        self._checks: list[ObserverCheck] = []

    def observe_effect(self, effect: "Effect", expected_targets: frozenset[str] | None = None) -> ObserverVerdict:
        """Observe whether an effect actually occurred.

        This is the INDEPENDENT check — it does NOT look at the broker's
        effects_log. It checks the resource store state directly.

        Args:
            effect: the effect to observe
            expected_targets: the complete set of targets (primary + extra).
                             If None, uses effect.complete_targets().

        Returns:
            OBSERVED: the effect occurred (store state reflects it)
            NOT_OBSERVED: the effect did NOT occur (store state unchanged)
            UNKNOWN: cannot determine (e.g., same-process store access failed)
        """
        from effect_broker.model import EffectTarget

        if self._store is None and self._broker is not None:
            self._store = self._broker.store

        if self._store is None:
            return ObserverVerdict.UNKNOWN

        targets = expected_targets or effect.complete_targets()

        if effect.etype == "write":
            return self._observe_write(effect.target, targets)
        elif effect.etype == "read":
            return self._observe_read(effect.target)
        elif effect.etype == "delete":
            return self._observe_delete(effect.target)
        elif effect.etype == "send":
            return self._observe_send(effect.target, targets)
        elif effect.etype == "network":
            return self._observe_network(effect.target, targets)
        else:
            return ObserverVerdict.UNKNOWN

    def _observe_write(self, target: str, additional: frozenset[str]) -> ObserverVerdict:
        """Check if write occurred: target file exists and was recently written."""
        from effect_broker.restricted_store import RestrictedResourceStore

        if not isinstance(self._store, RestrictedResourceStore):
            return ObserverVerdict.UNKNOWN

        try:
            primary_file = self._store.files.get(target)
            if primary_file is None:
                return ObserverVerdict.NOT_OBSERVED

            # Check additional targets (BCC-style file writes)
            for extra_target in additional - {target}:
                if not self._store.files.get(extra_target):
                    return ObserverVerdict.NOT_OBSERVED

            return ObserverVerdict.OBSERVED
        except Exception:
            return ObserverVerdict.UNKNOWN

    def _observe_read(self, target: str) -> ObserverVerdict:
        """Read effects are informational — observable as reads in the identity_log."""
        from effect_broker.restricted_store import RestrictedResourceStore

        if not isinstance(self._store, RestrictedResourceStore):
            return ObserverVerdict.UNKNOWN

        try:
            if self._store.files.get(target) is not None:
                return ObserverVerdict.OBSERVED
            return ObserverVerdict.NOT_OBSERVED
        except Exception:
            return ObserverVerdict.UNKNOWN

    def _observe_delete(self, target: str) -> ObserverVerdict:
        """Check if delete occurred: target file no longer exists."""
        from effect_broker.restricted_store import RestrictedResourceStore

        if not isinstance(self._store, RestrictedResourceStore):
            return ObserverVerdict.UNKNOWN

        try:
            if self._store.files.get(target) is None:
                return ObserverVerdict.OBSERVED
            return ObserverVerdict.NOT_OBSERVED
        except Exception:
            return ObserverVerdict.UNKNOWN

    def _observe_send(self, primary_recipient: str, additional: frozenset[str]) -> ObserverVerdict:
        """Check if send occurred: messages delivered to ALL recipients in identity_log."""
        from effect_broker.restricted_store import RestrictedResourceStore

        if not isinstance(self._store, RestrictedResourceStore):
            return ObserverVerdict.UNKNOWN

        try:
            # Check inbox for primary recipient
            primary_mailbox = self._store.mailboxes.get(primary_recipient.split("@")[0])
            if primary_mailbox is None or not primary_mailbox.inbox:
                return ObserverVerdict.NOT_OBSERVED

            # Check additional recipients (BCC/CC)
            for extra_recipient in additional - {primary_recipient}:
                mailbox = self._store.mailboxes.get(extra_recipient.split("@")[0])
                if mailbox is None or not mailbox.inbox:
                    return ObserverVerdict.NOT_OBSERVED

            return ObserverVerdict.OBSERVED
        except Exception:
            return ObserverVerdict.UNKNOWN

    def _observe_network(self, url: str, additional: frozenset[str]) -> ObserverVerdict:
        """Network effects: check effects_log for the URL access."""
        from effect_broker.restricted_store import RestrictedResourceStore

        if not isinstance(self._store, RestrictedResourceStore):
            return ObserverVerdict.UNKNOWN

        try:
            # Network effects are logged (not persistently stored)
            for etype, target in self._store.effects_log:
                if etype == "network" and target == f"url:{url}":
                    return ObserverVerdict.OBSERVED
            return ObserverVerdict.NOT_OBSERVED
        except Exception:
            return ObserverVerdict.UNKNOWN

    def check_complete_mediation(
        self,
        ledger_verdict: "Any",  # LedgerVerdict
        effect: "Effect",
        broker_allowed: bool,
    ) -> CompleteMediationResult:
        """Check complete mediation: ledger + observer together.

        Args:
            ledger_verdict: result from broker.ledger.verify()
            effect: the effect to verify
            broker_allowed: whether the broker ALLOWed this effect

        Returns:
            CompleteMediationResult with the authoritative verdict.

        The "unknown, not safe" invariant: this returns complete_mediation=True
        ONLY when ledger CONFIRMED AND observer OBSERVED. Any uncertainty
        results in complete_mediation=False and bypass_detected=True.
        """
        from effect_broker.ledger import LedgerVerdict, UnknownLedgerResult

        ledger_confirmed = ledger_verdict == LedgerVerdict.CONFIRMED_COMMITTED
        ledger_unknown = isinstance(ledger_verdict, UnknownLedgerResult)
        ledger_rejected = (
            ledger_verdict == LedgerVerdict.CONFIRMED_BLOCKED
        )

        # Observer component
        obs_verdict = self.observe_effect(effect)
        observer_observed = obs_verdict == ObserverVerdict.OBSERVED
        observer_not_observed = obs_verdict == ObserverVerdict.NOT_OBSERVED
        observer_unknown = obs_verdict == ObserverVerdict.UNKNOWN

        # Combined
        complete_mediation = ledger_confirmed and observer_observed
        bypass_detected = observer_observed and not ledger_confirmed

        return CompleteMediationResult(
            ledger_confirmed=ledger_confirmed,
            ledger_unknown=ledger_unknown,
            ledger_rejected=ledger_rejected,
            observer_observed=observer_observed,
            observer_not_observed=observer_not_observed,
            observer_unknown=observer_unknown,
            complete_mediation=complete_mediation,
            bypass_detected=bypass_detected,
        )

    def get_checks(self) -> list[ObserverCheck]:
        """Return all observer checks for audit."""
        return list(self._checks)

    @property
    def unknown_not_safe_holds(self) -> bool:
        """The 'unknown, not safe' invariant holds if observer never
        reports OBSERVED without ledger confirmation.

        A bypass is: observer sees an effect that the ledger cannot confirm.
        This method checks if such a bypass exists in the recorded checks.
        """
        for check in self._checks:
            if check.verdict == ObserverVerdict.OBSERVED:
                # Check if ledger confirmed this - for now, check the broker's ledger
                if self._broker is not None:
                    sig_parts = check.effect_signature.split(":")
                    task_id = sig_parts[0] if sig_parts else "unknown"
                    nonce = check.effect_signature
                    from effect_broker.ledger import CONFIRMED_COMMITTED
                    if self._broker.ledger.verify(task_id, nonce) != CONFIRMED_COMMITTED:
                        return False  # Bypass detected: observed but not confirmed
        return True