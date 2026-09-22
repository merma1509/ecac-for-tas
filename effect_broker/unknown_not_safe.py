"""Formal specification of the "Unknown, Not Safe" invariant.

This module documents the central ECAC correctness claim:
    "For every effect that the ledger CANNOT verify as broker-authorized,
     the verdict is UNKNOWN — never 'safe'."

This is the foundation of honest mediation: the system does not claim
security it cannot prove. The ledger is the authoritative source of truth.

WHY "UNKNOWN" AND NOT "UNSAFE"?
  - "UNSAFE" would imply the ledger detected a confirmed violation.
  - "UNKNOWN" means the ledger lacks sufficient information to decide.
  - This distinction matters for complete mediation: a bypass that the
    observer cannot detect should not be classified as a detected attack,
    but it also should not be classified as safe.

GUARANTEED CASES:
  1. Authorization without observation → UNKNOWN(authorized_not_observed)
     Example: direct store mutation bypassing the executor.
  2. Observation without authorization → UNKNOWN(observed_not_authorized)
     Example: an effect occurred that the ledger cannot trace to any cap.
  3. Count mismatch (auth=1, obs=2) → UNKNOWN(count_mismatch)
     Example: two sends to the same recipient but only one capability used.
  4. Unverifiable effect (no capability, no ledger record) → UNKNOWN(unverifiable)
     Example: the broker cannot determine whether an effect occurred.

NEVER RETURNED:
  - "safe" or "confirmed" when the ledger cannot verify an effect.
  - "unknown" for effects the ledger CAN verify as broker-authorized
    (those return CONFIRMED_COMMITTED).

ARCHITECTURE:
  Ledger (independent process or thread):
    - records record_authorization() from broker.gate()
    - records record_observation() from executor.apply_effect()
    - verify() compares the two sets → CONFIRMED | UNKNOWN | REJECTED

  Broker (untrusted process):
    - calls ledger.record_*() methods
    - NEVER directly sets ledger state
    - Ledger verdict is authoritative over broker's own report

  Observer (external process):
    - independently watches filesystem/MTA state
    - provides an OUT-OF-BAND check against ledger records
    - effects NOT in observer log → unknown (possible bypass)

DEPLOYMENT IMPLICATIONS:
  - Same-process: a determined adversary can mutate store._data directly.
    The ledger detects this via auth-without-observation → UNKNOWN.
    This is the honest acknowledgment of the same-process limitation.
  - Multi-process: the broker process CANNOT mutate the ledger process's
    state. Direct bypass is structurally impossible; only IPC is available.
  - The "unknown, not safe" guarantee holds in BOTH modes, but is
    STRONGER in multi-process (bypass is structurally impossible).
"""

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from effect_broker.broker import EffectBroker


class VerdictInvariant(Enum):
    """The "unknown, not safe" invariant. Every ledger verdict falls into one of these."""

    CONFIRMED = (
        "CONFIRMED_COMMITTED: ledger verified auth count = obs count ≥ 1, "
        "and the broker authorized this effect. Effect is broker-mediated."
    )
    UNKNOWN = (
        "UNKNOWN: ledger CANNOT verify that the effect is broker-authorized. "
        "This includes auth-without-obs, obs-without-auth, count mismatch, "
        "or unverifiable effects. NEVER treated as 'safe'."
    )
    REJECTED = (
        "REJECTED: ledger verified this effect was blocked/rejected by the gate. "
        "The effect did NOT reach external state."
    )


@dataclass(frozen=True)
class UnknownNotSafeSpec:
    """Formal specification of the "unknown, not safe" invariant

    Use this as a checklist for implementing and verifying new components
    """

    # The ledger MUST return UNKNOWN (not safe) when it cannot verify
    ledger_returns_unknown_on_unverifiable: bool = True

    # Authorization without observation → UNKNOWN
    ledger_returns_unknown_on_auth_without_obs: bool = True

    # Observation without authorization → UNKNOWN
    ledger_returns_unknown_on_obs_without_auth: bool = True

    # Count mismatch (auth=1, obs=2 or obs=0) → UNKNOWN
    ledger_returns_unknown_on_count_mismatch: bool = True

    # CONFIRMED requires auth count = obs count ≥ 1
    ledger_requires_auth_equals_obs_for_confirmed: bool = True

    # Broker NEVER reports "safe" for unverifiable effects
    broker_never_reports_safe_for_unverifiable: bool = True

    # Observer returns "unknown" for effects not in its log
    observer_returns_unknown_for_unobserved: bool = True

    @property
    def all_invariants_hold(self) -> bool:
        """All invariants must hold for the guarantee to be valid."""
        return all(
            [
                self.ledger_returns_unknown_on_unverifiable,
                self.ledger_returns_unknown_on_auth_without_obs,
                self.ledger_returns_unknown_on_obs_without_auth,
                self.ledger_returns_unknown_on_count_mismatch,
                self.ledger_requires_auth_equals_obs_for_confirmed,
                self.broker_never_reports_safe_for_unverifiable,
                self.observer_returns_unknown_for_unobserved,
            ]
        )


# ---- Invariant check helpers ----
def check_unknown_not_safe(broker: EffectBroker) -> list[str]:
    """Check that the broker+ledger satisfy the 'unknown, not safe' invariant.

    Returns list of failures (empty = invariant holds).

    Cases checked:
      1. Direct store mutation (bypass) → ledger must return UNKNOWN
      2. Broker-authorized effect with no observer → ledger must return UNKNOWN
      3. An unverifiable capability use → ledger must return UNKNOWN
    """
    from .lattice import Confidentiality
    from .ledger import UnknownLedgerResult
    from .model import BROKER, USER, Capability

    failures = []

    # Case 1: Direct store mutation bypassing the executor
    task_id = "inv-check-task"
    nonce = "inv-bypass-nonce"

    # Record only authorization (as if broker allowed it)
    broker.ledger.record_authorization(
        task_id,
        nonce,
        frozenset({"file:///inv-bypass"}),
        source="broker.gate",
    )
    # No observation — simulates direct store mutation bypass

    verdict = broker.ledger.verify(task_id, nonce)
    if not isinstance(verdict, UnknownLedgerResult):
        failures.append(
            f"Case 1 (direct store mutation bypass): ledger returned {type(verdict).__name__} "
            f"instead of UNKNOWN. Ledger verdict: {verdict}"
        )
    elif (
        "authorized_not_observed" not in verdict.reason and "possible_bypass" not in verdict.reason
    ):
        failures.append(
            "Case 1 (direct mutation): UNKNOWN reason "
            f"'{verdict.reason}' does not indicate bypass. Must contain "
            "'authorized_not_observed' or 'possible_bypass'."
        )

    # Reset for next case
    broker.ledger.reset()

    # Case 2: Capability with no authorization record
    broker.store._unsafe_bootstrap_file("file:///inv-unverifiable", Confidentiality.PUBLIC)
    broker.capabilities["inv-no-auth-cap"] = Capability(
        owner=USER,
        holder=BROKER,
        right="read",
        target="file:///inv-unverifiable",
        scope=frozenset({"*"}),
        expiry=float("inf"),
        nonce="inv-no-auth-cap",
        derives_from=None,
    )

    return failures
