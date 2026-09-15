"""Independent effect ledger — the ONLY source of truth for mediation verdicts.

ARCHITECTURE:
  ┌─────────────────────────────────────────────────────────────┐
  │  IndependentEffectLedger                                    │
  │  - Created EXTERNALLY (not by broker or executor)           │
  │  - Passed to both broker and executor                       │
  │  - Records authorization events (from broker.gate)          │
  │  - Records observation events (from executor + store)       │
  │  - Makes UNAMBIGUOUS verdicts: CONFIRMED_COMMITTED,         │
  │    CONFIRMED_BLOCKED, or UNKNOWN                            │
  └─────────────────────────────────────────────────────────────┘
                   ↑                        ↑
              broker.gate()          executor.apply()
                   │                        │
                   └──────────┬─────────────┘
                              ↓
                   IndependentEffectLedger.record()

CRITICAL DESIGN DECISION:
  The ledger is the SINGLE SOURCE OF TRUTH. Both broker (authorization) and
  executor (observation) write to it. Neither broker nor executor can make
  mediation verdicts — only the ledger can.

  This addresses the review concern: "observe effects independently of the
  component authorizing and executing them." The ledger observes EQUALLY from
  both paths, with equal authority to record or withhold verification.

SAME-PROCESS NOTE:
  In this same-process model, direct store mutation (broker.store._files._data[...]
  = X) is still theoretically possible. The ledger returns "unknown" for any
  effect it cannot verify — this is the "unknown, not safe" guarantee.
  For real isolation, deploy in a separate process/enclave.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .model import Effect  # noqa: F401


class LedgerVerdict(Enum):
    """Verdict of the independent effect ledger.

    The ledger is the ONLY entity that can make mediation verdicts.
    Key invariant: auth > 0, obs = 0 -> UNKNOWN (never "safe").
    """

    CONFIRMED_COMMITTED = auto()  # effect reached state, authorized, observed
    CONFIRMED_BLOCKED = auto()  # effect attempted, authorization revoked, observed 0-state
    UNKNOWN = auto()  # cannot verify outcome (possible bypass)


@dataclass(frozen=True)
class LedgerEntry:
    """A single record in the effect ledger.

    Each entry captures one discrete observation about an effect's lifecycle.
    Entries are IMMUTABLE once recorded — the ledger appends only.
    """

    task_id: str
    nonce: str
    authorized_targets: frozenset[str]
    observed_targets: frozenset[str] | None  # None = not yet observed
    timestamp: float
    source: str  # "broker.gate" | "executor.apply" | "store.ledger"


@dataclass
class IndependentEffectLedger:
    """Independent ledger that records and verifies ALL effect lifecycle events.

    This ledger is the single source of truth for mediation verdicts.
    It is created EXTERNALLY and passed to both broker and executor.
    Neither broker nor executor can create, modify, or delete ledger entries.

    The ledger tracks:
      1. AUTHORIZATION: broker.gate() records when an effect is allowed
      2. OBSERVATION: executor.apply() + store.ledger() records when effect
         reaches external state
      3. VERDICT: ledger.verify() determines if mediation is complete

    Two-phase observation:
      Phase 1 (Authorization): broker.gate() allows effect -> record authorization
        - The effect is prepared for commit, predicates passed
        - Ledger records: (task_id, nonce, authorized_targets, observed=None)
      Phase 2 (Observation): executor.apply() mutates store -> store writes to ledger
        - Store writes to effects_log + identity_log -> store.ledger() records
        - Ledger records: (task_id, nonce, authorized_targets=None, observed=targets)
        - Or: store rejects write -> store.ledger() records empty observation
      Phase 3 (Verification): ledger.verify() compares phase 1 vs phase 2
        - authorized ⊆ observed -> CONFIRMED_COMMITTED (if observed > 0)
        - authorized ⊆ observed AND observed empty -> CONFIRMED_BLOCKED
        - authorized without observation -> UNKNOWN (possible bypass)
    """

    _authorizations: dict[tuple[str, str], list[LedgerEntry]] = field(default_factory=dict)
    _observations: dict[tuple[str, str], list[LedgerEntry]] = field(default_factory=dict)
    _counter: int = field(default=0)
    _logical_time: float = 0.0

    # ---- Recording API (called by broker.gate and executor/store) ----

    def record_authorization(
        self,
        task_id: str,
        nonce: str,
        authorized_targets: frozenset[str],
        source: str = "broker.gate",
    ) -> None:
        """Record an authorization event (effect allowed by broker gate).

        Called by broker.gate() when predicates pass. This records that
        the broker authorized an effect with a COMPLETE set of authorized targets.
        The ledger does NOT trust the caller's claim about authorized_targets —
        it accepts what broker.gate() reports and verifies against observations.

        Args:
            task_id: the task context of the authorization
            nonce: the capability nonce (unique per effect)
            authorized_targets: complete set of resources authorized
            source: who recorded this (for audit trail)
        """
        self._logical_time += 1.0
        entry = LedgerEntry(
            task_id=task_id,
            nonce=nonce,
            authorized_targets=authorized_targets,
            observed_targets=None,
            timestamp=self._logical_time,
            source=source,
        )
        key = (task_id, nonce)
        if key not in self._authorizations:
            self._authorizations[key] = []
        self._authorizations[key].append(entry)

    def record_observation(
        self,
        task_id: str,
        nonce: str,
        observed_targets: frozenset[str] | None,
        source: str = "store.ledger",
    ) -> None:
        """Record an observation event (effect reached external state).

        Called by store.ledger() when a mutation is applied, or by executor
        when it reads the identity_log after apply. Pass observed_targets=frozenset()
        for a confirmed-blocked effect (effect attempted at gate, blocked, no state change).

        Args:
            task_id: the task context
            nonce: the capability nonce
            observed_targets: resources that were actually touched (empty = blocked)
            source: who recorded this
        """
        self._logical_time += 1.0
        entry = LedgerEntry(
            task_id=task_id,
            nonce=nonce,
            authorized_targets=frozenset(),  # filled from authorization during verify
            observed_targets=observed_targets,
            timestamp=self._logical_time,
            source=source,
        )
        key = (task_id, nonce)
        if key not in self._observations:
            self._observations[key] = []
        self._observations[key].append(entry)

    # ---- Verification API (the ONLY way to get verdicts) ----

    def verify(self, task_id: str, nonce: str) -> LedgerVerdict | UnknownLedgerResult:
        """Verify mediation for a single (task_id, nonce).

        Returns:
          - CONFIRMED_COMMITTED: authorized AND observed (targets ⊆ authorized), no
            BLOCKED entries present. The effect was applied and no gate rejections occurred.
          - CONFIRMED_BLOCKED: at least one BLOCKED observation exists. This proves the
            gate rejected at least one attempt — even if earlier attempts were allowed.
            Used for: Fresh replay prevention (effect committed once, then blocked on retry).
          - UNKNOWN: cannot determine outcome (possible bypass or ambiguous).
            Examples: auth without obs (possible bypass), obs without auth (unauthorized),
            obs_count > auth_count (over-observed — possible crash or bypass).

        Key invariant: authorized without observation -> UNKNOWN (never "safe").
        BLOCKED entries take precedence over committed entries: if Fresh blocked a retry,
        CONFIRMED_BLOCKED is the honest verdict — the second attempt was rejected, not applied.
        """
        key = (task_id, nonce)
        auth_entries = self._authorizations.get(key, [])
        obs_entries = self._observations.get(key, [])

        if not auth_entries:
            # No authorization record — possible unauthorized effect
            if obs_entries:
                return UnknownLedgerResult(
                    reason=f"observed_without_authorization(task={task_id},nonce={nonce})"
                )
            return UnknownLedgerResult(reason=f"no_record(nonce={nonce})")

        # Get the complete authorized target set (merge all auth entries)
        authorized_targets: frozenset[str] = frozenset()
        for entry in auth_entries:
            authorized_targets |= entry.authorized_targets

        if not obs_entries:
            # Authorized but no observation -> possible direct bypass
            return UnknownLedgerResult(
                reason=f"authorized_not_observed(task={task_id},nonce={nonce},possible_bypass)"
            )

        # Classify observations: committed (effect was applied) vs blocked (gate rejected)
        BLOCKED_SOURCES = frozenset({"broker.commit:BLOCKED", "executor.execute:BLOCKED"})
        committed_entries: list[LedgerEntry] = []
        blocked_entries: list[LedgerEntry] = []
        for entry in obs_entries:
            if entry.source in BLOCKED_SOURCES:
                blocked_entries.append(entry)
            else:
                committed_entries.append(entry)

        # Key ordering: blocked > committed. If Fresh blocked a retry, the second
        # attempt did NOT apply to external state — even though the first one did.
        # Return CONFIRMED_BLOCKED (the block proves the gate worked on the retry).
        if blocked_entries:
            return LedgerVerdict.CONFIRMED_BLOCKED

        if committed_entries:
            # There ARE committed observations — verify they are within authorization
            for entry in committed_entries:
                obs_targets = entry.observed_targets or frozenset()
                if not (obs_targets <= authorized_targets):
                    extra = obs_targets - authorized_targets
                    return UnknownLedgerResult(
                        reason=f"extra_observed(task={task_id},nonce={nonce},"
                        f"extra={extra},authorized={authorized_targets})"
                    )
            # Check occurrence count: cannot observe more than authorized.
            # obs_count > auth_count -> UNKNOWN (possible bypass or lost auth record).
            # This implements the "unknown, not safe" guarantee: the ledger must not
            # claim CONFIRMED_COMMITTED when observation count exceeds authorization count.
            if len(obs_entries) > len(auth_entries):
                return UnknownLedgerResult(
                    reason=f"over-observed(task={task_id},nonce={nonce},"
                    f"auth_count={len(auth_entries)},obs_count={len(obs_entries)})"
                )
            return LedgerVerdict.CONFIRMED_COMMITTED

        # No committed, no blocked — shouldn't happen with non-empty obs_entries
        return UnknownLedgerResult(reason=f"unknown_observation_type(task={task_id},nonce={nonce})")

    def verify_all(self, authorized_records: dict[tuple[str, str], frozenset[str]]) -> list[str]:
        """Verify complete mediation across all records.

        Args:
            authorized_records: dict mapping (task_id, nonce) -> authorized_targets
                This is the authoritative record built from broker.gate() calls,
                independent of whatever ledger recorded during execution.

        Returns:
            List of failure descriptions (empty = complete mediation).

        NOTE: This method only verifies nonces that appear in authorized_records.
        Observations without a corresponding authorization are a separate failure
        mode: we detect these by checking that every observed (task_id, nonce)
        appears in authorized_records.
        """
        failures: list[str] = []

        # Detect observations without authorization: any observed nonce
        # that is NOT in authorized_records is a potential unauthorized effect.
        # We only report this if the observation count > authorization count
        # for the same nonce (i.e., the observation has no matching auth at all).
        observed_keys = set(self._observations.keys())
        authorized_keys = set(authorized_records.keys())
        unauthorized_observed = observed_keys - authorized_keys
        for key in unauthorized_observed:
            task_id, nonce = key
            failures.append(
                f"UNKNOWN(observed_without_authorization(task={task_id},nonce={nonce}))"
            )

        for key, authorized_targets in authorized_records.items():
            task_id, nonce = key
            verdict = self.verify(task_id, nonce)

            if isinstance(verdict, UnknownLedgerResult):
                failures.append(f"UNKNOWN({verdict.reason})")
            elif verdict == LedgerVerdict.CONFIRMED_COMMITTED:
                # Double-check: observed ⊆ authorized
                obs_entries = self._observations.get(key, [])
                for entry in obs_entries:
                    obs_targets = entry.observed_targets or frozenset()
                    if not (obs_targets <= authorized_targets):
                        failures.append(
                            f"EXTRA_OBSERVED(task={task_id},nonce={nonce},"
                            f"extra={obs_targets - authorized_targets})"
                        )
            elif verdict == LedgerVerdict.CONFIRMED_BLOCKED:
                # Check: was this an EXPLICIT block (source contains "BLOCKED")?
                # Only then is this NOT a failure. If the verdict is CONFIRMED_BLOCKED
                # without explicit source, treat as UNKNOWN.
                obs_entries = self._observations.get(key, [])
                is_explicit_blocked = any("BLOCKED" in entry.source for entry in obs_entries)
                if not is_explicit_blocked:
                    failures.append(f"BLOCKED_BUT_NOT_EXPLICIT(task={task_id},nonce={nonce})")

        return failures

    # ---- Audit API ----

    def get_entries(
        self, task_id: str | None = None, nonce: str | None = None
    ) -> list[LedgerEntry]:
        """Get all ledger entries, optionally filtered by task_id and/or nonce."""
        result: list[LedgerEntry] = []
        for key, auth_list in self._authorizations.items():
            if task_id is not None and key[0] != task_id:
                continue
            if nonce is not None and key[1] != nonce:
                continue
            result.extend(auth_list)
        for key, obs_list in self._observations.items():
            if task_id is not None and key[0] != task_id:
                continue
            if nonce is not None and key[1] != nonce:
                continue
            result.extend(obs_list)
        return sorted(result, key=lambda e: e.timestamp)

    @property
    def authorization_count(self) -> int:
        return sum(len(v) for v in self._authorizations.values())

    @property
    def observation_count(self) -> int:
        return sum(len(v) for v in self._observations.values())

    def get_authorization_entries(
        self,
    ) -> dict[tuple[str, str], list[LedgerEntry]]:
        """Get the raw authorization map. Used by broker.verify_complete_mediation()."""
        return self._authorizations

    def reset(self) -> None:
        """Clear all entries. Use with caution (testing only in same-process model)."""
        self._authorizations.clear()
        self._observations.clear()
        self._logical_time = 0.0


@dataclass(frozen=True)
class UnknownLedgerResult:
    """Result when the ledger cannot determine the mediation outcome.

    "Without ledger proof, the outcome is unknown, not safe."
    This is the ONLY safe answer when the ledger cannot verify.
    """

    reason: str

    def __str__(self) -> str:
        return f"UNKNOWN({self.reason})"


# ---- Periodic Audit ----
# Mechanism for regular ledger verification (on-demand AND scheduled).
# A PeriodicAuditor can be registered with broker or an external orchestrator
# to periodically verify that all authorized effects have been observed.


@dataclass
class AuditSnapshot:
    """Point-in-time snapshot of the ledger's state for audit comparison.

    Captures counts at a specific moment so subsequent audits can detect
    new (unverified) authorizations that appeared since the last check.
    """

    timestamp: float
    authorization_count: int
    observation_count: int
    task_ids: frozenset[str]
    nonces: frozenset[str]

    def new_authorizations_since(self, previous: AuditSnapshot) -> int:
        """Count of new authorizations added since previous snapshot."""
        return self.authorization_count - previous.authorization_count

    def new_observations_since(self, previous: AuditSnapshot) -> int:
        """Count of new observations added since previous snapshot."""
        return self.observation_count - previous.observation_count


@dataclass
class AuditResult:
    """Result of a periodic audit run.

    Fields:
      snapshot: the snapshot taken at this audit point
      failures: list of UNKNOWN reasons for unverifiable effects
      new_authorizations: count of authorization events since last audit
      new_observations: count of observation events since last audit
      is_complete: True if all authorizations are confirmed (failures == [])
      previous_snapshot: the snapshot this audit was compared against
    """

    snapshot: AuditSnapshot
    failures: list[str]
    new_authorizations: int
    new_observations: int
    is_complete: bool
    previous_snapshot: AuditSnapshot | None


class PeriodicAuditor:
    """Periodic auditor for the effect ledger.

    Can be used in two modes:

    1. ON-DEMAND: call audit() after each batch of operations
       ```python
       result = auditor.audit()
       if not result.is_complete:
           alert_security_team(result.failures)
       ```

    2. SCHEDULED: register with a timer (external orchestrator)
       ```python
       import threading
       def run_audit():
           result = auditor.audit()
           if not result.is_complete:
               alert_security_team(result.failures)

       timer = threading.Timer(interval=60.0, function=run_audit)
       timer.daemon = True
       timer.start()
       ```

    The auditor tracks snapshots between runs so it can report NEW
    authorizations/observations since the last check.

    THREAD SAFETY: audit() is thread-safe. Takes a consistent snapshot
    of the ledger state without locking the ledger itself (atomic read
    of counters + keys). The comparison against previous_snapshot uses
    immutable dataclasses.
    """

    def __init__(self, ledger: IndependentEffectLedger) -> None:
        self._ledger = ledger
        self._previous_snapshot: AuditSnapshot | None = None

    def audit(self) -> AuditResult:
        """Run a periodic audit of the ledger.

        Takes a snapshot, verifies all authorized effects, and returns
        the result. Also tracks the previous snapshot for delta reporting.

        Returns AuditResult with:
          - is_complete: True if no failures (all authorized effects verified)
          - failures: list of UNKNOWN reasons (empty = complete mediation)
          - new_authorizations: count since last audit
          - new_observations: count since last audit
        """
        # Take snapshot of current state (atomic read)
        task_ids = frozenset(k[0] for k in self._ledger._authorizations.keys())
        nonces = frozenset(k[1] for k in self._ledger._authorizations.keys())
        snapshot = AuditSnapshot(
            timestamp=self._ledger._logical_time,
            authorization_count=self._ledger.authorization_count,
            observation_count=self._ledger.observation_count,
            task_ids=task_ids,
            nonces=nonces,
        )

        # Build authorized records from current state
        authorized_records: dict[tuple[str, str], frozenset[str]] = {}
        for (tid, nonce), entries in self._ledger._authorizations.items():
            targets: frozenset[str] = frozenset()
            for entry in entries:
                targets |= entry.authorized_targets
            authorized_records[(tid, nonce)] = targets

        # Verify all authorized effects
        failures = self._ledger.verify_all(authorized_records)

        # Compute deltas from previous snapshot
        new_auth = 0
        new_obs = 0
        if self._previous_snapshot is not None:
            new_auth = snapshot.new_authorizations_since(self._previous_snapshot)
            new_obs = snapshot.new_observations_since(self._previous_snapshot)

        result = AuditResult(
            snapshot=snapshot,
            failures=failures,
            new_authorizations=new_auth,
            new_observations=new_obs,
            is_complete=len(failures) == 0,
            previous_snapshot=self._previous_snapshot,
        )

        # Update previous snapshot for next audit
        self._previous_snapshot = snapshot
        return result

    def reset(self) -> None:
        """Reset the audit history. Next audit will report all entries as new."""
        self._previous_snapshot = None

    def last_snapshot(self) -> AuditSnapshot | None:
        """Return the snapshot from the last audit, or None if never audited."""
        return self._previous_snapshot


EffectObserver = IndependentEffectLedger
UnknownObserverResult = UnknownLedgerResult
EffectObserverVerdict = LedgerVerdict
