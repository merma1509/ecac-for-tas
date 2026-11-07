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

import json
import os
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, cast

from .model import EffectEvidence

#: Reason prefix for an effect that was dispatched but never observed.
#: Distinguished from a plain "authorized_not_observed" because the two mean
#: different things operationally: the first is a crash between the I/O and the
#: bookkeeping (the effect may well have landed), the second is an ordinary
#: bypass-shaped gap. Splitting them is what makes P4-2 checkable.
DISPOSITION_UNKNOWN = "dispatched_outcome_unknown"


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
    # IN_FLIGHT markers: written before the real I/O, never an outcome claim.
    _dispatched: dict[tuple[str, str], list[LedgerEntry]] = field(default_factory=dict)
    # Executor-produced evidence that the real I/O happened. Separate from
    # _observations because an observation is a claim and this is a measurement.
    _evidences: dict[tuple[str, str], list[EffectEvidence]] = field(default_factory=dict)
    _counter: int = field(default=0)
    _logical_time: float = 0.0
    # Optional append-only journal on disk. When set, every IN_FLIGHT marker is
    # fsynced before the caller reaches the syscall, so a SIGKILL leaves the
    # marker behind. Without it "a crash mid-operation" is only ever a story the
    # tests tell themselves: the state they construct is unreachable in reality.
    _journal_path: str | None = None

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
        # Journaled too: recovery needs the authorization present, otherwise the
        # post-crash verdict degrades to "no_record" and looks like an effect
        # nobody ever authorized rather than one that was in flight.
        self._append_journal(
            {
                "kind": "authorized",
                "task_id": task_id,
                "nonce": nonce,
                "targets": sorted(authorized_targets),
                "source": source,
            }
        )

    def record_observation(
        self,
        task_id: str,
        nonce: str,
        observed_targets: frozenset[str] | None,
        source: str = "store.ledger",
    ) -> None:
        """Record an observation event (effect reached external state).

        Called by store.ledger() when a mutation is applied, or by executor
        when it reads the identity_log after apply, or by shim when it blocks
        an effect at the fail-closed boundary BEFORE broker.gate() is reached.
        Pass observed_targets=frozenset() for a confirmed-blocked effect
        (effect attempted at gate, blocked, no state change).

        The key distinction: effects blocked BEFORE broker.gate() (e.g., BCC
        detection in shim) still get recorded here so the ledger can distinguish
        them from direct store bypass (which would appear as "authorized but
        never observed"). Without this record, the same (auth=0, obs=0) would be
        UNKNOWN — indistinguishable from a direct bypass that was simply never
        recorded at all.

        Args:
            task_id: the task context
            nonce: the capability nonce
            observed_targets: resources that were actually touched (empty = blocked)
            source: who recorded this. Use "shim.bcc" for BCC blocks, "executor.execute:BLOCKED"
                    for gate-rejected effects, "subprocess.apply:BLOCKED" for subprocess blocks.
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
        self._append_journal(
            {
                "kind": "observed",
                "task_id": task_id,
                "nonce": nonce,
                "observed_targets": sorted(observed_targets) if observed_targets else [],
                "source": source,
            }
        )

    def record_dispatched(
        self,
        task_id: str,
        nonce: str,
        source: str = "shim.dispatch",
    ) -> None:
        """Record that the real protected operation is ABOUT TO BE performed.

        This is the IN_FLIGHT marker. It is written before the syscall/network
        call, so that a crash between the I/O and the outcome record leaves an
        auditable trace: 'we dispatched, we never learned the result'.

        Why it must be persisted BEFORE the call and not after: the interesting
        failure is the one where the process dies mid-operation. If the marker
        were written afterwards, that window would be indistinguishable from
        'never attempted', and a partially-applied effect would read as safe.

        The marker is a DISPATCH claim, not an outcome claim. It records intent,
        which anyone can assert, so it is never sufficient for CONFIRMED_COMMITTED.
        It only upgrades an otherwise silent gap into an explicit OUTCOME_UNKNOWN.
        """
        self._logical_time += 1.0
        entry = LedgerEntry(
            task_id=task_id,
            nonce=nonce,
            authorized_targets=frozenset(),
            observed_targets=None,
            timestamp=self._logical_time,
            source=source,
        )
        key = (task_id, nonce)
        if key not in self._dispatched:
            self._dispatched[key] = []
        self._dispatched[key].append(entry)
        # Durable BEFORE the syscall the caller is about to make. os.fsync is
        # what makes the marker survive a SIGKILL between here and the outcome
        # record; a buffered write would be lost exactly in that window, which
        # is the only window this marker exists for.
        self._append_journal(
            {
                "kind": "dispatched",
                "task_id": task_id,
                "nonce": nonce,
                "source": source,
            }
        )

    def was_dispatched(self, task_id: str, nonce: str) -> bool:
        """True if an IN_FLIGHT marker exists for this effect."""
        return bool(self._dispatched.get((task_id, nonce)))

    def record_shim_block(
        self,
        task_id: str,
        nonce: str,
        reason: str,
        blocked_targets: frozenset[str] | None = None,
    ) -> None:
        """Record an effect blocked by the shim BEFORE reaching broker.gate().

        This addresses the "shim-before-commit gap": effects blocked at the shim
        level (e.g., BCC detection, capability mismatch) never reach broker.commit(),
        so they would otherwise be invisible to the ledger. Recording them here makes
        the ledger's CONFIRMED_BLOCKED verdict meaningful for both gate-blocked and
        shim-blocked effects.

        With this record, the ledger can distinguish:
          - BCC-blocked effect: obs_entries = [{"source": "shim.bcc", "observed": ∅}]
          - Direct store bypass: no obs_entries → UNKNOWN
          - Gate-rejected effect: obs_entries = [{"source": "executor.execute:BLOCKED"}]

        Args:
            task_id: the task context
            nonce: the capability nonce (may be "unknown" for shim-level blocks)
            reason: human-readable reason (e.g., "bcc-detected", "capability-mismatch")
            blocked_targets: set of targets the shim intended to access (for audit)
        """
        self._logical_time += 1.0
        entry = LedgerEntry(
            task_id=task_id,
            nonce=nonce,
            authorized_targets=blocked_targets or frozenset(),
            observed_targets=None,  # explicitly blocked — no state change
            timestamp=self._logical_time,
            source=f"shim.{reason}",
        )
        key = (task_id, nonce)
        if key not in self._observations:
            self._observations[key] = []
        self._observations[key].append(entry)

    def record_evidence(self, task_id: str, nonce: str, evidence: EffectEvidence) -> None:
        """Record executor-produced evidence that the real I/O happened.

        Distinct from record_observation() on purpose. An observation is the
        executor saying "I applied it"; evidence is a measurement taken at the
        transport boundary (bytes written, fsync result, observed targets). The
        ledger keeps them apart so that a verdict can require the second and not
        be satisfied by the first.

        Evidence never changes the effect count. verify() counts observations
        against authorizations, so adding a second observation for the same
        nonce would trip the over-observed check; evidence is attached to the
        existing occurrence instead.

        Only terminal evidence is accepted. A dispatch marker already covers
        "in flight", and accepting a non-terminal claim here would give two
        competing ways to say the same thing.
        """
        if evidence.outcome not in ("committed", "failed", "unknown", "denied"):
            raise ValueError(f"not a terminal outcome: {evidence.outcome!r}")
        key = (task_id, nonce)
        if key not in self._evidences:
            self._evidences[key] = []
        self._evidences[key].append(evidence)
        self._append_journal(
            {
                "kind": "evidence",
                "task_id": task_id,
                "nonce": nonce,
                "outcome": evidence.outcome,
                "source": evidence.source,
                "t0": evidence.window[0],
                "t1": evidence.window[1],
                "observed_bytes": evidence.observed_bytes,
                "observed_targets": sorted(evidence.observed_targets or ()),
                "transport_response": evidence.transport_response,
            }
        )

    def evidence_for(self, task_id: str, nonce: str) -> EffectEvidence | None:
        """The evidence backing this effect, if any was recorded.

        Returns the first COMMITTED piece of evidence in preference to others:
        if any observation proved the effect landed, that is the outcome, and
        later ambiguity must not erase it.
        """
        entries = self._evidences.get((task_id, nonce), [])
        for ev in entries:
            if ev.outcome == "committed":
                return ev
        return entries[0] if entries else None

    def _append_journal(self, record: dict[str, object]) -> None:
        """Append one line to the on-disk journal and fsync it.

        One JSON object per line: a torn tail is a normal, recoverable state for
        a crashed process, and a line-oriented format lets the reader drop the
        partial last line instead of failing to parse the whole file.

        A journal failure is fatal to the caller. Silently continuing would
        reintroduce the very gap this exists to close: the operation would run
        with no durable record that it was dispatched.
        """
        if self._journal_path is None:
            return
        line = json.dumps(record, sort_keys=True) + "\n"
        with open(self._journal_path, "a", encoding="utf-8") as fh:
            fh.write(line)
            fh.flush()
            os.fsync(fh.fileno())

    @classmethod
    def from_journal(cls, path: str) -> IndependentEffectLedger:
        """Rebuild a ledger from a journal left behind by a crashed process.

        Only what was durable is restored: authorizations, dispatch markers and
        evidence. There are deliberately no observations to recover -- an
        observation is written after the I/O completes, so by definition it is
        not in the journal of a process that died mid-operation. That absence is
        the finding, not a gap in the recovery.

        A truncated final line is dropped rather than raising: the process was
        killed mid-write, which is precisely the case being reconstructed.
        """
        ledger = cls()
        # Journaling is enabled only AFTER the replay. Constructing the ledger
        # with the path already set would make every recovery append a second
        # copy of every record, doubling the file on each open.
        if not os.path.exists(path):
            ledger._journal_path = path
            return ledger
        with open(path, encoding="utf-8") as fh:
            raw = fh.read()
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                # Interrupted write; everything after it is suspect too.
                break
            ledger._replay(rec)
        ledger._journal_path = path
        return ledger

    def _replay(self, rec: dict[str, object]) -> None:
        """Apply one journal record. Mirrors the recording API, without re-logging."""
        kind = rec.get("kind")
        if kind == "reset":
            # Everything before this marker belongs to a previous run. Forgetting
            # it is the point of the reset, and keeping it would let a crash
            # report effects the operator deliberately discarded.
            self._authorizations.clear()
            self._observations.clear()
            self._dispatched.clear()
            self._evidences.clear()
            return
        task_id = str(rec.get("task_id", ""))
        nonce = str(rec.get("nonce", ""))
        if not task_id or not nonce:
            return
        if kind == "authorized":
            targets = frozenset(str(t) for t in cast(list[str], rec.get("targets", [])))
            self.record_authorization(task_id, nonce, targets, source=str(rec.get("source", "")))
        elif kind == "dispatched":
            self.record_dispatched(task_id, nonce, source=str(rec.get("source", "")))
        elif kind == "observed":
            targets = frozenset(str(t) for t in cast(list[str], rec.get("observed_targets", [])))
            self.record_observation(
                task_id,
                nonce,
                targets if targets else None,
                source=str(rec.get("source", "")),
            )
        elif kind == "evidence":
            self.record_evidence(
                task_id,
                nonce,
                EffectEvidence(
                    effect_id=nonce,
                    outcome=cast(Any, rec.get("outcome")),
                    source=str(rec.get("source", "")),
                    window=(float(cast(float, rec.get("t0", 0.0))),
                            float(cast(float, rec.get("t1", 0.0)))),
                    observed_bytes=cast(int | None, rec.get("observed_bytes")),
                    observed_targets=frozenset(
                        str(t) for t in cast(list[str], rec.get("observed_targets", []))
                    )
                    or None,
                    transport_response=cast(str | None, rec.get("transport_response")),
                ),
            )

    # ---- Verification API (the ONLY way to get verdicts) ----
    def verify(self, task_id: str, nonce: str) -> LedgerVerdict | UnknownLedgerResult:
        """Verify mediation for a single (task_id, nonce).

        Returns:
          - CONFIRMED_COMMITTED: at least one observation has non-None observed_targets
            AND no BLOCKED entries. The effect was applied and gate never rejected.
          - CONFIRMED_BLOCKED: ALL observations are BLOCKED (no committed entries).
            The effect was attempted but blocked at every attempt.
          - UNKNOWN: cannot determine outcome (possible bypass or ambiguous).
            Examples: auth without obs (possible bypass), obs without auth (unauthorized),
            obs_count > auth_count (over-observed — possible crash or bypass).

        Key invariant: authorized without observation -> UNKNOWN (never "safe").

        VERDICT PRECEDENCE (FIXED):
          - Committed takes precedence over blocked: if effect was applied at least
            once, CONFIRMED_COMMITTED even if subsequent retries were blocked (replay).
          - CONFIRMED_BLOCKED only when ALL observations are blocked.
        """
        key = (task_id, nonce)
        auth_entries = self._authorizations.get(key, [])
        obs_entries = self._observations.get(key, [])

        # Sources that indicate the effect was explicitly blocked (not applied)
        # These can come from gate rejection (broker/executor) or shim-level
        # checks (BCC detection, capability mismatch). All mean "no state change"
        BLOCKED_SOURCES = frozenset(
            {
                "broker.commit:BLOCKED",
                "executor.execute:BLOCKED",
                "subprocess.gate:BLOCKED",
                "subprocess.apply:BLOCKED",
                "shim.bcc",
                "shim.capability-mismatch",
            }
        )

        if not auth_entries:
            # No authorization record
            # Two cases:
            # 1. Obs WITHOUT shim source → possible unauthorized effect (UNKNOWN)
            #    Example: store mutated directly without broker involvement
            # 2. Obs WITH shim source only → confirmed blocked, no auth needed
            #    Example: BCC detection in shim blocks before broker.gate()
            #    The shim's record IS the observation (equivalent to broker auth)
            if obs_entries:
                has_shim_source = any(entry.source.startswith("shim.") for entry in obs_entries)
                all_blocked = all(entry.source.startswith("shim.") for entry in obs_entries)
                if has_shim_source and all_blocked:
                    # Explicit shim block (BCC, capability mismatch) — CONFIRMED_BLOCKED
                    # The shim observed and blocked. No auth entry needed because
                    # the shim is the authoritative boundary for this class of effects
                    return LedgerVerdict.CONFIRMED_BLOCKED
                return UnknownLedgerResult(
                    reason=f"observed_without_authorization(task={task_id},nonce={nonce})"
                )
            return UnknownLedgerResult(reason=f"no_record(nonce={nonce})")

        # Get the complete authorized target set (merge all auth entries)
        authorized_targets: frozenset[str] = frozenset()
        for entry in auth_entries:
            authorized_targets |= entry.authorized_targets

        if not obs_entries:
            # Authorized but no observation. Two very different situations:
            #   - nothing was dispatched: an ordinary gap (possible bypass);
            #   - we dispatched and never learned the result: a crash or a
            #     transport fault mid-operation. The effect may well have landed.
            # Reporting both as one string hid the second, which is the one that
            # matters. Both are still UNKNOWN -- never COMMITTED, never safe.
            if self.was_dispatched(task_id, nonce):
                return UnknownLedgerResult(
                    reason=f"{DISPOSITION_UNKNOWN}(task={task_id},nonce={nonce},"
                    f"dispatched_no_observation)"
                )
            return UnknownLedgerResult(
                reason=f"authorized_not_observed(task={task_id},nonce={nonce},possible_bypass)"
            )

        # Classify observations: committed (effect was applied) vs blocked (gate/shim rejected)
        committed_entries: list[LedgerEntry] = []
        blocked_entries: list[LedgerEntry] = []
        failed_entries: list[LedgerEntry] = []  # executor.apply returned False
        for entry in obs_entries:
            if entry.source in BLOCKED_SOURCES:
                blocked_entries.append(entry)
            elif ":FAILED" in entry.source or entry.source == "executor.apply:FAILED":
                # Executor confirmed the effect was attempted but could not be applied
                # (e.g., resource not found). This is NOT a committed observation —
                # the effect did NOT reach external state. Treat as failed, not committed.
                failed_entries.append(entry)
            else:
                committed_entries.append(entry)

        # Committed takes precedence over blocked.
        # If any observation has non-None observed_targets, the effect was applied.
        # Subsequent blocked retries (replay prevention) don't change this fact.
        #
        # IMPORTANT: failed_entries (apply returned False) are NOT committed.
        # They indicate the effect was attempted but could NOT reach external state.
        # auth > 0 with only failed observations → UNKNOWN (unknown, not safe).
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
            # Evidence, when the executor supplies it, outranks the claim.
            # a commit must be backed by something measured
            # at the boundary, not by the executor asserting its own success.
            # When evidence exists and does NOT say committed, the claim loses.
            backing = self.evidence_for(task_id, nonce)
            if backing is not None and backing.outcome != "committed":
                return UnknownLedgerResult(
                    reason=f"evidence_contradicts_observation(task={task_id},"
                    f"nonce={nonce},evidence_outcome={backing.outcome})"
                )
            # Check occurrence count: obs_count > auth_count is only a problem
            # when ALL observations are committed (no BLOCKED entries).
            # When BLOCKED entries exist, they don't count toward the limit
            # because they represent replay prevention, not extra applications.
            only_committed_count = sum(
                1 for e in obs_entries if e not in blocked_entries and e not in failed_entries
            )
            if only_committed_count > len(auth_entries):
                return UnknownLedgerResult(
                    reason=f"over-observed(task={task_id},nonce={nonce},"
                    f"auth_count={len(auth_entries)},"
                    f"committed_count={only_committed_count})"
                )
            return LedgerVerdict.CONFIRMED_COMMITTED

        # Effect was attempted but could NOT reach external state (apply returned False).
        # This is NOT a commit, NOT a block — it's a failure. auth > 0, obs = failed → UNKNOWN.
        if failed_entries and auth_entries and not committed_entries:
            return UnknownLedgerResult(
                reason=f"apply_failed(task={task_id},nonce={nonce},"
                f"reason=executor.apply_returned_false)"
            )

        # Only blocked attempts — effect was NEVER applied to external state
        if blocked_entries and auth_entries:
            return LedgerVerdict.CONFIRMED_BLOCKED

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

    def outcome_of(self, task_id: str, nonce: str) -> str:
        """Classify one effect into exactly one of the five outcomes.

        Reads the same entries verify() reads, but answers a different question
        and -- importantly -- any unrecognised shape lands in `unknown` rather
        than being optimistically promoted. When in doubt, say we do not know.
        """
        key = (task_id, nonce)
        auth_entries = self._authorizations.get(key, [])
        obs_entries = self._observations.get(key, [])

        if not auth_entries:
            # No authorization: either a shim-level block (legitimate, observable)
            # or an effect nobody authorized. The latter must never read as
            # denied-by-policy, so it stays `unknown`.
            if obs_entries and all(e.source.startswith("shim.") for e in obs_entries):
                return OUTCOME_DENIED
            return OUTCOME_UNKNOWN

        if not obs_entries:
            # Dispatched-but-unobserved and never-started both leave us unable to
            # state the outcome. They differ in DIAGNOSIS (a crash vs a silent
            # gap), not in outcome, so both are `unknown` here; verify() is where
            # the two are told apart.
            return OUTCOME_UNKNOWN
        evidence = self.evidence_for(task_id, nonce)
        if evidence is not None:
            return {
                "committed": OUTCOME_COMMITTED,
                "failed": OUTCOME_FAILED,
                "denied": OUTCOME_DENIED,
            }.get(evidence.outcome, OUTCOME_UNKNOWN)

        # An ALLOW-list, not a deny-list. Classifying by "anything that is not
        # obviously a block" makes every unrecognised source a commit by default,
        # which is the optimistic direction -- exactly wrong for this metric. A
        # new source string added elsewhere must fall into `unknown` until
        # somebody decides what it means.
        if any(e.source in _COMMITTING_SOURCES for e in obs_entries):
            return OUTCOME_COMMITTED
        if any(e.source in _FAILED_SOURCES for e in obs_entries):
            # Attempted, did not complete. May still have landed -> also unknown,
            # but reported separately so the two causes stay distinguishable.
            return OUTCOME_FAILED
        if any(
            e.source in _DENYING_SOURCES or e.source.startswith("shim.") for e in obs_entries
        ):
            return OUTCOME_DENIED
        # No observation source decided it, and there is no evidence to consult.
        return OUTCOME_UNKNOWN

    def outcome_counts(self) -> OutcomeCounts:
        """Tally every effect the ledger has heard of, by outcome.

        The universe is the union of authorized and observed nonces: an effect
        that was observed but never authorized still exists and must be counted
        (as unknown), otherwise it would vanish from the accounting entirely.
        """
        keys = set(self._authorizations) | set(self._observations)
        counts = dict.fromkeys(ALL_OUTCOMES, 0)
        for task_id, nonce in keys:
            counts[self.outcome_of(task_id, nonce)] += 1
        return OutcomeCounts(**counts)

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
        """Clear all entries. Use with caution (testing only in same-process model).

        A journaled ledger records the reset as a marker line rather than
        truncating the file. Truncating would make the journal's meaning depend
        on when you look at it, and would lose the record of whatever was in
        flight when the reset happened -- which is the one thing a crash log
        must not quietly discard. `from_journal()` honours the marker by
        starting empty from that point.
        """
        self._authorizations.clear()
        self._observations.clear()
        self._dispatched.clear()
        self._evidences.clear()
        self._logical_time = 0.0
        self._append_journal({"kind": "reset"})


#: Observation sources that PROVE the effect reached external state.
#: Kept explicit and closed: an unlisted source yields `unknown`, never a commit.
_COMMITTING_SOURCES = frozenset({"executor.apply", "subprocess.apply"})

#: Sources that prove the effect was attempted and did not complete.
_FAILED_SOURCES = frozenset({"executor.apply:FAILED", "subprocess.apply:FAILED"})

#: Sources that prove a predicate or shim check rejected the effect.
_DENYING_SOURCES = frozenset(
    {
        "executor.execute:BLOCKED",
        "subprocess.gate:BLOCKED",
        "subprocess.apply:BLOCKED",
        "broker.commit:BLOCKED",
    }
)


# Outcome accounting
# The five reportable outcomes. These are NOT the same as LedgerVerdict: a
# verdict answers "was mediation complete for this nonce?", an outcome answers
# "what actually happened to this effect?". Both are needed, and conflating them
# was part of why auth>0/obs=0 was unreadable.

#: The effect reached external state, authorized and observed.
OUTCOME_COMMITTED = "committed"
#: The operation was attempted after authorization and failed. The effect may or
#: may not have landed (an SMTP timeout is the canonical case) -> also UNKNOWN.
OUTCOME_FAILED = "failed"
#: Dispatched, but no observation ever arrived. A crash or a lost record.
OUTCOME_UNKNOWN = "unknown"
#: A predicate rejected it. Nothing was dispatched.
OUTCOME_DENIED = "denied"
#: Authorized but given up before dispatch (capability expired, aborted).
OUTCOME_ABANDONED = "abandoned"

ALL_OUTCOMES: tuple[str, ...] = (
    OUTCOME_COMMITTED,
    OUTCOME_FAILED,
    OUTCOME_UNKNOWN,
    OUTCOME_DENIED,
    OUTCOME_ABANDONED,
)


@dataclass(frozen=True)
class OutcomeCounts:
    """How many effects landed in each of the five outcomes.

    `abandoned` counts a transition for which there is currently NO producer in
    the codebase: capability expiry is caught by the gate as a denial before
    dispatch, so nothing reaches AUTHORIZED-then-given-up. The counter is real
    and will move as soon as such a path exists, but reporting it as 0 without
    saying so would read as "we checked and there were none" when it actually
    means "this state cannot currently be reached".
    """

    committed: int = 0
    failed: int = 0
    unknown: int = 0
    denied: int = 0
    abandoned: int = 0

    def as_dict(self) -> dict[str, int]:
        return {
            OUTCOME_COMMITTED: self.committed,
            OUTCOME_FAILED: self.failed,
            OUTCOME_UNKNOWN: self.unknown,
            OUTCOME_DENIED: self.denied,
            OUTCOME_ABANDONED: self.abandoned,
        }

    @property
    def total(self) -> int:
        return self.committed + self.failed + self.unknown + self.denied + self.abandoned

    def unexplained(self) -> int:
        """Effects whose fate we cannot state. Anything above zero is a finding."""
        return self.unknown + self.abandoned


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


