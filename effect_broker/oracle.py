"""Independent evaluation oracle

The existing IndependentObserver (observer.py) wraps the broker's in-memory
resource store. That is a useful pattern demo, but it is NOT truly independent:
if the broker store is wrong or lies, the observer trusts it.

This module is the INDEPENDENT ORACLE required, it derives every
verdict from EXTERNAL, out-of-band sources that the broker does not own:

  - real OS filesystem   (via direct open() / os.path on disk)
  - real SMTP transaction log (RCPT TO + DATA records from the MTA)

The oracle NEVER reads the broker's resource store, effects_log, or ledger.
Given an "expected effect set" (what the ledger/broker claims happened), it
re-checks reality and reports a per-effect mismatch. This makes it possible to
REFUTE a ledger that reports success when the effect did not actually occur
(the exact failure mode fixed at the ledger layer, now verified from
outside).

NOTE ON "INDEPENDENT": In this prototype the oracle runs in the evaluation
process, so "independent" means "reads external state the broker does not
author" — the filesystem and the MTA log — not the broker's self-report. A
fully process-isolated oracle (separate process, separate trust domain) is the
production deployment target.
"""

from __future__ import annotations

import os
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ReconcileReport:
    """What `reconcile_unknowns` settled, and what it could not.

    `still_unknown` is a tuple of `task_id:nonce:reason` strings rather than a
    count: a run that left three will be debugged by someone who needs to know
    which three and why, and a number cannot answer either question.
    """

    settled: tuple[str, ...]
    still_unknown: tuple[str, ...]

    @property
    def all_settled(self) -> bool:
        return not self.still_unknown


@dataclass(frozen=True)
class OracleVerdict:
    """Result of the oracle re-checking one claimed effect against reality."""

    etype: str
    target: str
    claimed: bool  # what the ledger/broker claimed happened
    observed: bool  # what the external source actually shows
    matches: bool  # claimed == observed
    detail: str = ""


@dataclass(frozen=True)
class Occurrence:
    """One observed effect event — counted, never collapsed to a boolean.

    the observer emits events; verdicts are derived. Two
    identical writes are two Occurrences with the same payload_id, not one
    `exists=True`.
    """

    effect_id: str  # unique per occurrence
    payload_id: str  # digest of what was actually transmitted/written
    etype: str
    target: str
    targets: frozenset[str]  # full observed target set
    observed_at: float
    source: str  # "fs-diff" | "smtp-envelope" | "imap-uid"
    window: tuple[float, float]  # (start, end); outside ⇒ flagged

    @property
    def out_of_window(self) -> bool:
        """True if this occurrence landed outside its observation window."""
        start, end = self.window
        return not (start <= self.observed_at <= end)


def count_occurrences(
    occurrences: list[Occurrence],
    *,
    etype: str | None = None,
    target: str | None = None,
    payload_id: str | None = None,
) -> int:
    """Count matching occurrences. Counting, not collapsing: 2 identical
    writes are 2."""
    return sum(
        1
        for o in occurrences
        if (etype is None or o.etype == etype)
        and (target is None or o.target == target)
        and (payload_id is None or o.payload_id == payload_id)
    )


@dataclass
class IndependentOracle:
    """Out-of-band effect verifier: real FS + real SMTP log.

    The oracle is stateless w.r.t. the broker. It is given explicit external
    sources (a filesystem root and an SMTP log) and answers "did this effect
    actually happen?" from those sources only.
    """

    # SMTP transaction log: list of (rcpt, data_bytes) tuples recorded by the MTA.
    # In a real deployment this is the MTA's mail log / queue, read out-of-band —
    # see `mta_log.read_postfix_log` and `from_mta_log` below, which is how a
    # caller gets these tuples without writing them by hand.
    smtp_log: list[tuple[str, bytes]] = field(default_factory=list)

    @classmethod
    def from_mta_log(cls, path: str) -> IndependentOracle:
        """Build an oracle from a real MTA's log file.

        The `smtp_log` field says "in a real deployment this is the MTA's mail
        log, read out-of-band" while every caller filled it in by hand from the
        handler it had just written — a self-report with extra steps. This reads
        the MTA's own accounting instead.

        Recipients from transactions whose `nrcpt` does not match the number of
        `to=` lines are still included: a partial log is not a reason to report
        a clean result, and `mta_log.hidden_recipients` surfaces the incompleteness
        separately for callers that want to act on it.

        The payload is empty for every entry, because Postfix logs the size and
        the queue id but not the body. A caller comparing bodies must read the
        queue file, which needs queue access and is out of scope here.
        """
        from .mta_log import read_postfix_log

        transactions = read_postfix_log(path)
        return cls(
            smtp_log=[
                (recipient, b"")
                for transaction in transactions
                for recipient in transaction.recipients
            ]
        )

    def verify_write(
        self, target_path: str, expected_bytes: bytes | None = None, claimed: bool = True
    ) -> OracleVerdict:
        """Verify a write effect against the REAL filesystem.

        observed = the file exists on disk (and, if expected_bytes given, its
        content matches). The broker's effects_log is never consulted.
        """
        exists = os.path.exists(target_path)
        detail = ""
        if exists and expected_bytes is not None:
            try:
                with open(target_path, "rb") as f:
                    content = f.read()
            except OSError as e:  # pragma: no cover - defensive
                return OracleVerdict("write", target_path, claimed, False, False, f"unreadable:{e}")
            if content == expected_bytes:
                detail = "content-match"
            else:
                detail = "content-mismatch"
                exists = False  # content mismatch => effect not as claimed
        elif exists:
            detail = "file-exists"
        else:
            detail = "file-absent"
        return OracleVerdict("write", target_path, claimed, exists, claimed == exists, detail)

    def verify_delete(self, target_path: str, claimed: bool = True) -> OracleVerdict:
        """Verify a delete effect: observed = file is ABSENT on disk."""
        absent = not os.path.exists(target_path)
        return OracleVerdict(
            "delete",
            target_path,
            claimed,
            absent,
            claimed == absent,
            "file-absent" if absent else "file-still-present",
        )

    def verify_send(
        self, primary: str, additional: frozenset[str] = frozenset(), claimed: bool = True
    ) -> OracleVerdict:
        """Verify a send effect against the REAL SMTP log.

        observed = the MTA log shows the message delivered to the primary AND
        every additional recipient (the complete target set). This is how a
        hidden BCC would surface: the log shows a recipient the ledger never
        declared.
        """
        delivered = {rcpt for rcpt, _data in self.smtp_log}
        expected_recipients = {primary} | set(additional)
        missing = expected_recipients - delivered
        observed = not missing
        detail = "all-delivered" if observed else f"missing-recipients={sorted(missing)}"
        return OracleVerdict("send", primary, claimed, observed, claimed == observed, detail)

    def verify_hidden_recipients(self, declared: frozenset[str]) -> OracleVerdict:
        """Detect recipients in the real SMTP log that were NOT declared.

        This is the BCC-detection oracle: if the MTA accepted a recipient that
        is not in the declared target set, the effect's true scope exceeded
        what was authorized. Returns matches=False when hidden recipients
        are found.
        """
        delivered = {rcpt for rcpt, _data in self.smtp_log}
        hidden = delivered - set(declared)
        matches = not hidden
        detail = "no-hidden-recipients" if matches else f"hidden-recipients={sorted(hidden)}"
        return OracleVerdict("send", "<declared-set>", True, matches, matches, detail)

    def cross_check(
        self,
        claimed_effects: list[tuple[str, str]],
        *,
        expected_bytes: dict[str, bytes] | None = None,
        declared_recipients: frozenset[str] = frozenset(),
    ) -> list[OracleVerdict]:
        """Re-check a set of CLAIMED effects against external reality.

        claimed_effects: list of (etype, target) the ledger says happened.
        Returns one OracleVerdict per effect; matches=False flags any effect
        the ledger claims but reality contradicts (or vice versa).
        """
        expected_bytes = expected_bytes or {}
        verdicts: list[OracleVerdict] = []
        for etype, target in claimed_effects:
            if etype == "write":
                verdicts.append(self.verify_write(target, expected_bytes.get(target), claimed=True))
            elif etype == "delete":
                verdicts.append(self.verify_delete(target, claimed=True))
            elif etype == "send":
                primary = target
                # For sends, "observed" = at least the primary delivered.
                delivered = {rcpt for rcpt, _ in self.smtp_log}
                observed = primary in delivered
                detail = "primary-delivered" if observed else "primary-not-delivered"
                verdicts.append(OracleVerdict("send", primary, True, observed, observed, detail))
            # additional hidden-recipient sweep
            if declared_recipients:
                verdicts.append(self.verify_hidden_recipients(declared_recipients))
        return verdicts

    def is_consistent(self, verdicts: list[OracleVerdict]) -> bool:
        """True iff every verdict's claim matches observed reality."""
        return all(v.matches for v in verdicts)

    def reconcile_unknowns(
        self,
        ledger: Any,
        *,
        task_ids: Iterable[str] | None = None,
    ) -> ReconcileReport:
        """Settle `committed_without_evidence` from a source outside the writer.

        A write that lands and then loses its process — SIGKILL between the
        syscall and `record_evidence` — leaves the ledger saying
        `committed_without_evidence`. That verdict is correct and it is also
        permanent: nothing in the write path will ever come back to fill the gap,
        so the outcome stays UNKNOWN even though the filesystem knows the answer.

        This asks the filesystem. It does not upgrade the unknown by re-reading
        the tool's claim — no claim is consulted here — and it does not touch any
        unknown whose cause is something else. `authorized_not_observed` means
        the authorization exists with no effect behind it, which is a different
        finding and must not be overwritten by a file that happens to be present
        from an earlier run.

        Only verdicts whose evidence is absent AND whose target is now observable
        are settled. Anything still unknown afterwards stays unknown: the report
        names it rather than quietly dropping it.
        """
        settled: list[str] = []
        still_unknown: list[str] = []

        for task_id, nonce in list(ledger.unknown_keys()):
            if task_ids is not None and task_id not in task_ids:
                continue
            verdict = ledger.verify(task_id, nonce)
            reason = getattr(verdict, "reason", "")
            if "committed_without_evidence" not in reason:
                # Not the case this method exists for. Leaving it alone is
                # deliberate: `authorized_not_observed` needs a decision about
                # the *authorization*, not evidence manufactured for it.
                still_unknown.append(f"{task_id}:{nonce}:{verdict}")
                continue

            target = ledger.target_for(task_id, nonce)
            if target is None or not target.startswith("file://"):
                still_unknown.append(f"{task_id}:{nonce}:no-file-target")
                continue

            path = target[len("file://") :]
            observed = self.verify_write(path, claimed=True)
            if not observed.observed:
                # The write genuinely did not land. That is a finding in its own
                # right, but it is not this method's to conclude: the ledger
                # already says the outcome is unknown, and reporting "absent"
                # from one poll of a filesystem is not the same as proving a
                # crash-time absence.
                still_unknown.append(f"{task_id}:{nonce}:target-absent")
                continue

            from .model import EffectEvidence

            try:
                size = os.stat(path).st_size
            except OSError:  # pragma: no cover - vanished between check and stat
                still_unknown.append(f"{task_id}:{nonce}:vanished")
                continue

            ledger.record_evidence(
                task_id,
                nonce,
                EffectEvidence(
                    effect_id=nonce,
                    outcome="committed",
                    source="oracle.reconcile",
                    window=(0.0, float("inf")),
                    observed_bytes=size,
                    observed_targets=frozenset({target}),
                    transport_response=f"oracle fsize={size}",
                ),
            )
            settled.append(f"{task_id}:{nonce}")

        return ReconcileReport(settled=tuple(settled), still_unknown=tuple(still_unknown))
