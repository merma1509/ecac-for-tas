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
from dataclasses import dataclass, field


@dataclass(frozen=True)
class OracleVerdict:
    """Result of the oracle re-checking one claimed effect against reality."""

    etype: str
    target: str
    claimed: bool  # what the ledger/broker claimed happened
    observed: bool  # what the external source actually shows
    matches: bool  # claimed == observed
    detail: str = ""


@dataclass
class IndependentOracle:
    """Out-of-band effect verifier: real FS + real SMTP log.

    The oracle is stateless w.r.t. the broker. It is given explicit external
    sources (a filesystem root and an SMTP log) and answers "did this effect
    actually happen?" from those sources only.
    """

    # SMTP transaction log: list of (rcpt, data_bytes) tuples recorded by the MTA.
    # In a real deployment this is the MTA's mail log / queue, read out-of-band.
    smtp_log: list[tuple[str, bytes]] = field(default_factory=list)

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
            "delete", target_path, claimed, absent, claimed == absent,
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

    def verify_hidden_recipients(
        self, declared: frozenset[str]
    ) -> OracleVerdict:
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
                verdicts.append(
                    self.verify_write(target, expected_bytes.get(target), claimed=True)
                )
            elif etype == "delete":
                verdicts.append(self.verify_delete(target, claimed=True))
            elif etype == "send":
                primary = target
                # For sends, "observed" = at least the primary delivered.
                delivered = {rcpt for rcpt, _ in self.smtp_log}
                observed = primary in delivered
                detail = "primary-delivered" if observed else "primary-not-delivered"
                verdicts.append(
                    OracleVerdict("send", primary, True, observed, observed, detail)
                )
            # additional hidden-recipient sweep
            if declared_recipients:
                verdicts.append(self.verify_hidden_recipients(declared_recipients))
        return verdicts

    def is_consistent(self, verdicts: list[OracleVerdict]) -> bool:
        """True iff every verdict's claim matches observed reality."""
        return all(v.matches for v in verdicts)
