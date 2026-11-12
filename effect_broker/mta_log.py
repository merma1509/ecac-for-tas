"""Read a real MTA's own log to observe what it accepted.

The oracle has always had an `smtp_log` field whose docstring said "in a real
deployment this is the MTA's mail log / queue, read out-of-band". Nothing read
it: every caller filled the list in by hand from the handler it had just
written. That is a self-report with extra steps — the sending process describing
its own behaviour, which is exactly what an out-of-band observer exists to
avoid.

This module parses the log a real MTA writes. Postfix is the first target
because its log carries the two facts that matter:

  * ``nrcpt=N`` on the qmgr line — how many recipients the MTA itself counted
    for one queue id;
  * one ``to=<addr> ... status=...`` line per recipient, written by a process
    that never sees the client's declared recipient list.

An undeclared recipient (a BCC) therefore appears in the log as an address the
ledger never mentioned, and the sender cannot suppress it by lying about its
arguments: suppressing it would require editing the MTA's log, which is a
different threat model from "the tool lied".

WHAT THIS DOES NOT DO
    It is not a trust boundary. A process that can write to the MTA log can forge
    entries. The claim it supports is narrower and still worth having: the
    observations come from the MTA's own accounting rather than from the code
    being observed.

    Message bodies are NOT read. Postfix logs the queue id, sender, size and
    recipients, but not the payload, so `payload_id` is derived from what the log
    does carry. A caller that needs the body digest must read the queue file,
    which requires queue access and is deliberately out of scope.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

from .oracle import Occurrence

#: ``D1B553A0A4D: to=<a@b>, relay=..., status=sent (...)``
#: The status group is captured rather than required: ``deferred`` matters for
#: observation — the MTA accepted the recipient, delivery is a separate
#: question — and ``sent`` is only the ordinary case.
_RECIPIENT_LINE = re.compile(
    r"(?P<queue>[A-Z0-9]+):\s+to=<(?P<rcpt>[^>]+)>(?P<rest>.*?)status=(?P<status>[a-z]+)",
)

#: ``D1B553A0A4D: from=<tool@corp.com>, size=282, nrcpt=2 (queue active)``
#: `nrcpt` is the number that makes a suppressed BCC visible: it is the MTA's
#: own count, not ours.
_QUEUE_LINE = re.compile(
    r"(?P<queue>[A-Z0-9]+):\s+from=<(?P<sender>[^>]*)>,\s+size=(?P<size>\d+),\s+nrcpt=(?P<nrcpt>\d+)",
)


@dataclass(frozen=True)
class EnvelopeTransaction:
    """One queue id as the MTA recorded it.

    `recipients` is every address the MTA accepted for the transaction, in the
    order its log shows them. `declared_count` is the MTA's own `nrcpt`; when it
    disagrees with `len(recipients)` the log was rotated or truncated mid-
    transaction, and a caller must not conclude "no hidden recipient" from an
    incomplete picture.
    """

    queue_id: str
    sender: str
    size: int
    declared_count: int
    recipients: tuple[str, ...]
    statuses: dict[str, str]

    @property
    def complete(self) -> bool:
        """Whether every recipient the MTA counted appears in the log.

        False means the log is partial for this transaction. Treating a partial
        transaction as complete is how a hidden recipient goes unnoticed.
        """
        return len(self.recipients) == self.declared_count

    @property
    def payload_id(self) -> str:
        """Digest of what the log establishes about this message.

        Not the body: the MTA log does not carry it. This identifies the
        transaction (queue id + sender + size + recipients), so two sends of
        identical content to identical recipients remain two transactions —
        the counting behaviour `Occurrence` exists to support.
        """
        material = "\x1f".join([self.queue_id, self.sender, str(self.size), *self.recipients])
        return hashlib.sha256(material.encode("utf-8", errors="replace")).hexdigest()


def parse_postfix_log(text: str) -> list[EnvelopeTransaction]:
    """Parse a Postfix `maillog` into one transaction per queue id.

    Unknown lines are ignored rather than fatal: a mail log contains connection
    notices, policy rejections and other daemons' chatter, and a parser that
    refused the whole file on one unrecognised line would be useless in
    practice. What must not be ignored is a transaction whose recipient count
    does not match its `nrcpt` — that survives as ``complete == False``.
    """
    senders: dict[str, tuple[str, int, int]] = {}
    recipients: dict[str, list[str]] = {}
    statuses: dict[str, dict[str, str]] = {}

    for line in text.splitlines():
        queue_match = _QUEUE_LINE.search(line)
        if queue_match:
            senders[queue_match.group("queue")] = (
                queue_match.group("sender"),
                int(queue_match.group("size")),
                int(queue_match.group("nrcpt")),
            )
            continue

        rcpt_match = _RECIPIENT_LINE.search(line)
        if rcpt_match:
            queue_id = rcpt_match.group("queue")
            recipient = rcpt_match.group("rcpt")
            # Duplicates are kept: a repeated `to=` line for one recipient is
            # two log events, and collapsing them here would hide a retry from
            # `count_occurrences`.
            recipients.setdefault(queue_id, []).append(recipient)
            statuses.setdefault(queue_id, {})[recipient] = rcpt_match.group("status")

    transactions: list[EnvelopeTransaction] = []
    for queue_id, (sender, size, nrcpt) in senders.items():
        transactions.append(
            EnvelopeTransaction(
                queue_id=queue_id,
                sender=sender,
                size=size,
                # A transaction with no qmgr line cannot reach here, so this is
                # always the MTA's own number rather than our guess.
                declared_count=nrcpt,
                recipients=tuple(recipients.get(queue_id, ())),
                statuses=dict(statuses.get(queue_id, {})),
            )
        )
    return transactions


def read_postfix_log(path: str | Path) -> list[EnvelopeTransaction]:
    """Parse a Postfix log file. A missing file yields no transactions.

    A missing log is not an error: an oracle asked about a deployment with no MTA
    should report "nothing observed", and the caller decides whether that is a
    pass or a finding. Raising here would crash `verify_send` on a host that
    legitimately has no mail server.
    """
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeError):
        return []
    return parse_postfix_log(text)


def occurrences_from_transactions(
    transactions: list[EnvelopeTransaction],
    *,
    window: tuple[float, float],
    observed_at: float | None = None,
) -> list[Occurrence]:
    """One `Occurrence` per recipient the MTA accepted.

    Per recipient, not per transaction: the question a hidden-recipient check
    asks is "did the MTA accept an address nobody declared", and that is a
    property of a recipient. A single Occurrence carrying the whole target set
    would answer it too, but `count_occurrences(etype="send")` would then be
    counting transactions, which is not what its callers ask for.

    `observed_at` defaults to the end of the window, because a log is read after
    the fact and Postfix stamps no parseable epoch per line. Marking log-derived
    occurrences at the window edge is honest: they are known to have happened
    inside the run, not when within it.
    """
    stamp = window[1] if observed_at is None else observed_at
    occurrences: list[Occurrence] = []
    for transaction in transactions:
        targets = frozenset(transaction.recipients)
        for index, recipient in enumerate(transaction.recipients):
            occurrences.append(
                Occurrence(
                    # Stable within one transaction, distinct across them, so
                    # two sends to the same address do not collide.
                    effect_id=f"smtp:{transaction.queue_id}:{index}",
                    payload_id=transaction.payload_id,
                    etype="send",
                    target=recipient,
                    targets=targets,
                    observed_at=stamp,
                    source="smtp-envelope",
                    window=window,
                )
            )
    return occurrences


def hidden_recipients(
    transactions: list[EnvelopeTransaction],
    declared: frozenset[str],
) -> tuple[set[str], list[str]]:
    """Addresses the MTA accepted that nobody declared, plus incomplete ids.

    Returns `(hidden, incomplete_queue_ids)`. The second element is not a
    detail: a transaction whose log is partial can hide an address simply by the
    log not showing it, so a caller that ignores it would report "clean" on
    incomplete evidence. It is returned separately rather than folded into
    `hidden` because "we saw a hidden recipient" and "we could not see
    everything" call for different responses, and a set cannot express both.
    """
    hidden: set[str] = set()
    incomplete: list[str] = []
    for transaction in transactions:
        if not transaction.complete:
            incomplete.append(transaction.queue_id)
        hidden.update(set(transaction.recipients) - declared)
    return hidden, incomplete
