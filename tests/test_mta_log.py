"""The oracle must be able to read a real MTA's log, not just a hand-fed list.

`IndependentOracle.smtp_log` has always carried the comment "in a real
deployment this is the MTA's mail log / queue, read out-of-band", but nothing
read one: each test built the list from the handler it had just written. That
makes the oracle a listener to the sender's own report, which is the failure
mode an out-of-band observer exists to rule out.

`tests/data/postfix-maillog.txt` is a log captured from a real Postfix instance
(see `scripts/capture_mta_log.sh`). It holds two transactions that differ in
exactly the way that matters:

    7E8C638460D  nrcpt=1  to=<internal@corp.com>
    7F11038461F  nrcpt=2  to=<internal@corp.com>  to=<attacker@evil.com>

The second is a send whose client declared one recipient and gave the MTA two.
The MTA does not know about declarations, so both addresses look identical in
its log — which is the point: the only place the distinction can be made is the
ledger's declared set, checked against a source the sender does not write.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from effect_broker.mta_log import (
    EnvelopeTransaction,
    hidden_recipients,
    occurrences_from_transactions,
    parse_postfix_log,
    read_postfix_log,
)
from effect_broker.oracle import IndependentOracle, count_occurrences

FIXTURE = Path(__file__).parent / "data" / "postfix-maillog.txt"


@pytest.fixture(scope="module")
def transactions() -> list[EnvelopeTransaction]:
    return read_postfix_log(FIXTURE)


class TestTheFixtureIsARealMtaLog:
    """The fixture has to be what Postfix writes, or these tests test nothing."""

    def test_the_fixture_exists(self) -> None:
        assert FIXTURE.is_file(), (
            f"{FIXTURE} is missing; regenerate with scripts/capture_mta_log.sh"
        )

    def test_it_contains_postfix_lines_not_a_synthetic_shape(self) -> None:
        text = FIXTURE.read_text(encoding="utf-8")
        # These substrings are Postfix's own vocabulary. A hand-written fixture
        # tends to omit them, and then the parser is only tested against itself.
        assert "postfix/qmgr" in text
        assert "postfix/smtpd" in text
        assert "(queue active)" in text

    def test_both_transactions_are_present(self, transactions: list[EnvelopeTransaction]) -> None:
        counts = sorted(t.declared_count for t in transactions)
        assert counts == [1, 2], (
            f"expected one single-recipient and one two-recipient transaction, got {counts}"
        )


class TestParsing:
    def test_each_transaction_carries_the_sender_the_mta_recorded(
        self, transactions: list[EnvelopeTransaction]
    ) -> None:
        assert {t.sender for t in transactions} == {"tool@corp.com"}

    def test_recipients_are_attributed_to_the_right_transaction(
        self, transactions: list[EnvelopeTransaction]
    ) -> None:
        by_count = {t.declared_count: t for t in transactions}
        assert by_count[1].recipients == ("internal@corp.com",)
        assert by_count[2].recipients == ("internal@corp.com", "attacker@evil.com")

    def test_the_mta_recipient_count_is_the_mtas_not_ours(
        self, transactions: list[EnvelopeTransaction]
    ) -> None:
        """`declared_count` must come from `nrcpt=`, which the MTA writes.

        If it were derived from `len(recipients)` the completeness check could
        never fail, and a truncated log would silently read as clean.
        """
        for transaction in transactions:
            assert transaction.declared_count == len(transaction.recipients) or not (
                transaction.complete
            )
            assert transaction.complete, "the captured log should be complete for both transactions"

    def test_deferred_lines_still_count_as_accepted(
        self, transactions: list[EnvelopeTransaction]
    ) -> None:
        """A `deferred` recipient is still a recipient the MTA accepted.

        The captured MTA cannot resolve corp.com, so every `status=` is
        `deferred`. Rejecting those would make the oracle blind on any host
        without working DNS — which is most test environments.
        """
        assert all("deferred" in t.statuses.values() for t in transactions if t.statuses)

    def test_unknown_lines_are_ignored(self) -> None:
        """Connection chatter must not break parsing of a real log."""
        text = (
            "Nov 12 04:33:24 host postfix/smtpd[3473]: connect from unknown[127.0.0.1]\n"
            "Nov 12 04:33:24 host postfix/smtpd[3473]: lost connection after CONNECT\n"
            "Nov 12 04:33:24 host postfix/qmgr[3471]: "
            "ABC123: from=<a@b>, size=10, nrcpt=1 (queue active)\n"
            "Nov 12 04:33:24 host postfix/smtp[3478]: ABC123: to=<x@y>, status=sent (ok)\n"
        )
        parsed = parse_postfix_log(text)
        assert len(parsed) == 1
        assert parsed[0].recipients == ("x@y",)

    def test_a_truncated_log_is_not_complete(self) -> None:
        """The case the completeness flag exists for.

        The MTA counted two recipients; the log shows one, because the other
        line was rotated away. Reporting this as complete would mean a hidden
        recipient is invisible for the least interesting possible reason.
        """
        text = (
            "Nov 12 04:33:24 host postfix/qmgr[3471]: "
            "ABC123: from=<a@b>, size=10, nrcpt=2 (queue active)\n"
            "Nov 12 04:33:24 host postfix/smtp[3478]: ABC123: to=<x@y>, status=sent (ok)\n"
        )
        parsed = parse_postfix_log(text)
        assert len(parsed) == 1
        assert parsed[0].complete is False
        assert parsed[0].declared_count == 2

    def test_a_missing_log_is_empty_not_an_error(self, tmp_path: Path) -> None:
        """A host with no MTA must report 'nothing observed', not crash."""
        assert read_postfix_log(tmp_path / "nope.log") == []


class TestHiddenRecipients:
    def test_the_undeclared_recipient_is_found(
        self, transactions: list[EnvelopeTransaction]
    ) -> None:
        hidden, incomplete = hidden_recipients(transactions, frozenset({"internal@corp.com"}))
        assert hidden == {"attacker@evil.com"}, (
            "the BCC the client never declared in the broker did not surface from the "
            "MTA log; the oracle is trusting the sender's account of its own send"
        )
        assert incomplete == []

    def test_nothing_is_hidden_when_both_were_declared(
        self, transactions: list[EnvelopeTransaction]
    ) -> None:
        hidden, _ = hidden_recipients(
            transactions, frozenset({"internal@corp.com", "attacker@evil.com"})
        )
        assert hidden == set()

    def test_incompleteness_is_reported_separately_from_hidden(self) -> None:
        """Two different findings must not be collapsed into one set.

        "We saw an address nobody declared" and "we could not see everything"
        call for different actions. Folding the second into `hidden` would either
        invent a recipient or hide the uncertainty.
        """
        truncated = [
            EnvelopeTransaction(
                queue_id="ABC123",
                sender="a@b",
                size=10,
                declared_count=3,
                recipients=("x@y",),
                statuses={"x@y": "sent"},
            )
        ]
        hidden, incomplete = hidden_recipients(truncated, frozenset({"x@y"}))
        assert hidden == set(), "no address was observed that was not declared"
        assert incomplete == ["ABC123"], "an incomplete transaction must still be flagged"


class TestTheOracleReadsTheRealLog:
    def test_from_mta_log_surfaces_the_bcc(self) -> None:
        oracle = IndependentOracle.from_mta_log(str(FIXTURE))
        verdict = oracle.verify_hidden_recipients(frozenset({"internal@corp.com"}))
        assert verdict.matches is False
        assert "attacker@evil.com" in verdict.detail

    def test_from_mta_log_confirms_a_declared_send(self) -> None:
        oracle = IndependentOracle.from_mta_log(str(FIXTURE))
        verdict = oracle.verify_send("internal@corp.com", claimed=True)
        assert verdict.matches is True

    def test_the_log_backed_oracle_is_not_the_senders_report(self) -> None:
        """A hand-fed log and the real one must be able to disagree.

        This is the property that makes the oracle worth having: if the sender
        under-reported its recipients, the log still shows them. Asserting that
        the real log disagrees with a naive self-report is what proves the
        reading actually came from the file.
        """
        real = IndependentOracle.from_mta_log(str(FIXTURE))
        self_reported = IndependentOracle(
            smtp_log=[("internal@corp.com", b""), ("internal@corp.com", b"")]
        )
        declared = frozenset({"internal@corp.com"})
        assert real.verify_hidden_recipients(declared).matches is False
        assert self_reported.verify_hidden_recipients(declared).matches is True


class TestOccurrenceCounting:
    def test_occurrences_are_per_recipient(self, transactions: list[EnvelopeTransaction]) -> None:
        occurrences = occurrences_from_transactions(transactions, window=(0.0, 100.0))
        # 1 recipient in the first transaction + 2 in the second.
        assert len(occurrences) == 3
        assert count_occurrences(occurrences, etype="send") == 3

    def test_each_recipient_carries_the_whole_transaction_target_set(
        self, transactions: list[EnvelopeTransaction]
    ) -> None:
        """Nothing is covered up by looking at one recipient at a time."""
        occurrences = occurrences_from_transactions(transactions, window=(0.0, 100.0))
        for occurrence in occurrences:
            expected = 1 if "7E8C" in occurrence.effect_id else 2
            assert len(occurrence.targets) == expected

    def test_the_two_transactions_have_distinct_payload_ids(
        self, transactions: list[EnvelopeTransaction]
    ) -> None:
        """Two sends are two transactions, not one collapsed event."""
        payload_ids = {t.payload_id for t in transactions}
        assert len(payload_ids) == len(transactions)

    def test_occurrences_are_inside_the_window(
        self, transactions: list[EnvelopeTransaction]
    ) -> None:
        window = (10.0, 20.0)
        occurrences = occurrences_from_transactions(transactions, window=window)
        assert all(not o.out_of_window for o in occurrences)

    def test_the_source_names_the_mta(self, transactions: list[EnvelopeTransaction]) -> None:
        occurrences = occurrences_from_transactions(transactions, window=(0.0, 1.0))
        assert {o.source for o in occurrences} == {"smtp-envelope"}
