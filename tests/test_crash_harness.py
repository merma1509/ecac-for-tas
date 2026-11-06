"""A real crash between dispatch and outcome

The distinction this file defends: the previous tests constructed the
post-crash ledger state by hand. That proved `verify()` reads such a state
correctly, but not that the state is reachable — and a hand-built state is
reachable by definition, which is why it proved so little.

Here a child process is actually SIGKILLed while parked between the IN_FLIGHT
marker and the outcome record, and the parent reconstructs the ledger from what
survived on disk. If the marker were buffered, or written after the I/O, this
would report "authorized but never dispatched" — the silent gap — instead of
the unknown it must report.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap

import pytest

from effect_broker.ledger import DISPOSITION_UNKNOWN, IndependentEffectLedger, UnknownLedgerResult

# The child records an authorization and a dispatch marker, announces itself,
# then blocks forever in what stands for the syscall. The parent kills it there.
CRASHING_CHILD = textwrap.dedent(
    """
    import sys, time
    sys.path.insert(0, {root!r})
    from effect_broker.ledger import IndependentEffectLedger

    led = IndependentEffectLedger(_journal_path={journal!r})
    led.record_authorization("crash-task", "crash-nonce",
                             frozenset({{"file:///tmp/doomed"}}),
                             source="executor.execute")
    led.record_dispatched("crash-task", "crash-nonce", source="shim_real.dispatch")
    print("parked", flush=True)   # parent waits for this, then kills
    time.sleep(120)
    """
)


def _run_and_kill(journal: str) -> None:
    """Start the child, wait until it is parked past the marker, then SIGKILL it."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    script = CRASHING_CHILD.format(root=root, journal=journal)
    proc = subprocess.Popen(
        [sys.executable, "-c", script],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert proc.stdout is not None
        line = proc.stdout.readline()
        if line.strip() != "parked":
            stderr = proc.stderr.read() if proc.stderr else ""
            raise AssertionError(f"child failed before parking: {line!r} / {stderr}")
        os.kill(proc.pid, 9)
    finally:
        proc.wait(timeout=10)
        for stream in (proc.stdout, proc.stderr):
            if stream is not None:
                stream.close()


class TestSurvivesRealKill:
    """What the disk says after the process is gone."""

    @pytest.fixture
    def crashed_journal(self, tmp_path) -> str:
        journal = str(tmp_path / "ledger.journal")
        _run_and_kill(journal)
        return journal

    def test_the_child_was_actually_killed(self, crashed_journal) -> None:
        """Guard: a test that never ran the crash would pass for the wrong reason."""
        assert os.path.exists(crashed_journal), "the journal must survive the kill"
        with open(crashed_journal) as fh:
            content = fh.read()
        assert '"kind": "dispatched"' in content

    def test_recovered_ledger_reports_unknown_not_safe(self, crashed_journal) -> None:
        led = IndependentEffectLedger.from_journal(crashed_journal)
        verdict = led.verify("crash-task", "crash-nonce")

        assert isinstance(verdict, UnknownLedgerResult), (
            "a process killed mid-operation must not yield a safe verdict"
        )
        assert DISPOSITION_UNKNOWN in verdict.reason
        assert "dispatched_no_observation" in verdict.reason

    def test_recovery_distinguishes_dispatched_from_never_started(self, crashed_journal) -> None:
        """The whole point of persisting before the I/O.

        A marker written after the syscall would leave no trace here, and the
        verdict would be the ordinary bypass-shaped gap — a different, wrong,
        and quieter diagnosis.
        """
        led = IndependentEffectLedger.from_journal(crashed_journal)
        assert led.was_dispatched("crash-task", "crash-nonce") is True

    def test_recovered_ledger_can_still_count_outcomes(self, crashed_journal) -> None:
        led = IndependentEffectLedger.from_journal(crashed_journal)
        counts = led.outcome_counts()
        assert counts.unknown >= 1
        assert counts.committed == 0


class TestJournalRecoveryEdges:
    """The journal is a file a dead process wrote; recovery must tolerate that."""

    def test_truncated_final_line_is_dropped(self, tmp_path) -> None:
        """A kill mid-write leaves a partial line, which is not a parse failure."""
        journal = tmp_path / "torn.journal"
        journal.write_text(
            '{"kind": "authorized", "task_id": "t", "nonce": "n", '
            '"targets": ["file://a"], "source": "executor.execute"}\n'
            '{"kind": "dispatched", "task_id": "t", "non'
        )
        led = IndependentEffectLedger.from_journal(str(journal))
        # The complete line survived; the torn one is silently skipped.
        assert (("t", "n")) in led._authorizations
        assert led.was_dispatched("t", "n") is False

    def test_missing_journal_yields_an_empty_ledger(self, tmp_path) -> None:
        led = IndependentEffectLedger.from_journal(str(tmp_path / "nope.journal"))
        assert led.outcome_counts().unknown == 0

    def test_replay_does_not_grow_the_journal(self, tmp_path) -> None:
        """Replaying must not re-journal, or recovery would be quadratic."""
        journal = tmp_path / "stable.journal"
        led = IndependentEffectLedger(_journal_path=str(journal))
        led.record_authorization("t", "n", frozenset({"file://a"}), source="executor.execute")
        led.record_dispatched("t", "n")
        before = journal.read_text()

        IndependentEffectLedger.from_journal(str(journal))
        assert journal.read_text() == before, "reading the journal must not write to it"


class TestNoJournalMeansNoBehaviourChange:
    """The default stays in-memory; persistence is opt-in"""

    def test_default_ledger_writes_nothing(self, tmp_path) -> None:
        led = IndependentEffectLedger()
        led.record_authorization("t", "n", frozenset({"file://a"}), source="executor.execute")
        led.record_dispatched("t", "n")
        assert list(tmp_path.iterdir()) == []

    def test_in_memory_verdict_is_unchanged(self) -> None:
        led = IndependentEffectLedger()
        led.record_authorization("t", "n", frozenset({"file://a"}), source="executor.execute")
        led.record_dispatched("t", "n")
        verdict = led.verify("t", "n")
        assert isinstance(verdict, UnknownLedgerResult)
        assert DISPOSITION_UNKNOWN in verdict.reason
