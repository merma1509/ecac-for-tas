"""Wiring the journal into the build path.

The mechanism was proven in test_crash_harness.py; this file checks that a
caller can actually reach it. Without these, `journal_path` could be plumbed
through every layer and dropped at the last one, and every existing test would
still pass — the failure mode is silence, not an exception.
"""

from __future__ import annotations

import json
import os

from effect_broker.ledger import IndependentEffectLedger
from effect_broker.model import Capability, Task
from effect_broker.shim_real import RealFileShim
from effect_broker.traces import build


def _scoped_broker(journal_path: str | None, tmpdir: str):
    """Broker with a wildcard capability scoped to tmpdir."""
    canon = os.path.realpath(tmpdir)
    b = build(journal_path=journal_path)
    task = Task(
        task_id="journal-task",
        owner="User",
        ceiling=Capability(
            owner="User",
            holder="journal-tool",
            right="*",
            target="*",
            scope=frozenset({f"file://{canon}"}),
            expiry=float("inf"),
            nonce="journal-cap",
        ),
    )
    b.register_task(task)
    b.capabilities["journal-cap"] = task.ceiling
    return b, canon


def _kinds(path: str) -> list[str]:
    with open(path) as fh:
        return [json.loads(line)["kind"] for line in fh if line.strip()]


class TestBuildAcceptsAJournalPath:
    """build() must pass the path down, and default to writing nothing."""

    def test_build_without_a_path_writes_no_file(self, tmp_path) -> None:
        b, canon = _scoped_broker(None, str(tmp_path))
        shim = RealFileShim(b, task_id="journal-task", tool_name="journal-tool")
        shim.write(os.path.join(canon, "quiet.txt"), b"x")
        journals = list(tmp_path.glob("*.journal"))
        assert journals == [], "default build must stay in-memory"

    def test_journal_path_reaches_the_ledger(self, tmp_path) -> None:
        journal = str(tmp_path / "j.journal")
        b, _ = _scoped_broker(journal, str(tmp_path))
        assert b.ledger._journal_path == journal


class TestRealIoIsJournaled:
    """A write through the shim must leave all three record kinds."""

    def test_write_journals_authorization_dispatch_and_evidence(self, tmp_path) -> None:
        journal = str(tmp_path / "w.journal")
        b, canon = _scoped_broker(journal, str(tmp_path))
        shim = RealFileShim(b, task_id="journal-task", tool_name="journal-tool")

        shim.write(os.path.join(canon, "a.txt"), b"data")

        kinds = _kinds(journal)
        assert "authorized" in kinds
        assert "dispatched" in kinds, (
            "the in-flight marker is the record that makes a crash diagnosable; "
            "if it never reaches the journal, P4-2 is not actually wired"
        )
        assert "evidence" in kinds

    def test_dispatch_precedes_evidence_in_the_file(self, tmp_path) -> None:
        """Order in the journal is the order the process lived through it.

        If evidence came first, a crash between them would be impossible to
        reconstruct, and the marker would stop meaning what it claims.
        """
        journal = str(tmp_path / "order.journal")
        b, canon = _scoped_broker(journal, str(tmp_path))
        shim = RealFileShim(b, task_id="journal-task", tool_name="journal-tool")

        shim.write(os.path.join(canon, "ordered.txt"), b"y")

        kinds = _kinds(journal)
        assert kinds.index("dispatched") < kinds.index("evidence")

    def test_journaled_run_reconstructs_a_committed_effect(self, tmp_path) -> None:
        """After a clean run, recovery sees the evidence and agrees."""
        journal = str(tmp_path / "clean.journal")
        b, canon = _scoped_broker(journal, str(tmp_path))
        shim = RealFileShim(b, task_id="journal-task", tool_name="journal-tool")
        shim.write(os.path.join(canon, "clean.txt"), b"z")

        recovered = IndependentEffectLedger.from_journal(journal)
        ev = recovered.evidence_for("journal-task", shim.get_ops()[-1].nonce)
        assert ev is not None
        assert ev.outcome == "committed"


class TestResetLeavesAMarker:
    """reset() must discard the past without pretending it never happened."""

    def test_reset_appends_a_marker_and_forgets_prior_records(self, tmp_path) -> None:
        journal = str(tmp_path / "reset.journal")
        led = IndependentEffectLedger(_journal_path=journal)
        led.record_authorization("t", "old", frozenset({"file://a"}), source="executor.execute")
        led.record_dispatched("t", "old")

        led.reset()

        assert "reset" in _kinds(journal)
        # The marker is in the journal; the file is not truncated.
        assert "dispatched" in _kinds(journal)

        recovered = IndependentEffectLedger.from_journal(journal)
        assert recovered.was_dispatched("t", "old") is False, (
            "effects from before the reset must not reappear after recovery"
        )

    def test_records_after_a_reset_still_survive(self, tmp_path) -> None:
        journal = str(tmp_path / "after.journal")
        led = IndependentEffectLedger(_journal_path=journal)
        led.record_authorization("t", "old", frozenset({"file://a"}), source="executor.execute")
        led.reset()
        led.record_authorization("t", "new", frozenset({"file://b"}), source="executor.execute")
        led.record_dispatched("t", "new")

        recovered = IndependentEffectLedger.from_journal(journal)
        assert recovered.was_dispatched("t", "new") is True
        assert recovered.was_dispatched("t", "old") is False

    def test_reset_on_an_unjournaled_ledger_writes_nothing(self, tmp_path) -> None:
        led = IndependentEffectLedger()
        led.record_authorization("t", "n", frozenset({"file://a"}), source="executor.execute")
        led.reset()
        assert list(tmp_path.iterdir()) == []


class TestJournalPathDoesNotLeakBetweenRuns:
    """The module-level knob must not outlive the run that set it."""

    def test_collect_outcome_counts_clears_the_path_in_finally(self, tmp_path) -> None:
        from effect_broker import experiment

        journal = str(tmp_path / "run.journal")
        experiment.collect_outcome_counts(journal_path=journal)

        assert experiment._JOURNAL_PATH is None, (
            "a later run must not inherit the previous run's journal"
        )

    def test_default_run_writes_no_journal(self, tmp_path) -> None:
        from effect_broker import experiment

        experiment.collect_outcome_counts()
        assert list(tmp_path.iterdir()) == []


class TestConformanceSuiteDoesNotExerciseTheShims:
    """Documents a real limit rather than leaving it to be discovered.

    `python -m effect_broker --journal PATH` produces authorizations only: the
    conformance scenarios decide verdicts through broker.commit() and never
    reach a real file operation. The flag is therefore wired and correct, but it
    will not record an in-flight marker on that particular run. This test states
    that so nobody reads an empty set of markers as "no crash could happen".
    """

    def test_suite_journals_authorizations_without_dispatch(self, tmp_path) -> None:
        from effect_broker import experiment

        journal = str(tmp_path / "suite.journal")
        experiment.collect_outcome_counts(journal_path=journal)

        kinds = _kinds(journal)
        assert "authorized" in kinds, "the suite must at least be journaling"
        assert "dispatched" not in kinds, (
            "if this ever starts failing, the suite has begun driving real I/O "
            "and this docstring plus the --journal help text need revisiting"
        )

    def test_a_clean_run_does_not_recover_as_a_crash(self, tmp_path) -> None:
        """The bug this pins: without journaled observations, success looked fatal.

        A completed run left authorizations in the journal but no outcome
        records, so recovery reconstructed a field of dispatched-but-unobserved
        effects -- 29 unknowns for a run that failed nothing. A clean shutdown
        was indistinguishable from a kill, and the more successful the run, the
        worse the recovered picture.
        """
        from effect_broker import experiment

        journal = str(tmp_path / "clean_run.journal")
        experiment.collect_outcome_counts(journal_path=journal)

        recovered = IndependentEffectLedger.from_journal(journal)
        counts = recovered.outcome_counts()

        assert counts.unknown == 0, (
            "a run that completed must not recover as unknown; observations "
            "have to be journaled for the recovery to mean anything"
        )
        assert counts.committed > 0, "the suite commits effects; recovery must see them"
