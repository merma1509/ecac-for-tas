"""Reconciling an unknown from outside the process that caused it.

A write that lands and then loses its process — SIGKILL between the syscall and
`record_evidence` — leaves the ledger saying `committed_without_evidence`. That
verdict is correct and permanent: nothing in the write path comes back to fill
the gap, so the outcome stays UNKNOWN for the rest of the ledger's life even
though the filesystem knows the answer.

`IndependentOracle.reconcile_unknowns` asks the filesystem. These tests pin both
what it settles and — more importantly — what it must leave alone.
"""

from __future__ import annotations

import os
from unittest import mock

import pytest

from effect_broker.ledger import LedgerVerdict
from effect_broker.model import Capability, Task
from effect_broker.oracle import IndependentOracle
from effect_broker.shim_real import RealFileShim
from effect_broker.traces import build


@pytest.fixture
def scoped(tmp_path):
    canon = os.path.realpath(str(tmp_path))
    b = build()
    task = Task(
        task_id="t",
        owner="User",
        ceiling=Capability(
            owner="User",
            holder="tool",
            right="*",
            target="*",
            scope=frozenset({f"file://{canon}"}),
            expiry=float("inf"),
            nonce="cap",
        ),
    )
    b.register_task(task)
    b.capabilities["cap"] = task.ceiling
    return b, canon


def _torn_write(b, tmpdir: str):
    """A write that lands on disk and then dies before recording evidence.

    This is the shape the reconcile path exists for: the syscall succeeded, so
    the file is really there, but the process died before it could measure or
    record anything. The ledger cannot distinguish it from a write that never
    started, which is exactly why it says UNKNOWN.
    """
    shim = RealFileShim(b, task_id="t", tool_name="tool")
    target = os.path.join(tmpdir, "torn.txt")

    def die(*_args, **_kwargs):
        raise SystemExit("killed after the write, before measuring it")

    with mock.patch.object(RealFileShim, "_evidence_after_io", side_effect=die):
        with pytest.raises(SystemExit):
            shim._op("write", target, lambda _path: None, b"data")
    return target


class TestSettlingACrashTornWrite:
    def test_it_is_unknown_before_reconciliation(self, scoped) -> None:
        b, tmpdir = scoped
        target = _torn_write(b, tmpdir)
        assert os.path.exists(target), "the write must really have landed"
        assert b.ledger.unknown_keys(), "a torn write must be visible as unknown"
        assert isinstance(b.ledger.verify(*b.ledger.unknown_keys()[0]), object)

    def test_reconciliation_settles_it_as_committed(self, scoped) -> None:
        b, tmpdir = scoped
        target = _torn_write(b, tmpdir)
        key = b.ledger.unknown_keys()[0]

        report = IndependentOracle().reconcile_unknowns(b.ledger)

        assert len(report.settled) == 1
        assert report.all_settled
        assert b.ledger.verify(*key) is LedgerVerdict.CONFIRMED_COMMITTED
        assert os.path.getsize(target) == 4

    def test_the_settled_evidence_names_the_oracle_as_its_source(self, scoped) -> None:
        """An operator must be able to tell how an unknown got settled.

        Evidence attributed to the shim would read as if the write path had
        recorded it, which is precisely the confusion this method exists to
        remove.
        """
        b, tmpdir = scoped
        _torn_write(b, tmpdir)
        IndependentOracle().reconcile_unknowns(b.ledger)

        key = next(iter(b.ledger._observations))
        evidence = b.ledger.evidence_for(*key)
        assert evidence is not None
        assert evidence.source == "oracle.reconcile"


class TestWhatItMustNotTouch:
    def test_an_absent_target_is_left_unknown(self, scoped) -> None:
        """One poll of a filesystem is not proof the write never happened.

        A write could have landed and been cleaned up, or landed elsewhere. The
        ledger already says the outcome is unknown; turning that into a definite
        "did not happen" on this evidence would be a new claim, not a
        reconciliation.
        """
        b, tmpdir = scoped
        _torn_write(b, tmpdir)
        os.remove(os.path.join(tmpdir, "torn.txt"))

        report = IndependentOracle().reconcile_unknowns(b.ledger)

        assert report.settled == ()
        assert report.all_settled is False
        assert any("target-absent" in entry for entry in report.still_unknown)

    def test_authorized_but_unobserved_is_not_settled(self, scoped) -> None:
        """A different diagnosis, and one evidence must not overwrite.

        `authorized_not_observed` means the gate said yes and no effect followed.
        Creating a file to match that authorization would manufacture the very
        observation that is missing — the opposite of independent verification.
        """
        b, tmpdir = scoped
        path = os.path.join(tmpdir, "authorized-only.txt")

        b.ledger.record_authorization(
            "t", "cap", frozenset({f"file://{path}"}), source="executor.execute"
        )
        # The filesystem happens to have a file there, from anything at all.
        with open(path, "wb") as handle:
            handle.write(b"unrelated")

        report = IndependentOracle().reconcile_unknowns(b.ledger)

        assert report.settled == (), "an unobserved authorization must stay unknown"
        assert any("cap" in entry for entry in report.still_unknown)

    def test_a_non_file_target_is_left_unknown(self, scoped) -> None:
        """The oracle observes files; it must not claim to observe anything else.

        A `committed_without_evidence` effect whose target is not a file has no
        outside source this oracle can consult, so it stays unknown and says so
        rather than being dropped from the report.
        """
        b, _ = scoped
        b.ledger.record_authorization(
            "t", "cap", frozenset({"email://a@b"}), source="executor.execute"
        )
        # An apply observation with no evidence is the shape that reaches target
        # resolution; an authorization alone is stopped earlier by diagnosis.
        b.ledger.record_observation("t", "cap", frozenset({"email://a@b"}), source="executor.apply")

        report = IndependentOracle().reconcile_unknowns(b.ledger)

        assert report.settled == ()
        assert any("no-file-target" in entry for entry in report.still_unknown)

    def test_task_filter_limits_the_sweep(self, scoped) -> None:
        b, tmpdir = scoped
        _torn_write(b, tmpdir)
        report = IndependentOracle().reconcile_unknowns(b.ledger, task_ids={"other-task"})
        assert report.settled == ()
        assert b.ledger.unknown_keys(), "the effect must still be unknown"


class TestTheTwoLedgerViewsAgree:
    def test_outcome_counts_does_not_call_a_torn_write_committed(self, scoped) -> None:
        """The aggregate metric and the audit verdict must agree.

        `outcome_counts()` bucketed `executor.apply` as committed while
        `verify()` called the same effect `committed_without_evidence`. The
        metric is what gets reported, so the optimistic one was the one people
        read.
        """
        b, tmpdir = scoped
        _torn_write(b, tmpdir)

        counts = b.ledger.outcome_counts()
        assert counts.committed == 0
        assert counts.unknown >= 1

    def test_after_reconciliation_the_counts_follow(self, scoped) -> None:
        b, tmpdir = scoped
        _torn_write(b, tmpdir)
        IndependentOracle().reconcile_unknowns(b.ledger)

        counts = b.ledger.outcome_counts()
        assert counts.committed == 1
        assert counts.unknown == 0
