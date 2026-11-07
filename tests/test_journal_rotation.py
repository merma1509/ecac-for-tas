"""Bounded journal growth: rotation and what it costs.

An unbounded journal is a slow denial of service on the operator. At ~150 bytes
per effect it reaches ~150 MB per million effects, and every recovery reads all
of it. Rotation bounds both -- but it introduces a new way to be wrong: a reader
that starts in the middle of the history sees observations whose authorizations
live in a file that is no longer there, and reports effects nobody authorized.

These tests pin both halves: the file stays bounded, and the truncation is
reported rather than silently converting missing history into inventing bypass.
"""

from __future__ import annotations

import json
import os

from effect_broker.ledger import (
    IndependentEffectLedger,
    _journal_segments,
)


def _write_effects(ledger: IndependentEffectLedger, count: int, start: int = 0) -> None:
    """Each effect journals an authorization and a dispatch marker."""
    for i in range(start, start + count):
        ledger.record_authorization(
            "t", f"n{i}", frozenset({"file://a"}), source="executor.execute"
        )
        ledger.record_dispatched("t", f"n{i}")


def test_segments_are_listed_oldest_first(tmp_path) -> None:
    """Replay order must be chronological, else a later record loses to an earlier one."""
    path = str(tmp_path / "j.journal")
    for name in ("j.journal.2", "j.journal.1", "j.journal"):
        with open(tmp_path / name, "w", encoding="utf-8") as fh:
            fh.write("")

    # Highest suffix is the oldest segment; the live file is newest.
    assert _journal_segments(path) == [
        str(tmp_path / "j.journal.2"),
        str(tmp_path / "j.journal.1"),
        str(tmp_path / "j.journal"),
    ]


def test_no_segments_when_only_the_live_file_exists(tmp_path) -> None:
    path = str(tmp_path / "j.journal")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("")
    assert _journal_segments(path) == [path]


def test_journal_stays_within_the_bound(tmp_path) -> None:
    """The whole point: growth is capped, not merely slowed."""
    path = str(tmp_path / "j.journal")
    limit = 400
    ledger = IndependentEffectLedger(
        _journal_path=path, _journal_max_bytes=limit, _journal_keep=1
    )
    _write_effects(ledger, 40)

    live = os.path.getsize(path)
    assert live < limit + 200, f"live segment grew past the bound: {live}"


def test_rotation_retains_only_the_requested_segments(tmp_path) -> None:
    path = str(tmp_path / "j.journal")
    ledger = IndependentEffectLedger(
        _journal_path=path, _journal_max_bytes=200, _journal_keep=2
    )
    _write_effects(ledger, 30)

    names = [n for n in os.listdir(tmp_path) if n.startswith("j.journal")]
    # Live file plus at most `keep` rotated segments -- never an unbounded pile.
    assert len(names) <= 3, names
    assert "j.journal" in names


def test_rotated_file_starts_with_a_segment_marker(tmp_path) -> None:
    """The marker is what tells a reader its history was cut, not that it began."""
    path = str(tmp_path / "j.journal")
    ledger = IndependentEffectLedger(
        _journal_path=path, _journal_max_bytes=150, _journal_keep=1
    )
    _write_effects(ledger, 20)

    with open(path, encoding="utf-8") as fh:
        first = json.loads(fh.readline())
    assert first["kind"] == "segment"
    assert first["partial_history"] is True


def test_recovery_reports_truncation(tmp_path) -> None:
    """A silently truncated history reads as 'no bypasses found'. Say so instead."""
    path = str(tmp_path / "j.journal")
    ledger = IndependentEffectLedger(
        _journal_path=path, _journal_max_bytes=150, _journal_keep=1
    )
    _write_effects(ledger, 20)
    assert ledger.journal_truncated is False

    recovered = IndependentEffectLedger.from_journal(path)
    assert recovered.journal_truncated is True


def test_unrotated_journal_does_not_claim_truncation(tmp_path) -> None:
    """The flag must mean something: no rotation, no warning."""
    path = str(tmp_path / "j.journal")
    ledger = IndependentEffectLedger(_journal_path=path)
    _write_effects(ledger, 5)

    recovered = IndependentEffectLedger.from_journal(path)
    assert recovered.journal_truncated is False
    assert len(recovered.get_authorization_entries()) == 5


def test_recovery_keeps_the_newest_records(tmp_path) -> None:
    """Retention drops the oldest history; the recent history must still be exact."""
    path = str(tmp_path / "j.journal")
    ledger = IndependentEffectLedger(
        _journal_path=path, _journal_max_bytes=300, _journal_keep=2
    )
    _write_effects(ledger, 30)

    recovered = IndependentEffectLedger.from_journal(path)
    # The most recent effect is always in the live segment, whatever was dropped.
    assert recovered.was_dispatched("t", "n29") is True


def test_recovered_ledger_keeps_rotating(tmp_path) -> None:
    """A recovered ledger that forgets its bound grows forever after one restart."""
    path = str(tmp_path / "j.journal")
    ledger = IndependentEffectLedger(
        _journal_path=path, _journal_max_bytes=200, _journal_keep=1
    )
    _write_effects(ledger, 15)

    recovered = IndependentEffectLedger.from_journal(
        path, journal_max_bytes=200, journal_keep=1
    )
    before = os.path.getsize(path)
    _write_effects(recovered, 15, start=100)
    after = os.path.getsize(path)

    assert after < before + 400, "a recovered ledger must not resume unbounded growth"


def test_no_rotation_without_a_bound(tmp_path) -> None:
    """Default stays one file: every existing caller is unaffected."""
    path = str(tmp_path / "j.journal")
    ledger = IndependentEffectLedger(_journal_path=path)
    _write_effects(ledger, 30)

    names = [n for n in os.listdir(tmp_path) if n.startswith("j.journal")]
    assert names == ["j.journal"]
