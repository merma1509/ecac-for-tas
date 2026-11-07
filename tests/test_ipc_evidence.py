"""Evidence on the IPC path (multi-process half).

`RealFileShim` has two execution paths. The same-process one records
`EffectEvidence` after the syscall and was covered by test_io_evidence.py. The
IPC path -- where the I/O happens in a *different process* -- recorded only an
observation built from the reply dict, so a commit was being claimed on the
strength of "the IPC call returned". That is the failure mode P4-1 rejected for
the local path: the broker's own expectation standing in for proof.

These tests drive the real multi-process path through
`broker.create_real_file_shim()`, which is the only way `ipc_client` gets set.
Without them the new evidence code is unexercised, and "the suite is green"
would say nothing about it.
"""

from __future__ import annotations

import os
import pathlib

import pytest

from effect_broker.broker import EffectBroker
from effect_broker.ledger import LedgerVerdict
from effect_broker.model import Capability, Task


@pytest.fixture
def ipc_broker(tmp_path):
    """A multi-process broker with a capability scoped to tmp_path."""
    broker = EffectBroker(mode="multi-process")
    canon = str(pathlib.Path(tmp_path).resolve())
    task = Task(
        task_id="ipc-evidence",
        owner="User",
        ceiling=Capability(
            owner="User",
            holder="ipc-tool",
            right="*",
            target="*",
            scope=frozenset({f"file://{canon}"}),
            expiry=float("inf"),
            nonce="ipc-evidence-cap",
        ),
    )
    broker.register_task(task)
    broker.capabilities["ipc-evidence-cap"] = task.ceiling
    try:
        yield broker, canon
    finally:
        broker.shutdown()


def _last_nonce(shim) -> str:
    return shim.ops[-1].nonce


def _only_nonce(broker) -> str:
    """The single nonce the ledger knows about, for paths that log no shim op.

    On a failure the shim raises before appending to ops, so the nonce cannot
    be read back from there -- but the ledger has it, because the authorization
    and the dispatch marker were both recorded before the failure.
    """
    entries = broker.ledger.get_authorization_entries()
    assert len(entries) == 1, f"expected exactly one authorized effect, got {entries}"
    return next(iter(entries))[1]


class TestIpcWriteCarriesEvidence:
    """A write through the other process must produce measured evidence."""

    def test_write_records_evidence_from_the_executor(self, ipc_broker) -> None:
        broker, canon = ipc_broker
        shim = broker.create_real_file_shim(task_id="ipc-evidence", tool_name="ipc-tool")
        assert shim.ipc_client is not None, "fixture must be on the IPC path"

        payload = b"measured in the other process"
        shim.write(os.path.join(canon, "w.txt"), payload)

        ev = broker.ledger.evidence_for("ipc-evidence", _last_nonce(shim))
        assert ev is not None, "the IPC write path must record evidence"
        assert ev.outcome == "committed"
        assert ev.observed_bytes == len(payload), (
            "the size must be the one the executor measured with stat(), "
            "not the length of the request"
        )
        assert ev.transport_response is not None
        assert "subprocess" in ev.source or "shim_real" in ev.source

    def test_write_evidence_window_follows_the_dispatch_marker(self, ipc_broker) -> None:
        broker, canon = ipc_broker
        shim = broker.create_real_file_shim(task_id="ipc-evidence", tool_name="ipc-tool")
        shim.write(os.path.join(canon, "window.txt"), b"x")

        ev = broker.ledger.evidence_for("ipc-evidence", _last_nonce(shim))
        assert ev is not None
        start, end = ev.window
        assert end >= start, "an inverted window is not evidence"


class TestIpcDeleteCarriesEvidence:
    """A delete is only committed if the target is actually gone."""

    def test_delete_records_committed_evidence_when_target_is_gone(self, ipc_broker) -> None:
        broker, canon = ipc_broker
        shim = broker.create_real_file_shim(task_id="ipc-evidence", tool_name="ipc-tool")
        target = os.path.join(canon, "doomed.txt")
        shim.write(target, b"temporary")

        shim.delete(target)

        assert not os.path.exists(target)
        ev = broker.ledger.evidence_for("ipc-evidence", _last_nonce(shim))
        assert ev is not None
        assert ev.outcome == "committed", "the target is gone; this is a real commit"


class TestIpcFailureLeavesUnknownNotAbsence:
    """A failure across a process boundary cannot be reported as 'never ran'."""

    def test_failure_on_the_ipc_path_records_unknown_evidence(self, ipc_broker) -> None:
        broker, canon = ipc_broker
        shim = broker.create_real_file_shim(task_id="ipc-evidence", tool_name="ipc-tool")

        # A read of something that does not exist: authorized, dispatched,
        # then failed in the other process. The client wraps that failure in
        # RuntimeError, which is what this pins -- the first version only
        # handled OSError, so nothing was recorded at all.
        missing = os.path.join(canon, "not-there.txt")
        with pytest.raises((OSError, RuntimeError)):
            shim.read(missing)

        nonce = _only_nonce(broker)
        ev = broker.ledger.evidence_for("ipc-evidence", nonce)
        assert ev is not None, (
            "an empty evidence set would let the ledger treat a possibly-applied "
            "operation as never executed"
        )
        assert ev.outcome == "unknown"
        assert ev.observed_targets in (None, frozenset())


class TestIpcVerdictUsesEvidence:
    """The end-to-end claim: verify() sees the IPC commit as backed."""

    def test_verify_confirms_committed_write_over_ipc(self, ipc_broker) -> None:
        broker, canon = ipc_broker
        shim = broker.create_real_file_shim(task_id="ipc-evidence", tool_name="ipc-tool")
        shim.write(os.path.join(canon, "verified.txt"), b"backed by stat()")

        verdict = broker.ledger.verify("ipc-evidence", _last_nonce(shim))
        assert verdict is LedgerVerdict.CONFIRMED_COMMITTED, (
            f"evidence from the executor must settle the verdict; got {verdict}"
        )
