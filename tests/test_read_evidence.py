"""Regression: an authorized read must leave an observation in the ledger.

The bug this pins
-----------------
`RealFileShim` recorded a dispatch marker for `read` but never recorded
evidence afterwards — unlike `write` and `delete`. `Ledger.verify()` therefore
returned `UNKNOWN(committed_without_evidence)` for every legitimate read, and
`verify_complete_mediation()` reported `UNKNOWN` after a single approved read.

The invariant "authorized without observation → UNKNOWN, never safe" was upheld,
so nothing looked wrong. But an audit trail that cannot confirm the commonest
operation is not an audit trail: a real bypass and a normal read produced the
same verdict.

Fixed by recording evidence for reads in both branches (IPC and same-process),
measured on the bytes actually delivered.
"""

from __future__ import annotations

import os
import pathlib

import pytest

from effect_broker.broker import EffectBroker
from effect_broker.ledger import LedgerVerdict
from effect_broker.model import Capability, Task
from effect_broker.shim_real import RealFileShim
from effect_broker.traces import build


def _capability(scope_dir: str) -> Capability:
    return Capability(
        owner="User",
        holder="tool",
        right="*",
        target="*",
        scope=frozenset({f"file://{scope_dir}"}),
        expiry=float("inf"),
        nonce="cap",
        task_id="t",
    )


@pytest.fixture
def target_file(tmp_path: pathlib.Path) -> tuple[str, str]:
    scope_dir = str(tmp_path)
    target = os.path.join(scope_dir, "data.txt")
    with open(target, "w") as f:
        f.write("payload")
    return scope_dir, target


class TestSameProcessReadEvidence:
    def test_read_verifies_committed(self, target_file: tuple[str, str]) -> None:
        scope_dir, target = target_file
        broker = build()
        task = Task(task_id="t", owner="User", ceiling=_capability(scope_dir))
        broker.register_task(task)
        broker.capabilities["cap"] = task.ceiling

        shim = RealFileShim(broker=broker, task_id="t", tool_name="tool")
        assert shim.read(target) == b"payload"

        verdict = broker.ledger.verify("t", shim.ops[-1].nonce)
        assert verdict is LedgerVerdict.CONFIRMED_COMMITTED, (
            f"an approved same-process read verified as {verdict}: no observation "
            f"was recorded for it, so an audit cannot distinguish it from a bypass"
        )

    def test_read_evidence_reports_delivered_bytes(
        self, target_file: tuple[str, str]
    ) -> None:
        scope_dir, target = target_file
        broker = build()
        task = Task(task_id="t", owner="User", ceiling=_capability(scope_dir))
        broker.register_task(task)
        broker.capabilities["cap"] = task.ceiling

        shim = RealFileShim(broker=broker, task_id="t", tool_name="tool")
        shim.read(target)
        nonce = shim.ops[-1].nonce

        # Evidence lives in its own map, distinct from observations: it is the
        # transport-boundary measurement, not the executor's "I applied it".
        evidence = broker.ledger.evidence_for("t", nonce)
        assert evidence is not None, "no evidence recorded for the read"
        assert evidence.outcome == "committed"
        assert evidence.observed_bytes == len("payload"), (
            f"evidence must report the delivered byte count, got "
            f"{evidence.observed_bytes}"
        )

    def test_complete_mediation_passes_after_read(
        self, target_file: tuple[str, str]
    ) -> None:
        scope_dir, target = target_file
        broker = build()
        task = Task(task_id="t", owner="User", ceiling=_capability(scope_dir))
        broker.register_task(task)
        broker.capabilities["cap"] = task.ceiling

        RealFileShim(broker=broker, task_id="t", tool_name="tool").read(target)
        failures = broker.verify_complete_mediation()
        assert failures == [], (
            f"complete mediation reported {failures} after a single legit read"
        )


class TestMultiProcessReadEvidence:
    def test_read_verifies_committed(self, target_file: tuple[str, str]) -> None:
        scope_dir, target = target_file
        broker = EffectBroker(mode="multi-process")
        task = Task(task_id="t", owner="User", ceiling=_capability(scope_dir))
        broker.register_task(task)
        broker.capabilities["cap"] = task.ceiling
        try:
            shim = broker.create_real_file_shim(task_id="t", tool_name="tool")
            assert shim.read(target) == b"payload"
            verdict = broker.ledger.verify("t", shim.ops[-1].nonce)
            assert verdict is LedgerVerdict.CONFIRMED_COMMITTED, (
                f"approved multi-process read verified as {verdict}"
            )
            assert broker.verify_complete_mediation() == []
        finally:
            broker.shutdown()


class TestNoiseStillDetected:
    """Recording evidence for reads must not make the ledger trust everything."""

    def test_unauthorized_read_still_unknown(self, target_file: tuple[str, str]) -> None:
        """A nonce the gate never authorized must stay UNKNOWN, not become safe."""
        scope_dir, target = target_file
        broker = build()
        task = Task(task_id="t", owner="User", ceiling=_capability(scope_dir))
        broker.register_task(task)
        broker.capabilities["cap"] = task.ceiling
        RealFileShim(broker=broker, task_id="t", tool_name="tool").read(target)

        verdict = broker.ledger.verify("t", "never-authorized-nonce")
        assert str(verdict).startswith("UNKNOWN"), (
            f"unsupported nonce must verify as UNKNOWN, got {verdict}"
        )
        assert "no_record" in str(verdict)

