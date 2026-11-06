"""Evidence from the real filesystem boundary

The claim these tests defend: a COMMITTED verdict for a file effect is backed by
something measured after the syscall, not by the executor asserting success
before it. Before this, `executor.apply` was recorded inside broker.commit(),
which runs BEFORE the shim opens the file — so the ledger read "applied" for a
write that had not happened yet.

Every test here would have passed for the wrong reason under the old code
except where noted; the ones that fail without the change are the point.
"""

from __future__ import annotations

import os

import pytest

from effect_broker.ledger import LedgerVerdict
from effect_broker.model import Capability, EffectEvidence, EvidenceInsufficient, Task
from effect_broker.shim_real import RealFileShim
from effect_broker.traces import build


@pytest.fixture
def scoped(tmp_path):
    """A broker with a wildcard capability scoped to the temp directory."""
    canon = os.path.realpath(str(tmp_path))
    b = build()
    task = Task(
        task_id="evidence-task",
        owner="User",
        ceiling=Capability(
            owner="User",
            holder="evidence-tool",
            right="*",
            target="*",
            scope=frozenset({f"file://{canon}"}),
            expiry=float("inf"),
            nonce="evidence-cap",
        ),
    )
    b.register_task(task)
    b.capabilities["evidence-cap"] = Capability(
        owner="User",
        holder="evidence-tool",
        right="*",
        target="*",
        scope=frozenset({f"file://{canon}"}),
        expiry=float("inf"),
        nonce="evidence-cap",
    )
    return b, canon, task


class TestWriteEvidence:
    """A write's evidence must describe what landed on disk."""

    def test_successful_write_records_committed_evidence(self, scoped) -> None:
        b, tmpdir, task = scoped
        path = os.path.join(tmpdir, "out.txt")
        shim = RealFileShim(b, task_id="evidence-task", tool_name="evidence-tool")

        shim.write(path, b"hello")

        ops = shim.get_ops()
        assert ops, "the write must be logged"
        nonce = ops[-1].nonce
        ev = b.ledger.evidence_for("evidence-task", nonce)

        assert ev is not None, "a completed write must leave evidence behind"
        assert ev.outcome == "committed"
        assert ev.observed_bytes == 5, "evidence must report the size that landed"
        assert ev.transport_response is not None
        assert ev.observed_targets, "a commit claim needs an observed target"
        assert ev.source.startswith("shim_real.write")

    def test_evidence_size_is_read_from_disk_not_from_the_request(self, scoped) -> None:
        """The size must come from stat(), so a short write cannot look complete."""
        b, tmpdir, task = scoped
        path = os.path.join(tmpdir, "sized.txt")
        shim = RealFileShim(b, task_id="evidence-task", tool_name="evidence-tool")

        shim.write(path, b"0123456789")

        nonce = shim.get_ops()[-1].nonce
        ev = b.ledger.evidence_for("evidence-task", nonce)
        assert ev is not None
        assert ev.observed_bytes == os.stat(path).st_size == 10

    def test_verified_commit_is_backed_by_evidence(self, scoped) -> None:
        """The end-to-end claim of P4-1: COMMITTED here means the file exists."""
        b, tmpdir, task = scoped
        path = os.path.join(tmpdir, "proof.txt")
        shim = RealFileShim(b, task_id="evidence-task", tool_name="evidence-tool")

        shim.write(path, b"x")

        nonce = shim.get_ops()[-1].nonce
        assert b.ledger.verify("evidence-task", nonce) is LedgerVerdict.CONFIRMED_COMMITTED
        assert os.path.exists(path)


class TestDeleteEvidence:
    """A delete is only committed if the target is actually gone."""

    def test_delete_records_committed_evidence_when_target_is_gone(self, scoped) -> None:
        b, tmpdir, task = scoped
        path = os.path.join(tmpdir, "doomed.txt")
        with open(path, "w") as f:
            f.write("bye")

        shim = RealFileShim(b, task_id="evidence-task", tool_name="evidence-tool")
        shim.delete(path)

        nonce = shim.get_ops()[-1].nonce
        ev = b.ledger.evidence_for("evidence-task", nonce)
        assert ev is not None
        assert ev.outcome == "committed"
        assert ev.transport_response == "gone"
        assert not os.path.exists(path)


class TestFailureEvidence:
    """A failed syscall must leave UNKNOWN evidence, never a silent commits."""

    def test_missing_file_read_records_unknown_evidence(self, scoped) -> None:
        b, tmpdir, task = scoped
        path = os.path.join(tmpdir, "absent.txt")
        shim = RealFileShim(b, task_id="evidence-task", tool_name="evidence-tool")

        with pytest.raises(OSError):
            shim.read(path)

        # The effect was authorized, so the ledger knows the nonce; it must not
        # report a commit for a read whose syscall raised.
        nonces = list(b.ledger._authorizations)
        assert nonces, "the gate must have authorized this read"
        task_id, nonce = nonces[-1]
        ev = b.ledger.evidence_for(task_id, nonce)
        assert ev is not None, "a raised syscall must still leave evidence"
        assert ev.outcome == "unknown"
        assert ev.transport_response is None, "unknown evidence must not claim a reply"

    def test_failure_evidence_is_not_a_committed_verdict(self, scoped) -> None:
        b, tmpdir, task = scoped
        path = os.path.join(tmpdir, "absent2.txt")
        shim = RealFileShim(b, task_id="evidence-task", tool_name="evidence-tool")

        with pytest.raises(OSError):
            shim.read(path)

        task_id, nonce = list(b.ledger._authorizations)[-1]
        assert b.ledger.verify(task_id, nonce) is not LedgerVerdict.CONFIRMED_COMMITTED


class TestEvidenceOutranksObservation:
    """A claim without backing must lose to evidence that contradicts it."""

    def test_observation_without_committed_evidence_is_not_confirmed(self) -> None:
        from effect_broker.ledger import IndependentEffectLedger, UnknownLedgerResult

        led = IndependentEffectLedger()
        led.record_authorization("t", "n", frozenset({"file://a"}), source="executor.execute")
        led.record_observation("t", "n", frozenset({"file://a"}), source="executor.apply")
        # Evidence says the syscall failed; the observation claims it applied.
        led.record_evidence(
            "t",
            "n",
            EffectEvidence(
                effect_id="n",
                outcome="unknown",
                source="shim_real.write.syscall_error:OSError",
                window=(0.0, 1.0),
                observed_targets=frozenset(),
            ),
        )

        verdict = led.verify("t", "n")
        assert isinstance(verdict, UnknownLedgerResult), (
            "evidence must be able to veto a bare observation claim"
        )
        assert "evidence_contradicts_observation" in verdict.reason

    def test_committed_evidence_still_confirms(self) -> None:
        from effect_broker.ledger import IndependentEffectLedger

        led = IndependentEffectLedger()
        led.record_authorization("t", "n", frozenset({"file://a"}), source="executor.execute")
        led.record_observation("t", "n", frozenset({"file://a"}), source="executor.apply")
        led.record_evidence(
            "t",
            "n",
            EffectEvidence(
                effect_id="n",
                outcome="committed",
                source="shim_real.write.syscall",
                window=(0.0, 1.0),
                observed_targets=frozenset({"file://a"}),
                transport_response="fsize=5",
                observed_bytes=5,
            ),
        )
        assert led.verify("t", "n") is LedgerVerdict.CONFIRMED_COMMITTED


class TestEvidenceTypeCannotBeForged:
    """The type itself must reject an unbacked commit claim."""

    def test_committed_without_response_is_rejected(self) -> None:
        with pytest.raises(EvidenceInsufficient):
            EffectEvidence(
                effect_id="n",
                outcome="committed",
                source="somewhere",
                window=(0.0, 1.0),
                observed_targets=frozenset({"file://a"}),
            )

    def test_committed_without_targets_is_rejected(self) -> None:
        with pytest.raises(EvidenceInsufficient):
            EffectEvidence(
                effect_id="n",
                outcome="committed",
                source="somewhere",
                window=(0.0, 1.0),
                transport_response="250 OK",
            )

    def test_empty_source_is_rejected(self) -> None:
        with pytest.raises(EvidenceInsufficient):
            EffectEvidence(
                effect_id="n",
                outcome="unknown",
                source="   ",
                window=(0.0, 1.0),
            )
