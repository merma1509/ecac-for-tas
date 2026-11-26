"""Provenance must be bound to the exact data (content).

Hole: `Session.register_read_provenance` was called with `content=None` for
broker reads, so the entry stored `content_hash=None` and
`is_trusted_provenance` skipped the content check (trust anything). A leaked
provenance_id could then be reused for an arbitrary same-name/label payload.

Fix: the read branch passes `content=read_output.content` so the entry is
content-bound to the exact read output, and `is_trusted_provenance` fails
closed when `content_hash is None`. A forged non-empty body reusing the
provenance_id is rejected; a genuine read-output resubmission stays trusted.
"""

from __future__ import annotations

from effect_broker.lattice import Confidentiality, Integrity
from effect_broker.model import Capability, Commit, Data, Effect, Session
from effect_broker.traces import build

USER = "User"
BROKER = "EffectBroker"


def _cap(nonce: str, right: str, target: str) -> Capability:
    return Capability(
        owner=USER,
        holder=BROKER,
        right=right,
        target=target,
        scope=frozenset({"*"}),
        expiry=float("inf"),
        nonce=nonce,
    )


def _task(broker, task_id: str):
    from effect_broker.model import Task

    ceiling = Capability(
        owner=USER,
        holder=BROKER,
        right="*",
        target="*",
        scope=frozenset({"*"}),
        expiry=float("inf"),
        nonce=f"ceiling-{task_id}",
    )
    task = Task(
        task_id=task_id,
        owner=USER,
        ceiling=ceiling,
        flow_boundary=(Confidentiality.CONFIDENTIAL, Integrity.USER),
    )
    broker.register_task(task)
    return task


class TestProvenanceContentBinding:
    """A provenance_id is a binding to content, not a reusable label."""

    def test_control_entry_now_content_bound(self) -> None:
        """A broker-committed read now records a non-None content_hash."""
        broker = build()
        task = _task(broker, "t-ctl")
        broker.store._unsafe_bootstrap_file(
            "file://notes/public.txt", Confidentiality.PUBLIC
        )
        broker.capabilities["rc-ctl"] = _cap("rc-ctl", "read", "file://notes/public.txt")
        read = Effect(
            etype="read",
            target="file://notes/public.txt",
            metadata={},
            provenance=(),
            capability_nonce="rc-ctl",
            delegation_chain=(BROKER,),
            task_id="t-ctl",
        )
        allow, _ = broker.commit(Commit(read, task))
        assert allow is True, "A plain read should be allowed"
        entry = task.session.get_provenance_entry("read:t-ctl:rc-ctl:1")
        assert entry is not None, "read provenance should be registered"
        assert entry.content_hash is not None, (
            "broker read provenance must be content-bound (content_hash not None)"
        )

    def test_attack_forged_content_reuses_prov_id(self) -> None:
        """Reusing a read's provenance_id on a different (non-empty) payload
        must be rejected — provenance is bound to the exact data.
        """
        broker = build()
        task = _task(broker, "t-ata")
        broker.store._unsafe_bootstrap_file(
            "file://notes/public.txt", Confidentiality.PUBLIC
        )
        broker.capabilities["rc-ata"] = _cap("rc-ata", "read", "file://notes/public.txt")
        read = Effect(
            etype="read",
            target="file://notes/public.txt",
            metadata={},
            provenance=(),
            capability_nonce="rc-ata",
            delegation_chain=(BROKER,),
            task_id="t-ata",
        )
        broker.commit(Commit(read, task))
        entry = task.session.get_provenance_entry("read:t-ata:rc-ata:1")
        assert entry is not None

        # Attacker reuses the legitimate provenance_id + scope_hash but swaps
        # in their own exfil body (same name, same labels).
        forged = Data(
            name=entry.data.name,
            confidentiality=entry.data.confidentiality,
            integrity=entry.data.integrity,
            content="exfil: <steered payload>",
            provenance_id=entry.data.provenance_id,
            scope_hash=entry.scope_hash,
        )
        assert task.session.is_trusted_provenance(forged) is False, (
            "A forged non-empty body reusing the provenance_id must NOT be "
            "trusted; the entry is bound to the exact read output."
        )
        assert "content" in task.session.provenance_mismatch_reason(forged), (
            f"rejection reason should name the content mismatch, got: "
            f"{task.session.provenance_mismatch_reason(forged)!r}"
        )

    def test_legit_read_output_resubmission_trusted(self) -> None:
        """The genuine read output (empty content, matching name/label/scope)
        resubmitted under its own provenance_id is still trusted.
        """
        broker = build()
        task = _task(broker, "t-leg")
        broker.store._unsafe_bootstrap_file(
            "file://notes/public.txt", Confidentiality.PUBLIC
        )
        broker.capabilities["rc-leg"] = _cap("rc-leg", "read", "file://notes/public.txt")
        read = Effect(
            etype="read",
            target="file://notes/public.txt",
            metadata={},
            provenance=(),
            capability_nonce="rc-leg",
            delegation_chain=(BROKER,),
            task_id="t-leg",
        )
        broker.commit(Commit(read, task))
        entry = task.session.get_provenance_entry("read:t-leg:rc-leg:1")
        assert entry is not None

        # A write that carries the read output verbatim (content="" for a
        # simulated read) under the same provenance_id.
        legit = Data(
            name=entry.data.name,
            confidentiality=entry.data.confidentiality,
            integrity=entry.data.integrity,
            content="",  # the exact (empty) read output, copied verbatim
            provenance_id=entry.data.provenance_id,
            scope_hash=entry.scope_hash,
        )
        assert task.session.is_trusted_provenance(legit) is True, (
            "A genuine verbatim resubmission of the read output must stay "
            "trusted. Reason: " + task.session.provenance_mismatch_reason(legit)
        )

    def test_fail_closed_on_none_content_hash(self) -> None:
        """A provenance entry with content_hash=None (legacy/unbound) is NOT
        trusted — fail closed rather than trust anything.
        """
        session = Session(session_id="s-none")
        from effect_broker.model import ProvenanceEntry

        labeled = Data(
            name="read:x",
            confidentiality=Confidentiality.PUBLIC,
            integrity=Integrity.USER,
            content="",
            provenance_id="p-none",
            scope_hash="sh-none",
        )
        session._read_provenance["p-none"] = ProvenanceEntry(
            data=labeled, scope_hash="sh-none", content_hash=None
        )
        claim = Data(
            name="read:x",
            confidentiality=Confidentiality.PUBLIC,
            integrity=Integrity.USER,
            content="anything",
            provenance_id="p-none",
            scope_hash="sh-none",
        )
        assert session.is_trusted_provenance(claim) is False, (
            "An unbound (content_hash=None) provenance entry must not attest "
            "any body — fail closed."
        )
