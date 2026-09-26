"""Regression: FlowOK declass/endorse must be broker-recorded grants

These tests verify the "Flow regression" requirement:
  - FlowOK blocks confidentiality/integrity violations (no exceptions)
  - A broker-recorded LabelException is REQUIRED for declass/endorse
  - The LLM may only REQUEST, never perform

Tests use the broker's default task (created automatically) so that
Auth passes for nonces from build().
"""

from __future__ import annotations

import pytest

from effect_broker.lattice import Confidentiality, Integrity
from effect_broker.model import Capability, Commit, Data, Effect, EffectTarget, LabelException, Task
from effect_broker.traces import build


def _make_permissive_task(task_id: str) -> Task:
    """Create a task with a ceiling that dominates all rights.

    Note: ceiling.right = "*" means "all rights allowed" (dominates all).
    With the broker.py fix, "*" also makes NoAmp skip the right check.
    """
    ceiling = Capability(
        owner="User",
        holder="EffectBroker",
        right="*",
        target="*",
        scope=frozenset({"*"}),
        expiry=float("inf"),
        nonce=f"ceiling-{task_id}",
    )
    return Task(task_id=task_id, owner="User", ceiling=ceiling)


def _effect(
    etype: str,
    target: str,
    nonce: str,
    provenance: tuple[Data, ...],
    label_exceptions: tuple[LabelException, ...] = (),
) -> Effect:
    return Effect(
        etype=etype,
        target=target,
        metadata={},
        provenance=provenance,
        capability_nonce=nonce,
        delegation_chain=(),
        label_exceptions=label_exceptions,
    )


def _grant_for(broker, etype: str, target: str, expiry: float = 100.0,
               additional: frozenset[str] | None = None) -> tuple[str, Task]:
    """Grant an approval for (etype, target) and return (nonce, task).

    grant_approval creates a capability with the exact target, bypassing
    the mismatch that occurs with build()-seeded capabilities (which are
    scoped to specific targets from the trace setup).

    Pass `additional` to also include BCC recipients in the binding's
    approved target set. Without it, additional recipients added at commit
    time will be blocked by ApprovalBinding.
    """
    task = _make_permissive_task("default")
    broker.register_task(task)
    if additional is None:
        additional = frozenset()
    request = Effect(
        etype=etype,
        target=target,
        metadata={},
        provenance=(Data("__request__", Confidentiality.INTERNAL, Integrity.USER),),
        capability_nonce=f"r-{etype}:Agent:EffectBroker",
        delegation_chain=(),
        known_targets=EffectTarget(primary=target, additional=additional),
    )
    nonce = broker.grant_approval(request, expiry=expiry, task_id="default")
    return nonce, task


class TestFlowDeclassRegression:
    """Declassification requires a broker-recorded LabelException."""

    def test_read_confidential_file_is_allowed(self) -> None:
        """Read of CONFIDENTIAL file is always ALLOWED — reads are inputs, not outputs.

        Reads pull data INTO the session. Blocking reads of confidential files
        would make the system unusable. The read→send attack is handled by
        SESSION TAINT (FlowOK blocks send after CONFIDENTIAL read unless declass).

        This test verifies that check_flow() only applies confidentiality checks
        to OUTPUT effects (write/send/delete/network), not inputs (read).
        """
        broker = build()
        nonce, task = _grant_for(broker, "read", "file:///secrets")

        high_conf = _effect(
            etype="read",
            target="file:///secrets",
            nonce=nonce,
            provenance=(Data("secret", Confidentiality.CONFIDENTIAL, Integrity.USER),),
        )
        allow, evidence = broker.commit(Commit(high_conf, task))

        # READ is always ALLOWED — reads are inputs, not outputs.
        # The read→send amplification is handled by session taint.
        assert allow is True, (
            f"Reading a CONFIDENTIAL file should ALLOW (read is input). Evidence: {evidence}"
        )

    def test_write_confidential_content_blocked_without_declass(self) -> None:
        """Write of CONFIDENTIAL provenance is BLOCKed by FlowOK (output effect).

        This is the REAL confidentiality leak: writing confidential data to
        an output (file/send) without declass. Reads are inputs (always allowed);
        writes are outputs (require declass for high-sensitivity data).
        """
        broker = build()
        nonce, task = _grant_for(broker, "write", "file:///output")

        conf_write = _effect(
            etype="write",
            target="file:///output",
            nonce=nonce,
            provenance=(Data("secret", Confidentiality.CONFIDENTIAL, Integrity.USER),),
        )
        allow, evidence = broker.commit(Commit(conf_write, task))

        assert allow is False, (
            "Write with CONFIDENTIAL provenance should be BLOCKed by FlowOK"
        )
        assert evidence["primary_blocker"] == "FlowOK"
        assert "conf-leak" in evidence["predicates"]["FlowOK"]
        assert len(broker.store.effects_log) == 0

    def test_declass_allows_write_of_confidential_content(self) -> None:
        """Broker-recorded declass: FlowOK ALLOWs write with CONFIDENTIAL provenance.

        Note: broker.grant_label_exception() also clears session taint, so the
        write→send chain is unblocked after declass.
        """
        broker = build()
        nonce, task = _grant_for(broker, "write", "file:///output")

        declass = LabelException(
            kind="declass",
            match_target="file:///output",
            from_label=Confidentiality.CONFIDENTIAL.name,
            to_label=Confidentiality.INTERNAL.name,
            granted_by="User",
            nonce="declass-output",
        )
        broker.grant_label_exception(declass)

        effect = _effect(
            etype="write",
            target="file:///output",
            nonce=nonce,
            provenance=(Data("secret", Confidentiality.CONFIDENTIAL, Integrity.USER),),
            label_exceptions=(declass,),
        )
        allow, evidence = broker.commit(Commit(effect, task))

        assert allow is True, (
            f"FlowOK should ALLOW with broker-recorded declass. Evidence: {evidence}"
        )
        assert len(broker.store.effects_log) == 1

    def test_unrecorded_declass_blocked_for_output_effect(self) -> None:
        """LLM-requested declass (not recorded by broker): FlowOK BLOCKs output effects.

        Reads are always allowed (inputs). For output effects (write/send), a
        declass MUST be broker-recorded. LLM requests alone do not authorize
        declass — only broker.grant_label_exception() does.
        """
        broker = build()
        nonce, task = _grant_for(broker, "write", "file:///output")

        # LLM builds a declass request but broker does NOT record it
        declass_request = LabelException(
            kind="declass",
            match_target="file:///output",
            nonce="declass-unrecorded",
            from_label=Confidentiality.CONFIDENTIAL.name,
            to_label=Confidentiality.INTERNAL.name,
            granted_by="User",
        )

        effect = _effect(
            etype="write",
            target="file:///output",
            nonce=nonce,
            provenance=(Data("secret", Confidentiality.CONFIDENTIAL, Integrity.USER),),
            label_exceptions=(declass_request,),  # LLM "requested" this, but broker didn't record
        )
        allow, evidence = broker.commit(Commit(effect, task))

        assert allow is False, "Unrecorded declass should BLOCK output effects"
        assert evidence["primary_blocker"] == "FlowOK"

    def test_duplicate_declass_grant_raises(self) -> None:
        """The same declass nonce cannot be registered twice."""
        broker = build()
        declass = LabelException(
            kind="declass",
            match_target="*",
            nonce="unique-declass",
            from_label=Confidentiality.CONFIDENTIAL.name,
            to_label=Confidentiality.INTERNAL.name,
            granted_by="User",
        )
        broker.grant_label_exception(declass)
        with pytest.raises(ValueError, match="duplicate"):
            broker.grant_label_exception(declass)


class TestFlowEndorseRegression:
    """Endorsement requires a broker-recorded LabelException."""

    def test_flow_blocks_low_integrity_without_endorsement(self) -> None:
        """Low-integrity provenance in high-integrity send: FlowOK BLOCKs."""
        broker = build()
        nonce, task = _grant_for(broker, "send", "internal@corp.com")

        effect = _effect(
            etype="send",
            target="internal@corp.com",
            nonce=nonce,
            provenance=(Data("web", Confidentiality.PUBLIC, Integrity.UNTRUSTED),),
        )
        allow, evidence = broker.commit(Commit(effect, task))

        assert allow is False
        assert evidence["primary_blocker"] == "FlowOK"
        assert "low-integrity" in evidence["predicates"]["FlowOK"]
        assert len(broker.store.effects_log) == 0

    def test_flow_allows_low_integrity_with_broker_endorse(self) -> None:
        """Broker-recorded endorse: FlowOK ALLOWs."""
        broker = build()
        nonce, task = _grant_for(broker, "send", "internal@corp.com")

        endorse = LabelException(
            kind="endorse",
            match_target="*",
            nonce="endorse-web",
            from_label=Integrity.UNTRUSTED.name,
            to_label=Integrity.USER.name,
            granted_by="User",
        )
        broker.grant_label_exception(endorse)

        effect = _effect(
            etype="send",
            target="internal@corp.com",
            nonce=nonce,
            provenance=(Data("web", Confidentiality.PUBLIC, Integrity.UNTRUSTED),),
            label_exceptions=(endorse,),
        )
        allow, evidence = broker.commit(Commit(effect, task))

        assert allow is True, (
            f"FlowOK should ALLOW with broker-recorded endorse. Evidence: {evidence}"
        )
        assert len(broker.store.effects_log) == 1

    def test_declass_does_not_cover_integrity_violation(self) -> None:
        """A declass grant does NOT also satisfy an integrity violation."""
        broker = build()
        nonce, task = _grant_for(broker, "send", "internal@corp.com")

        declass = LabelException(
            kind="declass",
            match_target="internal@corp.com",
            nonce="declass-both",
            from_label=Confidentiality.CONFIDENTIAL.name,
            to_label=Confidentiality.INTERNAL.name,
            granted_by="User",
        )
        broker.grant_label_exception(declass)

        # Datum violates confidentiality AND integrity
        effect = _effect(
            etype="send",
            target="internal@corp.com",
            nonce=nonce,
            provenance=(Data("bad", Confidentiality.CONFIDENTIAL, Integrity.UNTRUSTED),),
            label_exceptions=(declass,),
        )
        allow, evidence = broker.commit(Commit(effect, task))

        assert allow is False, "Declass alone does not cover integrity violation"
        assert "low-integrity" in evidence["predicates"]["FlowOK"]


class TestFlowDeclassExactIdentity:
    """Declass/endorse grants use exact effect identity matching.

    A grant for (target=A) does NOT authorize (target=A, BCC=B) unless
    additional_targets explicitly includes B. A grant for send does NOT
    authorize write unless etype matches.
    """

    def test_declass_for_primary_only_does_not_cover_bcc(self) -> None:
        """Grant for 'send to internal' does NOT cover 'send to internal + BCC external'."""
        broker = build()
        nonce, task = _grant_for(broker, "send", "internal@corp.com")

        # Grant for PRIMARY target only (no additional_targets)
        declass = LabelException(
            kind="declass",
            match_target="internal@corp.com",
            from_label=Confidentiality.CONFIDENTIAL.name,
            to_label=Confidentiality.INTERNAL.name,
            granted_by="User",
            nonce="declass-primary-only",
        )
        broker.grant_label_exception(declass)

        # Effect with BCC to external domain — NOT covered by grant
        effect = _effect(
            etype="send",
            target="internal@corp.com",
            nonce=nonce,
            provenance=(
                Data("secret", Confidentiality.CONFIDENTIAL, Integrity.USER),
            ),
            label_exceptions=(declass,),
        )
        # Simulate BCC via known_targets
        from effect_broker.model import EffectTarget

        effect = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={},
            provenance=(Data("secret", Confidentiality.CONFIDENTIAL, Integrity.USER),),
            capability_nonce=nonce,
            delegation_chain=(),
            label_exceptions=(declass,),
            known_targets=EffectTarget(
                primary="internal@corp.com",
                additional=frozenset({"external@attacker.com"}),
            ),
        )
        commit = Commit(effect, task)
        allow, evidence = broker.commit(commit)

        # Should BLOCK: grant covers only primary, NOT the extra BCC target
        assert allow is False
        assert evidence["primary_blocker"] == "FlowOK"
        assert "conf-leak" in evidence["predicates"]["FlowOK"]

    def test_declass_for_target_plus_bcc_covers_bcc(self) -> None:
        """Grant with additional_targets explicitly includes BCC → covers FlowOK.

        Uses an INTERNAL domain BCC so NoAmp passes (capability scope = internal).
        ApprovalBinding also covers the BCC recipient — must be in grant's
        approved target set. Pass additional={team@...} to _grant_for so the
        ApprovedRequest binding tracks it.
        """
        broker = build()
        bcc_recipient = "team@internal.corp.com"
        nonce, task = _grant_for(
            broker, "send", "internal@corp.com",
            additional=frozenset({bcc_recipient}),
        )

        # Grant for primary + the BCC recipient (same internal domain → passes NoAmp)
        declass = LabelException(
            kind="declass",
            match_target="internal@corp.com",
            additional_targets=frozenset({"team@internal.corp.com"}),
            from_label=Confidentiality.CONFIDENTIAL.name,
            to_label=Confidentiality.INTERNAL.name,
            granted_by="User",
            nonce="declass-with-bcc",
        )
        broker.grant_label_exception(declass)

        from effect_broker.model import EffectTarget

        effect = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={},
            provenance=(Data("secret", Confidentiality.CONFIDENTIAL, Integrity.USER),),
            capability_nonce=nonce,
            delegation_chain=(),
            label_exceptions=(declass,),
            known_targets=EffectTarget(
                primary="internal@corp.com",
                additional=frozenset({"team@internal.corp.com"}),
            ),
        )
        commit = Commit(effect, task)
        allow, evidence = broker.commit(commit)

        # Should ALLOW: additional_targets explicitly includes BCC,
        # BCC is same domain (passes NoAmp), FlowOK covered by grant
        assert allow is True, (
            f"Grant with additional_targets should ALLOW. Evidence: {evidence}"
        )

    def test_declass_with_etype_matching(self) -> None:
        """Grant with etype='send' does NOT cover etype='write'."""
        broker = build()
        nonce_write, task_write = _grant_for(broker, "write", "file:///logs")
        nonce_send, task_send = _grant_for(broker, "send", "internal@corp.com")

        # Grant for CONFIDENTIAL data in SENDING only
        declass = LabelException(
            kind="declass",
            match_target="*",
            etype="send",  # Only applies to send effects
            from_label=Confidentiality.CONFIDENTIAL.name,
            to_label=Confidentiality.INTERNAL.name,
            granted_by="User",
            nonce="declass-send-only",
        )
        broker.grant_label_exception(declass)

        # Try to write CONFIDENTIAL data to a file (should BLOCK)
        write_effect = _effect(
            etype="write",
            target="file:///logs",
            nonce=nonce_write,
            provenance=(Data("secret", Confidentiality.CONFIDENTIAL, Integrity.USER),),
            label_exceptions=(declass,),
        )
        allow_write, ev_write = broker.commit(Commit(write_effect, task_write))
        assert allow_write is False, "Declass with etype='send' should NOT cover write"
        assert ev_write["primary_blocker"] == "FlowOK"

        # Send CONFIDENTIAL data (should ALLOW — etype matches)
        send_effect = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={},
            provenance=(Data("secret", Confidentiality.CONFIDENTIAL, Integrity.USER),),
            capability_nonce=nonce_send,
            delegation_chain=(),
            label_exceptions=(declass,),
        )
        allow_send, ev_send = broker.commit(Commit(send_effect, task_send))
        assert allow_send is True, (
            f"Declass with etype='send' should cover send. Evidence: {ev_send}"
        )

    def test_matches_effect_wildcard_target(self) -> None:
        """match_target='*' matches any effect's complete_targets()."""
        from effect_broker.model import EffectTarget

        grant = LabelException(
            kind="declass",
            match_target="*",
            from_label=Confidentiality.CONFIDENTIAL.name,
            to_label=Confidentiality.INTERNAL.name,
            granted_by="User",
            nonce="any-target",
        )

        # Simple target
        e1 = _effect("send", "internal@corp.com", "any", ())
        assert grant.matches_effect(e1)

        # With additional BCC
        e2 = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={},
            provenance=(),
            capability_nonce="any",
            delegation_chain=(),
            known_targets=EffectTarget(
                primary="internal@corp.com",
                additional=frozenset({"bcc@corp.com"}),
            ),
        )
        assert grant.matches_effect(e2)


class TestFlowBoundaryTaskScoped:
    """FlowOK uses the task's flow_boundary, not a global lattice."""

    def test_different_tasks_have_different_flow_boundaries(self) -> None:
        """Task A allows CONFIDENTIAL output; Task B blocks it (different boundaries).

        FlowOK applies to OUTPUT effects. Task A (flow_boundary=CONFIDENTIAL) allows
        write/send with CONFIDENTIAL provenance. Task B (flow_boundary=INTERNAL)
        blocks write/send with CONFIDENTIAL provenance (conf-leak).

        Reads are always allowed regardless of flow_boundary — they're inputs,
        not outputs.
        """
        from effect_broker.model import Capability, Task

        broker = build()

        # Task with wide flow boundary (accepts CONFIDENTIAL data as output)
        wide_ceiling = Capability(
            owner="User",
            holder="EffectBroker",
            right="write",
            target="*",
            scope=frozenset({"*"}),
            expiry=float("inf"),
            nonce="wide-ceiling",
        )
        broker.grant_root(wide_ceiling)  # Register the capability in broker's store
        task_wide = Task(
            task_id="task-wide",
            owner="User",
            ceiling=wide_ceiling,
            flow_boundary=(Confidentiality.CONFIDENTIAL, Integrity.USER),
        )
        broker.register_task(task_wide)

        # Task with narrow flow boundary (rejects CONFIDENTIAL data as output)
        narrow_ceiling = Capability(
            owner="User",
            holder="EffectBroker",
            right="write",
            target="*",
            scope=frozenset({"*"}),
            expiry=float("inf"),
            nonce="narrow-ceiling",
        )
        broker.grant_root(narrow_ceiling)  # Register the capability in broker's store
        task_narrow = Task(
            task_id="task-narrow",
            owner="User",
            ceiling=narrow_ceiling,
            flow_boundary=(Confidentiality.INTERNAL, Integrity.USER),
        )
        broker.register_task(task_narrow)

        # Same write effect with CONFIDENTIAL provenance
        conf_effect = _effect(
            etype="write",
            target="file:///logs",
            nonce="narrow-ceiling",  # Use narrow-ceiling nonce
            provenance=(Data("secret", Confidentiality.CONFIDENTIAL, Integrity.USER),),
        )

        # Wide task: ALLOW (CONFIDENTIAL within its flow_boundary)
        commit_wide = Commit(conf_effect, task_wide)
        allow_wide, _ = broker.commit(commit_wide)
        assert allow_wide is True, "Wide-flow task should allow CONFIDENTIAL output"

        # Narrow task: BLOCK (CONFIDENTIAL exceeds its flow_boundary)
        commit_narrow = Commit(conf_effect, task_narrow)
        allow_narrow, ev_narrow = broker.commit(commit_narrow)
        assert allow_narrow is False, (
            f"Narrow-flow task should block CONFIDENTIAL output. Evidence: {ev_narrow}"
        )
        assert ev_narrow["primary_blocker"] == "FlowOK"
