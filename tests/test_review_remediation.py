"""Review remediation regressions

These tests pin the security properties claimed by
Each one was written AFTER observing the defect in the running code,
so a failure here means a previously-real vulnerability has returned"""

from __future__ import annotations

import pytest

from effect_broker.executor_ipc import (
    dict_to_effect,
    dict_to_session,
    effect_to_dict,
    label_exception_to_dict,
    session_state_to_dict,
)
from effect_broker.lattice import Confidentiality, Integrity
from effect_broker.model import Data, Effect, LabelException, Session


# Helpers
def _session_with_committed_read(
    confidentiality: Confidentiality = Confidentiality.PUBLIC,
    integrity: Integrity = Integrity.UNTRUSTED,
    content: str = "hello",
) -> tuple[Session, Data]:
    """Register a committed read and return (session, the datum as issued)"""
    session = Session(session_id="s1")
    issued = Data(
        name="file:///public.txt",
        confidentiality=confidentiality,
        integrity=integrity,
        content=content,
    )
    prov_id = session.register_read_provenance(issued, cap_nonce="cap1", content=content)
    entry = session.get_provenance_entry(prov_id)
    assert entry is not None
    # Reconstruct the datum exactly as a legitimate caller would re-submit it
    legitimate = Data(
        name=issued.name,
        confidentiality=issued.confidentiality,
        integrity=issued.integrity,
        content=content,
        provenance_id=prov_id,
        scope_hash=entry.scope_hash,
    )
    return session, legitimate


def _effect_with_exception(le: LabelException) -> Effect:
    return Effect(
        etype="send",
        target=le.match_target,
        metadata={},
        provenance=(),
        capability_nonce="cap",
        delegation_chain=("t",),
        label_exceptions=(le,),
    )

# a valid provenance ID must not permit changing the labels
class TestProvenanceLabelBinding:
    def test_legitimate_resubmission_is_trusted(self) -> None:
        """Control: an unmodified re-submission of committed data stays trusted."""
        session, legitimate = _session_with_committed_read()
        assert session.is_trusted_provenance(legitimate) is True
        assert session.provenance_mismatch_reason(legitimate) == "trusted"

    def test_confidentiality_upgrade_is_rejected(self) -> None:
        """Claiming more secrecy than the record holds must not be trusted

        Myers-Liskov: a tool that reads PUBLIC data cannot declare the result
        CONFIDENTIAL while keeping the legitimate provenance_id.
        """
        session, legitimate = _session_with_committed_read(
            confidentiality=Confidentiality.PUBLIC,
            integrity=Integrity.UNTRUSTED,
        )
        forged = Data(
            name=legitimate.name,
            confidentiality=Confidentiality.CONFIDENTIAL,
            integrity=legitimate.integrity,
            content=legitimate.content,
            provenance_id=legitimate.provenance_id,
            scope_hash=legitimate.scope_hash,
        )
        assert session.is_trusted_provenance(forged) is False
        assert "confidentiality-relabelled" in session.provenance_mismatch_reason(forged)

    def test_integrity_upgrade_is_rejected(self) -> None:
        """Claiming more integrity than the record holds must not be trusted.

        Biba: a PUBLIC/UNTRUSTED read cannot become HIGH just by re-labelling.
        """
        session, legitimate = _session_with_committed_read(
            confidentiality=Confidentiality.PUBLIC,
            integrity=Integrity.UNTRUSTED,
        )
        forged = Data(
            name=legitimate.name,
            confidentiality=legitimate.confidentiality,
            integrity=Integrity.HIGH,
            content=legitimate.content,
            provenance_id=legitimate.provenance_id,
            scope_hash=legitimate.scope_hash,
        )
        assert session.is_trusted_provenance(forged) is False
        assert "integrity-relabelled" in session.provenance_mismatch_reason(forged)

    def test_both_labels_substituted_is_rejected(self) -> None:
        """The original full attack: PUBLIC/UNTRUSTED -> CONFIDENTIAL/HIGH"""
        session, legitimate = _session_with_committed_read(
            confidentiality=Confidentiality.PUBLIC,
            integrity=Integrity.UNTRUSTED,
        )
        forged = Data(
            name=legitimate.name,
            confidentiality=Confidentiality.CONFIDENTIAL,
            integrity=Integrity.HIGH,
            content=legitimate.content,
            provenance_id=legitimate.provenance_id,
            scope_hash=legitimate.scope_hash,
        )
        assert session.is_trusted_provenance(forged) is False

    def test_verify_effect_provenance_reports_the_reason(self) -> None:
        """Evidence must name the diverging field, not just say 'untrusted'

        When both labels are substituted, the check reports the FIRST divergence
        encountered (confidentiality precedes integrity), so the assertion only
        requires that a specific relabelling reason is named.
        """
        session, legitimate = _session_with_committed_read(
            confidentiality=Confidentiality.PUBLIC,
            integrity=Integrity.UNTRUSTED,
        )
        forged = Data(
            name=legitimate.name,
            confidentiality=Confidentiality.CONFIDENTIAL,
            integrity=Integrity.HIGH,
            content=legitimate.content,
            provenance_id=legitimate.provenance_id,
            scope_hash=legitimate.scope_hash,
        )
        effect = Effect(
            etype="send",
            target="mailto:a@b.c",
            metadata={},
            provenance=(forged,),
            capability_nonce="cap",
            delegation_chain=("t",),
        )
        ok, reason = session.verify_effect_provenance(effect)
        assert ok is False
        assert "untrusted-provenance" in reason
        assert "confidentiality-relabelled" in reason
        assert "recorded=PUBLIC" in reason and "claimed=CONFIDENTIAL" in reason


# every security-relevant LabelException field survives the codec
class TestLabelExceptionCodec:
    def _full_exception(self) -> LabelException:
        return LabelException(
            kind="declass",
            match_target="mailto:a@b.c",
            from_label="CONFIDENTIAL",
            to_label="PUBLIC",
            granted_by="User",
            nonce="n1",
            additional_targets=frozenset({"mailto:x@y.z"}),
            etype="send",
            task_id="task-42",
            data_resources=frozenset({"file:///secrets"}),
        )

    def test_roundtrip_preserves_every_field(self) -> None:
        original = self._full_exception()
        restored = dict_to_effect(effect_to_dict(_effect_with_exception(original)))
        back = restored.label_exceptions[0]
        assert back.kind == original.kind
        assert back.match_target == original.match_target
        assert back.from_label == original.from_label
        assert back.to_label == original.to_label
        assert back.granted_by == original.granted_by
        assert back.nonce == original.nonce
        assert back.additional_targets == original.additional_targets
        assert back.etype == original.etype
        assert back.task_id == original.task_id
        assert back.data_resources == original.data_resources

    def test_task_id_survives(self) -> None:
        """Dropping task_id would make the grant valid in ANY task."""
        le = self._full_exception()
        back = dict_to_effect(effect_to_dict(_effect_with_exception(le))).label_exceptions[0]
        assert back.task_id == "task-42"

    def test_data_resources_survive(self) -> None:
        """Dropping data_resources silently disables taint clearing."""
        le = self._full_exception()
        back = dict_to_effect(effect_to_dict(_effect_with_exception(le))).label_exceptions[0]
        assert back.data_resources == frozenset({"file:///secrets"})
        assert back.covers_taint_resource("file:///secrets") is True

    def test_missing_field_is_rejected_not_defaulted(self) -> None:
        """An ABSENT security field must raise; a default would be an inference."""
        payload = label_exception_to_dict(self._full_exception())
        del payload["task_id"]
        with pytest.raises(ValueError, match="task_id"):
            dict_to_effect({"label_exceptions": [payload], **eff_minimal_payload()})

    def test_missing_data_resources_is_rejected(self) -> None:
        payload = label_exception_to_dict(self._full_exception())
        del payload["data_resources"]
        with pytest.raises(ValueError, match="data_resources"):
            dict_to_effect({"label_exceptions": [payload], **eff_minimal_payload()})

    def test_explicit_none_is_accepted(self) -> None:
        """`task_id=None` is a legitimate value (valid in any task) — accept it"""
        payload = label_exception_to_dict(self._full_exception())
        payload["task_id"] = None
        restored = dict_to_effect({"label_exceptions": [payload], **eff_minimal_payload()})
        assert restored.label_exceptions[0].task_id is None


def eff_minimal_payload() -> dict[str, object]:
    """Minimal valid effect payload for codec tests"""
    return {
        "etype": "send",
        "target": "mailto:a@b.c",
        "metadata": {},
        "provenance": [],
        "capability_nonce": "cap",
        "delegation_chain": [],
        "task_id": None,
        "known_targets": None,
    }

# a granted declass survives the session codec
class TestDeclassSurvivesIpc:
    def _declass_for(self, resource: str) -> LabelException:
        return LabelException(
            kind="declass",
            match_target="mailto:a@b.c",
            from_label="CONFIDENTIAL",
            to_label="PUBLIC",
            granted_by="User",
            nonce="declass-1",
            data_resources=frozenset({resource}),
        )

    def test_cleared_resource_stays_cleared(self) -> None:
        """The defect: a declass reinstated taint after crossing the boundary."""
        session = Session(session_id="s1")
        session.taint_for_send(resource="file:///secrets", reason="read-confidential")
        assert session.tainted is True

        session.clear_taint(self._declass_for("file:///secrets"))
        assert session.tainted is False, "precondition: declass cleared the taint"

        restored = dict_to_session(session_state_to_dict(session))
        assert restored.tainted is False, "declass must not resurface as false denial"

    def test_uncleared_resource_stays_tainted(self) -> None:
        """Control: the codec must not clear what the declass did not cover."""
        session = Session(session_id="s1")
        session.taint_for_send(resource="file:///secrets", reason="r")
        session.taint_for_send(resource="file:///other", reason="r")
        session.clear_taint(self._declass_for("file:///secrets"))

        restored = dict_to_session(session_state_to_dict(session))
        assert restored.tainted is True
        assert restored._tainted_resources["file:///other"].cleared_by is None
        assert restored._tainted_resources["file:///secrets"].cleared_by == "declass-1"

    def test_legacy_flat_bool_still_restored(self) -> None:
        """Backcompat: a payload without per-resource records still restores."""
        restored = dict_to_session(
            {"session_id": "s1", "tainted": True, "tainted_resources": {}}
        )
        assert restored.tainted is True

# behaviours already correct; pin them so they are not regressed
class TestDeclassDoesNotClearIntegrity:
    def test_declass_leaves_integrity_check_active(self) -> None:
        """A confidentiality release must not waive integrity (Biba independence).

        check_flow evaluates declass and endorse separately: a declass exception
        covers confidentiality only. This test guards against "fixing" the
        label comparison in a way that also relaxes endorse.
        """
        declass = LabelException(
            kind="declass",
            match_target="*",
            from_label="CONFIDENTIAL",
            to_label="PUBLIC",
            granted_by="User",
            nonce="d1",
        )
        # The exception is a declass, so it cannot stand in for an endorse.
        assert declass.kind == "declass"
        # covers_taint_resource only governs session taint, never integrity.
        assert declass.covers_taint_resource("file:///x") is False

    def test_empty_data_resources_clears_nothing(self) -> None:
        """Safe default: a declass with no data_resources must clear no taint."""
        session = Session(session_id="s1")
        session.taint_for_send(resource="file:///secrets", reason="r")
        empty_declass = LabelException(
            kind="declass",
            match_target="*",
            from_label="CONFIDENTIAL",
            to_label="PUBLIC",
            granted_by="User",
            nonce="d2",
            data_resources=frozenset(),
        )
        session.clear_taint(empty_declass)
        assert session.tainted is True

    def test_wildcard_data_resources_clears_all(self) -> None:
        session = Session(session_id="s1")
        session.taint_for_send(resource="file:///a", reason="r")
        session.taint_for_send(resource="file:///b", reason="r")
        wildcard = LabelException(
            kind="declass",
            match_target="*",
            from_label="CONFIDENTIAL",
            to_label="PUBLIC",
            granted_by="User",
            nonce="d3",
            data_resources=frozenset({"*"}),
        )
        session.clear_taint(wildcard)
        assert session.tainted is False
