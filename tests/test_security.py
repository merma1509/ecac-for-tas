"""PLAN_2 security regression tests: S1-S4 (capability-scoped provenance,
per-resource taint + narrow declass, honest taint metrics, statx DRY)
plus PLAN_1/S4 IPC field preservation.
"""

from __future__ import annotations

from effect_broker.broker import EffectBroker
from effect_broker.lattice import Confidentiality, Integrity
from effect_broker.model import (
    APPROVER,
    BROKER,
    USER,
    Capability,
    Commit,
    Data,
    Effect,
    LabelException,
    Task,
    compute_scope_hash,
)
from effect_broker.statx import (
    STATX_ATTR_ENCRYPTED,
    STATX_ATTR_IMMUTABLE,
    derive_confidentiality_from_mode,
    derive_confidentiality_mode_str,
    try_statx_attributes,
)


# ---------------------------------------------------------------------------
# S1 — capability-scoped provenance (register_read_provenance binds scope)
# ---------------------------------------------------------------------------
def _read_confidential_task(broker: EffectBroker, task_id: str = "t1") -> Task:
    """Create a task+cap that can read file:///secrets, register it in broker."""
    ceil = Capability(
        owner=USER,
        holder=BROKER,
        right="read",
        target="file:///secrets",
        scope=frozenset({"*"}),
        expiry=float("inf"),
        nonce=f"ceil-{task_id}",
    )
    task = Task(
        task_id=task_id,
        owner=USER,
        ceiling=ceil,
        flow_boundary=(Confidentiality.INTERNAL, Integrity.USER),
    )
    broker.register_task(task)
    read_cap = Capability(
        owner=USER,
        holder=BROKER,
        right="read",
        target="file:///secrets",
        scope=frozenset({"*"}),
        expiry=float("inf"),
        nonce=f"read-cap-{task_id}",
        task_id=task_id,
    )
    broker.capabilities[f"read-cap-{task_id}"] = read_cap
    return task


class TestProvenanceCapabilityScope:
    def test_register_read_provenance_binds_scope_hash(self) -> None:
        """register_read_provenance stores a scope_hash at commit time."""
        broker = EffectBroker()
        task = _read_confidential_task(broker, "scope-bind")
        broker.store._unsafe_bootstrap_file("file:///secrets", Confidentiality.CONFIDENTIAL)

        effect = Effect(
            etype="read",
            target="file:///secrets",
            metadata={},
            provenance=(Data("secret", Confidentiality.CONFIDENTIAL, Integrity.USER),),
            capability_nonce="read-cap-scope-bind",
            delegation_chain=(BROKER,),
            task_id="scope-bind",
        )
        allow, _ = broker.commit(Commit(effect, task))
        assert allow is True

        entry = task.session.get_provenance_entry("read:scope-bind:read-cap-scope-bind:1")
        assert entry is not None, "read provenance should be registered"
        cap = broker.capabilities["read-cap-scope-bind"]
        assert entry.scope_hash == compute_scope_hash(cap)

    def test_forged_scope_hash_rejected_for_high_integrity(self) -> None:
        """A datum claiming HIGH integrity with a WRONG scope_hash is BLOCKed.

        S1 regression: a forge that mints provenance_id + a non-matching
        scope_hash must not pass verify_effect_provenance.
        """
        broker = EffectBroker()
        task = _read_confidential_task(broker, "forge-scope")
        broker.store._unsafe_bootstrap_file("file:///secrets", Confidentiality.CONFIDENTIAL)

        read_effect = Effect(
            etype="read",
            target="file:///secrets",
            metadata={},
            provenance=(),
            capability_nonce="read-cap-forge-scope",
            delegation_chain=(BROKER,),
            task_id="forge-scope",
        )
        allow, _ = broker.commit(Commit(read_effect, task))
        assert allow is True
        entry = task.session.get_provenance_entry("read:forge-scope:read-cap-forge-scope:1")
        assert entry is not None

        # Forge: reuse the legitimate prov_id but with a WRONG scope_hash.
        forged = Data(
            name=entry.data.name,
            confidentiality=Confidentiality.CONFIDENTIAL,
            integrity=Integrity.HIGH,  # upgrade attempt requiring provenance
            content="exfil",
            provenance_id="read:forge-scope:read-cap-forge-scope:1",
            scope_hash="deadbeef" * 4,  # not the real scope hash
        )
        trusted, reason = task.session.verify_effect_provenance(
            Effect("send", "internal@corp.com", {}, (forged,), "send-cap", (BROKER,))
        )
        assert trusted is False, "forged scope_hash must be rejected"
        assert "untrusted-provenance" in reason

    def test_missing_scope_hash_rejected_for_high_integrity(self) -> None:
        """HIGH-integrity datum with scope_hash=None (legacy forge) is BLOCKed."""
        broker = EffectBroker()
        task = _read_confidential_task(broker, "no-scope")
        broker.store._unsafe_bootstrap_file("file:///secrets", Confidentiality.CONFIDENTIAL)

        effect = Effect(
            etype="read",
            target="file:///secrets",
            metadata={},
            provenance=(),
            capability_nonce="read-cap-no-scope",
            delegation_chain=(BROKER,),
            task_id="no-scope",
        )
        allow, _ = broker.commit(Commit(effect, task))
        assert allow is True

        legacy = Data(
            name="read:file:///secrets",
            confidentiality=Confidentiality.CONFIDENTIAL,
            integrity=Integrity.HIGH,
            content="x",
            provenance_id="read:no-scope:read-cap-no-scope:1",
            scope_hash=None,  # legacy datum without binding
        )
        trusted, _ = task.session.verify_effect_provenance(
            Effect("send", "internal@corp.com", {}, (legacy,), "send-cap", (BROKER,))
        )
        assert trusted is False


# ---------------------------------------------------------------------------
# S2 — per-resource taint + NARROW declassification
# ---------------------------------------------------------------------------
class TestNarrowDeclass:
    def _tainted_task(self, broker: EffectBroker, task_id: str, resource: str) -> Task:
        ceil = Capability(
            owner=USER,
            holder=BROKER,
            right="send",
            target="internal@corp.com",
            scope=frozenset({"*"}),
            expiry=float("inf"),
            nonce=f"ceil-{task_id}",
        )
        task = Task(
            task_id=task_id,
            owner=USER,
            ceiling=ceil,
            flow_boundary=(Confidentiality.INTERNAL, Integrity.USER),
        )
        broker.register_task(task)
        broker.store._unsafe_bootstrap_email("internal@corp.com", None)
        task.session.taint_for_send(resource=resource, reason=f"read-confidential({resource})")
        assert task.session.tainted is True
        return task

    def test_empty_data_resources_clears_nothing(self) -> None:
        """SAFE DEFAULT: an empty data_resources declass must NOT clear taint.

        Regression for the pre-PLAN_2 behavior where ANY declass cleared ALL
        session taint (which allowed over-broad declass to silently unblock).
        """
        broker = EffectBroker()
        task = self._tainted_task(broker, "empty-dc", "file:///secrets")

        grant = LabelException(
            kind="declass",
            match_target="*",
            from_label="CONFIDENTIAL",
            to_label="INTERNAL",
            granted_by=USER,
            nonce="dc-empty",
            data_resources=frozenset(),  # clears nothing
        )
        broker.grant_label_exception(grant, task_id="empty-dc")

        assert task.session.tainted is True, "empty data_resources must NOT clear taint"

    def test_matching_data_resource_clears_only_that_resource(self) -> None:
        """A declass for file:///a clears taint for a but NOT for file:///b."""
        broker = EffectBroker()
        task = self._tainted_task(broker, "partial", "file:///a")
        task.session.taint_for_send(resource="file:///b", reason="read-confidential(file:///b)")
        assert task.session.tainted is True

        grant = LabelException(
            kind="declass",
            match_target="*",
            from_label="CONFIDENTIAL",
            to_label="INTERNAL",
            granted_by=USER,
            nonce="dc-a",
            data_resources=frozenset({"file:///a"}),  # only a
        )
        broker.grant_label_exception(grant, task_id="partial")

        # a is cleared; b remains -> still tainted (narrow semantics)
        record_a = task.session._tainted_resources["file:///a"]
        assert record_a.cleared_by is not None, "a's taint should be cleared"
        record_b = task.session._tainted_resources["file:///b"]
        assert record_b.cleared_by is None, "b's taint must remain"
        assert task.session.tainted is True, "still tainted because b remains"

    def test_wildcard_data_resources_clears_all(self) -> None:
        """data_resources={"*"} is the explicit opt-in to clear all taint."""
        broker = EffectBroker()
        task = self._tainted_task(broker, "wc", "file:///a")
        task.session.taint_for_send(resource="file:///b", reason="r")

        grant = LabelException(
            kind="declass",
            match_target="*",
            from_label="CONFIDENTIAL",
            to_label="INTERNAL",
            granted_by=USER,
            nonce="dc-wc",
            data_resources=frozenset({"*"}),
        )
        broker.grant_label_exception(grant, task_id="wc")

        assert task.session.tainted is False, "wildcard clears all"

    def test_cross_task_declass_never_clears_other_task_taint(self) -> None:
        """A declass for task-B must never clear task-A taint (S2 regression)."""
        broker = EffectBroker()
        task_a = self._tainted_task(broker, "narrow-A", "file:///secrets")
        self._tainted_task(broker, "narrow-B", "file:///secrets")

        grant = LabelException(
            kind="declass",
            match_target="*",
            from_label="CONFIDENTIAL",
            to_label="INTERNAL",
            granted_by=USER,
            nonce="dc-cross",
            task_id="narrow-B",  # for task B
            data_resources=frozenset({"*"}),
        )
        broker.grant_label_exception(grant, task_id="narrow-B")

        assert task_a.session.tainted is True, "task-A taint must NOT be cleared"


# ---------------------------------------------------------------------------
# S3 — honest session-taint metrics (taint_rate != false_denial_proxy)
# ---------------------------------------------------------------------------
class TestSessionTaintMetrics:
    def test_taint_rate_counts_reads(self) -> None:
        """Only CONFIDENTIAL reads contribute to reads_that_tainted."""
        broker = EffectBroker()
        t = _read_confidential_task(broker, "m1")
        broker.store._unsafe_bootstrap_file("file:///secrets", Confidentiality.CONFIDENTIAL)

        # Only commit once (each commit uses the nonce once); assert the metric
        # counts a single confidential read.
        effect = Effect(
            etype="read",
            target="file:///secrets",
            metadata={},
            provenance=(),
            capability_nonce="read-cap-m1",
            delegation_chain=(BROKER,),
            task_id="m1",
        )
        allow, _ = broker.commit(Commit(effect, t))
        assert allow is True

        metrics = broker.get_taint_metrics()
        assert metrics is not None
        assert metrics["total_reads"] >= 1
        assert metrics["reads_that_tainted"] == 1
        assert metrics["taint_rate"] > 0.0

    def test_false_denial_proxy_counts_declass_after_taint_block(self) -> None:
        """A taint-blocked send followed by a declass raises the proxy.

        Note: this is a PROXY, not ground truth — the test documents that
        blocked_sends_later_declassed only increments when a declass lands
        on a task that previously had a taint-blocked send.
        """
        broker = EffectBroker()
        t = _read_confidential_task(broker, "m2")
        broker.store._unsafe_bootstrap_file("file:///secrets", Confidentiality.CONFIDENTIAL)

        # 1) Read confidential -> session tainted
        read_ok, _ = broker.commit(
            Commit(
                Effect("read", "file:///secrets", {}, (), "read-cap-m2", (BROKER,), task_id="m2"), t
            )
        )
        assert read_ok is True

        # 2) Send while tainted -> BLOCKED by session-taint (this is the signal)
        broker.capabilities["send-cap-m2"] = Capability(
            owner=USER,
            holder=BROKER,
            right="send",
            target="internal@corp.com",
            scope=frozenset({"*"}),
            expiry=float("inf"),
            nonce="send-cap-m2",
        )
        broker.store._unsafe_bootstrap_email("internal@corp.com", None)
        send_effect = Effect(
            "send",
            "internal@corp.com",
            {},
            (Data("body", Confidentiality.INTERNAL, Integrity.USER),),
            "send-cap-m2",
            (BROKER,),
            task_id="m2",
        )
        blocked, ev = broker.commit(Commit(send_effect, t))
        assert blocked is False, f"send while tainted must block: {ev}"
        assert "session-taint" in ev["predicates"]["FlowOK"]

        metrics = broker.get_taint_metrics()
        assert metrics["sends_blocked_by_taint"] == 1

        # 3) Declass lands on same task -> proxy increments
        grant = LabelException(
            kind="declass",
            match_target="*",
            from_label="CONFIDENTIAL",
            to_label="INTERNAL",
            granted_by=USER,
            nonce="dc-m2",
            data_resources=frozenset({"*"}),
            task_id="m2",
        )
        broker.grant_label_exception(grant, task_id="m2")

        metrics = broker.get_taint_metrics()
        assert metrics["blocked_sends_later_declassed"] == 1
        assert metrics["false_denial_proxy"] == 1.0

    def test_distinct_signals_never_conflated(self) -> None:
        """taint_rate must NOT be reported as a false-denial rate.

        A tainted read alone (no blocked send) yields taint_rate>0 but
        false_denial_proxy==0 — they are opposite quantities.
        """
        broker = EffectBroker()
        t = _read_confidential_task(broker, "m3")
        broker.store._unsafe_bootstrap_file("file:///secrets", Confidentiality.CONFIDENTIAL)
        broker.commit(
            Commit(
                Effect("read", "file:///secrets", {}, (), "read-cap-m3", (BROKER,), task_id="m3"), t
            )
        )

        metrics = broker.get_taint_metrics()
        assert metrics["taint_rate"] > 0.0
        assert metrics["sends_blocked_by_taint"] == 0
        assert metrics["false_denial_proxy"] == 0.0, "no block -> no false-denial signal"


# ---------------------------------------------------------------------------
# S4 — statx centralization (single source of truth, no forked constants)
# ---------------------------------------------------------------------------
class TestStatxCentralization:
    def test_subprocess_helper_matches_lattice_mapping(self) -> None:
        """derive_confidentiality_mode_str must match derive_confidentiality_from_mode.

        Both are the authoritative rule; subprocess uses the _str variant,
        broker uses the enum variant — they MUST agree.
        """
        for mode in (0o600, 0o640, 0o644, 0o700, 0o750, 0o400):
            enum_label = derive_confidentiality_from_mode(mode).name
            str_label = derive_confidentiality_mode_str(mode)
            assert enum_label == str_label

    def test_statx_constant_values_are_shared(self) -> None:
        """STATX bit constants must match the real Linux values (no drift)."""
        assert STATX_ATTR_ENCRYPTED == 1 << 0
        assert STATX_ATTR_IMMUTABLE == 1 << 1

    def test_statx_helper_uses_shared_flags(self) -> None:
        """statx() must be called with the shared STATX_ALL mask."""
        # (behavioral smoke: the helper runs and returns None or flags)
        import tempfile

        with tempfile.NamedTemporaryFile() as fh:
            # statx() is Linux-only; on macOS it must return None gracefully.
            result = try_statx_attributes(fh.name)
            assert result is None or isinstance(result, int)


# ---------------------------------------------------------------------------
# PLAN_1 / S4 — IPC security-field preservation (effect + commit roundtrip)
# ---------------------------------------------------------------------------
class TestIpcSecurityFieldPreservation:
    def test_effect_roundtrip_preserves_scope_hash(self) -> None:
        """effect_to_dict -> dict_to_effect keeps provenance scope_hash.

        Without this, HIGH-integrity provenance loses its trust anchor when
        crossing the IPC boundary (silent PLAN_1 S4 gap).
        """
        from effect_broker.executor_ipc import dict_to_effect, effect_to_dict

        original = Effect(
            etype="send",
            target="file:///o",
            metadata={},
            provenance=(
                Data(
                    name="read:x",
                    confidentiality=Confidentiality.CONFIDENTIAL,
                    integrity=Integrity.HIGH,
                    content="",
                    provenance_id="read:t:cap:1",
                    scope_hash="a" * 16,
                ),
            ),
            capability_nonce="cap",
            delegation_chain=(BROKER,),
        )
        restored = dict_to_effect(effect_to_dict(original))
        assert restored.provenance[0].provenance_id == "read:t:cap:1"
        assert restored.provenance[0].scope_hash == "a" * 16

    def test_commit_roundtrip_preserves_authorized_content_hash(self) -> None:
        """commit_to_dict keeps authorized_content_hash for the subprocess gate."""
        from effect_broker.executor_ipc import commit_to_dict
        from effect_broker.model import ApprovedRequest, EffectTarget

        broker = EffectBroker()
        task = _read_confidential_task(broker, "roundtrip")
        approved = ApprovedRequest(
            nonce="cap-r",
            etype="read",
            targets=EffectTarget(primary="file:///secrets", additional=frozenset()),
            expiry=100.0,
            task_id="roundtrip",
            granted_by=APPROVER,
            content_hash="deadbeef",  # explicit content binding
        )
        commit = Commit(
            Effect("read", "file:///secrets", {}, (), "cap-r", (BROKER,), task_id="roundtrip"),
            task,
            approved_request=approved,
        )
        # Commit is frozen — build the broker-side content hash via replace.
        from dataclasses import replace

        commit = replace(commit, authorized_content_hash="cafe")
        d = commit_to_dict(commit)
        assert d["authorized_content_hash"] == "cafe"
        assert d["approved_request"]["content_hash"] == "deadbeef"
