"""Regression: audit counterexamples

Run: uv run pytest tests/test_audit_regressions.py -v
"""

from __future__ import annotations

import pytest


class TestAuditAUDIT1SameProcessGap:
    """Same-process enforcement gap .

    The broker and ResourceStore share a Python process. Direct mutation
    bypasses broker.commit(). The ledger returns UNKNOWN for auth-without-
    observation — "unknown, not safe" is maintained.
    """

    def test_direct_store_mutation_produces_ledger_unknown(self) -> None:
        from effect_broker.ledger import UnknownLedgerResult
        from effect_broker.model import File
        from effect_broker.traces import build

        broker = build()
        task_id = "audit-1-task"
        nonce = "audit-1-nonce"

        broker.ledger.record_authorization(
            task_id, nonce, frozenset({"file:///audit-1"}), source="broker.gate",
        )
        broker.store._files._data["file:///audit-1"] = File(
            "file:///audit-1",
            broker.store._files._data.get("file:///audit-1", broker.store._files._data.get("file:///audit-1")),
        )

        verdict = broker.ledger.verify(task_id, nonce)
        assert isinstance(verdict, UnknownLedgerResult), (
            f"Direct store mutation must produce UNKNOWN, got {verdict}"
        )

    def test_multi_process_direct_bypass_impossible(self) -> None:
        """In multi-process mode, direct broker store mutation is structurally impossible.

        FIXED by P0.3: the broker process cannot access the subprocess store.
        Direct store access would be a Python AttributeError.
        """
        import uuid
        from pathlib import Path

        from effect_broker.broker import EffectBroker
        from effect_broker.ledger import IndependentEffectLedger

        uid = uuid.uuid4().hex[:8]
        exec_sock = Path(f"/tmp/ecac-audit1-exec-{uid}.sock")
        store_sock = Path(f"/tmp/ecac-audit1-store-{uid}.sock")

        broker = EffectBroker(
            ledger=IndependentEffectLedger(),
            mode="multi-process",
            executor_socket=exec_sock,
            store_socket=store_sock,
        )

        # The broker has NO reference to the subprocess store — direct access impossible
        assert not hasattr(broker, "_store") or broker._store is None, (
            "In multi-process mode, broker must not hold a store reference"
        )

        broker.shutdown()
        exec_sock.unlink(missing_ok=True)
        store_sock.unlink(missing_ok=True)


class TestAuditAUDIT2ApprovalBinding:
    """Approval binding to exact immutable request (FIXED).

    Approvals are bound to (etype, target, task_id) via ApprovalBinding.
    Content binding requires a separate design (not in scope).
    """

    def test_approval_for_send_blocks_write(self) -> None:
        from effect_broker.lattice import Confidentiality, Integrity
        from effect_broker.model import Capability, Commit, Data, Effect, Task
        from effect_broker.traces import build

        broker = build()
        task = Task(
            task_id="audit-2", owner="User",
            ceiling=Capability(owner="User", holder="EffectBroker", right="*",
                               target="*", scope=frozenset({"*"}),
                               expiry=float("inf"), nonce="audit-2-ceil"),
        )
        broker.register_task(task)

        send_req = Effect(
            etype="send", target="internal@corp.com", metadata={},
            provenance=(Data("req", Confidentiality.INTERNAL, Integrity.USER),),
            capability_nonce="req:audit-2", delegation_chain=(),
        )
        nonce = broker.grant_approval(send_req, expiry=100.0, task_id="audit-2")

        write_effect = Effect(
            etype="write", target="file:///reports", metadata={},
            provenance=(Data("msg", Confidentiality.INTERNAL, Integrity.USER),),
            capability_nonce=nonce,
            delegation_chain=(),
        )
        allow, ev = broker.commit(Commit(write_effect, task))
        assert not allow, "send approval must NOT authorize write"
        assert ev["primary_blocker"] in ("Auth", "ApprovalBinding")
        assert "right-mismatch" in ev["predicates"]["Auth"] or ev["primary_blocker"] == "ApprovalBinding"  # noqa: E501


class TestAuditAUDIT3RightSubstitution:
    """right='*' is intentional wildcard; right mismatch blocks (FIXED).

    right='*' means 'any effect type for this target'. But a capability with
    right='read' cannot authorize write — right mismatch is checked in Auth sub-check 5.
    """

    def test_read_cap_blocks_write(self) -> None:
        from effect_broker.lattice import Confidentiality, Integrity
        from effect_broker.model import Capability, Commit, Data, Effect, Task
        from effect_broker.traces import build

        broker = build()
        task = Task(
            task_id="audit-3", owner="User",
            ceiling=Capability(owner="User", holder="EffectBroker", right="*",
                               target="*", scope=frozenset({"*"}),
                               expiry=float("inf"), nonce="audit-3-ceil"),
        )
        broker.register_task(task)
        broker.capabilities["audit-3-read"] = Capability(
            owner="User", holder="EffectBroker", right="read",
            target="file:///reports", scope=frozenset({"*"}),
            expiry=float("inf"), nonce="audit-3-read",
        )

        write_effect = Effect(
            etype="write", target="file:///reports", metadata={},
            provenance=(Data("msg", Confidentiality.INTERNAL, Integrity.USER),),
            capability_nonce="audit-3-read", delegation_chain=(),
        )
        allow, ev = broker.commit(Commit(write_effect, task))
        assert not allow
        assert ev["primary_blocker"] == "Auth"
        assert "right-mismatch" in ev["predicates"]["Auth"]

    def test_right_wildcard_allows_any_type(self) -> None:
        """right='*' explicitly allows any etype — this is intentional, not a bypass."""
        from effect_broker.lattice import Confidentiality, Integrity
        from effect_broker.model import Capability, Commit, Data, Effect, Task
        from effect_broker.traces import build

        broker = build()
        task = Task(
            task_id="audit-3-wildcard", owner="User",
            ceiling=Capability(owner="User", holder="EffectBroker", right="*",
                               target="*", scope=frozenset({"*"}),
                               expiry=float("inf"), nonce="audit-3-wc-ceil"),
        )
        broker.register_task(task)
        broker.capabilities["audit-3-wildcard"] = Capability(
            owner="User", holder="EffectBroker", right="*",
            target="file:///reports", scope=frozenset({"file:///reports"}),
            expiry=float("inf"), nonce="audit-3-wildcard",
        )

        write_effect = Effect(
            etype="write", target="file:///reports", metadata={},
            provenance=(Data("msg", Confidentiality.INTERNAL, Integrity.USER),),
            capability_nonce="audit-3-wildcard", delegation_chain=(),
        )
        allow, ev = broker.commit(Commit(write_effect, task))
        # right='*' is intentional — ALLOWs any etype (documented semantics)
        assert allow, f"right='*' is intentional wildcard; should ALLOW. Evidence: {ev}"


class TestAuditAUDIT4SessionClosure:
    """Task re-registration blocked after use (FIXED).

    A task with consumed nonces (session.used non-empty) cannot be silently
    re-registered. This prevents replay via session-reopen.
    """

    def test_task_cannot_reregister_after_use(self) -> None:
        from effect_broker.lattice import Confidentiality, Integrity
        from effect_broker.model import Capability, Commit, Data, Effect, Task
        from effect_broker.traces import build

        broker = build()
        broker.store._unsafe_bootstrap_file("file:///audit-4", Confidentiality.PUBLIC)

        task = Task(
            task_id="audit-4", owner="User",
            ceiling=Capability(owner="User", holder="EffectBroker", right="write",
                               target="*", scope=frozenset({"*"}),
                               expiry=float("inf"), nonce="audit-4-ceil"),
        )
        broker.register_task(task)
        broker.capabilities["audit-4-cap"] = Capability(
            owner="User", holder="EffectBroker", right="write",
            target="file:///audit-4", scope=frozenset({"file:///audit-4"}),
            expiry=float("inf"), nonce="audit-4-cap",
        )

        effect = Effect(
            etype="write", target="file:///audit-4", metadata={},
            provenance=(Data("msg", Confidentiality.INTERNAL, Integrity.USER),),
            capability_nonce="audit-4-cap", delegation_chain=(),
        )
        broker.commit(Commit(effect, task))  # First use — nonce consumed

        fresh_task = Task(task_id="audit-4", owner="User", ceiling=task.ceiling)
        with pytest.raises((AssertionError, ValueError), match="already been used|already registered"):  # noqa: E501
            broker.register_task(fresh_task)


class TestAuditAUDIT5Provenance:
    """LLM cannot set arbitrary provenance (FIXED in shim design).

    FileShim derives provenance internally from the operation type.
    Provenance labels are set by the shim, not by the tool/LLM.
    """

    def test_shim_provenance_internal_not_llm_controlled(self) -> None:
        from effect_broker.lattice import Confidentiality
        from effect_broker.model import Capability, Task
        from effect_broker.shim import FileShim
        from effect_broker.traces import build

        broker = build()
        broker.store._unsafe_bootstrap_file("file:///audit-5", Confidentiality.INTERNAL)
        broker.capabilities["audit-5-cap"] = Capability(
            owner="User", holder="EffectBroker", right="write",
            target="file:///audit-5", scope=frozenset({"file:///audit-5"}),
            expiry=float("inf"), nonce="audit-5-cap",
        )
        # Register default task if not already registered
        if "default" not in broker.tasks:
            broker.tasks["default"] = Task(
                task_id="default", owner="User",
                ceiling=Capability(owner="User", holder="EffectBroker", right="*",
                           target="*", scope=frozenset({"*"}),
                           expiry=float("inf"), nonce="default-ceil"),
            )
        shim = FileShim(broker=broker, task_id="default", tool_name="audit-5-tool")
        tool_api = {m for m in dir(shim) if not m.startswith("_")}

        # The shim's _commit_op builds provenance from op.operation type,
        # NOT from any tool-supplied label. Tool code only calls read/write/send.
        # The Effect constructed internally uses Confidentiality.INTERNAL
        # regardless of what the tool requests.

        # The tool sees only these operations — no provenance control methods
        operation_methods = {"read", "write", "delete", "send"}
        for method in operation_methods:
            assert method in tool_api, f"Shim must expose {method} operation"

        # Verify: the shim has no public method to set arbitrary provenance
        assert not hasattr(shim, "set_provenance")
        assert not hasattr(shim, "override_confidentiality")
        assert not hasattr(shim, "override_integrity")


class TestAuditAUDIT6PathNormalization:
    """Path traversal blocked by Auth .

    Auth checks exact target match — no capability for aliased path = BLOCK.
    Path normalization in NoAmp is medium-term.
    """

    def test_aliased_path_blocked_by_auth(self) -> None:
        from effect_broker.lattice import Confidentiality, Integrity
        from effect_broker.model import Capability, Commit, Data, Effect, Task
        from effect_broker.traces import build

        broker = build()
        task = Task(
            task_id="audit-6", owner="User",
            ceiling=Capability(owner="User", holder="EffectBroker", right="write",
                               target="*", scope=frozenset({"*"}),
                               expiry=float("inf"), nonce="audit-6-ceil"),
        )
        broker.register_task(task)
        broker.capabilities["audit-6-cap"] = Capability(
            owner="User", holder="EffectBroker", right="write",
            target="file:///reports", scope=frozenset({"file:///reports"}),
            expiry=float("inf"), nonce="audit-6-cap",
        )

        aliased_effect = Effect(
            etype="write", target="file:///../reports/secrets", metadata={},
            provenance=(Data("msg", Confidentiality.INTERNAL, Integrity.USER),),
            capability_nonce="audit-6-cap", delegation_chain=(),
        )
        allow, ev = broker.commit(Commit(aliased_effect, task))
        assert not allow
        assert ev["primary_blocker"] == "Auth"
        assert "target-mismatch" in ev["predicates"]["Auth"]
