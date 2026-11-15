"""Regression: a CONFIDENTIAL read must taint the session in BOTH modes.

The bug this pins
-----------------
`broker._apply_effect()` derived session taint BEFORE calling
`store.apply_effect()`. The restricted store creates file resources lazily
inside apply_effect(), so a pre-apply `store.resolve(target)` on a path the
store had never seen returned None, the `if file_res is not None` guard was
false, and the taint was silently skipped.

Consequence: in same-process mode a read of a 0o600 file left
`session.tainted == False`, so the follow-up read→send exfiltration passed
FlowOK and was ALLOWED — as long as the caller lied about provenance
(declared the secret bytes as PUBLIC, which is exactly what an attacker does).

Multi-process mode masked the bug: taint arrives there via the subprocess
`session_update` (B→A sync) instead of the pre-apply store lookup. The old
suite only exercised taint through a real read on the multi-process path, and
every same-process test called `session.taint_for_send()` by hand — so neither
pinned the broken path.

Both modes must now agree.
"""

from __future__ import annotations

import os

import pytest

from effect_broker.model import (
    Capability,
    Commit,
    Confidentiality,
    Data,
    Effect,
    EffectTarget,
    Integrity,
    Task,
)
from effect_broker.shim_real import RealFileShim
from effect_broker.traces import build


@pytest.fixture
def confidential_file(tmp_path: str) -> tuple[str, str]:
    """A 0o600 file (owner-only → CONFIDENTIAL) inside its own temp dir.

    Returns (scope_dir, secret_path). The scope covers the parent so the
    directory-modifying extra targets stay inside the mandate.
    """
    scope_dir = str(tmp_path)
    secret = os.path.join(scope_dir, "secrets.txt")
    with open(secret, "w") as f:
        f.write("TOP SECRET DATA")
    os.chmod(secret, 0o600)
    return scope_dir, secret


def _capability(scope_dir: str, *, scope_suffixes: tuple[str, ...] = ()) -> Capability:
    """Capability scoped to scope_dir plus any extra label scopes (internal/external)."""
    scope = {f"file://{os.path.realpath(scope_dir)}"}
    scope.update(scope_suffixes)
    return Capability(
        owner="User",
        holder="tool",
        right="*",
        target="*",
        scope=frozenset(scope),
        expiry=float("inf"),
        nonce="cap",
        task_id="t",
    )


def _lie_about_provenance(secret_bytes: bytes) -> Effect:
    """The attacker's move: send the secret, declare it PUBLIC (Integrity.USER)."""
    return Effect(
        etype="send",
        target="leak@external.com",
        metadata={"body": secret_bytes.decode(), "subject": "leak"},
        # Declared PUBLIC even though the bytes are CONFIDENTIAL. Only session
        # taint can catch this — a provenance-only check trusts this claim.
        provenance=(Data("looks-public", Confidentiality.PUBLIC, Integrity.USER),),
        capability_nonce="cap",
        delegation_chain=("tool",),
        task_id="t",
        known_targets=EffectTarget(
            primary="leak@external.com", additional=frozenset()
        ),
    )


class TestSameProcessTaint:
    """Same-process read of a CONFIDENTIAL file must taint the session."""

    def test_read_confidential_file_taints_session(
        self, confidential_file: tuple[str, str]
    ) -> None:
        scope_dir, secret = confidential_file
        broker = build()
        task = Task(task_id="t", owner="User", ceiling=_capability(scope_dir))
        broker.register_task(task)
        broker.capabilities["cap"] = task.ceiling

        shim = RealFileShim(broker=broker, task_id="t", tool_name="tool")
        assert shim.ipc_client is None, "same-process shim must not have IPC"

        content = shim.read(secret)
        assert content == b"TOP SECRET DATA"
        assert task.session.tainted is True, (
            "reading a 0o600 file must taint the session in same-process mode; "
            "taint was derived before store.apply_effect() created the resource"
        )
        assert secret in "".join(task.session._tainted_resources), (
            f"taint must be keyed by the read resource, got "
            f"{list(task.session._tainted_resources)}"
        )

    def test_taint_metrics_agree_with_session(
        self, confidential_file: tuple[str, str]
    ) -> None:
        """The operator-facing taint-rate must not report 0 for a tainting read."""
        scope_dir, secret = confidential_file
        broker = build()
        task = Task(task_id="t", owner="User", ceiling=_capability(scope_dir))
        broker.register_task(task)
        broker.capabilities["cap"] = task.ceiling

        RealFileShim(broker=broker, task_id="t", tool_name="tool").read(secret)

        metrics = broker.get_taint_metrics()
        assert metrics is not None
        assert metrics["total_reads"] == 1
        assert metrics["reads_that_tainted"] == 1, (
            "a CONFIDENTIAL read must be counted as tainting; "
            f"metrics reported {metrics}"
        )
        assert metrics["taint_rate"] == 1.0


class TestSameProcessExfiltrationBlocked:
    """The read→send attack must be blocked in same-process mode too."""

    def test_send_of_read_secret_with_faked_provenance_is_blocked(
        self, confidential_file: tuple[str, str]
    ) -> None:
        scope_dir, secret = confidential_file
        broker = build()
        task = Task(
            task_id="t",
            owner="User",
            # Both the file dir and the external label are in scope, so Auth and
            # NoAmp pass — only session taint can stop this send.
            ceiling=_capability(scope_dir, scope_suffixes=("internal", "external")),
        )
        broker.register_task(task)
        broker.capabilities["cap"] = task.ceiling

        content = RealFileShim(broker=broker, task_id="t", tool_name="tool").read(secret)

        allow, evidence = broker.commit(
            Commit(_lie_about_provenance(content), task, tool_name="tool")
        )

        assert allow is False, (
            "same-process read→send exfiltration was ALLOWED: the secret read from "
            "a 0o600 file was sent externally with PUBlic provenance"
        )
        assert "FlowOK" in str(evidence.get("primary_blocker", "")), (
            f"expected a flow blocker, got {evidence.get('primary_blocker')}"
        )
        flow = str(evidence["predicates"].get("FlowOK", ""))
        assert "session-taint" in flow or "taint" in flow.lower(), (
            f"the block must be attributable to session taint, got: {flow}"
        )

    def test_send_blocked_after_read_even_without_provenance_claim(
        self, confidential_file: tuple[str, str]
    ) -> None:
        """An empty provenance tuple must not slip past the taint check either."""
        scope_dir, secret = confidential_file
        broker = build()
        task = Task(
            task_id="t",
            owner="User",
            ceiling=_capability(scope_dir, scope_suffixes=("internal", "external")),
        )
        broker.register_task(task)
        broker.capabilities["cap"] = task.ceiling

        RealFileShim(broker=broker, task_id="t", tool_name="tool").read(secret)

        effect = Effect(
            etype="send",
            target="leak@external.com",
            metadata={"body": "irrelevant", "subject": "s"},
            provenance=(),
            capability_nonce="cap",
            delegation_chain=("tool",),
            task_id="t",
            known_targets=EffectTarget(
                primary="leak@external.com", additional=frozenset()
            ),
        )
        allow, evidence = broker.commit(Commit(effect, task, tool_name="tool"))
        assert allow is False
        assert "FlowOK" in str(evidence.get("primary_blocker", ""))


class TestBothModesAgree:
    """The two modes must reach the same verdict — no mode-dependent security."""

    def test_multi_process_read_also_taints(self, confidential_file: tuple[str, str]) -> None:
        """Guard against a regression in the B→A taint sync path."""
        from effect_broker.broker import EffectBroker

        scope_dir, secret = confidential_file
        broker = EffectBroker(mode="multi-process")
        task = Task(task_id="t", owner="User", ceiling=_capability(scope_dir))
        broker.register_task(task)
        broker.capabilities["cap"] = task.ceiling
        try:
            shim = broker.create_real_file_shim(task_id="t", tool_name="tool")
            shim.read(secret)
            assert task.session.tainted is True
        finally:
            broker.shutdown()
