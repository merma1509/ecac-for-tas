"""Regression: metadata file operations work identically in both modes.

The bug this pins
-----------------
`RestrictedResourceStore._apply_effect_inner` handled only
write / read / send / network / delete for File resources. `stat`, `exists` and
`listdir` fell through to `raise ValueError("effect type stat not applicable to
File")`.

In same-process mode the shim calls the store directly, so those calls blew up
AFTER the gate had already returned ALLOW. In multi-process mode the operation
runs in the executor subprocess and worked fine.

A mode difference in which shim calls succeed is a mode difference in what a
tool can be trusted with — and it made `RealFileShim.stat/exists/listdir`
unusable in the same-process configuration that the tests use most.

These ops mutate nothing, so the store records the audit entry and returns. They
must never be confused with content reads: no taint (PLAN_2 S4).
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
def workspace(tmp_path: pathlib.Path) -> tuple[str, str, str]:
    """Return (scope_dir, file_path, subdir_path)."""
    scope_dir = str(tmp_path)
    subdir = os.path.join(scope_dir, "sub")
    os.makedirs(subdir)
    target = os.path.join(subdir, "a.txt")
    with open(target, "w") as f:
        f.write("hello")
    return scope_dir, target, subdir


class TestSameProcessMetadataOps:
    def test_stat_succeeds(self, workspace: tuple[str, str, str]) -> None:
        scope_dir, target, _subdir = workspace
        broker = build()
        task = Task(task_id="t", owner="User", ceiling=_capability(scope_dir))
        broker.register_task(task)
        broker.capabilities["cap"] = task.ceiling

        shim = RealFileShim(broker=broker, task_id="t", tool_name="tool")
        result = shim.stat(target)

        assert result.st_size == len("hello")
        assert broker.ledger.verify("t", shim.ops[-1].nonce) is (
            LedgerVerdict.CONFIRMED_COMMITTED
        )

    def test_exists_succeeds(self, workspace: tuple[str, str, str]) -> None:
        scope_dir, target, _subdir = workspace
        broker = build()
        task = Task(task_id="t", owner="User", ceiling=_capability(scope_dir))
        broker.register_task(task)
        broker.capabilities["cap"] = task.ceiling

        shim = RealFileShim(broker=broker, task_id="t", tool_name="tool")
        assert shim.exists(target) is True
        assert broker.ledger.verify("t", shim.ops[-1].nonce) is (
            LedgerVerdict.CONFIRMED_COMMITTED
        )

    def test_listdir_succeeds(self, workspace: tuple[str, str, str]) -> None:
        scope_dir, _target, subdir = workspace
        broker = build()
        task = Task(task_id="t", owner="User", ceiling=_capability(scope_dir))
        broker.register_task(task)
        broker.capabilities["cap"] = task.ceiling

        shim = RealFileShim(broker=broker, task_id="t", tool_name="tool")
        assert shim.listdir(subdir) == ["a.txt"]
        assert broker.ledger.verify("t", shim.ops[-1].nonce) is (
            LedgerVerdict.CONFIRMED_COMMITTED
        )

    def test_metadata_ops_do_not_taint(self, workspace: tuple[str, str, str]) -> None:
        """PLAN_2 S4: metadata reveals no content, so it must not taint."""
        scope_dir, target, subdir = workspace
        os.chmod(target, 0o600)  # CONFIDENTIAL by permission bits
        broker = build()
        task = Task(task_id="t", owner="User", ceiling=_capability(scope_dir))
        broker.register_task(task)
        broker.capabilities["cap"] = task.ceiling

        shim = RealFileShim(broker=broker, task_id="t", tool_name="tool")
        shim.stat(target)
        shim.exists(target)
        shim.listdir(subdir)

        assert task.session.tainted is False, (
            "stat/exists/listdir observed METADATA, not content; they must not "
            "taint the session"
        )
        assert broker.verify_complete_mediation() == []


class TestModeParity:
    """Both modes must agree on every metadata operation."""

    @pytest.mark.parametrize("op_name", ["stat", "exists", "listdir"])
    def test_multi_process_matches(
        self, workspace: tuple[str, str, str], op_name: str
    ) -> None:
        scope_dir, target, subdir = workspace
        arg = subdir if op_name == "listdir" else target

        # same-process verdict
        same_broker = build()
        same_task = Task(task_id="t", owner="User", ceiling=_capability(scope_dir))
        same_broker.register_task(same_task)
        same_broker.capabilities["cap"] = same_task.ceiling
        same_shim = RealFileShim(
            broker=same_broker, task_id="t", tool_name="tool"
        )
        same_result = getattr(same_shim, op_name)(arg)
        same_verdict = same_broker.ledger.verify("t", same_shim.ops[-1].nonce)

        # multi-process verdict
        multi_broker = EffectBroker(mode="multi-process")
        multi_task = Task(task_id="t", owner="User", ceiling=_capability(scope_dir))
        multi_broker.register_task(multi_task)
        multi_broker.capabilities["cap"] = multi_task.ceiling
        try:
            multi_shim = multi_broker.create_real_file_shim(
                task_id="t", tool_name="tool"
            )
            multi_result = getattr(multi_shim, op_name)(arg)
            multi_verdict = multi_broker.ledger.verify("t", multi_shim.ops[-1].nonce)
        finally:
            multi_broker.shutdown()

        assert same_verdict is multi_verdict, (
            f"{op_name}: same-process gave {same_verdict}, "
            f"multi-process gave {multi_verdict}"
        )
        assert same_verdict is LedgerVerdict.CONFIRMED_COMMITTED

        # os.stat_result objects are not comparable across calls; compare the
        # fields that matter for a metadata operation.
        if op_name == "stat":
            assert same_result.st_size == multi_result.st_size
        else:
            assert same_result == multi_result
