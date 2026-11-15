"""Regression: a shim must be judged by ITS task, not the "default" one.

The bug this pins
-----------------
`FileShim._commit_op()` built `Commit(effect=effect, task=None, ...)`. `gate()`
resolves a None task by substituting `broker.tasks["default"]`, so every shim
call was evaluated against the DEFAULT task's ceiling rather than the ceiling of
the task the shim was constructed with.

`FileShim.__init__` takes a `task_id` and hands the same id to `IsolatedExecutor`,
so the parameter looked wired up — the task never reached the gate.

Exploit: a shim bound to a task whose ceiling covers only `file:///allowed`
read `file:///secret/creds.txt` successfully whenever the default task allowed
it. The tool's mandate was replaced by an unrelated task's mandate.

Fix: the shim resolves and passes its own Task, failing closed when the task is
not registered instead of silently inheriting another one's authority.
"""

from __future__ import annotations

import pytest

from effect_broker.broker import EffectBroker
from effect_broker.lattice import Confidentiality
from effect_broker.model import Capability, Task
from effect_broker.shim import FileShim, SecurityError


def _broker() -> EffectBroker:
    broker = EffectBroker(mode="same-process")
    # The default task is deliberately PERMISSIVE: if the shim falls back to it,
    # the tests below would pass the read and the bug would be invisible.
    wide = Capability(
        owner="User",
        holder="admin",
        right="*",
        target="*",
        scope=frozenset({"*"}),
        expiry=float("inf"),
        nonce="wide",
        task_id="default",
    )
    broker.register_task(Task(task_id="default", owner="User", ceiling=wide))
    broker.capabilities["wide"] = wide

    # The restricted task: its ceiling does NOT cover file:///secret.
    narrow = Capability(
        owner="User",
        holder="admin",
        right="*",
        target="*",
        scope=frozenset({"file:///allowed"}),
        expiry=float("inf"),
        nonce="narrow",
        task_id="restricted",
    )
    broker.register_task(Task(task_id="restricted", owner="User", ceiling=narrow))
    broker.capabilities["narrow"] = narrow

    broker.store._unsafe_bootstrap_file(
        "file:///secret/creds.txt", Confidentiality.CONFIDENTIAL
    )
    return broker


class TestShimUsesItsOwnTask:
    def test_read_outside_task_mandate_blocked(self) -> None:
        """A read the RESTRICTED task forbids must not be rescued by 'default'."""
        broker = _broker()
        # A reusable capability the tool legitimately holds...
        reuse = Capability(
            owner="User",
            holder="t",
            right="read",
            target="*",
            scope=frozenset({"*"}),
            expiry=float("inf"),
            nonce="reuse",
            task_id=None,
        )
        broker.capabilities["reuse"] = reuse

        shim = FileShim(broker=broker, task_id="restricted", tool_name="t")

        with pytest.raises(SecurityError) as exc:
            shim.read("file:///secret/creds.txt")
        assert "Auth" in str(exc.value), (
            f"expected an Auth refusal under the restricted ceiling, got {exc.value}"
        )

    def test_read_inside_task_mandate_allowed(self) -> None:
        """The fix must not block what the task's own ceiling permits."""
        broker = _broker()
        broker.store._unsafe_bootstrap_file(
            "file:///allowed/ok.txt", Confidentiality.PUBLIC
        )
        reuse = Capability(
            owner="User",
            holder="t",
            right="read",
            target="*",
            scope=frozenset({"*"}),
            expiry=float("inf"),
            nonce="reuse",
            task_id=None,
        )
        broker.capabilities["reuse"] = reuse

        shim = FileShim(broker=broker, task_id="restricted", tool_name="t")
        assert shim.read("file:///allowed/ok.txt") == "(simulated file content)"
        assert shim.op_log[-1].blocked is False

    def test_unregistered_task_fails_closed(self) -> None:
        """No silent fallback: an unknown task is an error, not a promotion."""
        broker = _broker()
        shim = FileShim(broker=broker, task_id="does-not-exist", tool_name="t")

        with pytest.raises(SecurityError) as exc:
            shim.read("file:///secret/creds.txt")
        assert "not registered" in str(exc.value)


class TestCrossHolderCapabilityLookup:
    """#8: capability lookup must not ignore the holder."""

    def test_capability_of_another_holder_is_not_borrowed(self) -> None:
        """A capability issued to `admin` must not authorize `malicious-tool`."""
        broker = EffectBroker(mode="same-process")
        admin_cap = Capability(
            owner="User",
            holder="admin",
            right="read",
            target="file:///secret/creds.txt",
            scope=frozenset({"*"}),
            expiry=float("inf"),
            nonce="admin-cap",
            task_id=None,
        )
        broker.register_task(Task(task_id="default", owner="User", ceiling=admin_cap))
        broker.capabilities["admin-cap"] = admin_cap
        broker.store._unsafe_bootstrap_file(
            "file:///secret/creds.txt", Confidentiality.CONFIDENTIAL
        )

        shim = FileShim(broker=broker, task_id="default", tool_name="malicious-tool")

        # The lookup itself must not hand back another holder's credential.
        assert shim._find_capability("read", "file:///secret/creds.txt") == (
            "no-cap-read-file:///secret/creds.txt"
        )
        with pytest.raises(SecurityError):
            shim.read("file:///secret/creds.txt")

    def test_own_capability_still_resolves(self) -> None:
        """Holder matching must not break lookup for the legitimate holder."""
        broker = EffectBroker(mode="same-process")
        own_cap = Capability(
            owner="User",
            holder="read-tool",
            right="read",
            target="file:///reports",
            scope=frozenset({"*"}),
            expiry=float("inf"),
            nonce="own-cap",
        )
        broker.register_task(Task(task_id="default", owner="User", ceiling=own_cap))
        broker.capabilities["own-cap"] = own_cap
        broker.store._unsafe_bootstrap_file("file:///reports", Confidentiality.INTERNAL)

        shim = FileShim(broker=broker, task_id="default", tool_name="read-tool")
        assert shim._find_capability("read", "file:///reports") == "own-cap"
        assert shim.read("file:///reports") == "(simulated file content)"

    def test_broker_holder_capability_still_resolves(self) -> None:
        """The EffectBroker holder is the shim acting on the broker's behalf."""
        broker = EffectBroker(mode="same-process")
        broker_cap = Capability(
            owner="User",
            holder="EffectBroker",
            right="read",
            target="*",
            scope=frozenset({"*"}),
            expiry=float("inf"),
            nonce="broker-cap",
        )
        broker.register_task(Task(task_id="default", owner="User", ceiling=broker_cap))
        broker.capabilities["broker-cap"] = broker_cap
        broker.store._unsafe_bootstrap_file("file:///reports", Confidentiality.INTERNAL)

        shim = FileShim(broker=broker, task_id="default", tool_name="any-tool")
        assert shim._find_capability("read", "file:///reports") == "broker-cap"
        assert shim.read("file:///reports") == "(simulated file content)"
