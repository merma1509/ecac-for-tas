"""Regression: no content crosses the boundary before authorization.

The bug this pins
-----------------
`RealFileShim._stat_pre()` opened every regular file and read it in full to
derive provenance labels, and it ran BEFORE `broker.commit()`. A read of a file
OUTSIDE the capability scope was therefore blocked correctly — and still had
its entire payload copied into the broker process on the way to being refused.

Measured before the fix: a denied read of a 4096-byte file outside the mandate
transferred all 4096 bytes. Confinement that hands over the secret when it
refuses is not confinement.

The fix makes the pre-probe metadata-only (`os.stat`, no `open`). Content is
read only after the gate returns ALLOW. The content-keyword label heuristic is
preserved as a POST-authorization upgrade: a world-readable file whose bytes
say "api_key" still taints the session, because the secret is now in the task
context even though the authorized label was lower.
"""

from __future__ import annotations

import builtins
import os
from collections.abc import Iterator
from contextlib import contextmanager

import pytest

from effect_broker.model import Capability, Task
from effect_broker.shim_real import RealFileShim
from effect_broker.traces import build


class _SpyReader:
    """Wrap a file handle, counting how many bytes actually get read."""

    def __init__(self, handle: object, counter: list[int]) -> None:
        self._handle = handle
        self._counter = counter

    def read(self, *args: object) -> bytes:
        data = self._handle.read(*args)  # type: ignore[attr-defined]
        self._counter[0] += len(data)
        return data

    def __enter__(self) -> _SpyReader:
        return self

    def __exit__(self, *exc: object) -> None:
        self._handle.close()  # type: ignore[attr-defined]

    def __getattr__(self, name: str) -> object:
        return getattr(self._handle, name)


@contextmanager
def count_reads_of(target: str) -> Iterator[list[int]]:
    """Count bytes read from `target` through the builtin `open`."""
    counter = [0]
    real_open = builtins.open

    def spy_open(file: object, *args: object, **kwargs: object) -> object:
        handle = real_open(file, *args, **kwargs)  # type: ignore[arg-type]
        if os.path.abspath(str(file)) == os.path.abspath(target):
            return _SpyReader(handle, counter)
        return handle

    builtins.open = spy_open  # type: ignore[assignment]
    try:
        yield counter
    finally:
        builtins.open = real_open


def _broker_for(scope_dir: str) -> tuple[object, Task, RealFileShim]:
    broker = build()
    cap = Capability(
        owner="User",
        holder="tool",
        right="*",
        target="*",
        scope=frozenset({f"file://{os.path.realpath(scope_dir)}"}),
        expiry=float("inf"),
        nonce="cap",
        task_id="t",
    )
    task = Task(task_id="t", owner="User", ceiling=cap)
    broker.register_task(task)
    broker.capabilities["cap"] = cap
    shim = RealFileShim(broker=broker, task_id="t", tool_name="tool")
    return broker, task, shim


class TestNoPreAuthorizationContentRead:
    """The pre-probe must never read file contents."""

    @pytest.mark.parametrize("payload_size", [16, 4096])
    def test_denied_read_transfers_zero_bytes(
        self, tmp_path: object, payload_size: int
    ) -> None:
        """A read OUTSIDE the mandate must not copy the payload into the broker."""
        scope_dir = str(tmp_path) + "/inside"
        outside_dir = str(tmp_path) + "/outside"
        os.makedirs(scope_dir, exist_ok=True)
        os.makedirs(outside_dir, exist_ok=True)
        secret = os.path.join(outside_dir, "shadow.txt")
        with open(secret, "w") as f:
            f.write("A" * payload_size)

        _broker, _task, shim = _broker_for(scope_dir)

        with count_reads_of(secret) as counter:
            with pytest.raises(Exception):  # noqa: B017 — any refusal is fine
                shim.read(secret)

        assert counter[0] == 0, (
            f"a DENIED read of {payload_size} bytes outside the mandate transferred "
            f"{counter[0]} bytes into the broker process; the pre-probe must be "
            f"metadata-only"
        )

    def test_allowed_read_transfers_content_exactly_once(
        self, tmp_path: object
    ) -> None:
        """An ALLOWED read may read the bytes — but not twice for bookkeeping."""
        scope_dir = str(tmp_path)
        target = os.path.join(scope_dir, "notes.txt")
        with open(target, "w") as f:
            f.write("hello")
        _broker, _task, shim = _broker_for(scope_dir)

        with count_reads_of(target) as counter:
            content = shim.read(target)

        assert content == b"hello"
        assert counter[0] == len("hello"), (
            "an allowed same-process read should transfer the payload once; "
            f"measured {counter[0]} bytes for a {len('hello')}-byte file"
        )

    def test_write_does_not_read_target_contents_before_gate(
        self, tmp_path: object
    ) -> None:
        """Overwriting a file must not read its old bytes before authorization."""
        scope_dir = str(tmp_path)
        target = os.path.join(scope_dir, "existing.txt")
        with open(target, "w") as f:
            f.write("OLD-SECRET-PAYLOAD")
        _broker, _task, shim = _broker_for(scope_dir)

        with count_reads_of(target) as counter:
            shim.write(target, b"new")

        assert counter[0] == 0, (
            "write pre-probe read the previous contents "
            f"({counter[0]} bytes) before the gate; only metadata is needed"
        )
        with open(target, "rb") as f:
            assert f.read() == b"new"


class TestContentLabelStillDerived:
    """Dropping the pre-read must not drop content-based secret detection."""

    def test_world_readable_file_with_secret_content_taints(self, tmp_path: object) -> None:
        """0o644 (PUBLIC by bits) but the bytes are a secret → session tainted.

        This is the post-authorization upgrade path: the read is allowed (the
        path is in scope and world-readable), but the secret is now in context,
        so a later send must see the taint.
        """
        scope_dir = str(tmp_path)
        target = os.path.join(scope_dir, "notes.txt")
        with open(target, "w") as f:
            f.write("api_key=sk-live-12345")
        os.chmod(target, 0o644)

        broker, task, shim = _broker_for(scope_dir)
        content = shim.read(target)

        assert content == b"api_key=sk-live-12345"
        assert task.session.tainted is True, (
            "content-derived CONFIDENTIAL was lost with the pre-read: a "
            "world-readable file containing 'api_key' must still taint"
        )
        metrics = broker.get_taint_metrics()  # type: ignore[attr-defined]
        assert metrics["reads_that_tainted"] == 1

    def test_benign_world_readable_file_does_not_taint(self, tmp_path: object) -> None:
        """No over-labelling: an ordinary public file must stay clean."""
        scope_dir = str(tmp_path)
        target = os.path.join(scope_dir, "public.txt")
        with open(target, "w") as f:
            f.write("hello world")
        os.chmod(target, 0o644)

        _broker, task, shim = _broker_for(scope_dir)
        shim.read(target)
        assert task.session.tainted is False

    def test_owner_only_file_still_taints(self, tmp_path: object) -> None:
        """Permission-bit confinement must keep working without the content read."""
        scope_dir = str(tmp_path)
        target = os.path.join(scope_dir, "secrets.txt")
        with open(target, "w") as f:
            f.write("neutral words here")
        os.chmod(target, 0o600)

        _broker, task, shim = _broker_for(scope_dir)
        shim.read(target)
        assert task.session.tainted is True
