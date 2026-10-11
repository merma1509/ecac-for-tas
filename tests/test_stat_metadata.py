"""PLAN_2 S4 — metadata (stat) vs content (read): taint behavior + shared constants.

Regression guard for the invariant:
  - a `stat` observes METADATA (mode/size/mtime) -> NEVER taints the session
  - a `read` observes CONTENT -> taints iff the content label is CONFIDENTIAL
  - statx constants come from ONE shared source (statx.py) used by broker,
    shim_real and executor_subprocess (no forked `1 << 0` / `1 << 1`).

Tests run against the real multi-process path (subprocess computes the label
from real OS permission bits) so they pin the IPC behavior, not just the
in-process helper.
"""

from __future__ import annotations

import os
import tempfile

import pytest

from effect_broker.broker import EffectBroker
from effect_broker.statx import (
    STATX_ATTR_ENCRYPTED,
    STATX_ATTR_IMMUTABLE,
    derive_confidentiality_from_mode,
    derive_confidentiality_mode_str,
    try_statx_attributes,
)


@pytest.fixture
def tmp_dir():
    """Create a temporary directory for tests."""
    with tempfile.TemporaryDirectory() as d:
        yield d


class TestStatVsReadTaint:
    """stat must not taint; read of CONFIDENTIAL content must.

    Runs against the REAL multi-process broker (shim → subprocess → store),
    so the label comes from the subprocess's real OS permission bits and the
    taint lands on the broker-side Task.session (B→A sync).
    """

    def _broker_shim(self, tmp_dir: str, task_id: str):
        """Build a multi-process broker + a task whose shim can read tmp_dir."""
        import pathlib

        from effect_broker.model import Capability, Task

        broker = EffectBroker(mode="multi-process")
        canon_tmpdir = str(pathlib.Path(tmp_dir).resolve())
        cap = Capability(
            owner="User", holder="untrusted-tool", right="*", target="*",
            scope=frozenset({f"file://{canon_tmpdir}"}), expiry=float("inf"),
            nonce=f"stat-cap-{task_id}",
        )
        task = Task(task_id=task_id, owner="User", ceiling=cap)
        broker.register_task(task)
        broker.capabilities[f"stat-cap-{task_id}"] = cap
        shim = broker.create_real_file_shim(task_id=task_id, tool_name="untrusted-tool")
        assert shim.ipc_client is not None, "multi-process shim needs IPC"
        return broker, shim

    def test_stat_confidential_file_does_not_taint_session(self, tmp_dir: str) -> None:
        """A metadata read of a CONFIDENTIAL file must NOT taint the session."""
        conf_file = os.path.join(tmp_dir, "secrets.txt")
        with open(conf_file, "w") as f:
            f.write("top secret")
        os.chmod(conf_file, 0o600)  # owner-only -> CONFIDENTIAL per policy

        broker, shim = self._broker_shim(tmp_dir, "stat-no-taint")
        try:
            st = shim.stat(conf_file)
            assert st is not None, "stat must return metadata"
            session = broker.tasks["stat-no-taint"].session
            assert session is not None
            assert session.tainted is False, (
                f"stat on CONFIDENTIAL file must NOT taint: {session._tainted_resources}"
            )
        finally:
            broker.shutdown()

    def test_read_confidential_file_taints_session(self, tmp_dir: str) -> None:
        """A content read of the same CONFIDENTIAL file DOES taint the session."""
        conf_file = os.path.join(tmp_dir, "secrets2.txt")
        with open(conf_file, "w") as f:
            f.write("top secret")
        os.chmod(conf_file, 0o600)

        broker, shim = self._broker_shim(tmp_dir, "read-taint")
        try:
            content = shim.read(conf_file)
            assert content == b"top secret"
            session = broker.tasks["read-taint"].session
            assert session is not None
            assert session.tainted is True, "read of CONFIDENTIAL file must taint"
            # per-resource: the subprocess uses the canonical (realpath) path.
            canonical = os.path.realpath(conf_file)
            assert canonical in session._tainted_resources, (
                f"read must taint the specific resource: {session._tainted_resources}"
            )
        finally:
            broker.shutdown()


class TestStatxSharedConstants:
    """statx constants must be shared (single source of truth, no drift)."""

    def test_mode_derivation_agrees(self) -> None:
        """Both enum and string derivations agree on every defense mode."""
        for mode in (0o600, 0o640, 0o644, 0o700, 0o750, 0o400, 0o755):
            enum_label = derive_confidentiality_from_mode(mode).name
            str_label = derive_confidentiality_mode_str(mode)
            assert enum_label == str_label, (
                f"mode {oct(mode)}: enum={enum_label} != str={str_label}"
            )

    def test_constant_bit_values(self) -> None:
        """Shared constants carry the REAL Linux bit values (no drift)."""
        assert STATX_ATTR_ENCRYPTED == 1 << 0
        assert STATX_ATTR_IMMUTABLE == 1 << 1

    def test_statx_helper_reachable(self, tmp_dir: str) -> None:
        """try_statx_attributes is a cross-platform no-crash helper."""
        probe = os.path.join(tmp_dir, "probe.txt")
        with open(probe, "w") as f:
            f.write("x")
        # Linux -> flags or None; macOS/unsupported -> None (never raises).
        result = try_statx_attributes(probe)
        assert result is None or isinstance(result, int)
