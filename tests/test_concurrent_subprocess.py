"""Concurrent tickets in both execution modes

`test_concurrent_replay.py` pins same-process thread behaviour. This module
runs the same attack through the multiprocess path (subprocess APPLY_COMMIT):
10 threads racing one nonce through IPC must yield exactly one commit.
"""

from __future__ import annotations

import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import pytest

from effect_broker.executor_ipc import ProcessExecutorClient, effect_to_dict
from effect_broker.executor_subprocess import ExecutorProcessHandle
from effect_broker.model import Effect


@pytest.fixture()
def executor(tmp_path: Path) -> ProcessExecutorClient:
    """A running executor subprocess on a short /tmp socket path."""
    uid = uuid.uuid4().hex[:8]
    sock = Path(f"/tmp/ecac-t-{uid}.sock")
    store_sock = Path(f"/tmp/ecac-st-{uid}.sock")
    handle = ExecutorProcessHandle(sock, store_sock)
    handle.start()
    try:
        yield ProcessExecutorClient(sock)
    finally:
        handle.stop()


def _effect(nonce: str, target: str = "user@internal.corp.com") -> Effect:
    return Effect(
        etype="send",
        target=target,
        metadata={"subject": "Hi", "body": f"body-{nonce}"},
        provenance=(),
        capability_nonce=nonce,
        delegation_chain=(),
    )


class TestConcurrentSameNonceSubprocess:
    """One nonce, many threads, one subprocess: exactly one commit."""

    def test_ten_threads_one_commit(self, executor: ProcessExecutorClient) -> None:
        nonce = "ticket-once"
        effect_dict = effect_to_dict(_effect(nonce))
        session = {"used": [], "revoked": [], "logical_time": 0.0}

        with ThreadPoolExecutor(max_workers=10) as pool:
            futures = [
                pool.submit(
                    executor.apply_commit,
                    effect_dict,
                    "ticket-task",
                    session,
                    True,
                    None,
                )
                for _ in range(10)
            ]
            results = [f.result() for f in as_completed(futures)]

        commits = [r for r in results if r.get("status") == "ok"]
        blocked = [r for r in results if r.get("status") == "blocked"]
        assert len(commits) == 1, f"expected 1 commit, got {len(commits)}"
        assert len(blocked) == 9, f"expected 9 Fresh blocks, got {len(blocked)}"
        assert all(b.get("blocker") == "Fresh" for b in blocked)

    def test_replay_after_completion_is_blocked(
        self, executor: ProcessExecutorClient
    ) -> None:
        """A nonce consumed in the subprocess stays consumed (replay via IPC)."""
        effect_dict = effect_to_dict(_effect("ticket-replay"))
        session = {"used": [], "revoked": [], "logical_time": 0.0}
        first = executor.apply_commit(effect_dict, "t", session, True, None)
        assert first.get("status") == "ok"
        second = executor.apply_commit(effect_dict, "t", session, True, None)
        assert second.get("status") == "blocked"
        assert second.get("blocker") == "Fresh"

    def test_different_nonces_both_commit(self, executor: ProcessExecutorClient) -> None:
        """Distinct tickets are independent — the check is per-nonce, not global."""
        session = {"used": [], "revoked": [], "logical_time": 0.0}
        r1 = executor.apply_commit(
            effect_to_dict(_effect("t-a", "a@internal.corp.com")), "t", session, True, None
        )
        r2 = executor.apply_commit(
            effect_to_dict(_effect("t-b", "b@internal.corp.com")), "t", session, True, None
        )
        assert r1.get("status") == "ok"
        assert r2.get("status") == "ok"
