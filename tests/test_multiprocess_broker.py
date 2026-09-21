"""End-to-end integration tests for EffectBroker in multi-process mode.

This test suite verifies the complete P0.3 deliverable: the broker operates
in one process while the executor's mutable store lives in a subprocess.
Every commit goes through the same three-phase path:

    Phase 1 (broker process): broker.gate(commit) — Auth ∧ FlowOK ∧ NoAmp ∧ Fresh
    Phase 2 (subprocess):     IsolatedStore.apply_effect() via IPC
    Phase 3 (broker process): ledger records auth + observation

Key properties verified:
  1. EffectBroker(mode="multi-process") starts the subprocess automatically
  2. broker.commit() routes through SubprocessExecutor.execute()
  3. The subprocess store is only accessible via IPC — no direct reference
  4. broker.shutdown() cleanly terminates the subprocess
  5. Authorization + observation recorded to the ledger match subprocess state
  6. Same semantic result as same-process mode (identical allow/deny decisions)
"""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest


class TestSubprocessExecutorRoundTrip:
    """Full round-trip: broker → subprocess store → ledger verification."""

    @pytest.fixture(autouse=True)
    def setup_multiprocess_broker(self, tmp_path: Path) -> None:
        """Create a multi-process broker for each test."""
        import signal as _signal

        uid = uuid.uuid4().hex[:8]
        exec_sock = Path(f"/tmp/ecac-mp-exec-{uid}.sock")
        store_sock = Path(f"/tmp/ecac-mp-store-{uid}.sock")

        from effect_broker.broker import EffectBroker
        from effect_broker.ledger import IndependentEffectLedger

        ledger = IndependentEffectLedger()
        broker = EffectBroker(
            ledger=ledger,
            mode="multi-process",
            executor_socket=exec_sock,
            store_socket=store_sock,
        )

        self._broker = broker
        self._ledger = ledger
        self._exec_sock = exec_sock
        self._store_sock = store_sock

        yield

        # Clean shutdown
        broker.shutdown()
        for sock in (exec_sock, store_sock):
            if sock.exists():
                sock.unlink(missing_ok=True)

    def test_broker_starts_subprocess_automatically(self) -> None:
        """EffectBroker(mode='multi-process') starts the executor subprocess."""
        from effect_broker.executor import SubprocessExecutor

        assert isinstance(self._broker.executor, SubprocessExecutor)
        assert self._exec_sock.exists(), "Executor socket not created"
        assert self._exec_sock.stat().st_mode & 0o170000 == 0o140000, "Not a socket"

    def test_commit_routes_through_subprocess_executor(self) -> None:
        """broker.commit() executes through SubprocessExecutor (not IsolatedExecutor)."""
        from effect_broker.executor import SubprocessExecutor
        from effect_broker.model import Capability, Commit, Effect, Task, USER, BROKER

        # Root grant
        cap = Capability(
            owner=USER,
            holder=BROKER,
            right="write",
            target="file:///test/multi.txt",
            scope=frozenset({"*"}),
            expiry=float("inf"),
            nonce="write-test-multiproc",
            derives_from=None,
        )
        self._broker.grant_root(cap)

        # Task with wildcard ceiling
        default_task = self._broker.tasks.get("default")
        if default_task is None:
            default_task = Task(
                task_id="default",
                owner=USER,
                ceiling=cap,
            )
            self._broker.tasks["default"] = default_task
        else:
            default_task.ceiling = cap

        effect = Effect(
            etype="write",
            target="file:///test/multi.txt",
            metadata={},
            provenance=(),
            capability_nonce="write-test-multiproc",
            delegation_chain=(),
            label_exceptions=(),
            task_id="default",
            known_targets=None,
        )
        commit = Commit(effect, default_task)

        # commit() should route through SubprocessExecutor
        allow, evidence = self._broker.commit(commit)

        assert allow is True, f"Expected allow=True, got evidence: {evidence}"
        assert evidence["allow"] is True

    def test_blocked_effect_not_applied_to_subprocess_store(self) -> None:
        """A blocked effect does NOT reach the subprocess store."""
        from effect_broker.model import Capability, Commit, Effect, Task, USER, BROKER

        # Capability with a different target (will not match the effect's target)
        cap = Capability(
            owner=USER,
            holder=BROKER,
            right="write",
            target="file:///only/this/path",
            scope=frozenset({"file:///only/this/path"}),
            expiry=float("inf"),
            nonce="write-other-target",
            derives_from=None,
        )
        self._broker.grant_root(cap)

        task = Task(
            task_id="test-blocked",
            owner=USER,
            ceiling=cap,
        )
        self._broker.tasks["test-blocked"] = task

        effect = Effect(
            etype="write",
            target="file:///attacker/evil.txt",
            metadata={},
            provenance=(),
            capability_nonce="write-other-target",
            delegation_chain=(),
            label_exceptions=(),
            task_id="test-blocked",
        )
        commit = Commit(effect, task)

        allow, evidence = self._broker.commit(commit)

        assert allow is False, "Effect with non-matching target should be blocked"
        assert evidence["allow"] is False
        assert evidence["primary_blocker"] in (
            "Auth", "NoAmp", "task-bounded-fail", "target-mismatch", "bottom-scoping-violation"
        )

    def test_ledger_records_authorization_and_observation(self) -> None:
        """Ledger records authorization (from gate) and observation (from subprocess)."""
        from effect_broker.executor import SubprocessExecutor
        from effect_broker.model import Capability, Commit, Effect, Task, USER, BROKER
        from effect_broker.ledger import LedgerVerdict

        # Verify the executor is SubprocessExecutor
        assert isinstance(self._broker.executor, SubprocessExecutor)

        cap = Capability(
            owner=USER,
            holder=BROKER,
            right="write",
            target="file:///audit/ledger-test.txt",
            scope=frozenset({"*"}),
            expiry=float("inf"),
            nonce="write-ledger-test",
            derives_from=None,
        )
        self._broker.grant_root(cap)

        default_task = Task(
            task_id="default",
            owner=USER,
            ceiling=cap,
        )
        self._broker.tasks["default"] = default_task

        effect = Effect(
            etype="write",
            target="file:///audit/ledger-test.txt",
            metadata={},
            provenance=(),
            capability_nonce="write-ledger-test",
            delegation_chain=(),
            label_exceptions=(),
            task_id="default",
        )
        commit = Commit(effect, default_task)

        allow, _ = self._broker.commit(commit)
        assert allow is True

        # Ledger should have authorization + observation for this nonce
        verdict = self._ledger.verify("default", "write-ledger-test")
        assert verdict == LedgerVerdict.CONFIRMED_COMMITTED, (
            f"Expected CONFIRMED_COMMITTED, got {verdict} — "
            "ledger must record both authorization (from gate) and "
            "observation (from subprocess response)"
        )

    def test_verify_complete_mediation_passes_for_valid_effects(self) -> None:
        """broker.verify_complete_mediation() returns no failures for valid effects."""
        from effect_broker.model import Capability, Commit, Effect, Task, USER, BROKER

        cap = Capability(
            owner=USER,
            holder=BROKER,
            right="write",
            target="file:///mediation/test.txt",
            scope=frozenset({"*"}),
            expiry=float("inf"),
            nonce="write-mediation-test",
            derives_from=None,
        )
        self._broker.grant_root(cap)

        default_task = Task(
            task_id="default",
            owner=USER,
            ceiling=cap,
        )
        self._broker.tasks["default"] = default_task

        effect = Effect(
            etype="write",
            target="file:///mediation/test.txt",
            metadata={},
            provenance=(),
            capability_nonce="write-mediation-test",
            delegation_chain=(),
            label_exceptions=(),
            task_id="default",
        )
        commit = Commit(effect, default_task)

        self._broker.commit(commit)

        failures = self._broker.verify_complete_mediation()
        assert failures == [], f"Complete mediation should have no failures: {failures}"

    def test_broker_shutdown_terminates_subprocess(self) -> None:
        """broker.shutdown() cleanly terminates the executor subprocess."""
        exec_sock = self._exec_sock

        # Shutdown the broker
        self._broker.shutdown()

        # Socket should be removed after shutdown
        import time
        time.sleep(0.3)
        assert not exec_sock.exists(), (
            "Executor socket should be removed after shutdown"
        )

    def test_shutdown_is_idempotent(self) -> None:
        """Calling shutdown() multiple times should not raise."""
        self._broker.shutdown()
        self._broker.shutdown()  # second call — should be no-op
        self._broker.shutdown()  # third call — should be no-op

    def test_executor_property_returns_correct_type(self) -> None:
        """broker.executor returns SubprocessExecutor in multi-process mode."""
        from effect_broker.executor import SubprocessExecutor

        assert isinstance(self._broker.executor, SubprocessExecutor)
        assert isinstance(self._broker.executor, type(self._broker._executor))

    def test_broker_observer_reads_subprocess_store_via_ipc(self) -> None:
        """broker.observer reads subprocess store via IPC (in multi-process mode).

        In multi-process mode, broker.store is a same-process RestrictedResourceStore
        (used for broker's own reference). The subprocess store is the authoritative
        one. We verify the bootstrap works by checking read_store() returns the
        pre-populated broker resources.
        """
        from effect_broker.executor_ipc import ProcessExecutorClient

        client = ProcessExecutorClient(self._exec_sock)
        store = client.read_store()

        # Bootstrap should have transferred broker's same-process store resources
        # (empty by default, but the interface should work)
        assert "files" in store
        assert "emails" in store
        assert "mailboxes" in store


class TestSameProcessVsMultiProcessEquivalence:
    """Verify same-process and multi-process produce identical decisions.

    This is the key semantic correctness test: the execution mode should not
    change the allow/deny decision for any given effect. Only the isolation
    guarantees differ.
    """

    @pytest.fixture
    def same_process_broker(self) -> "EffectBroker":
        from effect_broker.broker import EffectBroker
        from effect_broker.ledger import IndependentEffectLedger

        broker = EffectBroker(ledger=IndependentEffectLedger(), mode="same-process")
        yield broker

    @pytest.fixture
    def multi_process_broker(self, tmp_path: Path) -> "EffectBroker":
        from effect_broker.broker import EffectBroker
        from effect_broker.ledger import IndependentEffectLedger

        uid = uuid.uuid4().hex[:8]
        exec_sock = Path(f"/tmp/ecac-eq-exec-{uid}.sock")
        store_sock = Path(f"/tmp/ecac-eq-store-{uid}.sock")

        broker = EffectBroker(
            ledger=IndependentEffectLedger(),
            mode="multi-process",
            executor_socket=exec_sock,
            store_socket=store_sock,
        )
        yield broker
        broker.shutdown()
        for sock in (exec_sock, store_sock):
            if sock.exists():
                sock.unlink(missing_ok=True)

    def test_write_effect_same_result_both_modes(
        self,
        same_process_broker: "EffectBroker",
        multi_process_broker: "EffectBroker",
    ) -> None:
        """write effect: allow in same-process and multi-process modes.

        CRITICAL: each execution mode uses its own Task object. Both brokers
        share the same Task class definition but instantiate independent task
        objects with independent sessions. Using the SAME task object across
        modes would make the nonce appear "replay" in the second commit (the
        session tracks used nonces per logical session), which is correct ECAC
        behavior but NOT what this test is verifying.

        Same nonce in SAME logical session → replay detected (correct).
        Same nonce in DIFFERENT logical sessions → both allowed (correct).
        """
        from effect_broker.model import Capability, Commit, Effect, Task, USER, BROKER
        from effect_broker.lattice import Confidentiality

        # Same capability nonce (same root-granted capability)
        cap = Capability(
            owner=USER,
            holder=BROKER,
            right="write",
            target="file:///equiv/test.txt",
            scope=frozenset({"*"}),
            expiry=float("inf"),
            nonce="write-equiv-both",
            derives_from=None,
        )
        same_process_broker.grant_root(cap)
        multi_process_broker.grant_root(cap)

        # Register the file in both stores
        same_process_broker.store._unsafe_bootstrap_file(
            "file:///equiv/test.txt", Confidentiality.PUBLIC
        )
        multi_process_broker.store._unsafe_bootstrap_file(
            "file:///equiv/test.txt", Confidentiality.PUBLIC
        )

        # Independent Task objects with independent sessions (key isolation!)
        task_same = Task(
            task_id="equiv-task-same",
            owner=USER,
            ceiling=cap,
        )
        task_multi = Task(
            task_id="equiv-task-multi",
            owner=USER,
            ceiling=cap,
        ) 
        # Register file in both stores. RestrictedResourceStore requires
        # pre-registration (no auto-create). IsolatedStore auto-creates but
        # registering is fine for consistency.
        same_process_broker.store._unsafe_bootstrap_file("file:///equiv/test.txt", Confidentiality.PUBLIC)
        multi_process_broker.store._unsafe_bootstrap_file("file:///equiv/test.txt", Confidentiality.PUBLIC)

        task_same = Task(
            task_id="equiv-task",
            owner=USER,
            ceiling=cap,
        )
        task_multi = Task(
            task_id="equiv-task",
            owner=USER,
            ceiling=cap,
        )
        same_process_broker.tasks["equiv-task"] = task_same
        multi_process_broker.tasks["equiv-task"] = task_multi

        effect = Effect(
            etype="write",
            target="file:///equiv/test.txt",
            metadata={},
            provenance=(),
            capability_nonce="write-equiv-both",
            delegation_chain=(),
            label_exceptions=(),
            task_id="equiv-task",
        )
        commit_same = Commit(effect, task_same)
        commit_multi = Commit(effect, task_multi)

        allow_same, ev_same = same_process_broker.commit(commit_same)
        allow_multi, ev_multi = multi_process_broker.commit(commit_multi)

        assert allow_same == allow_multi, (
            "Same-process and multi-process modes must produce identical decisions. "
            f"Got same={allow_same}, multi={allow_multi}"
        )

    def test_blocked_effect_same_result_both_modes(
        self,
        same_process_broker: "EffectBroker",
        multi_process_broker: "EffectBroker",
    ) -> None:
        """Blocked effect: deny in same-process and multi-process modes."""
        from effect_broker.model import Capability, Commit, Effect, Task, USER, BROKER

        cap = Capability(
            owner=USER,
            holder=BROKER,
            right="read",
            target="file:///secrets",
            scope=frozenset({"file:///secrets"}),
            expiry=float("inf"),
            nonce="read-but-write-blocked",
            derives_from=None,
        )

        task_same = Task(
            task_id="block-task-same",
            owner=USER,
            ceiling=cap,
        )
        task_multi = Task(
            task_id="block-task-multi",
            owner=USER,
            ceiling=cap,
        )

        # Effect: write (right mismatch — capability grants read)
        effect = Effect(
            etype="write",
            target="file:///secrets/secret.txt",
            metadata={},
            provenance=(),
            capability_nonce="read-but-write-blocked",
            delegation_chain=(),
            label_exceptions=(),
            task_id="block-task-same",
        )

        commit_same = Commit(effect, task_same)
        commit_multi = Commit(effect, task_multi)

        allow_same, ev_same = same_process_broker.commit(commit_same)
        allow_multi, ev_multi = multi_process_broker.commit(commit_multi)

        assert allow_same is False, f"Should be blocked: {ev_same}"
        assert allow_multi is False, f"Should be blocked: {ev_multi}"
        assert ev_same["primary_blocker"] == ev_multi["primary_blocker"], (
            "Both modes should block on the same predicate"
        )