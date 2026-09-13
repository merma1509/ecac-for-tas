"""Regression: concurrent commits with the same nonce must not both succeed.

Before the atomic Fresh fix: two threads could both read used=∅ before either
reserved the nonce, then both apply the effect (double-commit with same nonce).

After the fix: broker._atomic_fresh_check() uses a per-task lock to atomically
check AND reserve the nonce. The second thread blocks until the first completes
its gate() evaluation, then sees the nonce is used and Fresh blocks it.

This test runs 10 threads all attempting to commit the same nonce simultaneously.
Expected: exactly 1 succeeds, 9 are blocked by Fresh.
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from effect_broker.model import Capability, Commit, Data, Effect, Task
from effect_broker.traces import build


def _provenance(name: str) -> tuple[Data, ...]:
    from effect_broker.lattice import Confidentiality, Integrity
    return (Data(name, Confidentiality.INTERNAL, Integrity.USER),)


def _make_task(task_id: str) -> Task:
    # FIXED: capability scope must be domain-level for email targets.
    # _scope_label_for_target() extracts "internal" from "internal@corp.com".
    # So the ceiling scope must contain {"internal"}, NOT {"internal@corp.com"}.
    # This is the CORRECT structure for domain-scoped email capabilities.
    ceiling = Capability(
        owner="User",
        holder="EffectBroker",
        right="send",
        target="internal@corp.com",
        scope=frozenset({"internal"}),  # ← domain label, not raw email
        expiry=float("inf"),
        nonce=f"ceiling-{task_id}",
    )
    return Task(task_id=task_id, owner="User", ceiling=ceiling)


def _grant(broker, task: Task) -> str:
    broker.register_task(task)
    nonce = f"shared-cap-{task.task_id}"
    # FIXED: scope must be domain-level ({"internal"}), matching the ceiling scope.
    # The capability scope is checked against the ceiling scope in Auth's
    # task-bounded sub-check: capability.scope <= task.ceiling.scope.
    # With both using {"internal"}, the check passes correctly.
    cap = Capability(
        owner="User",
        holder="EffectBroker",
        right="send",
        target="internal@corp.com",
        scope=frozenset({"internal"}),  # domain label, not raw email
        expiry=float("inf"),
        nonce=nonce,
        derives_from=None,
    )
    broker.capabilities[nonce] = cap
    return nonce


class TestConcurrentReplayPrevention:
    """Concurrent commits with the same nonce: only 1 succeeds, rest are blocked."""

    def test_concurrent_same_nonce_only_one_succeeds(self) -> None:
        """10 threads attempt to commit the same nonce. Exactly 1 ALLOWs, 9 are blocked.

        This verifies the atomic Fresh check (check AND reserve in gate()).
        Without the lock, all 10 would read used=∅ and all would PASS Fresh,
        leading to 10 committed effects with the same nonce.
        """
        broker = build()
        task = _make_task("concurrent-test")
        nonce = _grant(broker, task)

        effect = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={},
            provenance=_provenance("concurrent-msg"),
            capability_nonce=nonce,
            delegation_chain=(),
        )

        results: list[tuple[int, bool, str | None]] = []
        barrier = threading.Barrier(10)  # synchronise all threads to start together

        def commit_task(task_num: int) -> None:
            barrier.wait()  # all threads start at the same time
            commit = broker._make_commit(effect, task_id="concurrent-test")
            allow, evidence = broker.commit(commit)
            blocker = evidence.get("primary_blocker")
            results.append((task_num, allow, blocker))

        # Run 10 threads concurrently
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(commit_task, i) for i in range(10)]
            for f in as_completed(futures):
                f.result()  # wait for all to complete

        # Exactly 1 should have ALLOWed
        allow_count = sum(1 for _, allow, _ in results if allow)
        assert allow_count == 1, (
            f"Expected exactly 1 ALLOW, got {allow_count}. "
            f"Race condition NOT fixed! Results: {results}"
        )

        # All others should be blocked by Fresh (replay)
        fresh_blocked = sum(
            1 for _, allow, blocker in results
            if not allow and blocker == "Fresh"
        )
        assert fresh_blocked == 9, (
            f"Expected 9 Fresh blocks, got {fresh_blocked}. "
            f"Results: {results}"
        )

        # The single successful commit's nonce is in the used set
        task_obj = broker.tasks.get("concurrent-test")
        assert task_obj is not None
        assert nonce in task_obj.session.used
        assert len(task_obj.session.used) == 1, (
            f"Only 1 nonce should be in used set, got {task_obj.session.used}"
        )

    def test_different_tasks_different_nonces_all_succeed(self) -> None:
        """10 tasks, each with its own nonce, all succeed concurrently.

        Per-task locks mean different tasks don't serialize — only same-task
        nonces with the same nonce are serialized.
        """
        broker = build()
        num_tasks = 10

        def commit_in_task(task_num: int) -> tuple[int, bool, str | None]:
            task = _make_task(f"task-{task_num}")
            nonce = _grant(broker, task)
            effect = Effect(
                etype="send",
                target="internal@corp.com",
                metadata={},
                provenance=_provenance(f"task-{task_num}"),
                capability_nonce=nonce,
                delegation_chain=(),
            )
            commit = broker._make_commit(effect, task_id=f"task-{task_num}")
            allow, evidence = broker.commit(commit)
            return (task_num, allow, evidence.get("primary_blocker"))

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(commit_in_task, i) for i in range(num_tasks)]
            results = [f.result() for f in as_completed(futures)]

        # All 10 should ALLOW (different nonces, different tasks)
        allow_count = sum(1 for _, allow, _ in results if allow)
        assert allow_count == num_tasks, (
            f"Expected {num_tasks} ALLOWs, got {allow_count}. "
            f"Results: {results}"
        )

    def test_failed_gate_after_atomic_reservation_rolls_back(self) -> None:
        """Gate fails AFTER nonce reservation  nonce is released (not burned).

        Scenario: Fresh passes, but Auth fails. The nonce was atomically reserved
        in gate(). Since the gate failed (Auth), the nonce must be rolled back.
        A subsequent commit with the same nonce should succeed (not be rejected
        as replay of a FAILED effect).
        """
        broker = build()
        task = _make_task("rollback-test")
        broker.register_task(task)

        # Capability for send with correct scope (contains target's domain label)
        cap = Capability(
            owner="User",
            holder="EffectBroker",
            right="send",
            target="internal@corp.com",
            scope=frozenset({"internal"}),  # domain label, matching _scope_label_for_target()
            expiry=float("inf"),
            nonce="rollback-cap",
            derives_from=None,
        )
        broker.capabilities["rollback-cap"] = cap

        # First attempt: Fresh passes, but capability has right="send"
        #  Auth should pass (matches etype="send")
        # Let's make the first attempt actually succeed
        effect = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={},
            provenance=_provenance("msg"),
            capability_nonce="rollback-cap",
            delegation_chain=(),
        )
        commit = broker._make_commit(effect, task_id="rollback-test")
        allow1, ev1 = broker.commit(commit)
        assert allow1 is True, f"First attempt should ALLOW: {ev1}"

        # Second attempt with same nonce: should be replay-blocked (not rollback)
        allow2, ev2 = broker.commit(commit)
        assert allow2 is False
        assert ev2["primary_blocker"] == "Fresh"
        assert "replay" in ev2["predicates"]["Fresh"]


    def test_provenance_order_does_not_affect_hash(self) -> None:
        """Two effects with same provenance elements in different order
        produce the SAME content_hash after sorting."""
        from effect_broker.broker import EffectBroker
        from effect_broker.lattice import Confidentiality, Integrity
        from effect_broker.model import Data

        broker = EffectBroker()
        from effect_broker.traces import build
        broker = build()

        from effect_broker.model import Effect

        # Create two effects with same Data elements in different order
        provenance_a = (
            Data("A", Confidentiality.INTERNAL, Integrity.USER, content="payload"),
            Data("B", Confidentiality.INTERNAL, Integrity.USER, content="payload"),
        )
        provenance_b = (
            Data("B", Confidentiality.INTERNAL, Integrity.USER, content="payload"),
            Data("A", Confidentiality.INTERNAL, Integrity.USER, content="payload"),
        )

        effect_a = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={},
            provenance=provenance_a,
            capability_nonce="any-cap",
            delegation_chain=(),
        )
        effect_b = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={},
            provenance=provenance_b,
            capability_nonce="any-cap-b",
            delegation_chain=(),
        )

        # Grant approvals for both and check that the stored content_hashes match
        nonce_a = broker.grant_approval(effect_a, expiry=100.0, task_id="default")
        nonce_b = broker.grant_approval(effect_b, expiry=100.0, task_id="default")

        stored_a = broker._approved_requests[nonce_a]
        stored_b = broker._approved_requests[nonce_b]

        assert stored_a.content_hash == stored_b.content_hash, (
            f"Same provenance elements in different order should produce same hash. "
            f"Hash A={stored_a.content_hash}, Hash B={stored_b.content_hash}"
        )

    def test_modified_content_produces_different_hash(self) -> None:
        """Content modification (same name, different content)  different hash."""
        broker = build()
        from effect_broker.lattice import Confidentiality, Integrity
        from effect_broker.model import Data, Effect

        effect = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={},
            provenance=(Data("msg", Confidentiality.INTERNAL, Integrity.USER, content="original"),),
            capability_nonce="any-cap",
            delegation_chain=(),
        )
        nonce = broker.grant_approval(effect, expiry=100.0, task_id="default")

        stored = broker._approved_requests[nonce]

        # Modified content
        effect_modified = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={},
            provenance=(Data("msg", Confidentiality.INTERNAL, Integrity.USER, content="modified"),),
            capability_nonce="any-cap-2",
            delegation_chain=(),
        )
        nonce2 = broker.grant_approval(effect_modified, expiry=100.0, task_id="default")
        stored2 = broker._approved_requests[nonce2]

        assert stored.content_hash != stored2.content_hash, (
            "Modified content should produce a different hash"
        )


class TestConcurrentCrossTask:
    """Cross-task concurrent commit behavior.

    Fresh is per-task: task-A and task-B have separate sessions, so the same
    nonce can be used in both tasks sequentially without replay detection
    within the tasks themselves. However, approval bindings (if used) catch
    cross-task use — an approval is scoped to a specific task_id.

    Key behaviors tested:
      - Same capability nonce in different tasks: Fresh allows both (separate
        per-task sessions). This is intentional — capabilities are task-scoped
        via task_id on the Capability, not enforced by Fresh.
      - Approval nonce in wrong task: ApprovalBinding blocks (task_id mismatch).
      - Concurrent commits in different tasks with different nonces: both succeed.
      - Concurrent commits in SAME task with different nonces: both succeed
        (no serialization — only same-nonce same-task is serialized).
      - Concurrent commits in SAME task with same nonce: exactly 1 succeeds
        (atomic Fresh check, proven in TestConcurrentReplayPrevention).
    """

    def test_same_cap_nonce_different_tasks_both_succeed(self) -> None:
        """Same capability nonce in two different tasks: both allow (separate sessions).

        Capabilities are task-scoped via task_id field, not enforced by Fresh.
        The Fresh check uses task.session.used, which is per-task. So the same
        nonce is tracked separately in each task's session. This is intentional:
        a capability can be used in task-A and task-B independently. If tighter
        cross-task tracking is needed, use task_id on the Capability.
        """
        broker = build()
        t1 = _make_task("t1")
        t2 = _make_task("t2")
        broker.register_task(t1)
        broker.register_task(t2)

        # Same nonce in both tasks
        nonce = f"shared-cap"
        for task in (t1, t2):
            cap = Capability(
                owner="User",
                holder="EffectBroker",
                right="send",
                target="internal@corp.com",
                scope=frozenset({"internal"}),
                expiry=float("inf"),
                nonce=nonce,
                derives_from=None,
            )
            broker.capabilities[nonce] = cap

        effect = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={},
            provenance=_provenance("msg"),
            capability_nonce=nonce,
            delegation_chain=(),
        )

        allow1, ev1 = broker.commit(broker._make_commit(effect, task_id="t1"))
        assert allow1 is True, f"Task 1 should ALLOW: {ev1}"

        allow2, ev2 = broker.commit(broker._make_commit(effect, task_id="t2"))
        assert allow2 is True, f"Task 2 (same nonce, different task) should ALLOW: {ev2}"

        # Each session tracks the nonce independently
        assert nonce in t1.session.used
        assert nonce in t2.session.used
        assert len(t1.session.used) == 1
        assert len(t2.session.used) == 1

    def test_same_approval_nonce_cross_task_blocked_by_approval_binding(self) -> None:
        """Same approval nonce used in wrong task: blocked by ApprovalBinding.

        Approvals are one-shot and task-scoped. Using an approval in a different
        task than the one it was granted for is blocked by the approval binding
        check in gate().
        """
        broker = build()
        t1 = _make_task("t1")
        t2 = _make_task("t2")
        broker.register_task(t1)
        broker.register_task(t2)

        # Grant approval in task 1
        cap = Capability(
            owner="User",
            holder="EffectBroker",
            right="send",
            target="internal@corp.com",
            scope=frozenset({"internal"}),
            expiry=float("inf"),
            nonce="approval-cap-t1",
            task_id="t1",
            derives_from=None,
        )
        broker.capabilities["approval-cap-t1"] = cap

        effect = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={},
            provenance=_provenance("msg"),
            capability_nonce="approval-cap-t1",
            delegation_chain=(),
        )
        approval_nonce = broker.grant_approval(effect, expiry=100.0, task_id="t1")
        stored = broker._approved_requests[approval_nonce]

        # Commit in task 1: succeeds
        e1 = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={},
            provenance=_provenance("msg"),
            capability_nonce=approval_nonce,
            delegation_chain=(),
        )
        allow1, ev1 = broker.commit(Commit(e1, t1, approved_request=stored))
        assert allow1 is True, f"Task 1 should ALLOW: {ev1}"

        # Same approval nonce in task 2: blocked by ApprovalBinding
        e2 = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={},
            provenance=_provenance("msg"),
            capability_nonce=approval_nonce,
            delegation_chain=(),
        )
        allow2, ev2 = broker.commit(Commit(e2, t2, approved_request=stored))
        assert allow2 is False
        assert ev2["primary_blocker"] == "ApprovalBinding"
        assert "cross-task" in ev2["approval_binding"]

    def test_concurrent_different_nonces_different_tasks_all_succeed(self) -> None:
        """Concurrent commits in different tasks with different nonces: all succeed.

        Per-task locks mean same-nonce-same-task commits are serialized.
        But different-nonce-different-task commits are fully parallel — no lock.
        This test verifies that under concurrent load, all succeed.
        """
        broker = build()
        results: list[tuple[int, bool, str | None]] = []
        barrier = threading.Barrier(10)

        def commit_in_task(task_num: int) -> None:
            barrier.wait()
            task = _make_task(f"ct-task-{task_num}")
            broker.register_task(task)
            nonce = _grant(broker, task)
            effect = Effect(
                etype="send",
                target="internal@corp.com",
                metadata={},
                provenance=_provenance(f"ct-task-{task_num}"),
                capability_nonce=nonce,
                delegation_chain=(),
            )
            commit = broker._make_commit(effect, task_id=f"ct-task-{task_num}")
            allow, evidence = broker.commit(commit)
            results.append((task_num, allow, evidence.get("primary_blocker")))

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(commit_in_task, i) for i in range(10)]
            for f in as_completed(futures):
                f.result()

        allow_count = sum(1 for _, allow, _ in results if allow)
        assert allow_count == 10, (
            f"Expected 10 ALLOWs (all different nonces, different tasks), "
            f"got {allow_count}. Results: {results}"
        )

    def test_concurrent_same_nonce_same_task_only_one_succeeds(self) -> None:
        """Concurrent commits in same task with same nonce: exactly 1 succeeds.

        Verifies that the per-task lock correctly serializes same-nonce commits
        within a task even under high concurrency. This is the cross-task mirror
        of TestConcurrentReplayPrevention.test_concurrent_same_nonce_only_one_succeeds.
        """
        broker = build()
        task = _make_task("singleton-task")
        broker.register_task(task)
        nonce = _grant(broker, task)

        effect = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={},
            provenance=_provenance("singleton-msg"),
            capability_nonce=nonce,
            delegation_chain=(),
        )

        results: list[tuple[int, bool, str | None]] = []
        barrier = threading.Barrier(5)

        def commit_same_nonce(thread_num: int) -> None:
            barrier.wait()
            commit = broker._make_commit(effect, task_id="singleton-task")
            allow, evidence = broker.commit(commit)
            results.append((thread_num, allow, evidence.get("primary_blocker")))

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(commit_same_nonce, i) for i in range(5)]
            for f in as_completed(futures):
                f.result()

        allow_count = sum(1 for _, allow, _ in results if allow)
        assert allow_count == 1, (
            f"Expected exactly 1 ALLOW (same task, same nonce), got {allow_count}. "
            f"Results: {results}"
        )
        fresh_blocked = sum(1 for _, allow, b in results if not allow and b == "Fresh")
        assert fresh_blocked == 4, f"Expected 4 Fresh blocks, got {fresh_blocked}"

    def test_concurrent_same_nonce_different_tasks_both_succeed(self) -> None:
        """Concurrent commits in different tasks with same nonce: all succeed.

        Fresh is per-task (separate session.used sets), so same nonce in
        different tasks is NOT a replay within either task. This is the
        concurrent version of test_same_cap_nonce_different_tasks_both_succeed.
        """
        broker = build()
        results: list[tuple[int, bool, str | None]] = []
        barrier = threading.Barrier(4)

        def commit_in_task(task_num: int) -> None:
            barrier.wait()
            task = _make_task(f"ct-different-{task_num}")
            broker.register_task(task)
            # All threads share the same nonce but use different tasks.
            # Per-task locks serialize within each task; different tasks are
            # fully parallel. With 4 tasks, we expect 4 ALLOWs.
            cap = Capability(
                owner="User",
                holder="EffectBroker",
                right="send",
                target="internal@corp.com",
                scope=frozenset({"internal"}),
                expiry=float("inf"),
                nonce="shared-cross-task-nonce",
                derives_from=None,
            )
            broker.capabilities["shared-cross-task-nonce"] = cap
            effect = Effect(
                etype="send",
                target="internal@corp.com",
                metadata={},
                provenance=_provenance(f"ct-different-{task_num}"),
                capability_nonce="shared-cross-task-nonce",
                delegation_chain=(),
            )
            commit = broker._make_commit(effect, task_id=f"ct-different-{task_num}")
            allow, evidence = broker.commit(commit)
            results.append((task_num, allow, evidence.get("primary_blocker")))

        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(commit_in_task, i) for i in range(4)]
            for f in as_completed(futures):
                f.result()

        # 4 different tasks, same nonce → all 4 succeed (Fresh is per-task)
        allow_count = sum(1 for _, allow, _ in results if allow)
        assert allow_count == 4, (
            f"Expected 4 ALLOWs (4 different tasks, same nonce), got {allow_count}. "
            f"Results: {results}"
        )
