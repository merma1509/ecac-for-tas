import pytest

from effect_broker.lattice import Confidentiality, Integrity
from effect_broker.model import Capability, Data, Effect, Task
from effect_broker.traces import build


def _provenance(name: str, content: str = "") -> tuple[Data, ...]:
    return (Data(name, Confidentiality.INTERNAL, Integrity.USER, content=content),)


def _make_task(task_id: str, live: bool = True, ceiling_right: str = "send") -> Task:
    """Create a task with the specified session.live state and ceiling."""
    ceiling = Capability(
        owner="User",
        holder="EffectBroker",
        right=ceiling_right,
        target="*",
        scope=frozenset({"*"}),  # permissive scope — tests focus on session.live
        expiry=float("inf"),
        nonce=f"ceil-{task_id}",
    )
    task = Task(task_id=task_id, owner="User", ceiling=ceiling)
    if not live:
        assert task.session is not None
        task.session.live = False
    return task


def _grant(broker, task: Task, etype: str, target: str) -> str:
    """Grant a root-anchored capability in the task."""
    broker.register_task(task)
    nonce = f"cap-{task.task_id}-{etype}"
    cap = Capability(
        owner="User",
        holder="EffectBroker",
        right=etype,
        target=target,
        scope=frozenset({"*"}),
        expiry=float("inf"),
        nonce=nonce,
        derives_from=None,
    )
    broker.capabilities[nonce] = cap
    return nonce


class TestSessionLiveFalseBlocks:
    """FIXED: Session.live=False blocks all commits in this task (Fresh)."""

    def test_closed_session_blocks_commit(self) -> None:
        broker = build()
        task = _make_task("default", live=False)  # session is dead
        broker.register_task(task)
        nonce = _grant(broker, task, "send", "internal@corp.com")

        effect = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={},
            provenance=_provenance("msg"),
            capability_nonce=nonce,
            delegation_chain=(),
        )
        commit = broker._make_commit(effect, task_id="default")
        allow, evidence = broker.commit(commit)

        assert allow is False
        assert evidence["primary_blocker"] == "Fresh"
        assert "session-closed" in evidence["predicates"]["Fresh"]
        assert len(broker.store.effects_log) == 0

    def test_closed_session_blocks_even_with_valid_capability(self) -> None:
        broker = build()
        task = _make_task("default", live=False, ceiling_right="write")
        broker.register_task(task)
        nonce = _grant(broker, task, "write", "file:///reports")

        effect = Effect(
            etype="write",
            target="file:///reports",
            metadata={},
            provenance=_provenance("doc"),
            capability_nonce=nonce,
            delegation_chain=(),
        )
        commit = broker._make_commit(effect, task_id="default")
        allow, evidence = broker.commit(commit)

        assert allow is False
        assert evidence["primary_blocker"] == "Fresh"
        assert "session-closed" in evidence["predicates"]["Fresh"]

    def test_live_session_allows_commit(self) -> None:
        broker = build()
        task = _make_task("default", live=True)
        broker.register_task(task)
        nonce = _grant(broker, task, "send", "internal@corp.com")

        effect = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={},
            provenance=_provenance("msg"),
            capability_nonce=nonce,
            delegation_chain=(),
        )
        commit = broker._make_commit(effect, task_id="default")
        allow, evidence = broker.commit(commit)

        assert allow is True, f"Live session should ALLOW. Evidence: {evidence}"
        assert evidence["primary_blocker"] is None
        assert len(broker.store.effects_log) == 1

    def test_closing_task_a_does_not_affect_task_b(self) -> None:
        broker = build()
        task_a = _make_task("task-a", live=False)
        task_b = _make_task("task-b", live=True)
        broker.register_task(task_a)
        broker.register_task(task_b)

        nonce_a = _grant(broker, task_a, "send", "internal@corp.com")
        nonce_b = _grant(broker, task_b, "send", "internal@corp.com")

        effect_a = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={},
            provenance=_provenance("msg-a"),
            capability_nonce=nonce_a,
            delegation_chain=(),
        )
        allow_a, ev_a = broker.commit(broker._make_commit(effect_a, task_id="task-a"))
        assert allow_a is False
        assert "session-closed" in ev_a["predicates"]["Fresh"]

        effect_b = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={},
            provenance=_provenance("msg-b"),
            capability_nonce=nonce_b,
            delegation_chain=(),
        )
        allow_b, ev_b = broker.commit(broker._make_commit(effect_b, task_id="task-b"))
        assert allow_b is True, f"Closing task-A should NOT affect task-B. Evidence: {ev_b}"

        assert len(broker.store.effects_log) == 1
        assert broker.store.effects_log[0][0] == "send"

    def test_close_then_reopen_task(self) -> None:
        """FIXED: once a session is closed, it CANNOT be reopened.

        This enforces that "closed" is terminal — the task's authority ceiling
        is invalidated until a new Task with a fresh Session is registered.
        Trying to reopen a closed session raises ValueError.
        """
        broker = build()
        task = _make_task("default", live=False)  # start closed
        broker.register_task(task)
        nonce = _grant(broker, task, "send", "internal@corp.com")

        effect = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={},
            provenance=_provenance("msg"),
            capability_nonce=nonce,
            delegation_chain=(),
        )

        # 1. Closed: BLOCK
        allow1, ev1 = broker.commit(broker._make_commit(effect, task_id="default"))
        assert allow1 is False
        assert "session-closed" in ev1["predicates"]["Fresh"]

        # 2. Try to re-open the session — should raise ValueError (terminal closure)
        with pytest.raises(ValueError, match="cannot be reopened"):
            task.session.live = True

        # 3. Still closed: BLOCK
        allow3, ev3 = broker.commit(broker._make_commit(effect, task_id="default"))
        assert allow3 is False
        assert "session-closed" in ev3["predicates"]["Fresh"]

        # 4. Register a NEW task with a fresh session: ALLOW
        new_task = _make_task("new-session", live=True)
        broker.register_task(new_task)
        new_nonce = _grant(broker, new_task, "send", "internal@corp.com")
        new_effect = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={},
            provenance=_provenance("msg-new-session"),
            capability_nonce=new_nonce,
            delegation_chain=(),
        )
        allow4, ev4 = broker.commit(broker._make_commit(new_effect, task_id="new-session"))
        assert allow4 is True, f"New task with fresh session should ALLOW. Evidence: {ev4}"

    def test_reopen_with_replayed_nonce(self) -> None:
        """Replay is detected within a live session. Closing the session
        blocks all commits (session-closed), not replay. After closure,
        re-registration is required (cannot reopen the same session).
        """
        broker = build()
        task = _make_task("default", live=True)
        broker.register_task(task)
        nonce = _grant(broker, task, "send", "internal@corp.com")

        effect = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={},
            provenance=_provenance("msg"),
            capability_nonce=nonce,
            delegation_chain=(),
        )

        # First use: ALLOW (live session)
        allow1, _ = broker.commit(broker._make_commit(effect, task_id="default"))
        assert allow1 is True

        # Close the session: subsequent commits blocked by session-closed, not replay
        task.session.live = False

        # Second use with SAME nonce: Fresh BLOCKs (session-closed)
        allow2, ev2 = broker.commit(broker._make_commit(effect, task_id="default"))
        assert allow2 is False
        # Session-closed is the primary blocker (closed session, not replay)
        assert ev2["primary_blocker"] == "Fresh"
        assert "session-closed" in ev2["predicates"]["Fresh"]

        # Trying to reopen after close: ValueError
        with pytest.raises(ValueError, match="cannot be reopened"):
            task.session.live = True

    def test_session_close_with_different_tasks_per_broker(self) -> None:
        """Two tasks on the SAME broker: closing one does NOT affect the other.
        Sessions are per-task (separate lock + used set), so closing task-A
        does not affect task-B's nonce reservations or session state.
        """
        broker = build()
        task_closed = _make_task("session-closed-task", live=False, ceiling_right="read")
        task_open = _make_task("session-open-task", live=True, ceiling_right="read")
        broker.register_task(task_closed)
        broker.register_task(task_open)

        nonce_closed = _grant(broker, task_closed, "read", "file:///reports")
        nonce_open = _grant(broker, task_open, "read", "file:///reports")

        for task_id, nonce, expected in [
            ("session-closed-task", nonce_closed, False),
            ("session-open-task", nonce_open, True),
        ]:
            effect = Effect(
                etype="read",
                target="file:///reports",
                metadata={},
                provenance=_provenance(f"msg-{task_id}"),
                capability_nonce=nonce,
                delegation_chain=(),
            )
            allow, ev = broker.commit(broker._make_commit(effect, task_id=task_id))
            assert allow is expected, (
                f"Task {task_id}: expected allow={expected}, got allow={allow}. "
                f"Evidence: {ev}"
            )

    def test_cannot_reopen_a_closed_session(self) -> None:
        """Explicit test: once live=False, live=True raises ValueError."""
        broker = build()
        task = _make_task("default", live=True)
        broker.register_task(task)

        # Close it
        task.session.live = False
        assert task.session.live is False
        assert task.session._ever_closed is True

        # Reopen attempt raises
        with pytest.raises(ValueError, match="cannot be reopened"):
            task.session.live = True
