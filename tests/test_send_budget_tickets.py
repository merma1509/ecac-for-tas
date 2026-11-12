"""the send budget must be reserved before execution, not after.

The defect: the gate checked `send_count < max` and the executor incremented
after a successful apply. Between those two points lies the whole execution, so
N concurrent sends all observed `count < max` and all proceeded. With
`max_sends=1`, five concurrent sends were all allowed.

The fix is a ticket reserved atomically inside the gate. A ticket counts against
the budget, so the second concurrent sender sees `1 in flight` and is blocked.
"""

from __future__ import annotations

import threading

from effect_broker.broker import EffectBroker
from effect_broker.executor import IsolatedExecutor
from effect_broker.model import (
    USER,
    Capability,
    Confidentiality,
    Data,
    Effect,
    Integrity,
    Session,
    Task,
)

_RECIPIENT = "bob@corp.com"


def _provenance(name: str) -> tuple[Data, ...]:
    return (Data(name, Confidentiality.INTERNAL, Integrity.USER, content=b"x"),)


def _setup(max_sends: int, senders: int) -> tuple[EffectBroker, IsolatedExecutor, Task]:
    """A broker whose store really holds the recipient, so sends can apply."""
    broker = EffectBroker(mode="same-process")
    executor = IsolatedExecutor(broker=broker)
    broker.store._unsafe_bootstrap_email(_RECIPIENT, "internal")

    ceiling = Capability(
        owner=USER, holder="EffectBroker", right="*", target="*",
        scope=frozenset({"*"}), expiry=float("inf"), nonce="ceiling",
    )
    session = Session(session_id="budget")
    session.set_max_sends(max_sends)
    task = Task(task_id="budget-task", owner=USER, ceiling=ceiling, session=session)
    broker.register_task(task)

    # One distinct send capability per attempt: the test is about the budget,
    # so it must not be blocked by replay protection instead.
    for i in range(senders):
        broker.grant_root(
            Capability(
                owner=USER, holder="Agent", right="send", target="*",
                scope=frozenset({"*"}), expiry=float("inf"),
                nonce=f"send-{i}:Agent:EffectBroker", task_id="budget-task",
            )
        )
    return broker, executor, task


def _send(i: int) -> Effect:
    return Effect(
        etype="send",
        target=_RECIPIENT,
        metadata={"subject": f"s{i}", "body": "b"},
        provenance=_provenance(f"p{i}"),
        capability_nonce=f"send-{i}:Agent:EffectBroker",
        delegation_chain=("Approver", "broker-shim"),
    )


class TestAtomicSendBudget:
    def test_concurrent_sends_cannot_oversubscribe_the_budget(self, monkeypatch) -> None:
        """max_sends=1 with 5 concurrent sends must allow exactly one.

        The defect window is the whole execution: the gate checked the count and
        the executor incremented it only after the send landed. So the test must
        hold one sender *inside* that window while the others reach the gate.
        Without the hold, the first send finishes before the second arrives and
        the race never happens -- the test would pass against the buggy code,
        which is why the hold is load-bearing (verified by mutation).
        """
        broker, executor, task = _setup(max_sends=1, senders=5)
        results: list[bool] = []

        in_apply = threading.Event()
        release_apply = threading.Event()
        original_apply = executor.apply_effect

        def held_apply(effect, tsk):  # type: ignore[no-untyped-def]
            in_apply.set()
            release_apply.wait(timeout=5)  # park inside the defect window
            return original_apply(effect, tsk)

        monkeypatch.setattr(executor, "apply_effect", held_apply)

        def attempt(i: int) -> None:
            allow, _ = executor.execute(broker._make_commit(_send(i), task_id="budget-task"))
            results.append(allow)

        first = threading.Thread(target=attempt, args=(0,))
        first.start()
        assert in_apply.wait(timeout=5), "first send never reached apply"

        # Now the remaining senders race while one send is in flight.
        others = [threading.Thread(target=attempt, args=(i,)) for i in range(1, 5)]
        for t in others:
            t.start()
        for t in others:
            t.join()

        release_apply.set()
        first.join()

        assert sum(results) == 1, f"budget of 1 admitted {sum(results)} sends"

    def test_sequential_sends_respect_the_budget(self) -> None:
        """The ticket mechanism must not break the simple sequential case."""
        broker, executor, task = _setup(max_sends=2, senders=3)
        allowed = [
            executor.execute(broker._make_commit(_send(i), task_id="budget-task"))[0]
            for i in range(3)
        ]
        assert allowed == [True, True, False], allowed


class TestTicketAccounting:
    def test_ticket_is_consumed_on_success(self) -> None:
        broker, executor, task = _setup(max_sends=2, senders=1)
        executor.execute(broker._make_commit(_send(0), task_id="budget-task"))
        assert task.session is not None
        assert task.session.send_count == 1
        assert task.session._send_tickets == {}, "ticket must not outlive the send"

    def test_ticket_is_released_on_failed_apply(self) -> None:
        """A send that never applied must not consume budget or leak a ticket."""
        broker, executor, task = _setup(max_sends=1, senders=1)
        # Point at a recipient the store does not know: apply_effect fails.
        broker.store = broker.store  # keep type checkers honest
        effect = Effect(
            etype="send", target="nobody@corp.com",
            metadata={"subject": "s", "body": "b"},
            provenance=_provenance("p"),
            capability_nonce="send-0:Agent:EffectBroker",
            delegation_chain=("Approver", "broker-shim"),
        )
        allow, _ = executor.execute(broker._make_commit(effect, task_id="budget-task"))
        assert allow is True, "the gate allows; the apply is what fails"
        assert task.session is not None
        assert task.session.send_count == 0, "failed send must not spend budget"
        assert task.session._send_tickets == {}, "failed send must not leak a ticket"

    def test_blocked_send_does_not_leak_a_ticket(self) -> None:
        """A gate denial after reservation must roll the ticket back."""
        broker, executor, task = _setup(max_sends=1, senders=1)
        first, _ = executor.execute(broker._make_commit(_send(0), task_id="budget-task"))
        assert first is True
        # Reuse the now-consumed nonce: Fresh blocks, and no ticket may remain.
        again, evidence = executor.execute(
            broker._make_commit(_send(0), task_id="budget-task")
        )
        assert again is False
        assert evidence["primary_blocker"] in {"Fresh", "NoAmp"}
        assert task.session is not None
        assert task.session._send_tickets == {}
