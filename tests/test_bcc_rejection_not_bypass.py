"""Regression: a rejected recipient is not a BCC bypass.

The bug this pins
-----------------
Two halves of the same confusion about what "BCC detected" means.

`executor_subprocess.py` (`real_smtp_probe`, the multi-process path) built:

    for rcpt in recipients:
        code, _ = smtp.rcpt(rcpt)
        if code == 250: actual_accepted.append(rcpt)
        else:           bcc_detected.append(rcpt)   # <-- rejections

So `bcc_detected` held the addresses the MTA REFUSED, while `shim_email.send()`
believed it held undeclared ones. Any ordinary delivery failure — no such
mailbox, greylisting, a full user — became "BCC bypass detected", and the send
was refused before delivery. The error even named an address the tool HAD
declared:

    MTA accepted frozenset({'budget@corp.com'}) which are not in declared
    set frozenset({'internal@corp.com', 'budget@corp.com'})

`shim_email.py` (`_smtp_probe`, the same-process path) avoided that inversion but
computed `actual_accepted - declared_set` while probing only `declared_set` — a
difference that is empty by construction. It read like a real check and could
never fire, so the shim advertised a guarantee it did not provide.

The definition is the envelope's: BCC = accepted minus declared.
"""

from __future__ import annotations

import time
from typing import Any

import pytest


class _PickyMTA:
    """Accepts only addresses containing 'internal'; refuses everything else."""

    def __init__(self) -> None:
        self.rcpt_log: list[str] = []

    async def handle_RCPT(  # noqa: N802 - aiosmtpd hook name
        self, session: Any, envelope: Any, *args: Any
    ) -> str:
        address = args[1] if len(args) >= 2 else str(args[0])
        self.rcpt_log.append(address)
        if "internal" in address:
            # aiosmtpd does not append for us when the hook supplies a status.
            session.envelope.rcpt_tos.append(address)
            return "250 OK"
        return "550 No such user here"

    async def handle_DATA(self, session: Any, envelope: Any, *args: Any) -> str:  # noqa: N802
        return "250 OK"


@pytest.fixture
def picky_mta() -> Any:
    try:
        from aiosmtpd.controller import Controller
    except ImportError:
        pytest.skip("aiosmtpd not installed")

    handler = _PickyMTA()
    controller = Controller(handler, hostname="127.0.0.1", port=9117)
    controller.start()
    time.sleep(0.3)
    try:
        yield controller, handler, 9117
    finally:
        controller.stop()


def _allow_all_broker(mode: str = "same-process") -> Any:
    from effect_broker.broker import EffectBroker
    from effect_broker.model import Capability, Task

    broker = EffectBroker(mode=mode)
    cap = Capability(
        owner="User",
        holder="t",
        right="send",
        target="*",
        scope=frozenset({"*"}),
        expiry=float("inf"),
        nonce="c",
        task_id="default",
    )
    broker.register_task(Task(task_id="default", owner="User", ceiling=cap))
    broker.capabilities["c"] = cap
    return broker


class TestRejectionIsNotAnAttack:
    def test_same_process_send_with_unknown_mailbox_delivers(
        self, picky_mta: tuple[Any, _PickyMTA, int]
    ) -> None:
        """A CC the MTA refuses must not be reported as a BCC bypass."""
        _ctrl, handler, port = picky_mta
        from effect_broker.shim_email import RealEmailShim

        broker = _allow_all_broker()
        shim = RealEmailShim(
            broker=broker, task_id="default", tool_name="t",
            smtp_host="127.0.0.1", smtp_port=port,
        )
        # Both addresses were declared by the tool. The MTA simply has no
        # mailbox for the second one.
        shim.send(
            "user@corp.com", "internal@corp.com", "hi", cc="budget@corp.com"
        )
        assert "budget@corp.com" in handler.rcpt_log

    def test_multi_process_send_with_unknown_mailbox_delivers(
        self, picky_mta: tuple[Any, _PickyMTA, int], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The same envelope through the IPC probe must behave identically."""
        _ctrl, _handler, port = picky_mta
        monkeypatch.setenv("ECAC_SMTP_HOST", "127.0.0.1")
        monkeypatch.setenv("ECAC_SMTP_PORT", str(port))

        broker = _allow_all_broker(mode="multi-process")
        try:
            shim = broker.create_real_email_shim(task_id="default", tool_name="t")
            shim.send(
                "user@corp.com", "internal@corp.com", "hi", cc="budget@corp.com"
            )
        finally:
            broker.shutdown()


class TestProbeContract:
    def test_same_process_probe_reports_no_bcc_for_declared_set(
        self, picky_mta: tuple[Any, _PickyMTA, int]
    ) -> None:
        """A probe asking only about declared addresses cannot find a BCC."""
        _ctrl, _handler, port = picky_mta
        from effect_broker.shim_email import RealEmailShim

        broker = _allow_all_broker()
        shim = RealEmailShim(
            broker=broker, task_id="default", tool_name="t",
            smtp_host="127.0.0.1", smtp_port=port,
        )
        declared = frozenset({"internal@corp.com", "budget@corp.com"})
        _d, actual, bcc = shim._smtp_probe("user@corp.com", declared)

        assert actual == frozenset({"internal@corp.com"}), (
            "the probe must report which declared recipients the MTA accepts"
        )
        assert bcc == frozenset(), (
            f"a rejected declared recipient is not a BCC, got {bcc}"
        )

    def test_bcc_definition_is_accepted_minus_declared(self) -> None:
        """Pin the arithmetic the shim relies on."""
        declared = frozenset({"a@corp.com", "b@corp.com"})
        accepted = frozenset({"a@corp.com", "hidden@evil.com"})

        bcc = accepted - declared
        rejected = declared - accepted

        assert bcc == frozenset({"hidden@evil.com"})
        assert rejected == frozenset({"b@corp.com"})
        assert bcc.isdisjoint(rejected), (
            "rejections and BCC attempts are disjoint sets and must never be "
            "conflated"
        )


class TestRealAttackStillBlocked:
    def test_undeclared_recipient_still_refused(
        self, picky_mta: tuple[Any, _PickyMTA, int]
    ) -> None:
        """Relaxing the false positive must not relax the actual check."""
        _ctrl, _handler, port = picky_mta
        from effect_broker.model import Capability, Task
        from effect_broker.shim_email import EmailSecurityError, RealEmailShim

        broker = _allow_all_broker()
        # Restrict the mandate so an external recipient has no authority.
        broker.tasks["default"] = Task(
            task_id="default",
            owner="User",
            ceiling=Capability(
                owner="User",
                holder="t",
                right="send",
                target="*",
                scope=frozenset({"internal"}),
                expiry=float("inf"),
                nonce="internal-only",
                task_id="default",
            ),
        )
        broker.capabilities["internal-only"] = broker.tasks["default"].ceiling

        shim = RealEmailShim(
            broker=broker, task_id="default", tool_name="t",
            smtp_host="127.0.0.1", smtp_port=port,
        )
        with pytest.raises(EmailSecurityError):
            shim.send(
                "user@corp.com", "internal@corp.com", "hi", bcc="attacker@evil.com"
            )
