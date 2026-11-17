"""P3: attachments must be bound by the approval and survive the IPC boundary.

The reviewer's objection was narrow and testable: the canonical request listed
`attachments` as (name, digest) pairs, but nothing proved that a real send
carried them or that a substituted blob was refused. Writing this test found
that both were untrue:

- the live `RealEmailShim` had no attachment support at all — `send()` took no
  attachment argument and `metadata` never carried one, so an approval covered
  a message with no attachments regardless of what was transmitted;
- `canonical_request_from_effect` accepted attachment bytes only as `bytes`,
  but `executor_ipc._json_safe` base64-encodes them at the process boundary, so
  in multi-process mode every attachment silently dropped out of the request.
  `request_hash()` then differed between the two paths, and swapping the blob
  left the hash unchanged — in the most isolated mode the binding was absent.

Both are fixed; these tests fail if either regresses.
"""

from __future__ import annotations

import threading
from typing import Any

import pytest

from effect_broker.executor_ipc import dict_to_effect, effect_to_dict
from effect_broker.lattice import Confidentiality, Integrity
from effect_broker.model import (
    Data,
    Effect,
    canonical_request_from_effect,
)


def _send_effect(blob: bytes, name: str = "report.pdf") -> Effect:
    """A send effect carrying one attachment."""
    return Effect(
        etype="send",
        target="mailto:internal@corp.com",
        metadata={
            "subject": "quarterly",
            "body": "attached",
            "attachments": [{"name": name, "bytes": blob}],
        },
        provenance=(Data("shim-send", Confidentiality.INTERNAL, Integrity.USER),),
        capability_nonce="cap-1",
        delegation_chain=("tool", "RealEmailShim"),
    )


class TestAttachmentDigestAcrossIPC:
    """The binding must be identical on both sides of the process boundary."""

    def test_attachment_survives_serialisation(self) -> None:
        """A base64-encoded blob must be decoded, not silently dropped."""
        original = _send_effect(b"%PDF-1.7 quarterly numbers")
        revived = dict_to_effect(effect_to_dict(original))

        before = canonical_request_from_effect(original)
        after = canonical_request_from_effect(revived)

        assert before.attachments, "attachment missing from the same-process request"
        assert after.attachments, (
            "attachment vanished across IPC: the request carried no digest, so the "
            "approval authorized any attachment at all"
        )
        assert before.attachments == after.attachments

    def test_request_hash_matches_across_processes(self) -> None:
        """Same operation, same hash — otherwise the gate rejects or accepts wrongly."""
        original = _send_effect(b"payload")
        revived = dict_to_effect(effect_to_dict(original))
        assert (
            canonical_request_from_effect(original).request_hash()
            == canonical_request_from_effect(revived).request_hash()
        )

    def test_substituted_attachment_changes_hash_after_ipc(self) -> None:
        """Swapping the blob must move the hash in *both* modes.

        This is the security-relevant direction: the same-process path already
        detected the swap, so an IPC-blind hash meant isolation mode was the one
        place the substitution went unnoticed.
        """
        approved = dict_to_effect(effect_to_dict(_send_effect(b"benign")))
        tampered = dict_to_effect(effect_to_dict(_send_effect(b"exfiltrated")))

        assert (
            canonical_request_from_effect(approved).request_hash()
            != canonical_request_from_effect(tampered).request_hash()
        ), "attachment content is not bound after IPC"

    def test_non_utf8_attachment_round_trips(self) -> None:
        """Binary attachments must not be decoded with errors='replace'."""
        blob = b"\xff\xfe\x00\x01binary\x80"
        original = _send_effect(blob)
        revived = dict_to_effect(effect_to_dict(original))
        assert (
            canonical_request_from_effect(original).request_hash()
            == canonical_request_from_effect(revived).request_hash()
        )

    def test_attachment_name_is_bound(self) -> None:
        """Renaming the attachment must change the binding, not just its bytes."""
        one = _send_effect(b"same", name="invoice.pdf")
        two = _send_effect(b"same", name="invoice.exe")
        assert (
            canonical_request_from_effect(one).request_hash()
            != canonical_request_from_effect(two).request_hash()
        )


# ---------------------------------------------------------------------------
# Live SMTP: the attachment must actually be transmitted
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def smtp_server() -> Any:
    """A recording SMTP server on port 9027."""
    try:
        from aiosmtpd.controller import Controller
    except ImportError:
        pytest.skip("aiosmtpd not installed")

    class _Recorder:
        def __init__(self) -> None:
            self.data_log: list[bytes] = []
            self.rcpt_log: list[str] = []
            self._lock = threading.Lock()

        async def handle_RCPT(self, session: Any, envelope: Any, *args: Any) -> str:
            with self._lock:
                if len(args) >= 2:
                    self.rcpt_log.append(args[1])
                    if hasattr(session, "envelope"):
                        session.envelope.rcpt_tos.append(args[1])
            return "250 OK"

        async def handle_DATA(self, session: Any, envelope: Any, *args: Any) -> str:
            with self._lock:
                content = getattr(session.envelope, "content", b"") if hasattr(
                    session, "envelope"
                ) else b""
                self.data_log.append(content)
            return "250 OK"

    handler = _Recorder()
    controller = Controller(handler, hostname="127.0.0.1", port=9027, ready_timeout=5.0)
    controller.start()
    yield handler
    controller.stop()


def _make_broker() -> Any:
    from effect_broker.broker import EffectBroker
    from effect_broker.model import Capability, Task

    broker = EffectBroker()
    broker.tasks["default"] = Task(
        task_id="default",
        owner="User",
        ceiling=Capability(
            owner="User",
            holder="test-tool",
            right="send",
            target="*",
            scope=frozenset({"internal", "team"}),
            expiry=float("inf"),
            nonce="cap-send-internal",
        ),
    )
    broker.capabilities["cap-send-internal"] = Capability(
        owner="User",
        holder="test-tool",
        right="send",
        target="*",
        scope=frozenset({"internal", "team"}),
        expiry=float("inf"),
        nonce="cap-send-internal",
    )
    return broker


class TestLiveAttachmentTransmission:
    """What goes on the wire must be what the approval bound."""

    def test_attachment_appears_in_transmitted_message(self, smtp_server: Any) -> None:
        """The delivered message must contain the attachment as a MIME part."""
        from effect_broker.shim_email import RealEmailShim

        broker = _make_broker()
        shim = RealEmailShim(
            broker=broker,
            task_id="default",
            tool_name="test-tool",
            smtp_host="127.0.0.1",
            smtp_port=9027,
        )

        before = len(smtp_server.data_log)
        shim.send(
            "user@corp.com",
            "internal@corp.com",
            "see attachment",
            attachments=[{"name": "report.pdf", "bytes": b"%PDF-1.7 numbers"}],
        )

        delivered = smtp_server.data_log[before:]
        assert delivered, "no message reached the MTA"
        wire = delivered[-1]
        assert b"report.pdf" in wire, "attachment filename absent from the wire message"
        # base64 of the payload appears in the MIME body
        import base64 as _b64

        encoded = _b64.encodebytes(b"%PDF-1.7 numbers").replace(b"\n", b"")
        assert encoded[:20] in wire.replace(b"\n", b""), (
            "attachment payload absent from the wire message"
        )

    def test_attachment_digest_is_recorded_on_the_effect(self, smtp_server: Any) -> None:
        """The effect the broker authorized must carry the attachment binding."""
        from effect_broker.shim_email import RealEmailShim

        broker = _make_broker()
        captured: list[Effect] = []
        original_execute = broker.executor.execute

        def spy(commit: Any) -> Any:
            captured.append(commit.effect)
            return original_execute(commit)

        broker.executor.execute = spy  # type: ignore[method-assign]

        shim = RealEmailShim(
            broker=broker,
            task_id="default",
            tool_name="test-tool",
            smtp_host="127.0.0.1",
            smtp_port=9027,
        )
        shim.send(
            "user@corp.com",
            "internal@corp.com",
            "body",
            attachments=[{"name": "a.bin", "bytes": b"\x00\x01\x02"}],
        )

        assert captured, "executor never saw a commit"
        effect = captured[-1]
        assert effect.metadata.get("attachments"), (
            "the committed effect carried no attachment metadata, so the approval "
            "bound no attachment digest"
        )
        request = canonical_request_from_effect(effect)
        assert request.attachments, "canonical request for the live send had no attachment"
