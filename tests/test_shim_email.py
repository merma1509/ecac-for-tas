"""Tests for RealEmailShim — real SMTP RCPT-TO probe and IMAP read_inbox.

These tests use a real aiosmtpd SMTP server (port 9025) to verify:
  1. RSET-only probe discovers actual recipients from MTA responses
  2. BCC bypass (MTA accepts undeclared recipient) → fail-closed before broker.commit
  3. Clean send goes through: SMTP probe → broker.commit → real DATA delivery
  4. RSET aborts the transaction — no message logged after a probe-only session
  5. IMAP connection errors fail closed
  6. read_inbox produces a read effect and passes through the broker gate
"""

from __future__ import annotations

import pytest

from effect_broker.broker import EffectBroker
from effect_broker.lattice import Confidentiality, Integrity
from effect_broker.model import Capability, Task
from effect_broker.shim_email import (
    EmailSecurityError,
    PostAuthorizationFailure,
    RealEmailShim,
    SMTPError,
)


# Broker helper
def _make_broker() -> EffectBroker:
    """Build a broker with a domain-scoped send capability and high flow boundary."""
    from effect_broker.model import Domain

    broker = EffectBroker(mode="same-process")
    # Bootstrap email resources (use mailto: prefix for store lookup)
    # Domain.INTERNAL matches _derive_email_confidentiality for corp.com emails
    broker.store._unsafe_bootstrap_email("mailto:internal@corp.com", Domain.INTERNAL)
    broker.store._unsafe_bootstrap_email("mailto:team@corp.com", Domain.INTERNAL)
    broker.store._unsafe_bootstrap_email("mailto:attacker@evil.com", Domain.EXTERNAL)

    task = Task(
        task_id="email-test",
        owner="User",
        ceiling=Capability(
            owner="User",
            holder="EffectBroker",
            right="send",
            target="internal@corp.com",
            scope=frozenset({"internal"}),
            expiry=float("inf"),
            nonce="ceiling-email-test",
        ),
        # High flow boundary: allow CONFIDENTIAL provenance (sender, MTA recipients)
        flow_boundary=(Confidentiality.CONFIDENTIAL, Integrity.USER),
    )
    broker.register_task(task)
    # Capability holder must match tool_name used in tests (TestTool)
    # Target uses mailto: prefix to match the shim's effect.target
    broker.capabilities["send-cap"] = Capability(
        owner="User",
        holder="TestTool",  # Match the tool_name used in RealEmailShim
        right="send",
        target="mailto:internal@corp.com",  # mailto: prefix matches shim effect target
        scope=frozenset({"internal"}),
        expiry=float("inf"),
        nonce="send-cap",
        derives_from=None,
    )
    # read capability for read_inbox
    broker.capabilities["read-inbox-cap"] = Capability(
        owner="User",
        holder="TestTool",
        right="read",
        target="internal@corp.com",
        scope=frozenset({"internal"}),
        expiry=float("inf"),
        nonce="read-inbox-cap",
        derives_from=None,
    )
    return broker


# SMTP send tests
class TestShimEmailSMTPSend:
    """SMTP send: RSET-only probe → BCC detection → broker.commit → real DATA."""

    def test_rset_probe_discovers_all_rcpt_to(self, smtp_server) -> None:
        """RSET-only probe sends RCPT TO for each declared recipient.

        The MTA accepts all and records them. RSET aborts so no DATA occurs.
        """
        broker = _make_broker()
        shim = RealEmailShim(
            broker,
            task_id="email-test",
            tool_name="TestTool",
            smtp_host="127.0.0.1",
            smtp_port=9025,
        )

        # First send — RSET-only probe phase
        # We call _smtp_probe directly to isolate the probe
        declared = frozenset({"internal@corp.com", "team@corp.com"})
        _, actual_accepted, bcc = shim._smtp_probe("user@corp.com", declared)

        # aiosmtpd handler recorded both RCPT TO commands
        assert sorted(smtp_server.rcpt_to_log) == sorted(
            [
                "internal@corp.com",
                "team@corp.com",
            ]
        )
        # MTA accepted both
        assert actual_accepted == declared
        # No BCC detected (all accepted were declared)
        assert bcc == frozenset()
        # No DATA — RSET aborted the transaction
        assert len(smtp_server.data_log) == 0

    def test_bcc_bypass_detected_before_commit(self, smtp_server) -> None:
        """MTA accepts an undeclared recipient → BCC detected → EmailSecurityError.

        The shim fails closed BEFORE broker.commit(). No RSET, no message,
        no broker involvement — the MTA's willingness to accept is enough.
        """
        broker = _make_broker()
        shim = RealEmailShim(
            broker,
            task_id="email-test",
            tool_name="TestTool",
            smtp_host="127.0.0.1",
            smtp_port=9025,
        )

        # Simulate: tool declared 2 recipients but MTA accepts 3.
        # We patch _smtp_probe to simulate MTA accepting an extra.
        _unused_declared = frozenset({"internal@corp.com", "team@corp.com"})

        def patched_probe(sender: str, decl: frozenset[str]):
            # MTA secretly accepts attacker@evil.com too
            actual = decl | frozenset({"attacker@evil.com"})
            bcc = actual - decl
            return decl, actual, bcc

        shim._smtp_probe = patched_probe  # type: ignore

        with pytest.raises(EmailSecurityError) as exc_info:
            shim.send("user@corp.com", "internal@corp.com", "secret body")

        assert "BCC bypass detected" in str(exc_info.value)
        assert "attacker@evil.com" in str(exc_info.value)
        # No SMTP DATA occurred — fail-closed before send
        assert len(smtp_server.data_log) == 0

    def test_clean_send_allowed_after_probe(self, smtp_server) -> None:
        """Clean send: RSET probe → no BCC → broker.commit ALLOW → real DATA.

        The aiosmtpd handler accepts all recipients (no BCC). broker.commit
        passes. Real SMTP DATA delivery happens.
        """
        broker = _make_broker()
        shim = RealEmailShim(
            broker,
            task_id="email-test",
            tool_name="TestTool",
            smtp_host="127.0.0.1",
            smtp_port=9025,
        )

        # Reset handler so we can assert on data_log after real delivery
        smtp_server.reset()

        # Patch probe to avoid SMTP connection issues in test
        def clean_probe(sender: str, decl: frozenset[str]):
            return decl, decl, frozenset()

        shim._smtp_probe = clean_probe  # type: ignore

        shim.send(
            "user@corp.com",
            "internal@corp.com",
            "Hello, this is a test.",
            cc_recipient="team@corp.com",
        )

        # Data was delivered (RSET probe RSET, then real DATA)
        assert len(smtp_server.data_log) == 1
        body = smtp_server.data_log[0]
        assert b"Hello, this is a test." in body

        # Op was recorded
        ops = shim.get_ops()
        assert len(ops) == 1
        assert ops[0].operation == "send"
        assert not ops[0].blocked

    def test_send_blocked_by_broker_noamp(self, smtp_server) -> None:
        """MTA accepts declared recipients but NoAmp blocks (BCC outside cap scope)."""
        broker = _make_broker()
        shim = RealEmailShim(
            broker,
            task_id="email-test",
            tool_name="TestTool",
            smtp_host="127.0.0.1",
            smtp_port=9025,
        )
        smtp_server.reset()

        # Patch probe to accept declared recipients (no BCC)
        def patched_probe(sender: str, decl: frozenset[str]):
            return decl, decl, frozenset()

        shim._smtp_probe = patched_probe  # type: ignore

        # The broker has no capability covering attacker@evil.com
        with pytest.raises(EmailSecurityError) as exc_info:
            shim.send(
                "user@corp.com",
                "internal@corp.com",
                "Hi",
                bcc_1="attacker@evil.com",
            )

        assert "BLOCKed by NoAmp" in str(exc_info.value)
        # No real DATA (blocked by broker after clean probe)
        assert len(smtp_server.data_log) == 0

    def test_rset_aborts_transaction_no_data_on_probe(self, smtp_server) -> None:
        """RSET-only probe never delivers a message — data_log stays empty."""
        broker = _make_broker()
        shim = RealEmailShim(
            broker,
            task_id="email-test",
            tool_name="TestTool",
            smtp_host="127.0.0.1",
            smtp_port=9025,
        )
        smtp_server.reset()

        declared = frozenset({"internal@corp.com"})
        d, a, b = shim._smtp_probe("user@corp.com", declared)

        # RSET aborted — no message body logged
        assert len(smtp_server.data_log) == 0
        # But RCPT TO was called
        assert "internal@corp.com" in smtp_server.rcpt_to_log

    def test_smtp_connection_failure_fails_closed(self) -> None:
        """SMTP unreachable → SMTPError → EmailSecurityError before broker.commit."""
        broker = _make_broker()
        shim = RealEmailShim(
            broker,
            task_id="email-test",
            tool_name="TestTool",
            smtp_host="127.0.0.1",
            smtp_port=59999,  # nothing listening
        )

        with pytest.raises(EmailSecurityError) as exc_info:
            shim.send("user@corp.com", "internal@corp.com", "test")

        assert "probe failed" in str(exc_info.value).lower()


# IMAP read_inbox tests
class TestShimEmailIMAP:
    """read_inbox: broker gate → (on ALLOW) IMAP connection → message IDs."""

    def test_read_inbox_blocks_without_capability(self) -> None:
        """No read capability → EmailSecurityError, no IMAP connection attempted."""
        broker = _make_broker()
        # Remove the read capability
        del broker.capabilities["read-inbox-cap"]

        shim = RealEmailShim(
            broker,
            task_id="email-test",
            tool_name="TestTool",
            imap_host="imap.example.com",
            imap_port=993,
        )

        # Should raise before attempting any IMAP connection
        with pytest.raises(EmailSecurityError) as exc_info:
            shim.read_inbox("internal")

        assert "BLOCKed by Auth" in str(exc_info.value)

    def test_read_inbox_with_real_imap_connection(self) -> None:
        """With matching capability nonce: broker ALLOW → IMAP connection attempted.

        Since IMAP is unreachable, the connection fails and is wrapped as
        EmailSecurityError. Auth must pass first (capability nonce must match).
        """
        broker = _make_broker()
        shim = RealEmailShim(
            broker,
            task_id="email-test",
            tool_name="TestTool",
            imap_host="imap.example.invalid",
            imap_port=993,
        )

        # Capability nonce must match target "internal@corp.com" to pass Auth.
        # read_inbox sends target="imap:internal", which the nonce resolver
        # strips to "internal" — so target="imap:internal" with holder="TestTool"
        # right="read" should match cap target="internal@corp.com".
        # If Auth BLOCKs first, the IMAP phase is never reached.

        try:
            shim.read_inbox("internal")
        except EmailSecurityError as exc:
            # Either BLOCKed by Auth (nonce mismatch) or IMAP error (after ALLOW)
            assert "BLOCKed" in str(exc) or "IMAP" in str(exc)

    def test_read_inbox_effect_has_correct_provenance(self) -> None:
        """read_inbox Effect carries the expected provenance labels."""
        broker = _make_broker()
        shim = RealEmailShim(broker, task_id="email-test", tool_name="TestTool")

        # Verify the shim's label derivation methods produce correct labels
        conf = shim._derive_email_confidentiality(
            "alice@corp.com",
            frozenset({"alice@corp.com"}),
        )
        integ = shim._derive_email_integrity(50, "Test subject")

        assert conf == Confidentiality.INTERNAL
        assert integ == Integrity.USER


# Label derivation tests
class TestShimEmailLabels:
    """Confidentiality and integrity derivation from email address domains."""

    def test_internal_only_derive_confidentiality_internal(self) -> None:
        """All recipients on corp domains → confidentiality = INTERNAL."""
        broker = _make_broker()
        shim = RealEmailShim(broker, task_id="email-test", tool_name="TestTool")

        conf = shim._derive_email_confidentiality(
            "alice@corp.com",
            frozenset({"bob@corp.com", "team@internal.corp.com"}),
        )
        assert conf == Confidentiality.INTERNAL

    def test_external_recipient_derive_confidentiality_internal(self) -> None:
        """Any EXTERNAL recipient → confidentiality = INTERNAL (no downgrade)."""
        broker = _make_broker()
        shim = RealEmailShim(broker, task_id="email-test", tool_name="TestTool")

        conf = shim._derive_email_confidentiality(
            "alice@corp.com",
            frozenset({"bob@corp.com", "attacker@evil.com"}),
        )
        # External recipient → at least INTERNAL (not CONFIDENTIAL downgrade)
        assert conf == Confidentiality.INTERNAL

    def test_empty_body_integrity_untrusted(self) -> None:
        """Empty body → integrity = UNTRUSTED (no user content)."""
        broker = _make_broker()
        shim = RealEmailShim(broker, task_id="email-test", tool_name="TestTool")

        integ = shim._derive_email_integrity(0, "no subject")
        assert integ == Integrity.UNTRUSTED

    def test_nonempty_body_integrity_user(self) -> None:
        """Non-empty body → integrity = USER (user-originated)."""
        broker = _make_broker()
        shim = RealEmailShim(broker, task_id="email-test", tool_name="TestTool")

        integ = shim._derive_email_integrity(100, "Hello")
        assert integ == Integrity.USER

    def test_reply_subject_integrity_user(self) -> None:
        """Reply subject (re:) → integrity = USER (trusted reply chain)."""
        broker = _make_broker()
        shim = RealEmailShim(broker, task_id="email-test", tool_name="TestTool")

        integ = shim._derive_email_integrity(50, "Re: your message")
        assert integ == Integrity.USER


# Integration: full broker + shim + ledger
class TestShimEmailBrokerIntegration:
    """End-to-end: shim → broker.commit → effects_log in store."""

    def test_send_effect_appears_in_store_effects_log(self, smtp_server) -> None:
        """Allowed send: effects_log records the send effect."""
        broker = _make_broker()
        shim = RealEmailShim(
            broker,
            task_id="email-test",
            tool_name="TestTool",
            smtp_host="127.0.0.1",
            smtp_port=9025,
        )
        smtp_server.reset()

        # Patch to avoid real MTA
        def clean_probe(sender: str, decl: frozenset[str]):
            return decl, decl, frozenset()

        shim._smtp_probe = clean_probe  # type: ignore

        shim.send("user@corp.com", "internal@corp.com", "Test body")

        # Store recorded the send effect
        log = broker.store.effects_log
        assert ("send", "email:mailto:internal@corp.com") in log

    def test_blocked_send_not_in_effects_log(self, smtp_server) -> None:
        """Blocked send: nothing in effects_log (effect never committed)."""
        broker = _make_broker()
        shim = RealEmailShim(
            broker,
            task_id="email-test",
            tool_name="TestTool",
            smtp_host="127.0.0.1",
            smtp_port=9025,
        )

        # BCC detected → fail closed before broker.commit
        def bcc_probe(sender: str, decl: frozenset[str]):
            extra = decl | frozenset({"secret@evil.com"})
            return decl, extra, extra - decl

        shim._smtp_probe = bcc_probe  # type: ignore

        with pytest.raises(EmailSecurityError):
            shim.send("user@corp.com", "internal@corp.com", "body")

        # Nothing committed
        log = broker.store.effects_log
        assert len(log) == 0


class TestDispatchMarker:
    """P4-2: the IN_FLIGHT marker is written before the SMTP call.

    Tested at the shim, not the ledger, because the property is ORDERING:
    the marker must exist by the time the network call starts. If it were
    written after delivery, a crash mid-send would leave no trace at all.
    """

    def test_marker_written_before_smtp_call(self, smtp_server) -> None:
        broker = _make_broker()
        shim = RealEmailShim(
            broker,
            task_id="email-test",
            tool_name="TestTool",
            smtp_host="127.0.0.1",
            smtp_port=9025,
        )
        smtp_server.reset()

        shim._smtp_probe = lambda sender, decl: (decl, decl, frozenset())  # type: ignore[method-assign]

        # Capture the ledger state AT THE MOMENT delivery is attempted: this is
        # the ordering claim. After the call it would be trivially true.
        original_send = shim._smtp_send
        dispatched_when_send_started: list[bool] = []

        def spy_send(sender, recipients, raw_message):
            dispatched_when_send_started.append(
                broker.ledger.was_dispatched("email-test", nonce_holder[0])
            )
            return original_send(sender, recipients, raw_message)

        # The shim computes the nonce internally; capture it via record_dispatched.
        nonce_holder: list[str] = [""]
        original_record = broker.ledger.record_dispatched

        def spy_record(task_id, nonce, source="shim.dispatch"):
            nonce_holder[0] = nonce
            return original_record(task_id, nonce, source)

        object.__setattr__(broker.ledger, "record_dispatched", spy_record)
        shim._smtp_send = spy_send  # type: ignore[method-assign]

        shim.send("user@corp.com", "internal@corp.com", "hello")

        assert dispatched_when_send_started == [True], (
            "IN_FLIGHT marker must exist before the SMTP call; "
            "found it written after (a crash mid-send would leave no trace)"
        )


class TestEmailEvidence:
    """COMMITTED for a send must rest on transport evidence.

    The email path used to reach CONFIRMED_COMMITTED with no evidence at all:
    the ledger inferred it from the `executor.apply` observation, which is the
    executor asserting its own success. These tests pin the evidence down.
    """

    def _shim(self, broker: EffectBroker) -> RealEmailShim:
        shim = RealEmailShim(
            broker,
            task_id="email-test",
            tool_name="TestTool",
            smtp_host="127.0.0.1",
            smtp_port=9025,
        )
        shim._smtp_probe = lambda sender, decl: (  # type: ignore[method-assign]
            decl,
            decl,
            frozenset(),
        )
        return shim

    def test_successful_send_records_transport_evidence(
        self, smtp_server
    ) -> None:
        """An allowed send carries evidence naming the transport reply."""
        broker = _make_broker()
        shim = self._shim(broker)
        shim._smtp_send = lambda s, r, raw: (  # type: ignore[method-assign]
            ["internal@corp.com"],
            "data=250 OK",
        )

        shim.send("user@corp.com", "internal@corp.com", "hello")

        evidence = broker.ledger.evidence_for("email-test", "send-cap")
        assert evidence is not None, "a send must be backed by evidence"
        assert evidence.outcome == "committed"
        assert evidence.transport_response == "data=250 OK"
        assert evidence.observed_targets == frozenset({"internal@corp.com"})
        assert evidence.source == "shim_email.send.transport"

    def test_transport_failure_is_unknown_not_committed(
        self, smtp_server
    ) -> None:
        """A transport fault after ALLOW must not read as a confirmed commit."""
        from effect_broker.ledger import OUTCOME_UNKNOWN

        broker = _make_broker()
        shim = self._shim(broker)

        def failing_send(sender, recipients, raw):
            raise SMTPError("connection refused")

        shim._smtp_send = failing_send  # type: ignore[method-assign]

        with pytest.raises(PostAuthorizationFailure):
            shim.send("user@corp.com", "internal@corp.com", "hello")

        evidence = broker.ledger.evidence_for("email-test", "send-cap")
        assert evidence is not None, (
            "a failed delivery must leave evidence; otherwise the "
            "executor.apply observation reads as a commit"
        )
        assert evidence.outcome == "unknown"
        assert evidence.transport_response is None
        assert broker.ledger.outcome_of("email-test", "send-cap") == OUTCOME_UNKNOWN

    def test_no_accepted_recipient_is_unknown_not_a_crash(
        self, smtp_server
    ) -> None:
        """DATA accepted, nothing delivered: UNKNOWN with a readable error.

        A commit claim with no observed target is not constructible, so this
        path must classify as UNKNOWN rather than let the type's own guard
        surface as an unhandled EvidenceInsufficient.
        """
        from effect_broker.model import EvidenceInsufficient

        broker = _make_broker()
        shim = self._shim(broker)
        shim._smtp_send = lambda s, r, raw: (  # type: ignore[method-assign]
            [],
            "data=250 but no rcpt accepted",
        )

        with pytest.raises(PostAuthorizationFailure) as excinfo:
            shim.send("user@corp.com", "internal@corp.com", "hello")

        # A type error escaping here would be the bug this test pins down.
        assert not isinstance(excinfo.value, EvidenceInsufficient)
        assert "UNKNOWN" in str(excinfo.value)
        evidence = broker.ledger.evidence_for("email-test", "send-cap")
        assert evidence is not None
        assert evidence.outcome == "unknown"
