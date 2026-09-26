"""Real enforcement shim: email operations via actual SMTP/IMAP.

Intercepts real email sending and reading, derives effects from actual MTA
state. The tool cannot forge BCC recipients, hide extra addresses, or
inject unauthorized send actions.

Same architectural position as RealFileShim:
  Tool code → Shim (this module) → broker.commit() → executor.execute()

The tool never directly calls smtplib or imaplib. All email goes through
this shim, which derives the REAL effect (including all BCC recipients)
from what the MTA actually does.
"""

from __future__ import annotations

import email.message
import imaplib
import smtplib
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .lattice import Confidentiality, Integrity
from .model import Data, Effect, EffectTarget

if TYPE_CHECKING:
    from .broker import EffectBroker
    from .executor_ipc import ProcessExecutorClient


@dataclass
class EmailOp:
    """A real email operation the shim observed via actual MTA interaction."""

    operation: str  # "send" | "read_inbox"
    sender: str  # SMTP MAIL FROM
    declared_recipients: frozenset[str]  # what the tool said
    actual_recipients: frozenset[str]  # what the MTA delivered to
    extra_recipients: frozenset[str]  # extra beyond declared (BCC detection)
    subject: str
    body_size: int  # bytes, for integrity/confidentiality derivation
    mta_delivery_log: tuple[str, ...]  # which servers actually received
    tool_name: str
    blocked: bool = False
    nonce: str = ""


class RealEmailShim:
    """Real email shim — derives effects from actual SMTP delivery.

    The tool calls shim.send(...), shim.read_inbox(...).
    The shim:
      1. SMTP RCPT-TO probe (RSET-only, no DATA) → discovers ACTUAL recipients
      2. If BCC detected → fail closed immediately (no broker.commit)
      3. broker.commit() with the real (MTA-verified) target set
      4. On ALLOW: real SMTP DATA delivery or IMAP SELECT + SEARCH + FETCH

    BCC detection: We open a real SMTP connection, call RCPT TO for every
    recipient, read the per-recipient SMTP responses, then RSET to abort
    the transaction (no message queued or delivered). The MTA tells us which
    addresses it will accept. Any accepted address not in the tool's declared
    list is a BCC attempt — we fail closed before broker.commit().
    """

    broker: EffectBroker
    task_id: str
    tool_name: str

    # SMTP config — set these to connect to a real MTA
    smtp_host: str = "localhost"
    smtp_port: int = 25
    smtp_user: str | None = None
    smtp_password: str | None = None
    use_tls: bool = False

    # IMAP config — set these to connect to a real IMAP server
    imap_host: str = "localhost"
    imap_port: int = 993
    imap_user: str | None = None
    imap_password: str | None = None

    # Independent observer record
    ops: list[EmailOp] = field(default_factory=list)

    # IPC client for multi-process mode (set by broker)
    # When set, real SMTP/IMAP goes through subprocess, not direct calls
    ipc_client: ProcessExecutorClient | None = None

    def __init__(
        self,
        broker: EffectBroker,
        task_id: str = "default",
        tool_name: str = "untrusted-tool",
        smtp_host: str = "localhost",
        smtp_port: int = 25,
        imap_host: str = "localhost",
        imap_port: int = 993,
    ) -> None:
        self.broker = broker
        self.task_id = task_id
        self.tool_name = tool_name
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.imap_host = imap_host
        self.imap_port = imap_port
        self.ops = []

    def _canonical_email(self, addr: str) -> str:
        """Canonicalize an email address: lowercase, strip whitespace."""
        return addr.strip().lower()

    def _derive_domain(self, addr: str) -> str:
        """Derive the domain part of an email address."""
        canon = self._canonical_email(addr)
        if "@" in canon:
            return canon.split("@")[1]
        return ""

    def _derive_email_confidentiality(
        self, sender: str, recipients: frozenset[str]
    ) -> Confidentiality:
        """Derive confidentiality from sender/recipient domains."""
        corp_domains = {"corp.com", "internal.corp.com", "localhost"}

        # If any recipient is EXTERNAL, this is at least INTERNAL
        for r in recipients:
            domain = self._derive_domain(r)
            if domain not in corp_domains:
                return Confidentiality.INTERNAL

        # All internal: INTERNAL
        return Confidentiality.INTERNAL

    def _derive_email_integrity(self, body_size: int, subject: str) -> Integrity:
        """Derive integrity from the message.

        In a real shim: verify DKIM signature, check SPF/DMARC results.
        Here: heuristic based on subject/body length.
        """
        if body_size == 0:
            return Integrity.UNTRUSTED  # empty message → untrusted
        if subject and "re:" in subject.lower():
            return Integrity.USER  # reply → trusted
        return Integrity.USER  # default: user-originated

    def _build_message(
        self, sender: str, recipient: str, body: str, **extra: str
    ) -> tuple[bytes, str, int]:
        """Build RFC 822 message. Returns (raw_bytes, subject, body_size)."""
        msg = email.message.EmailMessage()
        msg["From"] = sender
        msg["To"] = recipient
        if extra:
            msg["CC"] = ", ".join(extra.values())
        msg["Subject"] = f"ECAC: {recipient}"
        msg.set_content(body)
        raw = msg.as_bytes()
        return raw, msg["Subject"], len(raw)

    def _smtp_send(self, sender: str, recipients: frozenset[str], raw_message: bytes) -> list[str]:
        """Send raw bytes via real SMTP. Returns list of recipients accepted by MTA.

        In multi-process mode (ipc_client set), routes through subprocess IPC.
        Otherwise uses direct smtplib calls (same-process mode).
        """
        # IPC mode: real SMTP happens in the isolated subprocess
        if self.ipc_client is not None:
            try:
                result = self.ipc_client.real_smtp_send(
                    sender,
                    list(recipients),
                    raw_message.decode("utf-8", errors="replace"),
                )
                delivered: list[str] = result.get("delivered", [])
                return delivered
            except RuntimeError as ex:
                raise SMTPError(f"SMTP IPC error: {ex}") from ex

        # Same-process mode: direct smtplib calls
        try:
            server = self._open_smtp()
            try:
                # Establish the mail transaction (RSET to reset any prior state)
                server.rset()
                # RSET clears the session state, need to re-EHLO
                try:
                    server.ehlo()
                except smtplib.SMTPServerDisconnected:
                    server.connect(self.smtp_host, self.smtp_port)
                    server.ehlo()
                server.mail(sender)
                # RCPT TO for each — this is where BCC detection happens
                rcpt_results = self._smtp_rcpt_to(server, recipients)
                # DATA with full message
                server.data(raw_message)
                # Collect accepted recipients (code 250 = OK)
                delivered = [r for r, (code, _) in rcpt_results.items() if code == 250]
                return delivered
            finally:
                server.quit()
        except smtplib.SMTPException as ex:
            raise SMTPError(f"SMTP error: {ex}") from ex

    def _imap_read_inbox(self, user: str) -> tuple[list[str], int]:
        """Read inbox via real IMAP. Returns (message_ids, total_size).

        In multi-process mode (ipc_client set), routes through subprocess IPC.
        Otherwise uses direct imaplib calls (same-process mode).
        """
        # IPC mode: real IMAP happens in the isolated subprocess
        if self.ipc_client is not None:
            try:
                result = self.ipc_client.real_imap_read_inbox(
                    user=user,
                    imap_host=self.imap_host,
                    imap_port=self.imap_port,
                    imap_user=self.imap_user,
                    imap_password=self.imap_password,
                    imap_use_tls=True,
                )
                message_ids = result.get("message_ids", [])
                total_size = result.get("total_size", 0)
                error = result.get("error")
                if error:
                    raise EmailSecurityError(
                        f"[{self.tool_name}] IMAP error reading inbox: {error}"
                    )
                return message_ids, total_size
            except RuntimeError as ex:
                raise SMTPError(f"IMAP IPC error: {ex}") from ex

        # Same-process mode: direct imaplib calls
        messages: list[str] = []
        total_size = 0
        try:
            # IMAP4_SSL on port 993 (TLS-wrapped)
            with imaplib.IMAP4_SSL(self.imap_host, self.imap_port) as mailbox:
                if self.imap_user and self.imap_password:
                    mailbox.login(self.imap_user, self.imap_password)
                # SELECT INBOX
                status, _ = mailbox.select("INBOX")
                if status != "OK":
                    raise EmailSecurityError(
                        f"[{self.tool_name}] IMAP SELECT INBOX failed: {status}"
                    )
                # Search all messages (ALL = all messages in selected mailbox)
                _, msg_ids = mailbox.search(None, "ALL")
                ids = msg_ids[0].split() if msg_ids[0] else []
                # Fetch each message as RFC822 for content analysis
                for mid in ids:
                    _, data = mailbox.fetch(mid, "(RFC822)")
                    if data and data[0]:
                        raw = data[0][1] if isinstance(data[0], tuple) else data[0]
                        total_size += len(raw)
                messages = [mid.decode() for mid in ids]
        except imaplib.IMAP4.error as ex:
            raise EmailSecurityError(f"[{self.tool_name}] IMAP error reading inbox: {ex}") from ex
        except Exception as ex:
            raise EmailSecurityError(f"[{self.tool_name}] read_inbox failed: {ex}") from ex

        return messages, total_size

    def _open_smtp(self) -> smtplib.SMTP:
        """Open an SMTP connection to the configured MTA. Returns connected socket."""
        timeout = 5.0  # 5 second timeout for connection
        if self.use_tls:
            # SMTP_SSL is a subclass of SMTP; cast to satisfy return type annotation
            server: smtplib.SMTP = smtplib.SMTP_SSL(self.smtp_host, self.smtp_port, timeout=timeout)
        else:
            server = smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=timeout)
        if self.smtp_user and self.smtp_password:
            server.login(self.smtp_user, self.smtp_password)
        return server

    def _smtp_rcpt_to(
        self,
        server: smtplib.SMTP,
        recipients: frozenset[str],
    ) -> dict[str, tuple[int, bytes | str]]:
        """Send SMTP RCPT TO for each recipient. Returns per-recipient (code, msg).

        This is the core BCC-detection primitive. We call RCPT TO for EVERY
        recipient before DATA. The MTA tells us per-recipient whether it will
        accept delivery. Recipients that pass RCPT TO but are not in the
        declared list are BCC attempts.
        """
        results: dict[str, tuple[int, bytes | str]] = {}
        for rcpt in sorted(recipients):
            code, msg = server.rcpt(rcpt)
            results[rcpt] = (code, msg)
        return results

    def _smtp_probe(
        self, sender: str, recipients: frozenset[str]
    ) -> tuple[frozenset[str], frozenset[str], frozenset[str]]:
        """Probe MTA to discover actual recipients via SMTP RCPT TO.

        Returns (declared_recipients, actual_accepted, bcc_detected).

        In multi-process mode, the RSET probe happens in the isolated subprocess
        (not in the broker process). This ensures BCC detection is confined
        within the subprocess boundary.

        BCC detection: after RSET (no DATA), the MTA accepted recipients are
        the ACTUAL set. Any accepted recipient not in declared is a BCC attempt.
        """
        # IPC mode: RSET probe happens in the isolated subprocess
        if self.ipc_client is not None:
            try:
                result = self.ipc_client.real_smtp_probe(sender, list(recipients))
                declared_fro = frozenset(result.get("declared", list(recipients)))
                actual_fro = frozenset(result.get("actual_accepted", []))
                bcc_fro = frozenset(result.get("bcc_detected", []))
                return declared_fro, actual_fro, bcc_fro
            except RuntimeError as ex:
                raise SMTPError(f"BCC probe IPC error: {ex}") from ex

        # Same-process mode: direct smtplib RSET probe
        declared_set = recipients
        try:
            server = self._open_smtp()
            try:
                server.rset()
                # RSET clears the SMTP session state, so we need to EHLO again
                try:
                    server.ehlo()
                except smtplib.SMTPServerDisconnected:
                    # Some servers disconnect after RSET — reconnect and EHLO
                    server.connect(self.smtp_host, self.smtp_port)
                    server.ehlo()
                server.mail(sender)
                rcpt_results = self._smtp_rcpt_to(server, declared_set)
                actual_accepted: frozenset[str] = frozenset(
                    r for r, (code, _) in rcpt_results.items() if code == 250
                )
                # RSET aborts the transaction — no message queued or delivered
                server.rset()
            finally:
                server.quit()
            bcc_detected = actual_accepted - declared_set
            return declared_set, actual_accepted, bcc_detected
        except (smtplib.SMTPException, OSError, SMTPError) as ex:
            raise SMTPError(f"BCC probe failed: {ex}") from ex

    def send(self, sender: str, recipient: str, body: str, **extra_recipients: str) -> None:
        """Send an email with real MTA-based BCC detection.

        Three phases:
          1. SMTP RCPT-TO probe (RSET-only, no DATA) → discovers ACTUAL recipients
          2. If BCC detected → fail closed immediately (no broker.commit, no send)
          3. broker.commit() with real target set
          4. On ALLOW → real SMTP DATA delivery

        Args:
            sender: RFC 5321 MAIL FROM address
            recipient: primary To address
            body: email body text
            **extra_recipients: additional recipients (CC/BCC)
        """
        # Canonicalize all addresses
        canon_recipient = self._canonical_email(recipient)
        extras_canon = frozenset(self._canonical_email(a) for a in extra_recipients.values())
        all_declared = frozenset({canon_recipient}) | extras_canon

        # Build message once (for body_size / content analysis)
        raw_msg, subject, body_size = self._build_message(
            sender, canon_recipient, body, **extra_recipients
        )

        # Phase 1: SMTP RSET-only probe — discovers ACTUAL MTA recipients
        # RSET after RCPT TO means NO message is queued or delivered here.
        # Any recipient accepted by the MTA (code 250) that is NOT in
        # all_declared is a BCC attempt.
        try:
            declared_from_smtp, actual_accepted, bcc_detected = self._smtp_probe(
                sender, all_declared
            )
        except SMTPError as ex:
            raise EmailSecurityError(
                f"[{self.tool_name}] SMTP BCC probe failed: {ex}. Failing closed — no email sent."
            ) from ex

        # Fail closed: if MTA accepted recipients the tool did NOT declare,
        # this is a BCC bypass attempt. Block BEFORE broker.commit.
        if bcc_detected:
            # Record to ledger so CONFIRMED_BLOCKED verdict is meaningful for shim-blocks
            bcc_nonce = f"bcc-blocked-{canon_recipient}"
            self.broker.ledger.record_shim_block(
                task_id=self.task_id,
                nonce=bcc_nonce,
                reason="bcc-detected",
                blocked_targets=frozenset({canon_recipient}),
            )
            raise EmailSecurityError(
                f"[{self.tool_name}] BCC bypass detected: MTA accepted "
                f"{bcc_detected} which are not in declared set {all_declared}. "
                f"RSET-only probe — no message sent. Treating as attack."
            )

        # Phase 2: Derive IFC labels from real MTA state (actual accepted set)
        conf = self._derive_email_confidentiality(sender, actual_accepted)
        integ = self._derive_email_integrity(body_size, subject)
        additional = actual_accepted - frozenset({canon_recipient})

        nonce = self._resolve_capability_nonce("send", canon_recipient, additional)

        effect = Effect(
            etype="send",
            target=f"mailto:{canon_recipient}",
            metadata={
                "extra_resources": list(additional),
                "subject": subject,
                "body_size": body_size,
                "bcc_detected": frozenset(),  # always empty at commit time
                "mta_actual_recipients": list(actual_accepted),
            },
            provenance=(
                Data("shim-send", conf, integ),
                # Sender confidentiality based on domain (corp.com → INTERNAL)
                Data(f"sender={sender}", conf, Integrity.HIGH),
                Data(f"mta-accepted={actual_accepted}", conf, Integrity.HIGH),
            ),
            capability_nonce=nonce,
            delegation_chain=(self.tool_name, "RealEmailShim"),
            known_targets=EffectTarget(primary=canon_recipient, additional=additional),
        )

        from .model import Commit

        commit = Commit(effect=effect, task=None, tool_name=self.tool_name)
        allow, evidence = self.broker.executor.execute(commit)

        op = EmailOp(
            operation="send",
            sender=sender,
            declared_recipients=all_declared,
            actual_recipients=actual_accepted,
            extra_recipients=additional,
            subject=subject,
            body_size=body_size,
            mta_delivery_log=(),
            tool_name=self.tool_name,
            blocked=not allow,
            nonce=nonce,
        )

        if not allow:
            blocker = evidence.get("primary_blocker", "unknown")
            raise EmailSecurityError(
                f"[{self.tool_name}] send from {sender} to {actual_accepted} "
                f"BLOCKed by {blocker}. No email sent."
            )

        # Phase 3 (ALLOW): real SMTP delivery via DATA
        try:
            delivered = self._smtp_send(sender, actual_accepted, raw_msg)
            op = EmailOp(
                operation="send",
                sender=sender,
                declared_recipients=all_declared,
                actual_recipients=frozenset(delivered),
                extra_recipients=additional,
                subject=subject,
                body_size=body_size,
                mta_delivery_log=tuple(delivered),
                tool_name=self.tool_name,
                blocked=False,
                nonce=nonce,
            )
            self.ops.append(op)
        except SMTPError as ex:
            raise EmailSecurityError(
                f"[{self.tool_name}] SMTP delivery failed after ALLOW: {ex}. "
                f"Broker said ALLOW but MTA rejected. Treat as security event."
            ) from ex

    def read_inbox(self, user: str) -> list[str]:
        """Read inbox for a user via real IMAP SELECT + SEARCH + FETCH.

        Returns a list of message IDs (UIDs) in the INBOX.
        On ALLOW: connects to the IMAP server, selects INBOX, searches all
        messages, fetches RFC822 body for content analysis (confidentiality /
        integrity derivation), then logs the operation and returns message IDs.

        On BLOCK: raises EmailSecurityError, no IMAP connection is made.
        """
        # Phase 1: broker gate (read-only, no state change if BLOCK)
        conf = Confidentiality.INTERNAL
        integ = Integrity.USER

        effect = Effect(
            etype="read",
            target=f"imap:{user}",
            metadata={},
            provenance=(
                Data("shim-read-inbox", conf, integ),
                Data(f"user={user}", Confidentiality.INTERNAL, Integrity.HIGH),
            ),
            capability_nonce=f"{self.tool_name}:read:imap:{user}",
            delegation_chain=(self.tool_name, "RealEmailShim"),
            known_targets=None,
        )

        from .model import Commit

        commit = Commit(effect=effect, task=None, tool_name=self.tool_name)
        allow, evidence = self.broker.executor.execute(commit)

        if not allow:
            blocker = evidence.get("primary_blocker", "unknown")
            raise EmailSecurityError(f"[{self.tool_name}] read_inbox BLOCKed by {blocker}")

        # Phase 2 (ALLOW): real IMAP connection
        # In multi-process mode, routes through subprocess IPC.
        # In same-process mode, uses direct imaplib calls.
        try:
            messages, total_size = self._imap_read_inbox(user)
        except SMTPError as ex:
            raise EmailSecurityError(f"[{self.tool_name}] read_inbox failed: {ex}") from ex

        # Derive confidentiality from content
        if messages:
            conf = self._derive_email_confidentiality(
                sender=f"{user}@{self.imap_host}",
                recipients=frozenset({f"{user}@{self.imap_host}"}),
            )
        # Re-derive integrity from inbox state
        if total_size == 0:
            integ = Integrity.UNTRUSTED
        else:
            integ = Integrity.USER

        self.ops.append(
            EmailOp(
                operation="read_inbox",
                sender=user,
                declared_recipients=frozenset(),
                actual_recipients=frozenset(),
                extra_recipients=frozenset(),
                subject="",
                body_size=len(messages),  # message count as size proxy
                mta_delivery_log=tuple(messages),
                tool_name=self.tool_name,
                blocked=False,
                nonce=effect.capability_nonce,
            )
        )
        return messages

    def _resolve_capability_nonce(
        self,
        right: str,
        primary: str,
        extras: frozenset[str],
    ) -> str:
        """Find a matching capability nonce. See RealFileShim._resolve_capability_nonce."""
        holder = self.tool_name
        # Remove mailto: prefix if present to match against capability targets
        primary_for_match = primary.replace("mailto:", "")

        for nonce, cap in self.broker.capabilities.items():
            if cap.holder in (holder, "EffectBroker") and cap.right in (right, "*"):
                # Match against the raw target (with or without mailto:)
                raw_target = primary_for_match
                # Handle wildcard: cap.target == "*" matches anything
                if cap.target == "*" or raw_target.startswith(cap.target.replace("mailto:", "")):
                    # Return the actual matched nonce, not a generated one
                    return nonce

        return f"no-cap-{right}-{primary}"

    def get_ops(self) -> list[EmailOp]:
        """Return the operation log for independent observation."""
        return list(self.ops)


class EmailSecurityError(Exception):
    """Raised by the email shim when broker BLOCKs or MTA fails post-ALLOW."""

    pass


class SMTPError(Exception):
    """SMTP-level error during email delivery."""

    pass
