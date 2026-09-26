"""Pytest configuration: suppress the same-process isolation advisory in tests.

The ResourceStore's SAME-PROCESS warning is legitimate production safety advice
(informing the deployer that real isolation requires a separate process/enclave).
It fires once per Python process (guarded by _warn_once()).

In test context, every test imports ResourceStore and the warning is noise.
We suppress it here so test output stays clean — it remains visible when
running traces directly (python run_traces.py) in production mode.
"""

from __future__ import annotations
import threading

import pytest

# Suppress BEFORE any test imports — this must be at module level, before
# pytest loads test modules (which import ResourceStore and trigger the warning).
import warnings

warnings.filterwarnings(
    "ignore",
    message="SAME-PROCESS: ResourceStore lives in the same Python process",
    category=UserWarning,
)


# ---------------------------------------------------------------------------
# SMTP test fixture
# ---------------------------------------------------------------------------
# aiosmtpd is only needed in test context; guard so the module loads fine
# even if aiosmtpd isn't installed in non-dev environments.
try:
    import asyncio
    from aiosmtpd.controller import Controller
    from aiosmtpd.smtp import SMTP, AuthResult, Envelope
    HAS_AIOSMTPD = True
except ImportError:
    HAS_AIOSMTPD = False
else:
    try:
        from authn import Authenticator  # noqa: F401
    except ImportError:
        pass  # authn not required for SMTP fixture


class RecordingSMTPHandler:
    """SMTP handler that records every RCPT TO recipient.

    Accepts all recipients (code 250) and records them. This lets tests
    verify that the shim's RSET-only probe correctly discovers recipients
    and that RSET aborts the transaction (no message is stored after RSET).

    Uses async handlers compatible with aiosmtpd 1.4.6:
    - handle_RCPT: args=(Envelope, address, rcpt_options), Envelope passed by VALUE
      so we update session.envelope directly for persistence between RCPT and DATA
    """

    def __init__(self) -> None:
        self.rcpt_to_log: list[str] = []   # recipients from RCPT TO commands
        self.data_log: list[bytes] = []    # message bodies from DATA commands
        self.message_log: list[tuple[str, list[str]]] = []  # (mail_from, [recipients])
        self._session = None
        self._lock = threading.Lock()

    def reset(self) -> None:
        self.rcpt_to_log.clear()
        self.data_log.clear()
        self.message_log.clear()

    async def handle_RCPT(self, session: Any, envelope: Any, *args: Any) -> str:
        """Async handler for aiosmtpd 1.4.6.

        NOTE: aiosmtpd 1.4.6 passes args=(Envelope, address, rcpt_options).
        The Envelope is passed BY VALUE, so we must update session.envelope
        directly (not args[0]) for the Envelope to persist between RCPT and DATA.
        """
        with self._lock:
            if len(args) >= 2:
                self.rcpt_to_log.append(args[1])
                if hasattr(session, 'envelope'):
                    session.envelope.rcpt_tos.append(args[1])
        return "250 OK"

    async def handle_DATA(self, session: Any, envelope: Any, *args: Any) -> str:
        """Async handler for aiosmtpd 1.4.6."""
        with self._lock:
            content = getattr(session.envelope, 'content', b'') if hasattr(session, 'envelope') else b''
            self.data_log.append(content)
        return "250 OK"


if HAS_AIOSMTPD:
    @pytest.fixture
    def smtp_server():
        """Start an aiosmtpd server on port 9025 for email shim tests.

        The server accepts all recipients (no BCC blocking) and records
        RCPT TO commands. Messages are logged but NOT actually delivered
        anywhere — the handler is a pure recorder.

        Usage:
            def test_something(smtp_server):
                # server is running on localhost:9025
                ...
        """
        import threading
        import time

        handler = RecordingSMTPHandler()

        def make_controller() -> Controller:
            return Controller(
                handler,
                hostname="localhost",
                port=9025,
                ready_timeout=5.0,
            )

        controller = make_controller()
        controller.start()
        # Give the server a moment to bind the socket
        time.sleep(0.05)

        yield handler

        controller.stop()
else:
    @pytest.fixture  # type: ignore[misc]
    def smtp_server():
        pytest.skip("aiosmtpd not installed — install with: pip install aiosmtpd")


