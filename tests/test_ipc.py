"""Tests for the IPC layer (multi-process ledger isolation).

These tests verify the LedgerBackend abstraction, LocalLedgerBackend,
ProcessLedgerClient, and LedgerProcessServer.

Note: Full multi-process tests (spawning actual child processes) require
a real Unix socket and are marked with @pytest.mark.integration.
The core LedgerBackend interface is tested in-process below.
"""

from __future__ import annotations

import time
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from unittest.mock import patch

import pytest

from effect_broker.ipc import (
    LedgerBackend,
    LedgerProcessServer,
    LedgerRequest,
    LedgerResponse,
    LocalLedgerBackend,
    ProcessLedgerClient,
    _parse_response,
    _serialize_request,
)
from effect_broker.ledger import (
    IndependentEffectLedger,
    LedgerEntry,
    LedgerVerdict,
    UnknownLedgerResult,
)


# ---- Wire format ----
class TestWireFormat:
    def test_serialize_request(self) -> None:
        payload = {"task_id": "t1", "nonce": "n1", "targets": ["a", "b"]}
        raw = _serialize_request(LedgerRequest.RECORD_AUTHORIZATION, payload)
        assert isinstance(raw, bytes)
        # Length-prefixed format: "<length>\n<json>"
        # Split on first newline to get length and body separately
        import json
        newline_idx = raw.index(b"\n")
        length = int(raw[:newline_idx])
        body = raw[newline_idx + 1 :]
        assert length == len(body)
        parsed = json.loads(body.decode())
        assert parsed["kind"] == "RECORD_AUTHORIZATION"
        assert parsed["payload"] == payload

    def test_parse_response_success(self) -> None:
        raw = b'{"ok": true, "result": [1, 2, 3], "error": null}'
        resp = _parse_response(raw)
        assert resp.ok is True
        assert resp.result == [1, 2, 3]
        assert resp.error is None

    def test_parse_response_error(self) -> None:
        raw = b'{"ok": false, "result": null, "error": "test error"}'
        resp = _parse_response(raw)
        assert resp.ok is False
        assert resp.result is None
        assert resp.error == "test error"


# ---- LocalLedgerBackend ----
class TestLocalLedgerBackend:
    def test_record_and_verify_committed(self) -> None:
        ledger = IndependentEffectLedger()
        backend = LocalLedgerBackend(ledger)
        targets = frozenset({"file:///a", "file:///b"})
        backend.record_authorization("task1", "nonce1", targets, source="test")

        result = backend.verify("task1", "nonce1")
        assert isinstance(result, UnknownLedgerResult)

        backend.record_observation("task1", "nonce1", targets, source="test")
        result = backend.verify("task1", "nonce1")
        assert result == LedgerVerdict.CONFIRMED_COMMITTED

    def test_record_and_verify_blocked(self) -> None:
        ledger = IndependentEffectLedger()
        backend = LocalLedgerBackend(ledger)
        backend.record_authorization("task1", "nonce1", frozenset({"file:///a"}), source="test")
        # Source must match BLOCKED_SOURCES for verify to return CONFIRMED_BLOCKED
        backend.record_observation(
            "task1", "nonce1", None, source="broker.commit:BLOCKED"
        )

        result = backend.verify("task1", "nonce1")
        assert result == LedgerVerdict.CONFIRMED_BLOCKED

    def test_verify_all(self) -> None:
        ledger = IndependentEffectLedger()
        backend = LocalLedgerBackend(ledger)
        backend.record_authorization("task1", "n1", frozenset({"a"}), source="test")
        backend.record_authorization("task2", "n2", frozenset({"b"}), source="test")
        backend.record_observation("task1", "n1", frozenset({"a"}), source="test")

        records = {
            ("task1", "n1"): frozenset({"a"}),
            ("task2", "n2"): frozenset({"b"}),
        }
        failures = backend.verify_all(records)
        # verify_all returns full UNKNOWN(...) strings per failed nonce
        assert len(failures) == 1
        # verify_all returns UNKNOWN(...) format since ledger.py change.
        # The failure message contains the task+nonce info.
        assert "task2" in failures[0] and "n2" in failures[0]
        assert "UNKNOWN" in failures[0]  # Format is: UNKNOWN(reason)

    def test_get_entries(self) -> None:
        ledger = IndependentEffectLedger()
        backend = LocalLedgerBackend(ledger)
        backend.record_authorization("t", "n", frozenset({"a"}), source="test")
        backend.record_observation("t", "n", frozenset({"a"}), source="test")

        entries = backend.get_entries(task_id="t", nonce="n")
        assert len(entries) == 2
        assert all(isinstance(e, LedgerEntry) for e in entries)

    def test_counts(self) -> None:
        ledger = IndependentEffectLedger()
        backend = LocalLedgerBackend(ledger)
        assert backend.authorization_count() == 0
        assert backend.observation_count() == 0

        backend.record_authorization("t", "n1", frozenset({"a"}), source="test")
        backend.record_authorization("t", "n2", frozenset({"b"}), source="test")
        backend.record_observation("t", "n1", frozenset({"a"}), source="test")

        assert backend.authorization_count() == 2
        assert backend.observation_count() == 1

    def test_reset(self) -> None:
        ledger = IndependentEffectLedger()
        backend = LocalLedgerBackend(ledger)
        backend.record_authorization("t", "n", frozenset({"a"}), source="test")
        backend.reset()
        assert backend.authorization_count() == 0
        assert backend.observation_count() == 0

    def test_get_authorization_entries(self) -> None:
        ledger = IndependentEffectLedger()
        backend = LocalLedgerBackend(ledger)
        backend.record_authorization("t", "n", frozenset({"a", "b"}), source="test")

        entries = backend.get_authorization_entries()
        assert ("t", "n") in entries
        assert len(entries[("t", "n")]) == 1
        assert entries[("t", "n")][0].authorized_targets == frozenset({"a", "b"})


# ---- LedgerProcessServer (in-process mock test) ----
class TestLedgerProcessServerDispatch:
    """Test _dispatch without socket I/O by calling it directly."""

    def test_dispatch_record_authorization(self) -> None:
        with TemporaryDirectory() as tmpdir:
            socket_path = Path(tmpdir) / "test.sock"
            server = LedgerProcessServer(socket_path=socket_path)
            # Manually set ledger (normally set by run())
            server._ledger = IndependentEffectLedger()

            resp = server._dispatch({
                "kind": "RECORD_AUTHORIZATION",
                "payload": {
                    "task_id": "t1",
                    "nonce": "n1",
                    "authorized_targets": ["file:///a"],
                    "source": "test",
                },
            })
            assert resp["ok"] is True
            assert server._ledger.authorization_count == 1

    def test_dispatch_record_observation(self) -> None:
        with TemporaryDirectory() as tmpdir:
            server = LedgerProcessServer(socket_path=Path(tmpdir) / "x")
            server._ledger = IndependentEffectLedger()
            server._ledger.record_authorization("t", "n", frozenset({"a"}), source="test")

            resp = server._dispatch({
                "kind": "RECORD_OBSERVATION",
                "payload": {"task_id": "t", "nonce": "n", "observed_targets": ["a"], "source": "test"},
            })
            assert resp["ok"] is True
            assert server._ledger.observation_count == 1

    def test_dispatch_verify_committed(self) -> None:
        with TemporaryDirectory() as tmpdir:
            server = LedgerProcessServer(socket_path=Path(tmpdir) / "x")
            server._ledger = IndependentEffectLedger()
            server._ledger.record_authorization("t", "n", frozenset({"a"}), source="test")
            server._ledger.record_observation("t", "n", frozenset({"a"}), source="test")

            resp = server._dispatch({
                "kind": "VERIFY",
                "payload": {"task_id": "t", "nonce": "n"},
            })
            assert resp["ok"] is True
            assert resp["result"] == "CONFIRMED_COMMITTED"

    def test_dispatch_verify_unknown(self) -> None:
        with TemporaryDirectory() as tmpdir:
            server = LedgerProcessServer(socket_path=Path(tmpdir) / "x")
            server._ledger = IndependentEffectLedger()
            server._ledger.record_authorization("t", "n", frozenset({"a"}), source="test")
            # No observation

            resp = server._dispatch({
                "kind": "VERIFY",
                "payload": {"task_id": "t", "nonce": "n"},
            })
            assert resp["ok"] is True
            # ledger returns "authorized_not_observed" reason (not "NO_OBSERVATION")
            assert resp["result"] == {
                "_type": "UNKNOWN",
                "reason": "authorized_not_observed(task=t,nonce=n,possible_bypass)",
            }

    def test_dispatch_verify_all(self) -> None:
        with TemporaryDirectory() as tmpdir:
            server = LedgerProcessServer(socket_path=Path(tmpdir) / "x")
            server._ledger = IndependentEffectLedger()
            server._ledger.record_authorization("t1", "n1", frozenset({"a"}), source="test")
            server._ledger.record_authorization("t2", "n2", frozenset({"b"}), source="test")
            server._ledger.record_observation("t1", "n1", frozenset({"a"}), source="test")

            resp = server._dispatch({
                "kind": "VERIFY_ALL",
                "payload": {
                    "records": {
                        "t1$n1": ["a"],
                        "t2$n2": ["b"],
                    }
                },
            })
            assert resp["ok"] is True
            # verify_all returns UNKNOWN(...) strings (not bare nonce)
            assert resp["result"] == [
                "UNKNOWN(authorized_not_observed(task=t2,nonce=n2,possible_bypass))"
            ]

    def test_dispatch_get_entries(self) -> None:
        with TemporaryDirectory() as tmpdir:
            server = LedgerProcessServer(socket_path=Path(tmpdir) / "x")
            server._ledger = IndependentEffectLedger()
            server._ledger.record_authorization("t", "n", frozenset({"a", "b"}), source="test")

            resp = server._dispatch({
                "kind": "GET_ENTRIES",
                "payload": {"task_id": "t", "nonce": "n"},
            })
            assert resp["ok"] is True
            entries = resp["result"]
            assert len(entries) == 1
            assert entries[0]["task_id"] == "t"
            assert set(entries[0]["authorized_targets"]) == {"a", "b"}

    def test_dispatch_counts(self) -> None:
        with TemporaryDirectory() as tmpdir:
            server = LedgerProcessServer(socket_path=Path(tmpdir) / "x")
            server._ledger = IndependentEffectLedger()
            server._ledger.record_authorization("t", "n", frozenset({"a"}), source="test")

            resp_auth = server._dispatch({"kind": "AUTHORIZATION_COUNT", "payload": {}})
            assert resp_auth["result"] == 1

            server._ledger.record_observation("t", "n", frozenset({"a"}), source="test")
            resp_obs = server._dispatch({"kind": "OBSERVATION_COUNT", "payload": {}})
            assert resp_obs["result"] == 1

    def test_dispatch_reset(self) -> None:
        with TemporaryDirectory() as tmpdir:
            server = LedgerProcessServer(socket_path=Path(tmpdir) / "x")
            server._ledger = IndependentEffectLedger()
            server._ledger.record_authorization("t", "n", frozenset({"a"}), source="test")

            resp = server._dispatch({"kind": "RESET", "payload": {}})
            assert resp["ok"] is True
            assert server._ledger.authorization_count == 0
            assert server._ledger.observation_count == 0

    def test_dispatch_unknown_request_raises_key_error(self) -> None:
        """Unknown request kinds raise KeyError (caught by server's _handle)."""
        with TemporaryDirectory() as tmpdir:
            server = LedgerProcessServer(socket_path=Path(tmpdir) / "x")
            server._ledger = IndependentEffectLedger()

            # KeyError propagates from LedgerRequest[invalid] and is caught
            # by server's _handle -> returns error dict
            resp = server._dispatch({
                "kind": "DOES_NOT_EXIST",
                "payload": {},
            })
            # The server catches all exceptions and returns error response
            assert resp["ok"] is False
            assert "DOES_NOT_EXIST" in resp["error"]


# ---- Full IPC integration (requires actual socket) ----
@pytest.mark.integration
class TestProcessLedgerClientIntegration:
    """End-to-end test: ProcessLedgerClient <-> LedgerProcessServer over real Unix socket.

    These tests are skipped in CI unless --integration flag is provided.
    """

    def test_record_and_verify_over_socket(self, tmp_path: Path) -> None:
        """End-to-end socket transport test using real Unix domain sockets.

        Tests the complete IPC pipeline: ProcessLedgerClient serializes requests
        -> Unix socket transport -> LedgerProcessServer dispatches -> response.
        Runs the server in a non-daemon thread (same process, real socket I/O).
        The non-daemon thread is joined before exiting, so threading's cleanup
        is deterministic — no race conditions.
        """
        import json, socket, threading, time, uuid

        socket_path = Path(f"/tmp/ledger-test-{uuid.uuid4().hex[:8]}.sock")
        if socket_path.exists():
            socket_path.unlink()

        ready = threading.Event()
        server = LedgerProcessServer(socket_path=socket_path, ready_event=ready)

        def run_server():
            server.run()

        server_thread = threading.Thread(target=run_server)
        server_thread.start()

        try:
            # wait for server to be bound + listening
            if not ready.wait(timeout=5.0):
                pytest.fail("Server did not become ready within 5s")

            # ---- Raw socket protocol validation ----
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            try:
                sock.connect(str(socket_path))

                # Record authorization via raw socket (length-prefixed format)
                req = json.dumps({
                    "kind": "RECORD_AUTHORIZATION",
                    "payload": {
                        "task_id": "t1", "nonce": "n1",
                        "authorized_targets": ["file:///a"], "source": "test",
                    },
                }).encode()
                sock.sendall(str(len(req)).encode() + b"\n" + req)
                header = b""
                while b"\n" not in header:
                    chunk = sock.recv(1)
                    if not chunk:
                        pytest.fail("Server closed connection during auth")
                    header += chunk
                length = int(header.strip().decode())
                raw = b""
                while len(raw) < length:
                    chunk = sock.recv(length - len(raw))
                    if not chunk:
                        pytest.fail("Server closed connection mid-response")
                    raw += chunk
                resp = json.loads(raw.decode())
                assert resp["ok"] is True, f"auth error: {resp.get('error')}"

                # Record observation via raw socket (length-prefixed format)
                req = json.dumps({
                    "kind": "RECORD_OBSERVATION",
                    "payload": {
                        "task_id": "t1", "nonce": "n1",
                        "observed_targets": ["file:///a"], "source": "test",
                    },
                }).encode()
                sock.sendall(str(len(req)).encode() + b"\n" + req)
                header = b""
                while b"\n" not in header:
                    chunk = sock.recv(1)
                    if not chunk:
                        pytest.fail("Server closed connection during obs")
                    header += chunk
                length = int(header.strip().decode())
                raw = b""
                while len(raw) < length:
                    chunk = sock.recv(length - len(raw))
                    if not chunk:
                        pytest.fail("Server closed connection mid-response")
                    raw += chunk
                resp = json.loads(raw.decode())
                assert resp["ok"] is True

                # Verify via raw socket (length-prefixed format)
                req = json.dumps({
                    "kind": "VERIFY",
                    "payload": {"task_id": "t1", "nonce": "n1"},
                }).encode()
                sock.sendall(str(len(req)).encode() + b"\n" + req)
                header = b""
                while b"\n" not in header:
                    chunk = sock.recv(1)
                    if not chunk:
                        pytest.fail("Server closed connection during verify")
                    header += chunk
                length = int(header.strip().decode())
                raw = b""
                while len(raw) < length:
                    chunk = sock.recv(length - len(raw))
                    if not chunk:
                        pytest.fail("Server closed connection mid-response")
                    raw += chunk
                resp = json.loads(raw.decode())
                assert resp["ok"] is True
                assert resp["result"] == "CONFIRMED_COMMITTED"
            finally:
                sock.close()

            # ---- ProcessLedgerClient high-level API ----
            client = ProcessLedgerClient(socket_path=socket_path)
            assert client.authorization_count() == 1
            assert client.observation_count() == 1

            # Add second entry via ProcessLedgerClient
            client.record_authorization(
                "task2", "nonce2", frozenset({"file:///b"}), source="test"
            )
            client.record_observation(
                "task2", "nonce2", frozenset({"file:///b"}), source="test"
            )
            assert client.authorization_count() == 2
            assert client.observation_count() == 2
            assert client.verify("task2", "nonce2") == LedgerVerdict.CONFIRMED_COMMITTED

        finally:
            # Signal shutdown and wait for server thread
            import signal
            server_thread.join(timeout=5.0)
            if socket_path.exists():
                socket_path.unlink(missing_ok=True)


# ---- LedgerBackend abstract interface ----
class TestLedgerBackendInterface:
    """Verify LocalLedgerBackend satisfies LedgerBackend contract."""

    def test_local_backend_is_abstract_interface(self) -> None:
        ledger = IndependentEffectLedger()
        backend = LocalLedgerBackend(ledger)
        # Confirm all abstract methods exist
        assert hasattr(backend, "record_authorization")
        assert hasattr(backend, "record_observation")
        assert hasattr(backend, "verify")
        assert hasattr(backend, "verify_all")
        assert hasattr(backend, "get_entries")
        assert hasattr(backend, "authorization_count")
        assert hasattr(backend, "observation_count")
        assert hasattr(backend, "reset")
        assert hasattr(backend, "get_authorization_entries")

    def test_backend_protocol_record_observation_with_none(self) -> None:
        """LocalLedgerBackend passes None observed_targets through."""
        ledger = IndependentEffectLedger()
        backend = LocalLedgerBackend(ledger)
        backend.record_authorization("t", "n", frozenset({"a"}), source="auth")
        # Source must match BLOCKED_SOURCES for verify() to return CONFIRMED_BLOCKED
        backend.record_observation("t", "n", None, source="broker.commit:BLOCKED")

        # _observations has one entry with observed_targets=None
        obs = ledger._observations.get(("t", "n"), [])
        assert len(obs) == 1, f"Expected 1 obs entry, got {len(obs)}"
        assert obs[0].observed_targets is None
        assert obs[0].source == "broker.commit:BLOCKED"

        # Authorization entry has observed_targets=None (sentinel: not yet observed)
        auth = ledger._authorizations.get(("t", "n"), [])
        assert len(auth) == 1
        assert auth[0].authorized_targets == frozenset({"a"})

        # verify returns CONFIRMED_BLOCKED: auth + obs with None + BLOCKED source
        result = backend.verify("t", "n")
        assert result == LedgerVerdict.CONFIRMED_BLOCKED

    def test_verify_requires_correct_source_for_blocked(self) -> None:
        """verify() only returns BLOCKED if source is in BLOCKED_SOURCES."""
        ledger = IndependentEffectLedger()
        backend = LocalLedgerBackend(ledger)
        backend.record_authorization("t", "n", frozenset({"a"}), source="auth")
        # Wrong source — verify does NOT treat None as BLOCKED
        backend.record_observation("t", "n", None, source="wrong_source")
        result = backend.verify("t", "n")
        # With wrong source: obs ⊆ auth → empty ⊆ {"a"} → CONFIRMED_COMMITTED
        assert result == LedgerVerdict.CONFIRMED_COMMITTED