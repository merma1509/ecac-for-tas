"""Tests for the IPC layer (multi-process ledger isolation)

These tests verify the LedgerBackend abstraction, LocalLedgerBackend,
ProcessLedgerClient, and LedgerProcessServer.

Note: Full multi-process tests (spawning actual child processes) require
a real Unix socket and are marked with @pytest.mark.integration.
The core LedgerBackend interface is tested in-process below.
"""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from effect_broker.ipc import (
    LedgerProcessServer,
    LedgerRequest,
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
                "payload": {"task_id": "t", "nonce": "n", "observed_targets": ["a"], "source": "test"},  # noqa: E501
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
        """End-to-end socket transport: ProcessLedgerClient <-> LedgerProcessServer.

        Runs the server in a daemon thread with a ready_event for synchronization.
        After all I/O completes, calls server.stop() to cleanly shut down the loop
        (no signal required, no join-timeout). The server thread exits immediately.
        """
        import json
        import socket
        import threading
        import uuid

        socket_path = Path(f"/tmp/ledger-test-{uuid.uuid4().hex[:8]}.sock")
        if socket_path.exists():
            socket_path.unlink()

        ready = threading.Event()
        server = LedgerProcessServer(socket_path=socket_path, ready_event=ready)

        def run_server() -> None:
            server.run()

        server_thread = threading.Thread(target=run_server, daemon=True)
        server_thread.start()

        try:
            # Wait for server to be bound + listening
            if not ready.wait(timeout=5.0):
                pytest.fail("Server did not become ready within 5s")

            # ---- Phase 1: Raw socket protocol (length-prefixed JSON) ----
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            try:
                sock.connect(str(socket_path))

                for kind, payload in [
                    (
                        "RECORD_AUTHORIZATION",
                        {
                            "task_id": "t1",
                            "nonce": "n1",
                            "authorized_targets": ["file:///a"],
                            "source": "test",
                        },
                    ),
                    (
                        "RECORD_OBSERVATION",
                        {
                            "task_id": "t1",
                            "nonce": "n1",
                            "observed_targets": ["file:///a"],
                            "source": "test",
                        },
                    ),
                    (
                        "VERIFY",
                        {"task_id": "t1", "nonce": "n1"},
                    ),
                ]:
                    req = json.dumps({"kind": kind, "payload": payload}).encode()
                    sock.sendall(str(len(req)).encode() + b"\n" + req)
                    header = b""
                    while b"\n" not in header:
                        chunk = sock.recv(1)
                        if not chunk:
                            pytest.fail("Server closed connection")
                        header += chunk
                    length = int(header.strip().decode())
                    raw = b""
                    while len(raw) < length:
                        chunk = sock.recv(length - len(raw))
                        if not chunk:
                            pytest.fail("Server closed connection mid-response")
                        raw += chunk
                    resp = json.loads(raw.decode())
                    assert resp["ok"] is True, f"{kind} failed: {resp.get('error')}"
                    if kind == "VERIFY":
                        assert resp["result"] == "CONFIRMED_COMMITTED"
            finally:
                sock.close()

            # ---- Phase 2: ProcessLedgerClient high-level API ----
            client = ProcessLedgerClient(socket_path=socket_path)
            assert client.authorization_count() == 1
            assert client.observation_count() == 1

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
            # Stop server cleanly — sets shutdown flag + closes socket.
            # No signal needed; no join-timeout; daemon thread exits immediately.
            server.stop()
            server_thread.join(timeout=2.0)
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


# ---- IPC end-to-end: broker + ProcessLedgerClient ----
@pytest.mark.integration
class TestBrokerWithProcessLedgerClient:
    """End-to-end: broker uses ProcessLedgerClient as its ledger backend.

    Verifies the production-ready path: broker + executor record to a
    separate ledger process, not a local in-process ledger.
    """

    def test_broker_commits_record_to_remote_ledger(self, tmp_path: Path) -> None:
        """Broker.commit() records to ProcessLedgerClient — authorized + observed."""
        import threading
        import uuid

        from effect_broker.broker import EffectBroker
        from effect_broker.model import Capability, Commit, Effect, Task

        socket_path = Path(f"/tmp/ledger-broker-test-{uuid.uuid4().hex[:8]}.sock")
        if socket_path.exists():
            socket_path.unlink()

        ready = threading.Event()
        server = LedgerProcessServer(socket_path=socket_path, ready_event=ready)

        server_thread = threading.Thread(target=server.run, daemon=True)
        server_thread.start()

        try:
            if not ready.wait(timeout=5.0):
                pytest.fail("Server did not become ready within 5s")

            # Broker uses ProcessLedgerClient as ledger backend
            client = ProcessLedgerClient(socket_path=socket_path)
            broker = EffectBroker(ledger=client)

            # Register task with permissive ceiling and grant capability
            ceiling = Capability(
                owner="User",
                holder="EffectBroker",
                right="*",
                target="*",
                scope=frozenset({"*"}),
                expiry=float("inf"),
                nonce="default-ceiling",
            )
            task = Task(task_id="remote-test", owner="User", ceiling=ceiling)
            broker.tasks["remote-test"] = task

            cap = Capability(
                owner="User",
                holder="EffectBroker",
                right="read",
                target="file:///reports",
                scope=frozenset({"*"}),
                expiry=float("inf"),
                nonce="cap-remote",
            )
            broker.capabilities["cap-remote"] = cap

            # Bootstrap the target resource so apply_effect() succeeds
            broker.store._unsafe_bootstrap_file("file:///reports", "INTERNAL")

            # Commit an effect
            effect = Effect(
                etype="read",
                target="file:///reports",
                metadata={},
                provenance=(),
                capability_nonce="cap-remote",
                delegation_chain=(),
            )
            commit = Commit(effect=effect, task=task)
            allow, ev = broker.commit(commit)

            assert allow is True, f"Commit should ALLOW: {ev}"

            # Verify ledger process received both authorization and observation
            assert client.authorization_count() == 1
            assert client.observation_count() == 1

            verdict = client.verify("remote-test", "cap-remote")
            assert verdict == LedgerVerdict.CONFIRMED_COMMITTED

        finally:
            server.stop()
            server_thread.join(timeout=2.0)
            if socket_path.exists():
                socket_path.unlink(missing_ok=True)

    def test_broker_blocked_effect_records_auth_only(self, tmp_path: Path) -> None:
        """BLOCKed effect: authorization recorded, but observation has None + BLOCKED source."""
        import threading
        import uuid

        from effect_broker.broker import EffectBroker
        from effect_broker.model import Capability, Commit, Effect, Task

        socket_path = Path(f"/tmp/ledger-broker-blocked-{uuid.uuid4().hex[:8]}.sock")
        if socket_path.exists():
            socket_path.unlink()

        ready = threading.Event()
        server = LedgerProcessServer(socket_path=socket_path, ready_event=ready)
        server_thread = threading.Thread(target=server.run, daemon=True)
        server_thread.start()

        try:
            if not ready.wait(timeout=5.0):
                pytest.fail("Server did not become ready within 5s")

            client = ProcessLedgerClient(socket_path=socket_path)
            broker = EffectBroker(ledger=client)

            ceiling = Capability(
                owner="User",
                holder="EffectBroker",
                right="*",
                target="*",
                scope=frozenset({"*"}),
                expiry=float("inf"),
                nonce="default-ceiling",
            )
            task = Task(task_id="blocked-test", owner="User", ceiling=ceiling)
            broker.tasks["blocked-test"] = task

            # No matching capability → BLOCKed by Auth
            effect = Effect(
                etype="send",
                target="internal@corp.com",
                metadata={},
                provenance=(),
                capability_nonce="no-such-cap",
                delegation_chain=(),
            )
            commit = Commit(effect=effect, task=task)
            allow, ev = broker.commit(commit)

            assert allow is False
            assert ev["primary_blocker"] == "Auth"

            # Authorization was recorded (gate evaluates predicates, including Auth)
            assert client.authorization_count() == 1
            # Observation recorded with None + BLOCKED source
            assert client.observation_count() == 1

            verdict = client.verify("blocked-test", "no-such-cap")
            assert verdict == LedgerVerdict.CONFIRMED_BLOCKED

        finally:
            server.stop()
            server_thread.join(timeout=2.0)
            if socket_path.exists():
                socket_path.unlink(missing_ok=True)

    def test_verify_complete_mediation_via_process_client(self, tmp_path: Path) -> None:
        """broker.verify_complete_mediation() works via ProcessLedgerClient."""
        import threading
        import uuid

        from effect_broker.broker import EffectBroker
        from effect_broker.model import Capability, Commit, Effect, Task

        socket_path = Path(f"/tmp/ledger-mediation-{uuid.uuid4().hex[:8]}.sock")
        if socket_path.exists():
            socket_path.unlink()

        ready = threading.Event()
        server = LedgerProcessServer(socket_path=socket_path, ready_event=ready)
        server_thread = threading.Thread(target=server.run, daemon=True)
        server_thread.start()

        try:
            if not ready.wait(timeout=5.0):
                pytest.fail("Server did not become ready within 5s")

            client = ProcessLedgerClient(socket_path=socket_path)
            broker = EffectBroker(ledger=client)

            ceiling = Capability(
                owner="User",
                holder="EffectBroker",
                right="*",
                target="*",
                scope=frozenset({"*"}),
                expiry=float("inf"),
                nonce="default-ceiling",
            )
            task = Task(task_id="mediation-test", owner="User", ceiling=ceiling)
            broker.tasks["mediation-test"] = task

            cap = Capability(
                owner="User",
                holder="EffectBroker",
                right="read",
                target="file:///reports",
                scope=frozenset({"*"}),
                expiry=float("inf"),
                nonce="cap-med",
            )
            broker.capabilities["cap-med"] = cap

            # Bootstrap the target resource
            broker.store._unsafe_bootstrap_file("file:///reports", "INTERNAL")

            effect = Effect(
                etype="read",
                target="file:///reports",
                metadata={},
                provenance=(),
                capability_nonce="cap-med",
                delegation_chain=(),
            )
            commit = Commit(effect=effect, task=task)
            broker.commit(commit)

            # verify_complete_mediation() calls client.get_authorization_entries()
            failures = broker.verify_complete_mediation()
            assert failures == [], f"Expected no failures, got: {failures}"

        finally:
            server.stop()
            server_thread.join(timeout=2.0)
            if socket_path.exists():
                socket_path.unlink(missing_ok=True)


class TestSessionSyncIPC:
    """Tests for SYNC_SESSION IPC between broker and executor subprocess."""

    def test_sync_session_stores_state_in_subprocess(self) -> None:
        """SYNC_SESSION request stores session state in executor's _session_states."""
        import threading
        from pathlib import Path

        from effect_broker.executor_subprocess import ExecutorServer

        socket_path = Path("/tmp/test-sync-session.sock")
        if socket_path.exists():
            socket_path.unlink()

        ready = threading.Event()
        server = ExecutorServer(socket_path, ready_event=ready)
        server_thread = threading.Thread(target=server.run, daemon=True)
        server_thread.start()
        ready.wait(timeout=5.0)

        try:
            from effect_broker.executor_ipc import ProcessExecutorClient, session_state_to_dict
            from effect_broker.model import Session

            client = ProcessExecutorClient(socket_path)

            # Create a mock session state
            session = Session(session_id="task-1")
            session.logical_time = 10.0
            session.used = frozenset({"nonce-1", "nonce-2"})
            session.revoked = frozenset({"revoked-1"})
            session.taint_for_send("test reason")  # sets _tainted = True
            session.live = True

            # Sync session state to subprocess
            result = client.sync_session(
                "task-1",
                session_state_to_dict(session),
            )

            assert result["task_id"] == "task-1"
            assert result["session_snapshot"]["session_id"] == "task-1"
            assert result["session_snapshot"]["logical_time"] == 10.0
            assert set(result["session_snapshot"]["used"]) == {"nonce-1", "nonce-2"}
            assert result["session_snapshot"]["revoked"] == ["revoked-1"]
            assert result["session_snapshot"]["tainted"] is True
            assert result["session_snapshot"]["live"] is True
            assert result["all_tasks"] == ["task-1"]

        finally:
            server.stop()
            server_thread.join(timeout=2.0)
            if socket_path.exists():
                socket_path.unlink()

    def test_sync_session_handles_multiple_tasks(self) -> None:
        """SYNC_SESSION stores state per-task_id, multiple tasks coexist."""
        import threading
        from pathlib import Path

        from effect_broker.executor_subprocess import ExecutorServer

        socket_path = Path("/tmp/test-sync-multi-task.sock")
        if socket_path.exists():
            socket_path.unlink()

        ready = threading.Event()
        server = ExecutorServer(socket_path, ready_event=ready)
        server_thread = threading.Thread(target=server.run, daemon=True)
        server_thread.start()
        ready.wait(timeout=5.0)

        try:
            from effect_broker.executor_ipc import ProcessExecutorClient, session_state_to_dict
            from effect_broker.model import Session

            client = ProcessExecutorClient(socket_path)

            # Sync two different tasks
            session1 = Session(session_id="task-A")
            session1.logical_time = 5.0
            session1.used = frozenset({"cap-A"})

            session2 = Session(session_id="task-B")
            session2.logical_time = 12.0
            session2.used = frozenset({"cap-B", "cap-C"})
            session2.taint_for_send("test reason for task-B")

            _unused_result1 = client.sync_session("task-A", session_state_to_dict(session1))
            result2 = client.sync_session("task-B", session_state_to_dict(session2))

            # After both syncs, all_tasks should include both tasks
            # Check in result2 which is the latest snapshot
            assert set(result2["all_tasks"]) == {"task-A", "task-B"}

            # After syncing task-B, subprocess's "current view" is task-B's state
            # (since we synced task-B last). Check that task-A was also stored.
            assert "task-A" in result2["all_tasks"]
            assert "task-B" in result2["all_tasks"]

        finally:
            server.stop()
            server_thread.join(timeout=2.0)
            if socket_path.exists():
                socket_path.unlink()

    def test_sync_session_replaces_existing_state(self) -> None:
        """SYNC_SESSION for same task_id replaces previous state."""
        import threading
        from pathlib import Path

        from effect_broker.executor_subprocess import ExecutorServer

        socket_path = Path("/tmp/test-sync-replace.sock")
        if socket_path.exists():
            socket_path.unlink()

        ready = threading.Event()
        server = ExecutorServer(socket_path, ready_event=ready)
        server_thread = threading.Thread(target=server.run, daemon=True)
        server_thread.start()
        ready.wait(timeout=5.0)

        try:
            from effect_broker.executor_ipc import ProcessExecutorClient, session_state_to_dict
            from effect_broker.model import Session

            client = ProcessExecutorClient(socket_path)

            session1 = Session(session_id="task-X")
            session1.logical_time = 1.0
            session1.used = frozenset({"nonce-A"})

            session2 = Session(session_id="task-X")
            session2.logical_time = 99.0
            session2.used = frozenset({"nonce-A", "nonce-B", "nonce-C"})

            client.sync_session("task-X", session_state_to_dict(session1))
            result = client.sync_session("task-X", session_state_to_dict(session2))

            # Latest snapshot should reflect session2's state
            assert result["session_snapshot"]["logical_time"] == 99.0
            assert set(result["session_snapshot"]["used"]) == {"nonce-A", "nonce-B", "nonce-C"}

        finally:
            server.stop()
            server_thread.join(timeout=2.0)
            if socket_path.exists():
                socket_path.unlink()
