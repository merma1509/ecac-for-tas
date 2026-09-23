"""IPC layer for multi-process ledger isolation.

ARCHITECTURE
────────────
In a production deployment, the IndependentEffectLedger lives in an isolated
process (or enclave) that is NOT reachable by the broker or executor except
through this IPC interface:

    ┌─────────────────────┐     IPC (Unix socket / TCP)     ┌─────────────────┐
    │  broker + executor  │ ──────────────────────────────► │ Ledger Process  │
    │  (same process or   │     record_authorization()      │                 │
    │   separate process) │     record_observation()        │ Independent     │
    └─────────────────────┘     verify()                    │ EffectLedger    │
                                     verify_all()           │                 │
                                                            └─────────────────┘

The broker/executor share a LedgerBackend client that forwards all calls over
IPC. The ledger process is the single writer; no other component can mutate
the ledger state directly.

USAGE
─────
# Option A: Same-process (development / same-process model)
broker = EffectBroker(ledger=None)  # creates local IndependentEffectLedger

# Option B: Multi-process (production)
from effect_broker.ipc import LedgerProcessHandle, ProcessLedgerClient
ledger_process = LedgerProcessHandle(socket_path="/tmp/ecac-ledger.sock")
client = ProcessLedgerClient(ledger_process.socket_path)
broker = EffectBroker(ledger=client)
# On shutdown:
ledger_process.stop()
"""

from __future__ import annotations

import json
import socket
import subprocess
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .ledger import (
        IndependentEffectLedger,
        LedgerEntry,
        LedgerVerdict,
        UnknownLedgerResult,
    )


class LedgerRequest(Enum):
    """Wire format for ledger IPC requests."""

    RECORD_AUTHORIZATION = auto()
    RECORD_OBSERVATION = auto()
    VERIFY = auto()
    VERIFY_ALL = auto()
    GET_ENTRIES = auto()
    AUTHORIZATION_COUNT = auto()
    OBSERVATION_COUNT = auto()
    RESET = auto()
    GET_AUTHORIZATION_ENTRIES = auto()


@dataclass(frozen=True)
class LedgerResponse:
    """Wire format for ledger IPC responses."""

    ok: bool
    result: Any
    error: str | None = None


class LedgerBackend(ABC):
    """Abstract interface for ledger backends.

    Both local (in-process IndependentEffectLedger) and remote
    (ProcessLedgerClient via IPC) backends implement this.
    """

    @abstractmethod
    def record_authorization(
        self,
        task_id: str,
        nonce: str,
        authorized_targets: frozenset[str],
        source: str,
    ) -> None:
        """Record an authorization event (effect passed broker gate)."""

    @abstractmethod
    def record_observation(
        self,
        task_id: str,
        nonce: str,
        observed_targets: frozenset[str] | None,
        source: str,
    ) -> None:
        """Record an observation event (effect was applied or blocked)."""

    @abstractmethod
    def verify(self, task_id: str, nonce: str) -> LedgerVerdict | UnknownLedgerResult:
        """Verify the outcome of a single effect."""

    @abstractmethod
    def verify_all(self, authorized_records: dict[tuple[str, str], frozenset[str]]) -> list[str]:
        """Verify multiple nonces at once. Returns list of failure nonces."""

    @abstractmethod
    def get_entries(
        self, task_id: str | None = None, nonce: str | None = None
    ) -> list[LedgerEntry]:
        """Get ledger entries, optionally filtered."""

    @abstractmethod
    def authorization_count(self) -> int:
        """Total authorization entries."""

    @abstractmethod
    def observation_count(self) -> int:
        """Total observation entries."""

    @abstractmethod
    def reset(self) -> None:
        """Clear all entries."""

    @abstractmethod
    def get_authorization_entries(
        self,
    ) -> dict[tuple[str, str], list[LedgerEntry]]:
        """Get the raw authorization map. Internal use only."""
        raise NotImplementedError


# ---- Local in-process backend (keeps existing behavior) ----
class LocalLedgerBackend(LedgerBackend):
    """Wraps a local IndependentEffectLedger as a LedgerBackend."""

    def __init__(self, ledger: IndependentEffectLedger) -> None:
        self._ledger = ledger

    def record_authorization(
        self,
        task_id: str,
        nonce: str,
        authorized_targets: frozenset[str],
        source: str,
    ) -> None:
        self._ledger.record_authorization(task_id, nonce, authorized_targets, source)

    def record_observation(
        self,
        task_id: str,
        nonce: str,
        observed_targets: frozenset[str] | None,
        source: str,
    ) -> None:
        self._ledger.record_observation(task_id, nonce, observed_targets, source)

    def verify(self, task_id: str, nonce: str) -> LedgerVerdict | UnknownLedgerResult:
        return self._ledger.verify(task_id, nonce)

    def verify_all(self, authorized_records: dict[tuple[str, str], frozenset[str]]) -> list[str]:
        return self._ledger.verify_all(authorized_records)

    def get_entries(
        self, task_id: str | None = None, nonce: str | None = None
    ) -> list[LedgerEntry]:
        return self._ledger.get_entries(task_id, nonce)

    def authorization_count(self) -> int:
        return self._ledger.authorization_count

    def observation_count(self) -> int:
        return self._ledger.observation_count

    def reset(self) -> None:
        self._ledger.reset()

    def get_authorization_entries(
        self,
    ) -> dict[tuple[str, str], list[LedgerEntry]]:
        """Get the raw authorization map. Used by broker.verify_complete_mediation()."""
        return self._ledger._authorizations


# ---- IPC wire format ----
def _serialize_request(kind: LedgerRequest, payload: dict[str, Any]) -> bytes:
    # Length-prefixed format: "<length>\n<json>" — matches LedgerProcessServer._handle
    body = json.dumps({"kind": kind.name, "payload": payload}).encode()
    return str(len(body)).encode() + b"\n" + body


def _parse_response(raw: bytes) -> LedgerResponse:
    data = json.loads(raw.decode())
    return LedgerResponse(ok=data["ok"], result=data["result"], error=data.get("error"))


# ---- Multi-process backend via Unix domain socket ----
class ProcessLedgerClient(LedgerBackend):
    """IPC client: forwards all ledger calls to a ledger process over Unix socket.

    Usage:
        client = ProcessLedgerClient("/tmp/ecac-ledger.sock")
        broker = EffectBroker(ledger=client)
    """

    def __init__(self, socket_path: str | Path) -> None:
        self._path = Path(socket_path)
        self._lock = threading.Lock()  # serialize concurrent IPC calls
        self._connected = False

    def _send(self, req: LedgerRequest, payload: dict[str, Any]) -> Any:
        """Send a request and return the parsed result. Raises on error."""
        with self._lock:
            try:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                    sock.settimeout(30.0)
                    sock.connect(str(self._path))
                    sock.sendall(_serialize_request(req, payload))
                    # Read response length prefix
                    header = b""
                    while b"\n" not in header:
                        header += sock.recv(1)
                    length = int(header.strip().decode())
                    raw = b""
                    while len(raw) < length:
                        chunk = sock.recv(length - len(raw))
                        if not chunk:
                            raise ConnectionError("Ledger process closed connection")
                        raw += chunk
                    resp = _parse_response(raw)
            except OSError as e:
                raise RuntimeError(
                    f"Ledger IPC failed ({req.name}): {e}. Ensure the ledger process is running."
                ) from e

        if not resp.ok:
            raise RuntimeError(f"Ledger IPC error: {resp.error}")

        return resp.result

    # ---- LedgerBackend implementation ----
    def record_authorization(
        self,
        task_id: str,
        nonce: str,
        authorized_targets: frozenset[str],
        source: str,
    ) -> None:
        self._send(
            LedgerRequest.RECORD_AUTHORIZATION,
            {
                "task_id": task_id,
                "nonce": nonce,
                "authorized_targets": list(authorized_targets),
                "source": source,
            },
        )

    def record_observation(
        self,
        task_id: str,
        nonce: str,
        observed_targets: frozenset[str] | None,
        source: str,
    ) -> None:
        self._send(
            LedgerRequest.RECORD_OBSERVATION,
            {
                "task_id": task_id,
                "nonce": nonce,
                "observed_targets": (
                    list(observed_targets) if observed_targets is not None else None
                ),
                "source": source,
            },
        )

    def verify(self, task_id: str, nonce: str) -> LedgerVerdict | UnknownLedgerResult:
        from .ledger import LedgerVerdict, UnknownLedgerResult

        result = self._send(LedgerRequest.VERIFY, {"task_id": task_id, "nonce": nonce})
        if isinstance(result, dict) and result.get("_type") == "UNKNOWN":
            return UnknownLedgerResult(reason=result["reason"])
        return LedgerVerdict[result]

    def verify_all(self, authorized_records: dict[tuple[str, str], frozenset[str]]) -> list[str]:
        serialized = {
            f"{tid}${nonce}": list(targets) for (tid, nonce), targets in authorized_records.items()
        }
        return self._send(LedgerRequest.VERIFY_ALL, {"records": serialized})  # type: ignore[no-any-return]

    def get_entries(
        self, task_id: str | None = None, nonce: str | None = None
    ) -> list[LedgerEntry]:
        from .ledger import LedgerEntry

        # Raw dict entries — reconstruct LedgerEntry objects
        raw = self._send(LedgerRequest.GET_ENTRIES, {"task_id": task_id, "nonce": nonce})
        return [
            LedgerEntry(
                task_id=e["task_id"],
                nonce=e["nonce"],
                authorized_targets=frozenset(e["authorized_targets"]),
                observed_targets=(
                    frozenset(e["observed_targets"]) if e["observed_targets"] is not None else None
                ),
                timestamp=e["timestamp"],
                source=e["source"],
            )
            for e in raw
        ]

    def authorization_count(self) -> int:
        return self._send(LedgerRequest.AUTHORIZATION_COUNT, {})  # type: ignore[no-any-return]

    def observation_count(self) -> int:
        return self._send(LedgerRequest.OBSERVATION_COUNT, {})  # type: ignore[no-any-return]

    def reset(self) -> None:
        self._send(LedgerRequest.RESET, {})

    def get_authorization_entries(
        self,
    ) -> dict[tuple[str, str], list[LedgerEntry]]:
        from .ledger import LedgerEntry

        raw = self._send(LedgerRequest.GET_AUTHORIZATION_ENTRIES, {})
        result: dict[tuple[str, str], list[LedgerEntry]] = {}
        for key_str, entries in raw.items():
            tid, nonce = key_str.split("$", 1)
            result[(tid, nonce)] = [
                LedgerEntry(
                    task_id=e["task_id"],
                    nonce=e["nonce"],
                    authorized_targets=frozenset(e["authorized_targets"]),
                    observed_targets=(
                        frozenset(e["observed_targets"])
                        if e["observed_targets"] is not None
                        else None
                    ),
                    timestamp=e["timestamp"],
                    source=e["source"],
                )
                for e in entries
            ]
        return result


# ---- Ledger process server (runs in separate process) ----
class LedgerProcessServer:
    """Standalone server that runs IndependentEffectLedger over IPC.

    This is the process that ProcessLedgerClient connects to.
    Run as: python -m effect_broker.ledger_process [--socket /tmp/ecac-ledger.sock]

    For testing, pass a `ready_event: threading.Event` to have the server signal
    readiness (after bind+listen, before the main accept loop) so callers can
    synchronize connection attempts without relying on timing sleeps or socket
    file existence checks.
    """

    def __init__(
        self,
        socket_path: str | Path,
        ready_event: threading.Event | None = None,
    ) -> None:
        self._path = Path(socket_path)
        self._ledger: IndependentEffectLedger | None = None  # set in run()
        # Optional event to signal after bind/listen are complete (for test sync)
        self._ready_event = ready_event
        self._shutdown = threading.Event()
        self._server: socket.socket | None = None

    def stop(self) -> None:
        """Stop the server loop from any thread. Works via socket close + shutdown flag."""
        self._shutdown.set()
        if self._server is not None:
            try:
                self._server.close()
            except OSError:
                pass

    def run(self) -> None:
        """Main server loop. Blocks until stop() is called or a signal is received."""
        import signal

        from .ledger import IndependentEffectLedger

        ledger: IndependentEffectLedger = IndependentEffectLedger()
        self._ledger = ledger
        self._shutdown.clear()

        # Clean up any existing socket
        if self._path.exists():
            self._path.unlink()

        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(str(self._path))
        server.listen(10)
        self._server = server

        def shutdown_handler(_sig: Any, _frame: Any) -> None:
            self._shutdown.set()
            try:
                server.close()
            except OSError:
                pass

        if self._ready_event is not None:
            self._ready_event.set()

        try:
            signal.signal(signal.SIGINT, shutdown_handler)
            signal.signal(signal.SIGTERM, shutdown_handler)
        except (ValueError, OSError):
            pass

        while True:
            if self._shutdown.is_set():
                break
            server.settimeout(1.0)
            try:
                conn, _ = server.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

        self._server = None
        if self._path.exists():
            self._path.unlink(missing_ok=True)

    def _handle(self, conn: socket.socket) -> None:
        """Handle a single IPC connection."""
        try:
            while True:
                # Read length-prefixed request
                header = b""
                while b"\n" not in header:
                    chunk = conn.recv(1)
                    if not chunk:
                        return
                    header += chunk
                length = int(header.strip().decode())

                raw = b""
                while len(raw) < length:
                    chunk = conn.recv(length - len(raw))
                    if not chunk:
                        return
                    raw += chunk

                req = json.loads(raw.decode())
                resp = self._dispatch(req)
                resp_bytes = json.dumps(resp).encode()
                conn.sendall(str(len(resp_bytes)).encode() + b"\n" + resp_bytes)
        except Exception as e:
            try:
                err_resp = json.dumps({"ok": False, "result": None, "error": str(e)}).encode()
                conn.sendall(str(len(err_resp)).encode() + b"\n" + err_resp)
            except Exception:
                pass
        finally:
            conn.close()

    def _dispatch(self, req: dict[str, Any]) -> dict[str, Any]:
        """Dispatch a request to the ledger and return a response dict."""
        from .ledger import UnknownLedgerResult

        try:
            kind = LedgerRequest[req["kind"]]
        except KeyError:
            return {
                "ok": False,
                "result": None,
                "error": f"Unknown request kind: {req['kind']}",
            }
        payload = req["payload"]

        # _dispatch is called only after run() sets self._ledger
        assert self._ledger is not None
        ledger = self._ledger

        try:
            match kind:
                case LedgerRequest.RECORD_AUTHORIZATION:
                    ledger.record_authorization(
                        payload["task_id"],
                        payload["nonce"],
                        frozenset(payload["authorized_targets"]),
                        payload["source"],
                    )
                    return {"ok": True, "result": True}

                case LedgerRequest.RECORD_OBSERVATION:
                    targets_raw = payload["observed_targets"]
                    obs: frozenset[str] | None = frozenset(targets_raw) if targets_raw else None
                    ledger.record_observation(
                        payload["task_id"], payload["nonce"], obs, payload["source"]
                    )
                    return {"ok": True, "result": True}

                case LedgerRequest.VERIFY:
                    result = ledger.verify(payload["task_id"], payload["nonce"])
                    if isinstance(result, UnknownLedgerResult):
                        return {"ok": True, "result": {"_type": "UNKNOWN", "reason": result.reason}}
                    return {"ok": True, "result": result.name}

                case LedgerRequest.VERIFY_ALL:
                    records = {
                        tuple(k.split("$")): frozenset(v) for k, v in payload["records"].items()
                    }
                    failures = ledger.verify_all(records)
                    return {"ok": True, "result": failures}

                case LedgerRequest.GET_ENTRIES:
                    entries = ledger.get_entries(payload.get("task_id"), payload.get("nonce"))
                    return {
                        "ok": True,
                        "result": [
                            {
                                "task_id": e.task_id,
                                "nonce": e.nonce,
                                "authorized_targets": list(e.authorized_targets),
                                "observed_targets": (
                                    list(e.observed_targets) if e.observed_targets else None
                                ),
                                "timestamp": e.timestamp,
                                "source": e.source,
                            }
                            for e in entries
                        ],
                    }

                case LedgerRequest.AUTHORIZATION_COUNT:
                    return {"ok": True, "result": ledger.authorization_count}

                case LedgerRequest.OBSERVATION_COUNT:
                    return {"ok": True, "result": ledger.observation_count}

                case LedgerRequest.RESET:
                    ledger.reset()
                    return {"ok": True, "result": True}

                case LedgerRequest.GET_AUTHORIZATION_ENTRIES:
                    return {
                        "ok": True,
                        "result": {
                            f"{tid}${nonce}": [
                                {
                                    "task_id": e.task_id,
                                    "nonce": e.nonce,
                                    "authorized_targets": list(e.authorized_targets),
                                    "observed_targets": (
                                        list(e.observed_targets)
                                        if e.observed_targets is not None
                                        else None
                                    ),
                                    "timestamp": e.timestamp,
                                    "source": e.source,
                                }
                                for e in entries
                            ]
                            for (tid, nonce), entries in ledger.get_authorization_entries().items()
                        },
                    }

        except Exception as e:
            return {"ok": False, "result": None, "error": str(e)}


# ---- Ledger process lifecycle manager ----
class LedgerProcessHandle:
    """Starts and stops a LedgerProcessServer subprocess.

    Usage:
        handle = LedgerProcessHandle("/tmp/ecac-ledger.sock")
        handle.start()          # blocks until socket is listening
        client = ProcessLedgerClient(handle.socket_path)
        # ... use client ...
        handle.stop()           # terminates the ledger subprocess
    """

    def __init__(self, socket_path: str | Path) -> None:
        self._socket_path = Path(socket_path)
        self._proc: subprocess.Popen[bytes] | None = None

    @property
    def socket_path(self) -> Path:
        """Path to the Unix socket. Connect via ProcessLedgerClient."""
        return self._socket_path

    def start(self, timeout: float = 5.0) -> None:
        """Start the ledger subprocess and wait for it to be listening."""
        import subprocess
        import sys
        import time

        # Use -m to run as a module so effect_broker imports resolve correctly.
        # Change to the package root so -m resolves effect_broker as a package.
        ecac_root = Path(__file__).parent.parent  # project root (contains effect_broker/)
        script = ecac_root / "effect_broker" / "ledger_process.py"
        if self._socket_path.exists():
            self._socket_path.unlink()
        self._proc = subprocess.Popen(
            [sys.executable, "-m", "effect_broker.ledger_process",
             "--socket", str(self._socket_path)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=str(ecac_root),
        )
        # Wait for socket file to appear (proves bind() succeeded).
        # After the file exists, wait 500ms for the accept loop to fully start.
        start = time.monotonic()
        while (time.monotonic() - start) < timeout:
            if self._proc.poll() is not None:
                raise RuntimeError(f"Ledger process exited early: {self._proc.returncode}")
            if self._socket_path.exists():
                break
            time.sleep(0.05)
        else:
            self._proc.terminate()
            self._proc.wait(timeout=2)
            raise RuntimeError(
                f"Ledger socket never created within {timeout}s (socket: {self._socket_path})"
            )
        time.sleep(0.5)  # Let accept loop fully start

    def stop(self, timeout: float = 2.0) -> None:
        """Terminate the ledger subprocess."""
        import subprocess

        if self._proc is None:
            return
        self._proc.terminate()
        try:
            self._proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self._proc.kill()
            self._proc.wait()
        finally:
            self._proc = None
            if self._socket_path.exists():
                self._socket_path.unlink(missing_ok=True)
