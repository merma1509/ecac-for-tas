"""IPC wire protocol for broker ↔ executor subprocess.

ARCHITECTURE
────────────
The executor runs in an ISOLATED process (not the broker's process).
The broker sends serialized Commit objects; the executor:
  1. Applies the effect to its own store copy
  2. Returns observed targets (what actually changed)
  3. The observed targets are sent to the ledger (in a THIRD process)

    ┌──────────────┐  execute(commit)  ┌─────────────────────┐
    │  broker      │ ────────────────► │  Executor Process   │
    │  (process 1) │  allow/evidence   │  (process 2)        │
    │              │ ◄──────────────── │  - IsolatedStore    │
    └──────────────┘                   │  - Applies effects  │
              │                        └─────────────────────┘
              │ record_observation()             │
              ▼                                  │ read_store() for
    ┌──────────────┐  verify()                   │ independent
    │  Ledger      │ ◄─────── observed_targets ──┘ verification
    │  Process 3   │
    └──────────────┘

SERIALIZATION
─────────────
Commit/Effect/Capability are serialized as plain dicts (no class refs).
The executor process deserializes, applies, returns observed_targets as a frozenset.
"""

from __future__ import annotations

import json
import threading
from enum import Enum, auto
from pathlib import Path
from typing import Any, cast


class ExecutorRequest(Enum):
    """Wire format: broker → executor subprocess."""

    EXECUTE = auto()  # Apply an simulated effect (internal store only)
    APPLY_EFFECT = auto()  # Apply an effect with REAL OS/SMTP operations (moved from broker)
    APPLY_COMMIT = auto()  # Atomic commit: Fresh check + nonce reserve + apply in subprocess
    SYNC_SESSION = (
        auto()
    )  # Sync session state from broker to subprocess (used, revoked, taint, clock)
    GET_SESSION = auto()  # Get session state from subprocess to broker (B→A, no overwrite)
    READ_STORE = auto()  # Observer reads actual store state for verification
    READ_EMAILS = auto()  # Observer reads emails for duplicate accounting
    READ_FILES = auto()  # Observer reads files
    READ_MAILBOXES = auto()  # Observer reads mailboxes
    BOOTSTRAP = auto()  # Bootstrap initial resources (files/emails/mailboxes)
    SHUTDOWN = auto()  # Clean shutdown


# ---- Dataclass serialization ----
# These helpers convert frozen dataclasses to/from plain dicts for IPC.
# All classes are imported from .model and converted explicitly here.
def effect_to_dict(effect: Any) -> dict[str, Any]:
    """Serialize an Effect to a plain dict for IPC."""

    return {
        "etype": effect.etype,
        "target": effect.target,
        "metadata": dict(effect.metadata),
        "provenance": [
            {
                "name": d.name,
                "confidentiality": d.confidentiality.name,
                "integrity": d.integrity.name,
                "content": d.content,
            }
            for d in effect.provenance
        ],
        "capability_nonce": effect.capability_nonce,
        "delegation_chain": list(effect.delegation_chain),
        "label_exceptions": [
            {
                "kind": le.kind,
                "match_target": le.match_target,
                "additional_targets": list(le.additional_targets),
                "etype": le.etype,
                "from_label": le.from_label,
                "to_label": le.to_label,
                "granted_by": le.granted_by,
                "nonce": le.nonce,
            }
            for le in effect.label_exceptions
        ],
        "task_id": effect.task_id,
        "known_targets": (
            {
                "primary": effect.known_targets.primary,
                "additional": list(effect.known_targets.additional),
            }
            if effect.known_targets is not None
            else None
        ),
    }


def dict_to_effect(d: dict[str, Any]) -> Any:
    """Deserialize a dict back to an Effect."""
    from .lattice import Confidentiality, Integrity
    from .model import Data, Effect, EffectTarget, LabelException

    provenance = tuple(
        Data(
            name=p["name"],
            confidentiality=Confidentiality[p["confidentiality"]],
            integrity=Integrity[p["integrity"]],
            content=p.get("content", ""),
        )
        for p in d["provenance"]
    )

    label_exceptions = tuple(
        LabelException(
            kind=le["kind"],
            match_target=le["match_target"],
            additional_targets=frozenset(le.get("additional_targets", [])),
            etype=le.get("etype"),
            from_label=le["from_label"],
            to_label=le["to_label"],
            granted_by=le["granted_by"],
            nonce=le["nonce"],
        )
        for le in d.get("label_exceptions", [])
    )

    known_targets = None
    if d.get("known_targets"):
        known_targets = EffectTarget(
            primary=d["known_targets"]["primary"],
            additional=frozenset(d["known_targets"].get("additional", [])),
        )

    return Effect(
        etype=d["etype"],
        target=d["target"],
        metadata=dict(d["metadata"]),
        provenance=provenance,
        capability_nonce=d["capability_nonce"],
        delegation_chain=tuple(d.get("delegation_chain", [])),
        label_exceptions=label_exceptions,
        task_id=d.get("task_id"),
        known_targets=known_targets,
    )


def commit_to_dict(commit: Any) -> dict[str, Any]:
    """Serialize a Commit to a plain dict for IPC."""

    return {
        "effect": effect_to_dict(commit.effect),
        "task_id": commit.task.task_id if commit.task else None,
        "task_ceiling": (
            {
                "owner": commit.task.ceiling.owner,
                "holder": commit.task.ceiling.holder,
                "right": commit.task.ceiling.right,
                "target": commit.task.ceiling.target,
                "scope": list(commit.task.ceiling.scope),
                "expiry": commit.task.ceiling.expiry,
                "nonce": commit.task.ceiling.nonce,
                "task_id": commit.task.ceiling.task_id,
            }
            if commit.task
            else None
        ),
        "tool_name": commit.tool_name,
        "approved_request": (
            {
                "nonce": commit.approved_request.nonce,
                "etype": commit.approved_request.etype,
                "targets": {
                    "primary": commit.approved_request.targets.primary,
                    "additional": list(commit.approved_request.targets.additional),
                },
                "expiry": commit.approved_request.expiry,
                "task_id": commit.approved_request.task_id,
                "granted_by": commit.approved_request.granted_by,
            }
            if commit.approved_request
            else None
        ),
    }


# ---- IPC wire helpers ----
def serialize_request(kind: ExecutorRequest, payload: dict[str, Any]) -> bytes:
    """Serialize a request: length-prefixed JSON."""
    body = json.dumps({"kind": kind.name, "payload": payload}).encode()
    return str(len(body)).encode() + b"\n" + body


def parse_response(raw: bytes) -> dict[str, Any]:
    """Parse a JSON response."""
    return cast(dict[str, Any], json.loads(raw.decode()))


def send_and_receive(
    socket_path: str | Path,
    kind: ExecutorRequest,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Send a request and receive the response over Unix socket."""
    import socket as _sock

    with _sock.socket(_sock.AF_UNIX, _sock.SOCK_STREAM) as s:
        s.settimeout(30.0)
        s.connect(str(socket_path))
        s.sendall(serialize_request(kind, payload))
        header = b""
        while b"\n" not in header:
            header += s.recv(1)
        length = int(header.strip().decode())
        raw = b""
        while len(raw) < length:
            chunk = s.recv(length - len(raw))
            if not chunk:
                raise ConnectionError("Executor process closed connection")
            raw += chunk
    return parse_response(raw)


def session_state_to_dict(session: Any) -> dict[str, Any]:
    """Serialize Session to a plain dict for IPC.

    Includes: session_id, logical_time, used, revoked, taint, live.
    """
    return {
        "session_id": session.session_id,
        "logical_time": session.logical_time,
        "used": list(session.used),
        "revoked": list(session.revoked),
        "tainted": session.tainted,
        "live": session.live,
    }


def dict_to_session(d: dict[str, Any]) -> Any:
    """Deserialize a dict back to a Session."""
    from .model import Session

    # Session requires session_id as the first argument
    session = Session(session_id=d.get("session_id", "unknown"))
    session.logical_time = d.get("logical_time", 0.0)
    session.used = set(d.get("used", []))
    session.revoked = set(d.get("revoked", []))
    session._tainted = d.get("tainted", False)
    session.live = d.get("live", True)
    return session


class ProcessExecutorClient:
    """IPC client: broker talks to executor subprocess over Unix socket.

    The broker sends serialized Effect dicts; the executor:
      1. Deserializes the effect
      2. Applies it to its isolated store
      3. Returns observed targets (what actually changed)

    The broker then forwards observed_targets to the ledger.
    This ensures the ledger's observation comes from the executor's store,
    NOT from the broker's own report.

    Usage:
        client = ProcessExecutorClient("/tmp/ecac-executor.sock")
        result = client.execute(effect_dict)  # returns observed_targets
        store_state = client.read_store()     # for independent observer
    """

    def __init__(self, socket_path: str | Path) -> None:
        self._path = Path(socket_path)
        self._lock = threading.Lock()

    def execute(self, effect_dict: dict[str, Any]) -> dict[str, Any]:
        """Apply an effect in the isolated executor process.

        Returns: {"observed_targets": list[str], "effects_log": list}
        Raises: RuntimeError if the executor process is unreachable.
        """
        with self._lock:
            resp = send_and_receive(self._path, ExecutorRequest.EXECUTE, {"effect": effect_dict})
        if not resp.get("ok"):
            raise RuntimeError(f"Executor IPC error: {resp.get('error')}")
        # Flat response: direct fields
        resp.pop("ok", None)
        return resp

    def apply_commit(
        self,
        effect_dict: dict[str, Any],
        task_id: str,
        session_snapshot: dict[str, Any],
        reserve_nonce: bool = True,
    ) -> dict[str, Any]:
        """Atomic commit: Fresh check + nonce reserve + apply in subprocess.

        This implements the atomic commit protocol from the session sync fix:
        1. Subprocess receives A's session snapshot
        2. Fresh check (replay + revoked) in subprocess using A's snapshot
        3. If Fresh: nonce reserved, effect applied, taint tracked
        4. Returns session_update with updated state

        Args:
            effect_dict: Serialized effect to apply
            task_id: Task ID for session tracking
            session_snapshot: A's session state at gate time
            reserve_nonce: Whether to reserve the nonce in the subprocess

        Returns:
            Success: {"status": "ok", "observed_targets": [...], "session_update": {...}}
            Blocked: {"status": "blocked", "blocker": "Fresh", "reason": "replay|revoked|expired"}
            Error: {"status": "error", "reason": str}
        """
        with self._lock:
            resp = send_and_receive(
                self._path,
                ExecutorRequest.APPLY_COMMIT,
                {
                    "effect": effect_dict,
                    "task_id": task_id,
                    "session_snapshot": session_snapshot,
                    "reserve_nonce": reserve_nonce,
                },
            )
        if not resp.get("ok"):
            raise RuntimeError(f"Apply commit error: {resp.get('error')}")
        resp.pop("ok", None)
        return resp

    def read_store(self) -> dict[str, Any]:
        """Read the complete executor store state (for independent observer)."""
        with self._lock:
            resp = send_and_receive(self._path, ExecutorRequest.READ_STORE, {})
        if not resp.get("ok"):
            raise RuntimeError(f"Executor IPC error: {resp.get('error')}")
        resp.pop("ok", None)
        return resp

    def read_files(self) -> dict[str, Any]:
        """Read just the files state."""
        with self._lock:
            resp = send_and_receive(self._path, ExecutorRequest.READ_FILES, {})
        if not resp.get("ok"):
            raise RuntimeError(f"Executor IPC error: {resp.get('error')}")
        resp.pop("ok", None)
        return resp

    def read_emails(self) -> dict[str, Any]:
        """Read just the emails state."""
        with self._lock:
            resp = send_and_receive(self._path, ExecutorRequest.READ_EMAILS, {})
        if not resp.get("ok"):
            raise RuntimeError(f"Executor IPC error: {resp.get('error')}")
        resp.pop("ok", None)
        return resp

    def read_mailboxes(self) -> dict[str, Any]:
        """Read just the mailboxes state."""
        with self._lock:
            resp = send_and_receive(self._path, ExecutorRequest.READ_MAILBOXES, {})
        if not resp.get("ok"):
            raise RuntimeError(f"Executor IPC error: {resp.get('error')}")
        resp.pop("ok", None)
        return resp

    def bootstrap(
        self,
        files: list[dict[str, str]] | None = None,
        emails: list[dict[str, str]] | None = None,
        mailboxes: list[str] | None = None,
    ) -> None:
        """Bootstrap initial resources in the executor subprocess.

        Must be called BEFORE any execute() calls. This is the ONLY way
        to populate the subprocess store with external resources (F ∪ E ∪ M).

        Args:
            files: list of {"path": "...", "sensitivity": "CONFIDENTIAL|INTERNAL|PUBLIC"}
            emails: list of {"address": "...", "domain": "INTERNAL|EXTERNAL"}
            mailboxes: list of mailbox usernames
        """
        with self._lock:
            resp = send_and_receive(
                self._path,
                ExecutorRequest.BOOTSTRAP,
                {
                    "files": files or [],
                    "emails": emails or [],
                    "mailboxes": mailboxes or [],
                },
            )
        if not resp.get("ok"):
            raise RuntimeError(f"Executor bootstrap error: {resp.get('error')}")

    # ---- Real OS/SMTP operations (executed in subprocess) ----
    # These methods send REAL file/SMTP operations to the subprocess,
    # ensuring actual I/O happens in the isolated process, not in broker.

    def real_file_read(self, path: str, task_id: str = "default") -> dict[str, Any]:
        """Read a real file in the executor subprocess.

        Returns: {"ok": bool, "content": bytes | None, "confidentiality": str,
                  "session_update": dict, "error": str | None}
        """
        with self._lock:
            resp = send_and_receive(
                self._path,
                ExecutorRequest.APPLY_EFFECT,
                {"op": "real_read", "path": path, "task_id": task_id},
            )
        if not resp.get("ok"):
            raise RuntimeError(f"Real file read error: {resp.get('error')}")
        resp.pop("ok", None)
        return resp

    def real_file_write(
        self, path: str, content: bytes, task_id: str = "default"
    ) -> dict[str, Any]:
        """Write content to a real file in the executor subprocess.

        Returns: {"ok": bool, "path": str, "confidentiality": str,
                  "session_update": dict, "error": str | None}
        """
        import base64

        with self._lock:
            resp = send_and_receive(
                self._path,
                ExecutorRequest.APPLY_EFFECT,
                {
                    "op": "real_write",
                    "path": path,
                    "content": base64.b64encode(content).decode(),
                    "task_id": task_id,
                },
            )
        if not resp.get("ok"):
            raise RuntimeError(f"Real file write error: {resp.get('error')}")
        resp.pop("ok", None)
        return resp

    def real_file_delete(self, path: str, task_id: str = "default") -> dict[str, Any]:
        """Delete a real file in the executor subprocess.

        Returns: {"ok": bool, "error": str | None}
        """
        with self._lock:
            resp = send_and_receive(
                self._path,
                ExecutorRequest.APPLY_EFFECT,
                {"op": "real_delete", "path": path, "task_id": task_id},
            )
        if not resp.get("ok"):
            raise RuntimeError(f"Real file delete error: {resp.get('error')}")
        resp.pop("ok", None)
        return resp

    def real_file_stat(self, path: str, task_id: str = "default") -> dict[str, Any]:
        """Stat a real file in the executor subprocess.

        Returns: {"ok": bool, "stat": dict | None, "confidentiality": str,
                  "session_update": dict, "error": str | None}
        """
        with self._lock:
            resp = send_and_receive(
                self._path,
                ExecutorRequest.APPLY_EFFECT,
                {"op": "real_stat", "path": path, "task_id": task_id},
            )
        if not resp.get("ok"):
            raise RuntimeError(f"Real file stat error: {resp.get('error')}")
        resp.pop("ok", None)
        return resp

    def real_file_listdir(self, path: str, task_id: str = "default") -> dict[str, Any]:
        """List a real directory in the executor subprocess.

        Returns: {"ok": bool, "entries": list[str] | None, "error": str | None}
        """
        with self._lock:
            resp = send_and_receive(
                self._path,
                ExecutorRequest.APPLY_EFFECT,
                {"op": "real_listdir", "path": path, "task_id": task_id},
            )
        if not resp.get("ok"):
            raise RuntimeError(f"Real file listdir error: {resp.get('error')}")
        resp.pop("ok", None)
        return resp

    def real_smtp_send(
        self,
        sender: str,
        recipients: list[str],
        body: str,
    ) -> dict[str, Any]:
        """Send a real email via SMTP in the executor subprocess.

        Returns: {"ok": bool, "delivered": list[str], "error": str | None}
        """
        with self._lock:
            resp = send_and_receive(
                self._path,
                ExecutorRequest.APPLY_EFFECT,
                {"op": "real_smtp_send", "sender": sender, "recipients": recipients, "body": body},
            )
        if not resp.get("ok"):
            raise RuntimeError(f"Real SMTP send error: {resp.get('error')}")
        resp.pop("ok", None)
        return resp

    def real_smtp_probe(self, sender: str, recipients: list[str]) -> dict[str, Any]:
        """Probe SMTP server for BCC detection in executor subprocess.

        Sends RSET-only probe (RCPT TO for each recipient), returns the set
        of actually-accepted recipients. The transaction is aborted (RSET)
        so no message is queued.

        Returns: {
            "ok": bool,
            "declared": list[str],
            "actual_accepted": list[str],
            "bcc_detected": list[str],
            "error": str | None
        }
        """
        with self._lock:
            resp = send_and_receive(
                self._path,
                ExecutorRequest.APPLY_EFFECT,
                {"op": "real_smtp_probe", "sender": sender, "recipients": recipients},
            )
        if not resp.get("ok"):
            raise RuntimeError(f"Real SMTP probe error: {resp.get('error')}")
        resp.pop("ok", None)
        return resp

    def real_imap_read_inbox(
        self,
        user: str,
        imap_host: str,
        imap_port: int,
        imap_user: str | None = None,
        imap_password: str | None = None,
        imap_use_tls: bool = True,
    ) -> dict[str, Any]:
        """Read inbox for a user via real IMAP in the executor subprocess.

        Connects to IMAP server (TLS-wrapped), selects INBOX, searches all
        messages, and fetches RFC822 body for content analysis. All IMAP
        operations happen in the isolated subprocess, not in the broker.

        Returns: {
            "ok": bool,
            "message_ids": list[str],
            "total_size": int,
            "error": str | None
        }
        """
        with self._lock:
            resp = send_and_receive(
                self._path,
                ExecutorRequest.APPLY_EFFECT,
                {
                    "op": "real_imap_read_inbox",
                    "user": user,
                    "imap_host": imap_host,
                    "imap_port": imap_port,
                    "imap_user": imap_user,
                    "imap_password": imap_password,
                    "imap_use_tls": imap_use_tls,
                },
            )
        if not resp.get("ok"):
            raise RuntimeError(f"Real IMAP read_inbox error: {resp.get('error')}")
        resp.pop("ok", None)
        return resp

    def shutdown(self) -> None:
        """Send SHUTDOWN to the executor subprocess for clean termination."""
        with self._lock:
            send_and_receive(self._path, ExecutorRequest.SHUTDOWN, {})

    def sync_session(
        self,
        task_id: str,
        session_state: dict[str, Any],
    ) -> dict[str, Any]:
        """Sync session state from broker to subprocess.

        Sends the broker's session state (used nonces, revoked, taint, logical_time)
        to the subprocess. The subprocess can then perform local Fresh checks
        and maintain an independent audit trail of session state.

        This ensures the subprocess has a consistent view of session state
        for:
        1. Independent Fresh checking (replay prevention)
        2. Audit trail of session state at each execution
        3. Independent verification for ledger

        Args:
            task_id: The task ID this session belongs to
            session_state: Serialized session state from broker

        Returns:
            {"ok": bool, "session_snapshot": dict} — subprocess's current view
        """
        with self._lock:
            resp = send_and_receive(
                self._path,
                ExecutorRequest.SYNC_SESSION,
                {"task_id": task_id, "session_state": session_state},
            )
        if not resp.get("ok"):
            raise RuntimeError(f"Session sync error: {resp.get('error')}")
        resp.pop("ok", None)
        return resp
