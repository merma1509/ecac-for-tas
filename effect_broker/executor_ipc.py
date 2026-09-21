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
from typing import Any


class ExecutorRequest(Enum):
    """Wire format: broker → executor subprocess."""

    EXECUTE = auto()      # Apply an effect, return observed_targets
    READ_STORE = auto()   # Observer reads actual store state for verification
    READ_EMAILS = auto()  # Observer reads emails for duplicate accounting
    READ_FILES = auto()   # Observer reads files
    READ_MAILBOXES = auto()  # Observer reads mailboxes
    BOOTSTRAP = auto()    # Bootstrap initial resources (files/emails/mailboxes)
    SHUTDOWN = auto()     # Clean shutdown


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
    return json.loads(raw.decode())


def send_and_receive(socket_path: str | Path, kind: ExecutorRequest, payload: dict[str, Any]) -> dict[str, Any]:
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
        return resp["result"]

    def read_store(self) -> dict[str, Any]:
        """Read the complete executor store state (for independent observer)."""
        with self._lock:
            resp = send_and_receive(self._path, ExecutorRequest.READ_STORE, {})
        if not resp.get("ok"):
            raise RuntimeError(f"Executor IPC error: {resp.get('error')}")
        return resp["result"]

    def read_files(self) -> dict[str, Any]:
        """Read just the files state."""
        with self._lock:
            resp = send_and_receive(self._path, ExecutorRequest.READ_FILES, {})
        if not resp.get("ok"):
            raise RuntimeError(f"Executor IPC error: {resp.get('error')}")
        return resp["result"]

    def read_emails(self) -> dict[str, Any]:
        """Read just the emails state."""
        with self._lock:
            resp = send_and_receive(self._path, ExecutorRequest.READ_EMAILS, {})
        if not resp.get("ok"):
            raise RuntimeError(f"Executor IPC error: {resp.get('error')}")
        return resp["result"]

    def read_mailboxes(self) -> dict[str, Any]:
        """Read just the mailboxes state."""
        with self._lock:
            resp = send_and_receive(self._path, ExecutorRequest.READ_MAILBOXES, {})
        if not resp.get("ok"):
            raise RuntimeError(f"Executor IPC error: {resp.get('error')}")
        return resp["result"]

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

    def shutdown(self) -> None:
        """Send SHUTDOWN to the executor subprocess for clean termination.

        The subprocess will exit its run loop and close its socket.
        The process handle will then terminate/kill the process.
        """
        with self._lock:
            resp = send_and_receive(self._path, ExecutorRequest.SHUTDOWN, {})
        # Ignore response errors — we just want to trigger shutdown.
        # The process handle will ensure cleanup regardless.
        return
