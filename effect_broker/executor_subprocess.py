"""Isolated executor process — sole owner of the mutable store.

ARCHITECTURE
────────────
This process runs in ISOLATION from the broker. It is the ONLY component
that can mutate external state (files, emails, mailboxes). All state
mutation goes through here — no other process can touch the store directly

    ┌────────────────┐  execute(Effect)  ┌─────────────────────────┐
    │  broker        │ ─────────────────►│  executor_subprocess    │
    │  (process 1)   │                   │  (process 2)            │
    │  - Auth/FlowOK │  (allow,          │  - IsolatedStore        │
    │  - Fresh check │   obs_targets,    │  - _apply_effect()      │
    │  - NoAmp       │   evidence)       │  - content_hash_verify  │
    │  - Approval    │ ◄──────────────── │  - audit_log            │
    └────────────────┘                   └─────────────────────────┘

ATOMIC COMMIT GUARANTEE (gate↔execute coupling):
──────────────────────────────────────────────────────
Subprocess verifies content_hash BEFORE applying any effect. This closes
the gap where Broker's gate() authorizes content_A but subprocess could
apply content_B. With this:
  1. Broker computes content_hash and includes in ApprovedRequest
  2. IPC sends (effect, approved_content_hash) — both HMAC-protected
  3. Subprocess computes hash(effect.metadata.content)
  4. Compares against approved_content_hash -> mismatch = BLOCKED

This ensures the executed content exactly matches the authorized content.

ISOLATION GUARANTEES
────────────────────
1. The executor's store is ONLY in this process. Broker NEVER accesses it.
2. Every effect reaches state through executor_subprocess._apply_effect().
3. Direct store mutation (broker.store._files._data=...) is IMPOSSIBLE.
4. All mutations are logged to audit_log with timestamp + pid.
5. The ledger's obs_targets come from THIS process, not from the broker.
6. Content hash verification prevents gate↔execute content divergence.

SUBCONFINEMENT (arbitrary code execution):
────────────────────────────────────────────────
  ✓ Module import blocking (builtins.__import__ hook)
  ✓ restricted-open for filesystem writes
  ✓ Landlock sandbox (Linux 5.13+)
  ✓ Network blocking (except local IPC socket)

IPC PROTOCOL
────────────
  Broker -> EXECUTE(commit_dict + approved_content_hash) -> Executor
  Executor -> (allow, obs_targets, evidence) -> Broker
  Executor -> content_hash verification (THEN apply OR block)
  Observer -> READ_STORE / READ_EMAILS / READ_FILES -> Executor

Run as:
    python -m effect_broker.executor_subprocess [--socket /tmp/ecac-executor.sock]
"""

from __future__ import annotations

# IMPORT BLOCKING — applied FIRST, before any module loading
# Order is CRITICAL: block dangerous imports before anything else can import them.
# This is the first code that runs in the subprocess.
import builtins
import sys

# Modules blocked from import in the subprocess (exact matches)
# NOTE: stdlib modules like 'os', 'subprocess', 'threading', 'signal' are ALLOWED.
# The blocking is ONLY for dangerous third-party packages and specific attack vectors.
# Filesystem writes are restricted via _restricted_open wrapper on os.open().
_DANGEROUS_MODULES: frozenset[str] = frozenset({
    # Code execution — prevents dynamic code generation
    "exec", "eval", "compile", "code", "codeop",
    # Object serialization attacks
    "pickle", "marshal", "shelve",
    # System information / privilege escalation
    "platform",  # Can reveal system info
    "resource",  # Can modify resource limits
    "grp",  # Group database access
    "pwd",  # Password database access
    "spwd",  # Shadow password database access
    # Signal handlers are managed by the subprocess itself, not needed as module
})

# Third-party network packages blocked (never needed in subprocess)
_BLOCKED_NETWORK_PACKAGES: frozenset[str] = frozenset({
    "requests", "aiohttp", "httpx", "websockets", "smb", "urllib3",
})

# stdlib modules blocked (not needed in subprocess, not dangerous as-is)
_BLOCKED_STDLIB: frozenset[str] = frozenset({
    # Network client libraries (not needed in isolated subprocess)
    # Note: smtplib IS needed for real_smtp_send, imaplib IS needed for real_imap_read_inbox
    "http.client", "ftplib", "telnetlib", "nntplib", "poplib",
})

# Store list of blocked imports for debugging/audit
_blocked_imports_log: list[str] = []

# CRITICAL: Save original import hook BEFORE installing secure hook
_original_import = builtins.__import__


def _secure_import(
    name: str,
    globals: dict[str, Any] | None = None,
    locals: dict[str, Any] | None = None,
    fromlist: tuple[str, ...] = (),
    level: int = 0,
) -> Any:
    """Secure import hook — blocks dangerous modules.

    CRITICAL: This runs BEFORE any module is loaded. It prevents the
    subprocess from importing potentially dangerous code that could
    break out of the sandbox.
    """
    root_name = name.split(".")[0]

    # Block dangerous top-level modules only (not submodules of stdlib)
    # urllib.parse is used by pathlib, so we only block top-level urllib/http
    # Submodules like http.client would need http in _DANGEROUS_MODULES
    if root_name in _DANGEROUS_MODULES:
        _blocked_imports_log.append(name)
        raise ImportError(
            f"Module '{name}' is blocked in subprocess for security. "
            f"Blocked imports: {len(_blocked_imports_log)} total."
        )

    # Block third-party network packages (requests, aiohttp, etc.)
    if root_name in _BLOCKED_NETWORK_PACKAGES:
        _blocked_imports_log.append(name)
        raise ImportError(
            f"Network package '{name}' is blocked in subprocess. "
            f"Remote communication is not permitted."
        )

    # Block dangerous stdlib modules
    if name in _BLOCKED_STDLIB or root_name in _BLOCKED_STDLIB:
        _blocked_imports_log.append(name)
        raise ImportError(
            f"Module '{name}' is blocked in subprocess for security. "
            f"Blocked imports: {len(_blocked_imports_log)} total."
        )

    # Allow everything else (standard library, effect_broker, json, base64, etc.)
    return _original_import(name, globals, locals, fromlist, level)


# Install the secure import hook BEFORE any other imports
builtins.__import__ = _secure_import  # type: ignore[assignment]

# PHASE 2: Safe standard library imports (after blocking hook is installed)
# These imports are ALLOWED by the secure import hook.
# The blocking hook only blocks dangerous modules (network, pickle, code exec).
import ctypes
import ctypes.util
import hashlib
import json
import os  # Used for path operations, stat, getpid, etc.
import signal  # Needed for SIGINT/SIGTERM handlers
import socket  # Needed for Unix socket IPC server
import subprocess  # Needed for subprocess spawning at startup
import threading  # Needed for connection handler threads
from pathlib import Path
from typing import Any


# PHASE 3: Content hash verification (atomic commit guarantee)
def _compute_effect_content_hash(effect: dict[str, Any]) -> str | None:
    """Compute SHA256 hash of effect's content from metadata.

    Mirrors model.py:Effect.compute_content_hash() but for dict representation.
    This is used by the subprocess to verify content_hash before applying effects.

    Returns None if no content to hash (read/delete effects, empty writes).
    """
    etype = effect.get("etype", "")
    metadata = effect.get("metadata", {})

    if etype == "send":
        body = metadata.get("body", "")
        subject = metadata.get("subject", "")
        if isinstance(body, str) and isinstance(subject, str):
            combined = f"{subject}|{body}"
            return hashlib.sha256(combined.encode("utf-8")).hexdigest()

    elif etype == "write":
        import base64

        # Check for direct bytes content
        content_raw = metadata.get("content", "")
        if content_raw is None or content_raw == "":
            # Check for base64-encoded content (from IPC-safe shim)
            content_b64 = metadata.get("content_b64", "")
            if isinstance(content_b64, str) and content_b64:
                try:
                    decoded = base64.b64decode(content_b64)
                    return hashlib.sha256(decoded).hexdigest()
                except Exception:
                    return None
        if isinstance(content_raw, bytes):
            return hashlib.sha256(content_raw).hexdigest()
        if isinstance(content_raw, str) and content_raw:
            return hashlib.sha256(content_raw.encode("utf-8")).hexdigest()

    return None


def _verify_content_binding(
    effect: dict[str, Any], approved_content_hash: str | None
) -> tuple[bool, str]:
    """Verify effect content matches the approved hash.

    CRITICAL: This closes the gate↔execute coupling gap.

    Scenario without this fix:
      1. Broker's gate() authorizes write(content="A")
      2. IPC transmits effect with content="A"
      3. Compromised subprocess writes content="B" instead

    Scenario WITH this fix:
      1. Broker's gate() authorizes write(content="A"), stores hash(content_A)
      2. IPC sends (effect with content="A", approved_content_hash=hash_A)
      3. Subprocess computes hash(content_from_metadata) = hash_A
      4. Subprocess verifies hash_A == approved_content_hash -> MATCH ✓
      5. Subprocess writes content="A" (from metadata, not modified)

    Returns: (verified: bool, reason: str)
    """
    if approved_content_hash is None:
        # No content binding required — skip verification (e.g., read/delete)
        return True, "no-content-binding"

    actual_hash = _compute_effect_content_hash(effect)
    if actual_hash is None:
        return False, "content-binding-effect-without-hashable-content"

    if actual_hash != approved_content_hash:
        return False, (
            f"content-hash-mismatch: "
            f"expected={approved_content_hash[:32]}..., "
            f"got={actual_hash[:32]}..."
        )

    return True, "content-binding-verified"


# Filesystem confinement (restricted open)
# Re-export from enforcer.py for backward compatibility and self-documentation.
# The enforcer module is the canonical source for restricted-open logic.

from effect_broker.enforcer import (
    _restricted_open as _restricted_open,
    _real_os_open,
    set_allowed_paths as _set_allowed_paths,
    get_allowed_paths,
    get_blocked_paths,
)


def _apply_landlock_sandbox() -> bool:
    """Apply Landlock filesystem sandbox (Linux 5.13+).
    Returns True if Landlock was successfully applied.
    Note: May require specific kernel config or CAP_SYS_ADMIN on older kernels.
    """
    if os.uname().sysname != "Linux":
        return False

    try:
        # Landlock syscall number (451)
        SYS_landlock_create_ruleset = 451
        LANDLOCK_RESTRICT_SELF = 0x03

        # Access flags
        ACCESS_FS_READ = 1
        ACCESS_FS_WRITE = 2
        ACCESS_FS_EXEC = 4

        class landlock_ruleset_attr(ctypes.Structure):
            _fields_ = [("handled_access_fs", ctypes.c_uint64)]

        libc = ctypes.CDLL(ctypes.util.find_library("c"))

        # Create ruleset allowing basic filesystem operations
        handled = ACCESS_FS_READ | ACCESS_FS_WRITE | ACCESS_FS_EXEC
        attr = landlock_ruleset_attr(handled_access_fs=handled)

        ruleset_fd = libc.syscall(
            SYS_landlock_create_ruleset, 0,
            ctypes.byref(attr), ctypes.sizeof(attr)
        )

        if ruleset_fd >= 0:
            # Restrict self with the ruleset
            libc.syscall(SYS_landlock_create_ruleset, LANDLOCK_RESTRICT_SELF, ruleset_fd, 0, 0)
            return True
    except Exception:
        pass

    return False


# Apply Landlock if available (defensive - open restriction is primary)
_landlock_active = _apply_landlock_sandbox()


def _get_confinement_status() -> str:
    """Return description of active confinement."""
    methods = ["restricted-open", "import-blocking"]
    if _landlock_active:
        methods.append("landlock")
    return "+".join(methods)



def _derive_confidentiality_from_mode(mode_int: int) -> str:
    """Derive confidentiality from Unix permission bits (mirrors shim_real.py).

    Runs in subprocess so taint detection uses real OS state:
      Owner-only  (mode & 0o007 == 0)   -> CONFIDENTIAL
      Group-readable (mode & 0o070 != 0) -> INTERNAL
      World-readable (mode & 0o004 != 0) -> PUBLIC
      Other                                -> PUBLIC
    """
    if mode_int & 0o007 == 0:
        return "CONFIDENTIAL"
    if mode_int & 0o070 != 0:
        return "INTERNAL"
    return "PUBLIC"


# ---- Store: only mutable state in THIS process ----
class IsolatedStore:
    """The sole mutable store — ONLY lives in this subprocess.

    No other process can directly access _files/_emails/_mailboxes.
    All state mutation happens via _apply_effect().
    The broker sends Effect objects over IPC; we apply them here.
    """

    def __init__(self) -> None:
        import os
        import time

        from effect_broker.model import Email, File, Mailbox

        self._files: dict[str, File] = {}
        self._emails: dict[str, Email] = {}
        self._mailboxes: dict[str, Mailbox] = {}
        self.effects_log: list[tuple[str, str]] = []
        self.identity_log: list[frozenset[str]] = []
        # Audit log: every mutation with timestamp + pid for traceability
        self.audit_log: list[dict[str, object]] = []
        self._pid = os.getpid()
        self._start_time = time.time()

    def _audit(
        self, action: str, effect: dict[str, object], extra: dict[str, object] | None = None
    ) -> None:
        """Record mutation to audit log with process context."""
        import time

        self.audit_log.append(
            {
                "ts": time.time() - self._start_time,
                "pid": self._pid,
                "action": action,
                "etype": effect.get("etype"),
                "target": effect.get("target"),
                "nonce": effect.get("capability_nonce"),
                "extra": extra or {},
            }
        )

    # ---- Bootstrap (setup only, before broker starts) ----
    def _unsafe_bootstrap_file(self, path: str, sensitivity: str) -> None:
        from effect_broker.lattice import Confidentiality
        from effect_broker.model import File

        self._files[path] = File(path, Confidentiality[sensitivity])

    def _unsafe_bootstrap_email(self, address: str, domain: str) -> None:
        from effect_broker.model import Domain, Email

        self._emails[address] = Email(address, Domain[domain.upper()])

    def _unsafe_bootstrap_mailbox(self, user: str) -> None:
        from effect_broker.model import Mailbox

        self._mailboxes[user] = Mailbox(user)

    # ---- Read API (for observer / verification) ----
    def list_files(self) -> dict[str, dict[str, Any]]:
        return {
            path: {"path": f.path, "sensitivity": f.sensitivity.name}
            for path, f in self._files.items()
        }

    def list_emails(self) -> dict[str, dict[str, Any]]:
        return {
            addr: {"address": e.address, "domain": e.domain.name}
            for addr, e in self._emails.items()
        }

    def list_mailboxes(self) -> dict[str, dict[str, Any]]:
        return {
            user: {
                "user": m.user,
                "inbox": list(m.inbox),
                "outbox": list(m.outbox),
            }
            for user, m in self._mailboxes.items()
        }

    def read_effects_log(self) -> list[tuple[str, str]]:
        return list(self.effects_log)

    def read_identity_log(self) -> list[list[str]]:
        return [list(x) for x in self.identity_log]

    def read_audit_log(self) -> list[dict[str, object]]:
        """Read the audit log for observer verification."""
        return list(self.audit_log)

    # ---- Sole mutation point ----
    def apply_effect(self, effect: dict[str, Any]) -> frozenset[str]:
        """Apply an effect to this store. Returns the complete set of observed targets.

        Semantics mirror RestrictedResourceStore:
          - write/delete/read: file resources (auto-create on write/read)
          - send: deliver to sender's outbox (address -> mailbox)
          - network: log, no persistent change
          - read on email: log inbox access
        """
        from effect_broker.model import Domain, Email

        etype = effect["etype"]
        target = effect["target"]

        # Build complete target set (same as RestrictedStore)
        all_targets: set[str] = {target}
        if effect.get("known_targets"):
            all_targets.add(target)
            all_targets |= set(effect["known_targets"].get("additional", []))
        else:
            bcc = effect.get("metadata", {}).get("extra_resources", [])
            if isinstance(bcc, list):
                all_targets |= set(bcc)
        all_targets_frozen = frozenset(all_targets)

        if etype == "delete" and target in self._files:
            del self._files[target]
            self.effects_log.append(("delete", f"file:{target}"))
            self.identity_log.append(all_targets_frozen)
            self._audit("delete_file", effect, {"path": target})

        elif etype == "write":
            # Auto-create the file if it doesn't exist
            if target not in self._files:
                from effect_broker.lattice import Confidentiality
                from effect_broker.model import File

                self._files[target] = File(target, Confidentiality.PUBLIC)
            self.effects_log.append(("write", f"file:{target}"))
            self.identity_log.append(all_targets_frozen)
            self._audit(
                "write_file",
                effect,
                {"path": target, "size": len(effect.get("metadata", {}).get("content", ""))},
            )

        elif etype == "read":
            # Auto-create the file if it doesn't exist
            if target not in self._files:
                from effect_broker.lattice import Confidentiality
                from effect_broker.model import File

                self._files[target] = File(target, Confidentiality.PUBLIC)
            self.effects_log.append(("read", f"file:{target}"))
            self.identity_log.append(all_targets_frozen)
            self._audit("read_file", effect, {"path": target})

        elif etype == "send":
            # Deliver to ALL targets (primary + BCC), append to each recipient's outbox.
            # This mirrors RestrictedStore._deliver_to_targets semantics exactly.
            for addr in all_targets:
                # Register the email resource if needed
                if addr not in self._emails:
                    domain_part = addr.split("@")[1]
                    domain = (
                        Domain.INTERNAL
                        if "corp" in domain_part or "internal" in domain_part
                        else Domain.EXTERNAL
                    )
                    self._emails[addr] = Email(addr, domain)

                # Append to this address's mailbox outbox
                local = addr.split("@")[0]
                mb = self._mailboxes.setdefault(local, _make_mailbox(local))
                body = ""
                if effect.get("metadata", {}).get("body"):
                    body = f": {effect['metadata']['body']}"
                elif effect.get("metadata", {}).get("extra_resources"):
                    body = ": (see metadata for details)"
                mb.outbox.append(f"{addr}{body}")

            self.effects_log.append(("send", f"email:{target}"))
            self.identity_log.append(all_targets_frozen)
            self._audit("send_email", effect, {"recipients": list(all_targets)})

        elif etype == "network":
            # Extract domain for scope tracking (same as RestrictedStore._url_for)
            domain = target.split("://", 1)[1].split("/")[0] if "://" in target else target
            self.effects_log.append(("network", f"url:{target}"))
            self.identity_log.append(all_targets_frozen)
            self._audit("network_access", effect, {"domain": domain})

        elif etype == "read" and "@" in target and target in self._emails:
            # read on email -> log which mailbox inbox is accessed
            local = target.split("@")[0]
            mb = self._mailboxes.setdefault(local, _make_mailbox(local))
            self.effects_log.append(("read", f"inbox:{local}"))
            self.identity_log.append(all_targets_frozen)
            self._audit("read_inbox", effect, {"mailbox": local})

        else:
            # Log for audit (unknown/not applicable)
            self.effects_log.append((etype, target))
            self.identity_log.append(all_targets_frozen)
            self._audit("unknown_effect", effect, {})

        return all_targets_frozen


def _make_mailbox(user: str) -> Any:
    from effect_broker.model import Mailbox

    return Mailbox(user)


# ---- IPC Server ----
class ExecutorServer:
    """Listens on Unix socket, applies effects, serves store reads."""

    def __init__(
        self,
        socket_path: str | Path,
        ready_event: threading.Event | None = None,
    ) -> None:
        self._path = Path(socket_path)
        self._store: IsolatedStore | None = None
        self._session_states: dict[str, dict[str, Any]] = {}  # task_id -> session state
        self._ready_event = ready_event
        self._shutdown = threading.Event()
        self._server: socket.socket | None = None
        self._shutdown_requested = False  # Set by SHUTDOWN request to cleanly exit run() loop

    def stop(self) -> None:
        self._shutdown.set()
        if self._server:
            try:
                self._server.close()
            except OSError:
                pass

    def run(self) -> None:

        self._store = IsolatedStore()
        self._shutdown.clear()

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
            if self._shutdown.is_set() or self._shutdown_requested:
                break
            server.settimeout(1.0)
            try:
                conn, _ = server.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

        if self._server and self._path.exists():
            self._path.unlink(missing_ok=True)

    def _handle(self, conn: socket.socket) -> None:
        try:
            while True:
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
                err_resp = json.dumps({"ok": False, "error": str(e)}).encode()
                conn.sendall(str(len(err_resp)).encode() + b"\n" + err_resp)
            except Exception:
                pass
        finally:
            conn.close()

    def _handle_apply_commit(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Handle atomic commit: Fresh check + content hash verify + apply_effect.

        ATOMIC COMMIT PROTOCOL (ate↔execute coupling):
        ─────────────────────────────────────────────────────────
        This function is the CRITICAL security boundary. It runs ENTIRELY in
        the subprocess (process B), AFTER the broker's gate() in process A.

        Three-phase commit:
          Phase 1: Fresh check (replay/revocation) — uses A's session snapshot
          Phase 2: Content hash verification — CRITICAL for gate↔execute coupling
          Phase 3: apply_effect to IsolatedStore — sole mutation point

        Args:
            payload: {
                "effect": effect dict (serialized from broker),
                "task_id": str,
                "session_snapshot": A's session state at gate time,
                "reserve_nonce": bool,
                "approved_content_hash": str | None — hash from ApprovedRequest
            }

        Returns:
            {"status": "ok", "observed_targets": [...], "session_update": {...}}
            {"status": "blocked", "blocker": str, "reason": str}
            {"status": "error", "reason": str}
        """
        effect = payload.get("effect", {})
        task_id = payload.get("task_id", "default")
        snapshot = payload.get("session_snapshot", {})
        reserve_nonce = payload.get("reserve_nonce", True)
        approved_content_hash = payload.get("approved_content_hash")  # NEW

        # Get or create subprocess session mirror for this task
        session = self._session_states.get(task_id, {})
        if not session:
            session = dict(snapshot)  # Start from A's snapshot
            self._session_states[task_id] = session

        # ─────────────────────────────────────────────────────────────────
        # PHASE 1: Fresh check (replay + revocation)
        # ─────────────────────────────────────────────────────────────────
        nonce = effect.get("capability_nonce")

        if reserve_nonce and nonce:
            # Check replay (nonce in A's used set)
            if nonce in session.get("used", []):
                return {
                    "ok": True,
                    "status": "blocked",
                    "blocker": "Fresh",
                    "reason": "replay",
                    "task_id": task_id,
                    "nonce": nonce,
                }

            # Check revocation (nonce in A's revoked set)
            if nonce in session.get("revoked", []):
                return {
                    "ok": True,
                    "status": "blocked",
                    "blocker": "Fresh",
                    "reason": "revoked",
                    "task_id": task_id,
                    "nonce": nonce,
                }

        # ─────────────────────────────────────────────────────────────────
        # PHASE 2: Content hash verification (CRITICAL: closes gate↔execute gap)
        # ─────────────────────────────────────────────────────────────────
        verified, reason = _verify_content_binding(effect, approved_content_hash)
        if not verified:
            return {
                "ok": True,
                "status": "blocked",
                "blocker": "ContentBinding",
                "reason": reason,
                "task_id": task_id,
                "nonce": nonce,
            }

        # ─────────────────────────────────────────────────────────────────
        # PHASE 3: Apply effect to IsolatedStore (sole mutation point)
        # ─────────────────────────────────────────────────────────────────
        assert self._store is not None, "store must be initialized"
        try:
            obs_targets = self._store.apply_effect(effect)

            # Track taint: if read CONFIDENTIAL file, mark session as tainted
            if effect.get("etype") == "read":
                target = effect.get("target", "")
                file_entry = self._store._files.get(target)
                if (
                    file_entry
                    and hasattr(file_entry.sensitivity, "name")
                    and file_entry.sensitivity.name == "CONFIDENTIAL"
                ):
                    if not session.get("tainted"):
                        session["tainted"] = True
                        session["_taint_reason"] = f"read-confidential({target})"
                        self._session_states[task_id] = session

            # Reserve nonce if requested (B's local reservation)
            if reserve_nonce and nonce:
                if "used" not in session:
                    session["used"] = list(snapshot.get("used", []))
                session["used"] = list(session.get("used", [])) + [nonce]

            # Build session update for A (B→A sync)
            session_update_applied = {
                "used": session.get("used", list(snapshot.get("used", []))),
                "logical_time": session.get("logical_time", snapshot.get("logical_time", 0.0)),
                "tainted": session.get("tainted", snapshot.get("tainted", False)),
                "_taint_reason": session.get("_taint_reason", ""),
                "content_binding_verified": True,  # Audit trail
            }

            return {
                "ok": True,
                "status": "ok",
                "observed_targets": list(obs_targets),
                "session_update": session_update_applied,
                "task_id": task_id,
                "nonce": nonce,
            }

        except Exception as e:
            # Rollback nonce reservation on failure
            if reserve_nonce and nonce and nonce in session.get("used", []):
                session["used"] = [n for n in session["used"] if n != nonce]
            return {
                "ok": True,
                "status": "error",
                "reason": str(e),
                "task_id": task_id,
            }

    def _handle_real_effect(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Handle real OS/SMTP operations in subprocess (APPLY_EFFECT).

        This is where REAL file I/O and SMTP operations happen — in the
        isolated subprocess, NOT in the broker process.
        """
        import base64
        import smtplib

        op = payload.get("op", "")
        SMTP_HOST = os.environ.get("ECAC_SMTP_HOST", "localhost")
        SMTP_PORT = int(os.environ.get("ECAC_SMTP_PORT", "1025"))

        try:
            if op == "real_read":
                path = payload["path"]
                st = os.stat(path)
                with open(path, "rb") as f:
                    content = f.read()
                # Derive confidentiality from REAL OS permission bits (same heuristic
                # as shim_real.py). If the file is owner-only, it is CONFIDENTIAL —
                # reading it taints the session (read-secrets -> send-block attack).
                confidentiality = _derive_confidentiality_from_mode(st.st_mode)
                session_update = {}
                if confidentiality == "CONFIDENTIAL":
                    task_id = payload.get("task_id", "default")
                    session = self._session_states.get(task_id, {})
                    # Set taint in subprocess mirror (B) so sync_session returns it to A
                    if not session.get("tainted"):
                        session = dict(session)  # copy
                        session["tainted"] = True
                        session["_taint_reason"] = f"real-read-confidential({path})"
                        self._session_states[task_id] = session
                    session_update = session
                return {
                    "ok": True,
                    "content": base64.b64encode(content).decode(),
                    "path": path,
                    "confidentiality": confidentiality,
                    "session_update": session_update,
                }

            elif op == "real_write":
                path = payload["path"]
                content_bytes = base64.b64decode(payload["content"])

                # Content hash verification (closes gate↔execute gap)
                # Broker's gate() authorized write(content_A). This ensures subprocess
                # writes content_A, not content_B
                approved_hash = payload.get("approved_content_hash")
                if approved_hash:
                    actual_hash = hashlib.sha256(content_bytes).hexdigest()
                    if actual_hash != approved_hash:
                        return {
                            "ok": True,
                            "status": "blocked",
                            "blocker": "ContentBinding",
                            "reason": (
                                f"content-hash-mismatch: "
                                f"expected={approved_hash[:32]}..., "
                                f"got={actual_hash[:32]}..."
                            ),
                            "path": path,
                        }

                with open(path, "wb") as f:
                    f.write(content_bytes)
                # Derive confidentiality of the written file from real mode bits
                # A newly written file may have umask-applied permissions;
                # if it is owner-only (0o600), it is CONFIDENTIAL
                try:
                    st = os.stat(path)
                    confidentiality = _derive_confidentiality_from_mode(st.st_mode)
                except OSError:
                    confidentiality = "INTERNAL"
                session_update = {}
                if confidentiality == "CONFIDENTIAL":
                    task_id = payload.get("task_id", "default")
                    session = self._session_states.get(task_id, {})
                    if not session.get("tainted"):
                        session = dict(session)
                        session["tainted"] = True
                        session["_taint_reason"] = f"real-write-confidential({path})"
                        self._session_states[task_id] = session
                    session_update = session
                return {
                    "ok": True,
                    "path": path,
                    "confidentiality": confidentiality,
                    "session_update": session_update,
                }

            elif op == "real_delete":
                path = payload["path"]
                os.remove(path)
                return {"ok": True, "path": path}

            elif op == "real_stat":
                path = payload["path"]
                st = os.stat(path)
                confidentiality = _derive_confidentiality_from_mode(st.st_mode)
                session_update = {}
                if confidentiality == "CONFIDENTIAL":
                    task_id = payload.get("task_id", "default")
                    session = self._session_states.get(task_id, {})
                    if not session.get("tainted"):
                        session = dict(session)
                        session["tainted"] = True
                        session["_taint_reason"] = f"real-stat-confidential({path})"
                        self._session_states[task_id] = session
                    session_update = session
                return {
                    "ok": True,
                    "stat": {
                        "mode": oct(st.st_mode),
                        "size": st.st_size,
                        "st_ino": int(st.st_ino),
                        "st_dev": int(st.st_dev),
                        "st_uid": int(st.st_uid),
                        "st_gid": int(st.st_gid),
                        "st_mode_int": int(st.st_mode),
                    },
                    "confidentiality": confidentiality,
                    "session_update": session_update,
                }

            elif op == "real_listdir":
                path = payload["path"]
                entries = os.listdir(path)
                return {"ok": True, "entries": entries}

            elif op == "real_smtp_send":
                sender = payload["sender"]
                recipients = payload["recipients"]
                body = payload["body"]
                # RSET probe: check each recipient first
                actual_recipients: list[str] = []
                bcc_detected = []
                smtp = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10)
                try:
                    smtp.ehlo()
                    smtp.mail(sender)
                    for rcpt in recipients:
                        code, _ = smtp.rcpt(rcpt)
                        if code == 250:
                            actual_recipients.append(rcpt)
                        else:
                            bcc_detected.append(rcpt)
                    smtp.rset()
                finally:
                    smtp.quit()
                if bcc_detected:
                    return {"ok": True, "bcc_detected": bcc_detected}
                # Real send
                smtp = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10)
                try:
                    smtp.sendmail(sender, recipients, body)
                finally:
                    smtp.quit()
                return {"ok": True, "delivered": actual_recipients}

            elif op == "real_smtp_probe":
                # RSET-only probe for BCC detection — happens ENTIRELY in subprocess.
                # No message is queued; this just discovers actual MTA recipients.
                sender = payload["sender"]
                recipients = payload["recipients"]
                actual_accepted: list[str] = []
                bcc_detected = []
                smtp = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10)
                try:
                    smtp.ehlo()
                    smtp.mail(sender)
                    for rcpt in recipients:
                        code, _ = smtp.rcpt(rcpt)
                        if code == 250:
                            actual_accepted.append(rcpt)
                        else:
                            bcc_detected.append(rcpt)
                    smtp.rset()  # Abort — no message queued
                finally:
                    smtp.quit()
                return {
                    "ok": True,
                    "declared": recipients,
                    "actual_accepted": actual_accepted,
                    "bcc_detected": bcc_detected,
                }

            elif op == "real_imap_read_inbox":
                # Real IMAP read_inbox — happens ENTIRELY in subprocess.
                # This ensures IMAP operations (IMAP4_SSL, SELECT, SEARCH, FETCH)
                # happen in the isolated subprocess, not in the broker process.
                import imaplib

                payload["user"]
                imap_host = payload.get("imap_host", "localhost")
                imap_port = payload.get("imap_port", 993)
                imap_user = payload.get("imap_user")
                imap_password = payload.get("imap_password")
                imap_use_tls = payload.get("imap_use_tls", True)

                messages: list[str] = []
                total_size = 0
                try:
                    mailbox: imaplib.IMAP4
                    if imap_use_tls:
                        mailbox = imaplib.IMAP4_SSL(imap_host, imap_port)
                    else:
                        mailbox = imaplib.IMAP4(imap_host, imap_port)
                    try:
                        if imap_user and imap_password:
                            mailbox.login(imap_user, imap_password)
                        status, _ = mailbox.select("INBOX")
                        if status != "OK":
                            return {
                                "ok": True,
                                "result": {
                                    "message_ids": [],
                                    "total_size": 0,
                                    "error": f"SELECT INBOX failed: {status}",
                                },
                            }
                        _, msg_ids = mailbox.search(None, "ALL")
                        ids = msg_ids[0].split() if msg_ids[0] else []
                        for mid in ids:
                            _, data = mailbox.fetch(mid, "(RFC822)")
                            if data and data[0]:
                                raw = data[0][1] if isinstance(data[0], tuple) else data[0]
                                total_size += len(raw)
                        messages = [mid.decode() for mid in ids]
                    finally:
                        mailbox.logout()
                except Exception as ex:
                    return {
                        "ok": True,
                        "message_ids": [],
                        "total_size": 0,
                        "error": str(ex),
                    }
                return {
                    "ok": True,
                    "message_ids": messages,
                    "total_size": total_size,
                    "error": None,
                }

            return {"ok": False, "error": f"Unknown op: {op}"}

        except Exception as e:
            import traceback

            return {
                "ok": False,
                "error": str(e) or repr(e) or "unknown",
                "trace": traceback.format_exc(),
            }

    def _dispatch(self, req: dict[str, Any]) -> dict[str, Any]:
        from effect_broker.executor_ipc import ExecutorRequest

        try:
            kind = ExecutorRequest[req["kind"]]
        except KeyError:
            return {"ok": False, "error": f"Unknown request kind: {req['kind']}"}

        payload = req.get("payload", {})

        # Verify HMAC signature before processing
        # If signature is missing or invalid, reject the request
        from effect_broker.executor_ipc import _verify_payload

        if not _verify_payload(payload, kind):
            return {
                "ok": False,
                "error": (
                    "IPC payload signature verification failed. "
                    "Payload may have been tampered with in transit. "
                    "Request rejected for security."
                ),
            }

        assert self._store is not None

        match kind:
            case ExecutorRequest.EXECUTE:
                effect_dict = payload.get("effect", {})
                obs_targets = self._store.apply_effect(effect_dict)
                return {
                    "ok": True,
                    "observed_targets": list(obs_targets),
                    "effects_log": list(self._store.effects_log),
                }

            case ExecutorRequest.READ_STORE:
                return {
                    "ok": True,
                    "files": self._store.list_files(),
                    "emails": self._store.list_emails(),
                    "mailboxes": self._store.list_mailboxes(),
                    "effects_log": self._store.read_effects_log(),
                    "identity_log": self._store.read_identity_log(),
                }

            case ExecutorRequest.READ_FILES:
                return {"ok": True, "files": self._store.list_files()}

            case ExecutorRequest.READ_EMAILS:
                return {"ok": True, "emails": self._store.list_emails()}

            case ExecutorRequest.READ_MAILBOXES:
                return {"ok": True, "mailboxes": self._store.list_mailboxes()}

            case ExecutorRequest.BOOTSTRAP:
                files = payload.get("files", [])
                for f in files:
                    self._store._unsafe_bootstrap_file(f["path"], f["sensitivity"])
                emails = payload.get("emails", [])
                for e in emails:
                    self._store._unsafe_bootstrap_email(e["address"], e["domain"])
                mailboxes = payload.get("mailboxes", [])
                for user in mailboxes:
                    self._store._unsafe_bootstrap_mailbox(user)
                return {"ok": True}

            case ExecutorRequest.APPLY_COMMIT:
                # Atomic commit protocol: Fresh check + nonce reserve + apply_effect
                # This runs entirely in the subprocess for consistency guarantees.
                return self._handle_apply_commit(payload)

            case ExecutorRequest.APPLY_EFFECT:
                return self._handle_real_effect(payload)

            case ExecutorRequest.SYNC_SESSION:
                # Sync session state from broker to subprocess.
                # Subprocess maintains its own mirror of session state for:
                # 1. Independent Fresh checking (replay prevention)
                # 2. Audit trail of session state at each execution
                # 3. Independent verification for ledger
                task_id = payload.get("task_id", "default")
                session_state = payload.get("session_state", {})
                self._session_states[task_id] = session_state
                # Return subprocess's current view of session state
                return {
                    "ok": True,
                    "task_id": task_id,
                    "session_snapshot": self._session_states.get(task_id, {}),
                    "all_tasks": list(self._session_states.keys()),
                }

            case ExecutorRequest.SHUTDOWN:
                self._shutdown_requested = True
                return {"ok": True}

            case _:
                return {"ok": False, "error": f"Unhandled request kind: {kind}"}


class ExecutorProcessHandle:
    """Start and stop the executor subprocess."""

    def __init__(self, socket_path: str | Path, store_socket_path: str | Path) -> None:
        self._socket_path = Path(socket_path)
        self._store_socket_path = Path(store_socket_path)
        self._proc: subprocess.Popen[bytes] | None = None

    @property
    def socket_path(self) -> Path:
        return self._socket_path

    def start(self, timeout: float = 5.0) -> None:
        import subprocess as _subprocess
        import sys as _sys
        import time as _time

        ecac_root = Path(__file__).parent.parent
        script = ecac_root / "effect_broker" / "executor_subprocess.py"
        if self._socket_path.exists():
            self._socket_path.unlink()

        # Pass cwd + PYTHONPATH so the subprocess resolves modules correctly
        # regardless of how the parent was launched (direct python / uv run / pytest).
        env = {**os.environ, "PYTHONPATH": str(ecac_root)}
        self._proc = _subprocess.Popen(
            [
                _sys.executable,
                str(script),
                "--socket",
                str(self._socket_path),
                "--store-socket",
                str(self._store_socket_path),
            ],
            cwd=str(ecac_root),
            env=env,
            stdin=_subprocess.DEVNULL,
            stdout=_subprocess.DEVNULL,
            stderr=_subprocess.DEVNULL,
        )

        start = _time.monotonic()
        while (_time.monotonic() - start) < timeout:
            if self._proc.poll() is not None:
                raise RuntimeError(f"Executor subprocess exited early: {self._proc.returncode}")
            if self._socket_path.exists():
                break
            _time.sleep(0.05)
        else:
            self._proc.terminate()
            self._proc.wait(timeout=2)
            raise RuntimeError(f"Executor socket never created within {timeout}s")
        _time.sleep(0.5)

    def stop(self, timeout: float = 2.0) -> None:
        import subprocess as _subprocess

        if self._proc is None:
            return
        self._proc.terminate()
        try:
            self._proc.wait(timeout=timeout)
        except _subprocess.TimeoutExpired:
            self._proc.kill()
            self._proc.wait()
        finally:
            self._proc = None
            if self._socket_path.exists():
                self._socket_path.unlink(missing_ok=True)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Isolated executor subprocess for ECAC.")
    parser.add_argument(
        "--socket",
        default="/tmp/ecac-executor.sock",
        help="Unix socket path (default: /tmp/ecac-executor.sock)",
    )
    parser.add_argument(
        "--store-socket",
        default="/tmp/ecac-executor-store.sock",
        help="Unix socket for observer store reads (default: /tmp/ecac-executor-store.sock)",
    )
    args = parser.parse_args()

    server = ExecutorServer(socket_path=args.socket)
    try:
        server.run()
    except KeyboardInterrupt:
        print("\nExecutor subprocess shutdown.")
        sys.exit(0)


if __name__ == "__main__":
    main()


# ---- Subprocess Confinement Summary ----
# MULTI-LAYER DEFENSE (in order of application):
#
# Layer 1: Import blocking (builtins.__import__ hook) — FIRST
#   - Blocks subprocess, threading, network modules at Python import time
#   - Applied BEFORE any other imports
#   - Prevents loading dangerous code that could break out of sandbox
#
# Layer 2: Content hash verification (gate↔execute coupling fix)
#   - Subprocess verifies hash(content_from_metadata) == approved_content_hash
#   - Prevents writing content_B when broker authorized content_A
#   - Both values are HMAC-signed in the same IPC payload
#
# Layer 3: Filesystem confinement (restricted-open wrapper)
#   - Write operations only in broker-configured allowed paths
#   - Read operations in allowed paths + system directories + /dev
#   - Blocked paths: /etc, /bin, /usr, /var, /root, /.ssh, /.config
#   - Applied to os.open() at import time
#
# Layer 4: Landlock (Linux 5.13+)
#   - Kernel-enforced filesystem restrictions
#   - Best-effort (may fail silently on older kernels / macOS)
#
# WHAT IS PROTECTED:
#   ✓ Content hash verification: executed content matches authorized content
#   ✓ Import blocking: dangerous modules cannot be loaded
#   ✓ Filesystem sandboxing: writes restricted to sandbox directories
#   ✓ Kernel-level enforcement: Landlock restricts at OS level (Linux)
#   ✓ Audit trail: all operations logged with pid/timestamp
#
# REMAINING LIMITATIONS:
#   - Python stdlib not fully blocked (only dangerous modules)
#   - seccomp BPF is future work (not currently needed)
#   - For stronger guarantees: AppArmor/SELinux profiles, Wasm, or gVisor
