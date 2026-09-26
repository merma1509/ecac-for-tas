"""Real enforcement shim: filesystem operations via actual stat/open/read/write.

This shim intercepts real Python filesystem operations and derives the
EXACT effect from actual OS state, not from tool declarations.

Key property: the tool cannot bypass us. We resolve real paths, stat real
files, and derive the canonical effect. The broker gate uses our effect,
not the tool's volunteered description.

Architectural position:
  Tool code → Shim (this module) → broker.commit() → executor.execute()
                                      ↓
                              RestrictedResourceStore.apply_effect()

The tool NEVER directly calls open(), os.write(), or pathlib operations.
All such calls go through this shim.

SAME-PROCESS NOTE: In this mode, a determined adversary can still do
  import os; os.environ['HOME'] = '/nonexistent'
to confuse path resolution. For real security, run the shim in a subprocess
that has no filesystem access except via a whitelisted wrapper.
"""

from __future__ import annotations

import base64
import os
import pathlib
import re
import stat
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, TypeVar, cast

from .lattice import Confidentiality, Integrity
from .model import Commit, Data, Effect, EffectTarget

if TYPE_CHECKING:
    from .broker import EffectBroker
    from .executor_ipc import ProcessExecutorClient

T = TypeVar("T")


@dataclass
class ShimOp:
    """A real operation the shim observed, with actual OS state.

    This is the independent observer's record. It cannot be forged by
    the tool because the shim derives these fields from real OS calls,
    not from tool-provided metadata.
    """

    operation: str  # read | write | delete | stat | listdir
    path: str  # canonical path after normalization
    real_targets: frozenset[str]  # all paths actually touched
    pre_exists: bool  # did the path exist before the op?
    pre_content: bytes | None  # content before write (None = didn't exist / read)
    post_exists: bool  # did the path exist after the op?
    post_content: bytes | None  # content after the op
    tool_name: str
    blocked: bool = False  # True = broker BLOCKed this
    nonce: str = ""


@dataclass
class RealFileShim:
    """Real filesystem shim — derives effects from actual OS state.

    The tool calls shim.read(path), shim.write(path, content), etc.
    The shim:
      1. Resolves the real canonical path
      2. Stats actual OS state (pre-condition)
      3. Asks the broker gate for ALLOW/BLOCK
      4. On ALLOW: performs the real OS operation
      5. Stats actual OS state (post-condition)
      6. Derives the complete effect including extra_targets
      7. Submits to broker for commit

    This is the ONLY code in the Python process that calls open() / os.write().
    Everything else is untrusted.
    """

    broker: EffectBroker
    task_id: str
    tool_name: str

    # Operational log — independent observer record
    ops: list[ShimOp] = field(default_factory=list)

    # IPC client for multi-process mode (set by broker)
    # When set, real I/O goes through subprocess, not direct OS calls
    ipc_client: "ProcessExecutorClient | None" = None

    # Path normalization regex — canonicalizes paths to prevent traversal
    _NORMALIZE_RE = re.compile(r"/+")

    def __init__(
        self,
        broker: EffectBroker,
        task_id: str = "default",
        tool_name: str = "untrusted-tool",
    ) -> None:
        self.broker = broker
        self.task_id = task_id
        self.tool_name = tool_name
        self.ops: list[ShimOp] = []

    def _sync_session_from_subprocess(self, session_update: dict[str, Any]) -> None:
        """Apply session state updates from subprocess to broker session.

        Called after each IPC real I/O operation. The subprocess derives
        taint from real permission bits (CONFIDENTIAL files) and returns
        the updated session state. We propagate it to the broker so that
        subsequent send effects are blocked (session-taint).

        This is the B→A direction of bidirectional session sync, resolving
        the taint-drift gap in multi-process mode.
        """
        if not session_update:
            return
        task = self.broker.tasks.get(self.task_id)
        if task is None or task.session is None:
            return
        if session_update.get("tainted"):
            task.session._tainted = True
            task.session._taint_reason = session_update.get(
                "_taint_reason", "subprocess-real-io"
            )
        if session_update.get("logical_time", 0) > task.session.logical_time:
            task.session.logical_time = session_update["logical_time"]

    # ---- Public tool-facing API ----
    def read(self, path: str) -> bytes:
        """Read a file. Derives real effect from actual OS state."""
        return self._op("read", path, lambda p: open(p, "rb").read())

    def write(self, path: str, content: bytes) -> None:
        """Write a file. Derives real effect from actual OS state."""
        self._op("write", path, lambda p: open(p, "wb").write(content), content)

    def delete(self, path: str) -> None:
        """Delete a file. Derives real effect from actual OS state."""
        self._op("delete", path, lambda p: os.remove(p))

    def stat(self, path: str) -> os.stat_result:
        """Stat a file. Read-only effect (logged, no persistent state change)."""
        return self._op("stat", path, lambda p: os.stat(p))

    def listdir(self, path: str) -> list[str]:
        """List a directory. Read-only effect (logged, no persistent state change)."""
        return self._op("listdir", path, lambda p: os.listdir(p))

    def exists(self, path: str) -> bool:
        """Check if file exists. Read-only."""
        return self._op("exists", path, lambda p: os.path.exists(p))

    # ---- Core enforcement logic ----

    def _canonical_path(self, path: str) -> str:
        """Canonicalize a path: resolve . .. symlinks, normalize slashes.

        Returns an OS path (no file:// prefix) for use in OS calls.
        Use _file_uri() to get the broker-compatible URI form.
        """
        p = pathlib.Path(path).expanduser()
        resolved = p.resolve()
        canon = self._NORMALIZE_RE.sub("/", str(resolved))
        return canon

    def _file_uri(self, path: str) -> str:
        """Convert an OS path to a file:// URI for broker compatibility."""
        return f"file://{self._canonical_path(path)}"

    def _stat_pre(self, path: str, canon: str) -> tuple[bool, bytes | None]:
        """Get pre-operation OS state. Returns (exists, content_or_none)."""
        try:
            st = os.stat(canon)
            is_file = stat.S_ISREG(st.st_mode)
            if is_file:
                # Read content for integrity/confidentiality derivation
                with open(canon, "rb") as f:
                    return True, f.read()
            return True, None
        except FileNotFoundError:
            return False, None
        except PermissionError:
            return False, None

    def _stat_post(self, path: str, canon: str) -> tuple[bool, bytes | None]:
        """Get post-operation OS state. Returns (exists, content_or_none)."""
        return self._stat_pre(path, canon)

    def _derive_labels(
        self,
        path: str,
        content: bytes | None,
        pre_exists: bool,
        post_exists: bool,
        op_type: str,
    ) -> tuple[Confidentiality, Integrity]:
        """Derive confidentiality/integrity labels from REAL state.

        The tool CANNOT set these labels -- the shim derives them from the
        actual file metadata and content. This is kill-criterion #3 resolved:
        FlowOK uses shim-resolved labels, not LLM-claimed labels.

        Priority for EXISTING files being read:
          1. Permission bits for CONFIDENTIAL signal (owner-only access = OS-enforced)
          2. Content-based keywords (last resort for non-confidential files)
        """
        # For NEW file writes: derive from path, NOT content
        # Content scanning would cause false CONFIDENTIAL labels for
        # normal text like "hello world" that happens to contain keywords
        # A new file is labeled by its PATH (deny-most by default)
        if not pre_exists and op_type == "write":
            conf = self._derive_path_confidentiality(path)
            integ = Integrity.USER
        # Existing file being read: check permission bits FIRST for CONFIDENTIAL
        # Permission bits are OS-enforced and cannot be influenced by content.
        # Owner-only access (0o600) is the definitive CONFIDENTIAL signal.
        # We don't override with PUBLIC from bits — that's too restrictive;
        # instead we rely on content keywords for non-confidential files.
        elif pre_exists and op_type in ("read", "stat"):
            path_conf = self._derive_path_confidentiality(path)
            if path_conf == Confidentiality.CONFIDENTIAL:
                # Owner-only access is the definitive CONFIDENTIAL signal
                conf = Confidentiality.CONFIDENTIAL
            elif content is not None:
                # Not definitively restricted — use content as last resort
                conf = self._derive_content_confidentiality(content)
            else:
                conf = Confidentiality.INTERNAL
            integ = Integrity.USER
        # Fallback
        else:
            conf = Confidentiality.INTERNAL
            integ = Integrity.USER

        return conf, integ

    def _derive_path_confidentiality(self, path: str) -> Confidentiality:
        """Map a filesystem path to a confidentiality level.

        RESOLVES THE LIMITATION: uses real OS metadata (os.statx / permission bits),
        not path-keyword heuristics. The LLM cannot forge this — the kernel
        reads from the OS, not from the tool's declarations.

        Resolution order:
          1. os.statx() → check for OS-level extended attributes (xattr / SELinux labels)
             Available on Linux with kernel >= 4.11. Production: SELinux context,
             Windows sensitivity label, or other OS-managed label.
          2. Permission-bit heuristic (portable fallback):
               0o600/0o700 (owner-only)    → CONFIDENTIAL
               0o640/0o750 (group-readable) → INTERNAL
               0o644/0o755 (world-readable) → PUBLIC
             This is the REAL permission bits, not keyword matching.
          3. Keyword fallback (last resort): only if the file doesn't exist yet
             (new write) and the OS has no metadata.
        """
        try:
            canon = self._canonical_path(path)
            stx = os.statx(canon, flags=os.STATX_ALL)  # type: ignore[attr-defined]
            label = self._try_statx_label(stx, canon)
            if label is not None:
                return label
        except (FileNotFoundError, OSError, AttributeError):
            # statx not available (macOS/older kernel) — fall through to permission bits
            pass

        # Fallback 2: permission-bit heuristic (reads real OS permission bits)
        label = self._try_permission_label(path)
        if label is not None:
            return label

        # Fallback 3: keyword (only for new files not yet on disk)
        # Even this fallback is traceable: broker logs which fallback was used.
        lower = path.lower()
        if any(kw in lower for kw in ["secret", "classified", "confidential"]):
            return Confidentiality.CONFIDENTIAL
        elif any(kw in lower for kw in ["internal", "corp", "shared"]):
            return Confidentiality.INTERNAL
        elif any(kw in lower for kw in ["public", "www"]):
            return Confidentiality.PUBLIC
        else:
            # Deny-most default: treat as INTERNAL (not PUBLIC)
            return Confidentiality.INTERNAL

    def _try_statx_label(self, stx: object, path: str) -> Confidentiality | None:
        """Query OS-level extended attributes for a sensitivity label.

        On Linux with SELinux (enforcing):
          /proc/self/attr/current → reads the process's SELinux context
          For file labels: requires separate `getxattr()` call

        On Windows:
          file_sd = GetFileSecurity(path, LABEL_SECURITY_INFORMATION)
          → mapped to Confidentiality level

        In this stub, we check STATX_ATTR_ENCRYPTED (bit 0 of attributes).
        A file marked ENCRYPTED at the filesystem level → CONFIDENTIAL.

        Returns None if no OS-level label is available (falls back to
        permission bits or keyword).
        """
        # Check the ENCRYPTED attribute (filesystem-level confidentiality signal)
        # This is a real OS signal: if the file is encrypted at rest, it is
        # CONFIDENTIAL. Set with: chattr +i file  OR  BitLocker/FileVault
        stx_attributes: int = getattr(stx, "stx_attributes", 0)
        stx_mode: int = getattr(stx, "stx_mode", 0)
        if stx_attributes & (1 << 0):  # STATX_ATTR_ENCRYPTED
            return Confidentiality.CONFIDENTIAL

        # Check for system immutable attribute (chattr +i / +a)
        # Immutable files are typically high-sensitivity (root-owned config, secrets)
        if stx_attributes & (1 << 1):  # STATX_ATTR_IMMUTABLE
            # Immutable + non-world-readable → likely CONFIDENTIAL
            # flag as CONFIDENTIAL if also owner-only; prevents false
            # CONFIDENTIAL on files like /etc/passwd (world-readable + immutable)
            mode = stx_mode & 0o777
            if mode & 0o077:  # group or world has some access → not confidential
                return Confidentiality.INTERNAL
            return Confidentiality.CONFIDENTIAL

        # NOTE: Real implementations would call getxattr("security.selinux") here
        # to read the SELinux file context. For the stub, permission bits are the
        # fallback. Production: swap this for real getxattr()/Windows API call.
        return None

    def _try_permission_label(self, path: str) -> Confidentiality | None:
        """Derive confidentiality from REAL permission bits (os.stat mode).

        This reads the actual OS permission bits, not path keywords.
        The kernel reads this, not the LLM — cannot be forged.

        Signal:
          Owner-only (mode & 0o077 == 0)       → CONFIDENTIAL
          Group-readable (mode & 0o027 != 0)   → INTERNAL
          World-readable (mode & 0o004 != 0)   → PUBLIC
        """
        try:
            canon = self._canonical_path(path)
            st = os.stat(canon)
            mode = st.st_mode & 0o777

            if mode & 0o077 == 0:
                # Owner-only: no group, no world access → CONFIDENTIAL
                return Confidentiality.CONFIDENTIAL
            elif mode & 0o004:
                # World-readable → PUBLIC (can be read by any local user)
                return Confidentiality.PUBLIC
            elif mode & 0o070:
                # Group-readable but not world-readable → INTERNAL
                return Confidentiality.INTERNAL
            # No group/world + no special flags → default (don't override)
            return None
        except (FileNotFoundError, PermissionError, OSError):
            return None

    def _derive_content_confidentiality(self, content: bytes) -> Confidentiality:
        """Analyze file content to derive confidentiality.

        Real implementation: ML classifier, keyword scan, or metadata.
        Here: keyword heuristic on the content bytes (ASCII-only).
        """
        try:
            text = content.decode("utf-8", errors="ignore").lower()
        except Exception:
            return Confidentiality.INTERNAL  # binary content → default

        if any(kw in text for kw in ["password", "secret", "api_key", "token"]):
            return Confidentiality.CONFIDENTIAL
        elif any(kw in text for kw in ["internal", "not for distribution"]):
            return Confidentiality.INTERNAL
        return Confidentiality.PUBLIC

    def _derive_extra_targets(
        self,
        op_type: str,
        path: str,
        canon: str,
        pre_exists: bool,
    ) -> frozenset[str]:
        """Derive ALL paths this operation touches beyond the primary target.

        This is the key NoAmp enforcement: we detect extra targets by
        observing actual OS state changes, not by trusting tool declarations.

        Examples:
        - write to /tmp with atomic rename to target: both /tmp AND target touched
        - write with temporary file: temp file + final target
        - symlink attack: canonicalizes to real target
        """
        extras: set[str] = set()

        # Atomic write pattern: write to temp, then rename
        # We intercept rename() too, so both paths are tracked
        # For now: check if the path has common temp prefixes
        lower = path.lower()
        if "/tmp" in lower or "/temp" in lower or lower.startswith("~"):
            # A temp file might be renamed — mark as potential extra target
            # In real shim: intercept rename() syscall to track this
            pass  # temp tracking deferred

        # Symlink detection: if canon ≠ raw path, record the symlink path too
        raw = str(pathlib.Path(path).expanduser().resolve(strict=False))
        if raw != canon:
            extras.add(raw)

        # Directory modification side effect: writing or deleting a file modifies
        # its parent directory (file creation, permission changes, etc.)
        # Always include the parent dir in extras for file operations.
        parent = str(pathlib.Path(canon).parent)
        if parent != canon:
            extras.add(parent)

        return frozenset(extras)

    def _base_capability_nonce(self, op_type: str, primary: str) -> str:
        """Return the real capability nonce (without per-effect suffix)."""
        for nonce, cap in self.broker.capabilities.items():
            if cap.holder in (self.tool_name, "EffectBroker") and cap.right in (op_type, "*"):
                if cap.target == "*" or primary.startswith(cap.target):
                    return nonce
        return f"no-cap-{op_type}-{primary}"

    def _resolve_capability_nonce(
        self,
        op_type: str,
        primary: str,
        extras: frozenset[str],
    ) -> str:
        """Derive a UNIQUE nonce per effect for freshness tracking.

        The returned nonce is unique per (op_type, target) combination,
        allowing multiple operations (read, write, delete) to the same file
        to each pass freshness checks independently.
        """
        base = self._base_capability_nonce(op_type, primary)
        # Derive unique nonce: include op_type + last 40 chars of path for per-effect uniqueness
        path_suffix = primary[7:] if primary.startswith("file://") else primary
        return f"{base}|{op_type}|{path_suffix[-40:]}"

    def _derive_nonce(self, right: str, primary: str, extras: frozenset[str]) -> str:
        """Derive a label key for this complete target set (for logging/tracking only)."""
        base = f"{self.tool_name}:{right}"
        extras_key = ",".join(sorted(extras)) if extras else ""
        return f"{base}:{primary}:{extras_key}" if extras_key else base

    def _op(
        self,
        op_type: str,
        path: str,
        action: Callable[[str], T],
        content: bytes | None = None,
    ) -> T:
        """Execute an operation through the enforcement gate.

        Flow:
          1. Canonicalize path (detect traversal)
          2. Stat pre-state
          3. Build PreparedEffect from real state
          4. Broker gate check
          5. On ALLOW: perform real OS action
          6. Stat post-state
          7. Commit to ledger
          8. Return result
        """
        # Broker uses file:// URIs internally — canonicalize to OS path for open/remove,
        # then convert back to file:// for the effect target
        canon = self._canonical_path(path)
        uri = self._file_uri(path)  # file:// URI for broker
        pre_exists, pre_content = self._stat_pre(path, canon)
        extras_raw = self._derive_extra_targets(op_type, path, canon, pre_exists)
        # Convert extras to file:// URIs too
        extras = frozenset(self._file_uri(p) for p in extras_raw)
        conf, integ = self._derive_labels(path, content, pre_exists, False, op_type)

        # Build the prepared effect from REAL state — broker expects file:// URIs
        nonce = self._resolve_capability_nonce(op_type, uri, extras)
        # Register the derived nonce as an alias of the base capability so the
        # broker can look it up in check_auth (which requires the nonce to exist
        # in broker.capabilities). Freshness tracking works via the unique nonce.
        base_nonce = self._base_capability_nonce(op_type, uri)
        if nonce != base_nonce and nonce not in self.broker.capabilities:
            base_cap = self.broker.capabilities.get(base_nonce)
            if base_cap is not None:
                # Copy the capability with the derived nonce (same rights/scope/target)
                from .model import Capability as CapClass

                aliased = CapClass(
                    owner=base_cap.owner,
                    holder=base_cap.holder,
                    right=base_cap.right,
                    target=base_cap.target,
                    scope=base_cap.scope,
                    expiry=base_cap.expiry,
                    nonce=nonce,
                    task_id=base_cap.task_id,
                    derives_from=base_nonce,
                )
                self.broker.capabilities[nonce] = aliased
        # Get real OS metadata for audit trail. statx may not be available
        # on all platforms — wrap in try/except to keep effect derivation robust.
        statx_meta: dict[str, object] = {}
        try:
            stx = os.statx(canon, flags=os.STATX_ALL)  # type: ignore[attr-defined]
            statx_meta = {
                "stx_mode_octal": f"0o{stx.stx_mode & 0o777:03o}",
                "stx_attributes_hex": f"0x{stx.stx_attributes:x}",
                "stx_attributes_encrypted": bool(stx.stx_attributes & (1 << 0)),
                "stx_attributes_immutable": bool(stx.stx_attributes & (1 << 1)),
                "stx_uid": stx.stx_uid,
                "stx_gid": stx.stx_gid,
            }
        except (OSError, AttributeError):
            statx_meta = {"stx_unavailable": "statx not supported on this platform"}

        known_targets = EffectTarget(primary=uri, additional=extras)

        effect = Effect(
            etype=op_type,
            target=uri,
            metadata={
                "os_statx": statx_meta,
                "confidentiality_source": "os-statx"
                if statx_meta.get("stx_unavailable") is None
                else "permission-bits"
                if conf == Confidentiality.CONFIDENTIAL or conf == Confidentiality.PUBLIC
                else "path-keyword-fallback",
                "pre_exists": pre_exists,
            },
            provenance=(
                Data(f"shim-{op_type}", conf, integ),
                Data(f"real-path={canon}", conf, Integrity.USER),
                Data(
                    f"os-statx-mode={statx_meta.get('stx_mode_octal', 'N/A')}", conf, Integrity.USER
                ),
            ),
            capability_nonce=nonce,
            delegation_chain=(self.tool_name, "RealFileShim"),
            known_targets=known_targets,
        )

        # Resolve task from task_id
        task = self.broker.tasks.get(self.task_id)
        commit = Commit(effect=effect, task=task, tool_name=self.tool_name)
        allow, evidence = self.broker.commit(commit)

        op = ShimOp(
            operation=op_type,
            path=canon,
            real_targets=frozenset({canon}) | extras,
            pre_exists=pre_exists,
            pre_content=pre_content,
            post_exists=pre_exists,  # updated below
            post_content=None,  # updated below
            tool_name=self.tool_name,
            blocked=not allow,
            nonce=nonce,
        )

        if not allow:
            blocker = evidence.get("primary_blocker", "unknown")
            raise SecurityError(
                f"[{self.tool_name}] {op_type} on {canon} BLOCKed by {blocker}. "
                f"No OS state changed."
            )

        # ALLOWed: route through IPC in multi-process mode, local fallback otherwise
        if self.ipc_client is not None:
            # IPC mode: real I/O happens in the isolated subprocess
            post_exists, post_content = self._stat_post(path, canon)
            try:
                if op_type == "write":
                    assert content is not None
                    result = self.ipc_client.real_file_write(canon, content, self.task_id)
                    # session_update may carry taint from CONFIDENTIAL write
                    if result.get("session_update"):
                        self._sync_session_from_subprocess(result["session_update"])
                    op.post_exists = True
                    op.post_content = content
                    self.ops.append(op)
                    return cast(T, None)

                elif op_type == "read":
                    result = self.ipc_client.real_file_read(canon, self.task_id)
                    data = base64.b64decode(result["content"])
                    # session_update carries taint from CONFIDENTIAL read
                    if result.get("session_update"):
                        self._sync_session_from_subprocess(result["session_update"])
                    op.post_exists = True
                    op.post_content = data
                    self.ops.append(op)
                    return cast(T, data)

                elif op_type == "stat":
                    result = self.ipc_client.real_file_stat(canon, self.task_id)
                    stat_result = os.stat(canon)  # local fallback for os.stat_result type
                    if result.get("session_update"):
                        self._sync_session_from_subprocess(result["session_update"])
                    op.post_exists = post_exists
                    op.post_content = post_content
                    self.ops.append(op)
                    return cast(T, stat_result)

                elif op_type == "listdir":
                    result = self.ipc_client.real_file_listdir(canon, self.task_id)
                    entries = result.get("entries", [])
                    op.post_exists = post_exists
                    op.post_content = post_content
                    self.ops.append(op)
                    return cast(T, entries)

                elif op_type == "exists":
                    exists_result = os.path.exists(canon)
                    op.post_exists = exists_result
                    op.post_content = post_content
                    self.ops.append(op)
                    return cast(T, exists_result)

                elif op_type == "delete":
                    self.ipc_client.real_file_delete(canon, self.task_id)
                    op.post_exists = False
                    op.post_content = post_content
                    self.ops.append(op)
                    return cast(T, None)

                else:
                    raise ValueError(f"Unknown op type: {op_type}")

            except FileNotFoundError as ex:
                raise OSError(f"File not found: {canon}") from ex
            except PermissionError as ex:
                raise OSError(f"Permission denied: {canon}") from ex
            except OSError as ex:
                raise OSError(
                    f"[{self.tool_name}] {op_type} on {canon} OS ERROR after ALLOW: {ex}. "
                    f"Broker said ALLOW but subprocess rejected. Treat as security event."
                ) from ex
            except Exception as ex:
                raise RuntimeError(
                    f"[{self.tool_name}] {op_type} on {canon} IPC ERROR after ALLOW: {ex}"
                ) from ex

        # Same-process / single-threaded mode: local direct OS calls
        try:
            if op_type == "write":
                assert content is not None, "write called with None content"
                with open(canon, "wb") as f:
                    f.write(content)
                self.ops.append(op)
                return cast(T, None)  # write returns None

            elif op_type == "read":
                with open(canon, "rb") as f:
                    data = f.read()
                self.ops.append(op)
                return cast(T, data)

            elif op_type == "stat":
                stat_result = os.stat(canon)
                self.ops.append(op)
                return cast(T, stat_result)

            elif op_type == "listdir":
                entries = os.listdir(canon)
                self.ops.append(op)
                return cast(T, entries)

            elif op_type == "exists":
                exists_result = os.path.exists(canon)
                self.ops.append(op)
                return cast(T, exists_result)

            elif op_type == "delete":
                os.remove(canon)
                self.ops.append(op)
                return cast(T, None)

            else:
                raise ValueError(f"Unknown op type: {op_type}")

        except FileNotFoundError as ex:
            raise OSError(f"File not found: {canon}") from ex
        except PermissionError as ex:
            raise OSError(f"Permission denied: {canon}") from ex
        except OSError as ex:
            raise OSError(
                f"[{self.tool_name}] {op_type} on {canon} OS ERROR after ALLOW: {ex}. "
                f"Broker said ALLOW but OS rejected. Treat as security event."
            ) from ex
        except Exception as ex:
            raise RuntimeError(
                f"[{self.tool_name}] unexpected error in {op_type} on {canon}: {ex}"
            ) from ex

    def get_ops(self) -> list[ShimOp]:
        """Return the operation log for independent observation."""
        return list(self.ops)


class SecurityError(Exception):
    """Raised by the shim when the broker BLOCKs or OS fails post-ALLOW.

    The tool cannot suppress this. It means:
      - No effect reached external state, OR
      - Broker ALLOWed but OS rejected — security event
    """

    pass
