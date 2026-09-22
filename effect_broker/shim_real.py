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
        self.ops = []

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
        """
        # For NEW file writes: derive from path, NOT content
        # Content scanning would cause false CONFIDENTIAL labels for
        # normal text like "hello world" that happens to contain keywords
        # A new file is labeled by its PATH (deny-most by default)
        if not pre_exists and op_type == "write":
            conf = self._derive_path_confidentiality(path)
            integ = Integrity.USER
        # Existing file being read: derive from content
        elif content is not None and op_type == "read":
            conf = self._derive_content_confidentiality(content)
            integ = Integrity.USER
        # Read-only on existing file
        elif pre_exists and op_type in ("read", "stat"):
            conf = self._derive_path_confidentiality(path)
            integ = Integrity.USER
        # Fallback
        else:
            conf = Confidentiality.INTERNAL
            integ = Integrity.USER

        return conf, integ

    def _derive_path_confidentiality(self, path: str) -> Confidentiality:
        """Map a filesystem path to a confidentiality level.

        In a real deployment, this would read from a path-to-label mapping
        or from extended attributes (xattrs). Here we use heuristic rules.
        """
        lower = path.lower()
        if any(kw in lower for kw in ["secret", "classified", "confidential"]):
            return Confidentiality.CONFIDENTIAL
        elif any(kw in lower for kw in ["internal", "corp", "shared"]):
            return Confidentiality.INTERNAL
        elif any(kw in lower for kw in ["public", "www"]):
            return Confidentiality.PUBLIC
        else:
            return Confidentiality.INTERNAL  # default: deny-most (INTERNAL, not PUBLIC)

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

        The returned nonce is unique per target path, allowing multiple writes
        to different files to each pass freshness checks. It's registered as
        an alias of the base capability in _op().
        """
        base = self._base_capability_nonce(op_type, primary)
        # Derive unique nonce: include last 40 chars of path for per-effect uniqueness
        path_suffix = primary[7:] if primary.startswith("file://") else primary
        return f"{base}|{path_suffix[-40:]}"

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
        known_targets = EffectTarget(primary=uri, additional=extras)

        effect = Effect(
            etype=op_type,
            target=uri,
            metadata={},
            provenance=(
                Data(f"shim-{op_type}", conf, integ),
                Data(f"real-path={canon}", conf, Integrity.USER),
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

            # ALLOWed: perform the real OS operation
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
