"""Enforcer: filesystem and network access control for untrusted tool process.

This module is the ONLY path through which an untrusted tool process can perform:
    - Filesystem operations (read/write/delete)
    - Network operations (SMTP send)

Architectural invariant:
    All real I/O in the tool process MUST go through this module.
    Direct calls to open(), os.write(), smtplib.SMTP.sendmail() bypass
    this module and bypass the broker → UNACCEPTABLE.

Design principles:
    1. DEFENSE IN DEPTH: multiple layers of enforcement
    2. FAIL-CLOSED: unknown paths are blocked by default
    3. MINIMAL SURFACE: only allow what's needed for tool execution

Layers of enforcement:
  Layer 1: Broker gate (Auth/FlowOK/NoAmp/Fresh) — evaluates capability
           grants BEFORE any I/O. This is the PRIMARY layer.
  Layer 2: Restricted open (this module) — OS-level path confinement.
           Catches bugs where tool accidentally writes outside sandbox.
  Layer 3: Landlock (optional kernel feature) — future defense.
  Layer 4: Import blocking — prevents tool from importing sensitive modules.

Usage:
    This module is auto-loaded by ExecutorSubprocess at import time.
    It patches os.open() to use _restricted_open() in the subprocess.

    The broker process is NOT affected — os.open() is patched ONLY
    in the subprocess process (not in the broker).
"""

from __future__ import annotations

import os
import sys
from pathlib import PurePosixPath
from typing import Any

# Filesystem Confinement (restricted open)
# Save REAL os.open BEFORE any patching.
# This is used by _restricted_open() to perform the actual I/O,
# and by the broker process (which doesn't patch os.open).
_real_os_open: Any = os.open

# Paths that are ALLOWED for file operations (sandboxed directories).
# Set by broker via set_allowed_paths() during subprocess bootstrap.
_ALLOWED_PATHS: frozenset[str] = frozenset()

# Paths that are BLOCKED regardless of any other permission.
_BLOCKED_PATHS: frozenset[str] = frozenset({
    "/etc",
    "/bin",
    "/usr",
    "/lib",
    "/lib64",
    "/sbin",
    "/usr/sbin",
    "/var",
    "/root",
    "/.ssh",
    "/.config",
})

# Write intent: flags that indicate a write operation
_WRITE_MODE_FLAGS = frozenset({
    os.O_WRONLY,
    os.O_RDWR,
    os.O_CREAT,
    os.O_TRUNC,
    os.O_EXCL,
})

# Special device files needed for subprocess.Popen (stdin/stdout/stderr redirection)
_ALLOWED_DEVICES = frozenset({
    "/dev/null",
    "/dev/zero",
    "/dev/random",
    "/dev/urandom",
})


def set_allowed_paths(paths: frozenset[str]) -> None:
    """Set the allowed filesystem paths for the subprocess.

    Called by the broker during subprocess bootstrap to configure the sandbox.

    Args:
        paths: Set of allowed directory paths (e.g., {"/tmp", "/data/reports"}).
               All writes must be within these paths.
               Reads are allowed within these paths AND system directories.
    """
    global _ALLOWED_PATHS
    _ALLOWED_PATHS = paths


def _has_write_intent(args: tuple[Any, ...]) -> bool:
    """Check if any arg in args indicates write intent."""
    for arg in args:
        if isinstance(arg, int) and arg in _WRITE_MODE_FLAGS:
            return True
    return False


def _is_path_blocked(path: str) -> bool:
    """Check if a path is in blocked system paths."""
    for blocked in _BLOCKED_PATHS:
        if path == blocked or path.startswith(blocked + "/"):
            return True
    return False


def _is_path_in_allowed_dirs(path: str) -> bool:
    """Check if path is within any configured allowed directory."""
    if not _ALLOWED_PATHS:
        return False
    for allowed in _ALLOWED_PATHS:
        if path == allowed or path.startswith(allowed + "/"):
            return True
    return False


def _restricted_open(path: str, *args: Any, **kwargs: Any) -> int:
    """Restricted open() — only allows operations in sandboxed directories.

    SECURITY INVARIANTS:
      - Writes ONLY allowed in broker-configured allowed paths
      - Reads allowed in allowed paths + system directories + device files
      - System paths (/etc, /bin, etc.) are BLOCKED for ALL operations
      - Device files (/dev/null, etc.) are ALLOWED (needed for subprocess)

    This is the ONLY path for file I/O in the subprocess. Any attempt to
    access files outside the sandbox raises PermissionError.

    Args:
        path: File path to open
        *args, **kwargs: Forwarded to os.open()

    Returns:
        File descriptor (int) from os.open()

    Raises:
        PermissionError: If path is outside sandbox or in blocked paths
        OSError: If os.open() fails for other reasons
    """
    path_str = str(path)

    # Allow special device files (needed for subprocess.Popen)
    if path_str in _ALLOWED_DEVICES:
        return _real_os_open(path, *args, **kwargs)

    # Block all access to sensitive system paths
    if _is_path_blocked(path_str):
        raise PermissionError(
            f"Restricted open: path '{path_str}' is blocked. "
            f"Blocked prefixes: {sorted(_BLOCKED_PATHS)}"
        )

    # Write operations: ONLY allowed in broker-configured sandbox paths
    if _has_write_intent(args):
        if _is_path_in_allowed_dirs(path_str):
            return _real_os_open(path, *args, **kwargs)
        raise PermissionError(
            f"Write denied to '{path_str}'. "
            f"Only allowed within sandbox paths: {sorted(_ALLOWED_PATHS)}"
        )

    # Read operations: allowed in sandbox paths + some system dirs (config)
    if _is_path_in_allowed_dirs(path_str):
        return _real_os_open(path, *args, **kwargs)

    # Allow reading system config files (needed for some tools)
    _ALLOWED_READ_SYSTEM = frozenset({"/etc", "/usr", "/bin", "/sbin", "/lib"})
    for sys_dir in _ALLOWED_READ_SYSTEM:
        if path_str == sys_dir or path_str.startswith(sys_dir + "/"):
            return _real_os_open(path, *args, **kwargs)

    # Allow reading device files
    if path_str.startswith("/dev/"):
        return _real_os_open(path, *args, **kwargs)

    # Default: deny
    raise PermissionError(
        f"Read denied for '{path_str}'. "
        f"Allowed: sandbox paths {sorted(_ALLOWED_PATHS)}, "
        f"system dirs /etc,/usr,/bin,/sbin,/lib,/dev"
    )


# Apply restricted-open patch (subprocess only)
# The patch is applied at import time IF we're in the subprocess process.
# The broker process also imports this module but should NOT apply the patch
# because it needs os.open for subprocess.Popen operations.
#
# Detection: we check sys.argv[0] for "executor_subprocess" to identify
# when this script is run directly as __main__ (subprocess) vs imported
# by the broker (broker process).
#
# Additionally, the broker may pass env var ECAC_SUBPROCESS=1 to explicitly
# indicate subprocess mode.

_EXECUTOR_MAIN = (
    len(sys.argv) > 0
    and "executor_subprocess" in str(sys.argv[0])
) or os.environ.get("ECAC_SUBPROCESS") == "1"

if _EXECUTOR_MAIN:
    os.open = _restricted_open  # type: ignore[assignment]


# Import Blocking
#
# IMPLEMENTATION: Lives in executor_subprocess.py
# It is applied FIRST, before ANY other imports, as a builtins.__import__ hook.
# This ordering is CRITICAL: the hook blocks dangerous imports BEFORE they load.
#
# The blocklists are:
#   _DANGEROUS_MODULES: exec, eval, pickle, marshal, platform, resource, pwd, grp
#   _BLOCKED_NETWORK_PACKAGES: requests, aiohttp, httpx, websockets, smb, urllib3
#   _BLOCKED_STDLIB: http.client, ftplib, telnetlib, nntplib, poplib
#
# Allowed modules (NOT blocked):
#   - os, subprocess, signal, socket (for I/O and IPC)
#   - ctypes, ctypes.util (for Landlock detection)
#   - smtplib, imaplib (needed for real_smtp_send, real_imap_read_inbox)
#   - All effect_broker internal modules
#
# See executor_subprocess.py for the full implementation and the
# _secure_import() hook that enforces this.


# Verification helpers
def is_restricted_open_active() -> bool:
    """Return True if restricted open is active (os.open is patched)."""
    return os.open is _restricted_open


def get_allowed_paths() -> frozenset[str]:
    """Return the currently configured allowed paths."""
    return _ALLOWED_PATHS


def get_blocked_paths() -> frozenset[str]:
    """Return the blocked system paths."""
    return _BLOCKED_PATHS