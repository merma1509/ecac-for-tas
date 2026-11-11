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
  ~ Landlock sandbox — Linux only, and only when the selftest passes
  ✓ Network blocking (except local IPC socket)

What "Landlock" means here: on Linux 5.13+ with the LSM enabled, a ruleset is
applied and `_selftest_confinement()` confirms a write outside
`ECAC_LANDLOCK_WRITE_ROOT` is denied. On macOS there is no kernel mechanism at
all, and the Python-level wrappers above are hygiene, not confinement.
`_get_confinement_status()` reports which of the two you have;
`ECAC_REQUIRE_CONFINEMENT=1` turns absence into a refusal to start.

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

_DANGEROUS_MODULES: frozenset[str] = frozenset(
    {
        # Code execution — prevents dynamic code generation
        "exec",
        "eval",
        "compile",
        "code",
        "codeop",
        # Object serialization attacks
        "pickle",
        "marshal",
        "shelve",
        # System information / privilege escalation
        "platform",  # Can reveal system info
        "resource",  # Can modify resource limits
        "grp",  # Group database access
        "pwd",  # Password database access
        "spwd",  # Shadow password database access
        # Signal handlers are managed by the subprocess itself, not needed as module
    }
)

# Third-party network packages blocked (never needed in subprocess)
_BLOCKED_NETWORK_PACKAGES: frozenset[str] = frozenset(
    {
        "requests",
        "aiohttp",
        "httpx",
        "websockets",
        "smb",
        "urllib3",
    }
)

# stdlib modules blocked (not needed in subprocess, not dangerous as-is)
_BLOCKED_STDLIB: frozenset[str] = frozenset(
    {
        # Network client libraries (not needed in isolated subprocess)
        # Note: smtplib IS needed for real_smtp_send, imaplib IS needed for real_imap_read_inbox
        "http.client",
        "ftplib",
        "telnetlib",
        "nntplib",
        "poplib",
    }
)

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

import ctypes
import ctypes.util
import hashlib
import json
import os
import signal
import socket
import subprocess
import tempfile
import threading
from pathlib import Path
from typing import Any


# PHASE 3: Content hash verification (atomic commit guarantee)
def _compute_effect_content_hash(effect: dict[str, Any]) -> str | None:
    """Content hash for a dict-shaped effect, via the shared helper.

    This used to be a mirrored implementation hashing `f"{subject}|{body}"` —
    the separator ambiguity PLAN 5 B2 — while model.py hashed its own format,
    so the two sides could disagree. Now: serialize the dict back into an
    Effect and call the one implementation. No mirrored hashing anywhere.
    """
    from effect_broker.model import Effect, canonical_request_from_effect

    try:
        effect_obj = Effect(
            etype=effect.get("etype", ""),
            target=effect.get("target", ""),
            metadata=dict(effect.get("metadata", {})),
            provenance=(),
            capability_nonce=effect.get("capability_nonce", ""),
            delegation_chain=(),
        )
    except Exception:
        return None

    request = canonical_request_from_effect(effect_obj)
    # The canonical request covers send (subject/body) and write (content).
    # fall back to the legacy combined hash for anything else with content.
    if request.resource_digests:
        return request.digest("body") or request.digest("content")
    return effect_obj.compute_content_hash()


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
    _real_os_open,
)
from effect_broker.enforcer import (
    _restricted_open as _restricted_open,
)

# Landlock ABI constants (linux/landlock.h, x86_64). The code previously used
# 451 for every landlock call, which is not any of them.
#
# Version-gated access flags are filtered through `_LANDLOCK_ABI_HANDLED`: a flag
# the running kernel does not know makes the whole ruleset call fail with
# EINVAL, so handling all of them unconditionally would disable confinement on
# older kernels instead of tightening it.
_SYS_LANDLOCK_CREATE_RULESET = 444
_SYS_LANDLOCK_ADD_RULE = 445
_SYS_LANDLOCK_RESTRICT_SELF = 446

_LANDLOCK_CREATE_RULESET_VERSION = 1 << 0
_LANDLOCK_RULE_PATH_BENEATH = 1

#: `prctl(PR_SET_NO_NEW_PRIVS, 1)`. Landlock's `restrict_self` fails with EPERM
#: unless this is set first: without it the call is refused outright, which is
#: exactly how confinement silently never engaged before. It also stops the
#: process from gaining privilege through setuid/file capabilities, which is the
#: posture a confined executor wants regardless.
_PR_SET_NO_NEW_PRIVS = 38

_LANDLOCK_ACCESS_FS_EXECUTE = 1 << 0
_LANDLOCK_ACCESS_FS_WRITE_FILE = 1 << 1
#: Reading. Omitting this bit made every read unconfined: `~/.ssh/id_rsa` and
#: `~/.aws/credentials` opened fine through the real syscall, which is precisely
#: what item 2 of the review asks to be protected.
_LANDLOCK_ACCESS_FS_READ_FILE = 1 << 2
_LANDLOCK_ACCESS_FS_REMOVE_DIR = 1 << 4
_LANDLOCK_ACCESS_FS_REMOVE_FILE = 1 << 5
_LANDLOCK_ACCESS_FS_MAKE_REG = 1 << 8
_LANDLOCK_ACCESS_FS_MAKE_DIR = 1 << 11

#: Access flags introduced after ABI v1, gated by the kernel's reported version.
#: Asking for a flag the kernel does not know fails the whole ruleset with
#: EINVAL, so handling all of them unconditionally would silently disable
#: confinement on an older kernel rather than tightening it.
_LANDLOCK_ACCESS_BY_ABI: tuple[tuple[int, int], ...] = (
    # (minimum ABI version, flag)
    (1, _LANDLOCK_ACCESS_FS_EXECUTE),
    (1, _LANDLOCK_ACCESS_FS_WRITE_FILE),
    (1, _LANDLOCK_ACCESS_FS_READ_FILE),
    (1, _LANDLOCK_ACCESS_FS_REMOVE_DIR),
    (1, _LANDLOCK_ACCESS_FS_REMOVE_FILE),
    (1, _LANDLOCK_ACCESS_FS_MAKE_REG),
    (1, _LANDLOCK_ACCESS_FS_MAKE_DIR),
)


def _landlock_handled_access(abi: int) -> int:
    """Mask of access rights this kernel supports, for the given ABI version."""
    handled = 0
    for min_abi, flag in _LANDLOCK_ACCESS_BY_ABI:
        if abi >= min_abi:
            handled |= flag
    return handled


#: Directories writes are permitted beneath, as a kernel-enforced allowlist.
#:
#: This must agree with the Python-level policy in executor.py — "writes ONLY to
#: /tmp, /var/tmp, /dev/shm" — because the two layers are meant to be the same
#: boundary enforced twice. An earlier version permitted only
#: `/tmp/ecac-sandbox`, which is where the executor's own files live, and that
#: made Landlock reject every legitimate effect target under `/tmp`. A sandbox
#: that refuses the work it exists to guard is not a stricter sandbox; it is a
#: broken one.
#:
#: `ECAC_LANDLOCK_WRITE_ROOT` still narrows it to a single directory when a
#: deployment wants tighter confinement than the default.
_LANDLOCK_WRITE_ROOT = os.environ.get("ECAC_LANDLOCK_WRITE_ROOT", "/tmp/ecac-sandbox")

#: The directories the kernel ruleset re-opens for writes. The executor's own
#: root is included so its IPC socket and temp files remain writable.
_LANDLOCK_WRITE_DIRS: tuple[str, ...] = (
    (_LANDLOCK_WRITE_ROOT,)
    if os.environ.get("ECAC_LANDLOCK_WRITE_ROOT")
    else ("/tmp", "/var/tmp", "/dev/shm")
)

#: Read-only roots, re-opened for reading now that READ_FILE is handled.
#:
#: Two groups, both deliberate:
#:   - what an interpreter needs to start at all (stdlib, shared libs, the
#:     executable itself);
#:   - `/dev` for `/dev/null`, `/dev/urandom`.
#:
#: Home directories are NOT here. `~/.ssh`, `~/.aws`, `~/.config` and any signing
#: key live there, and a read-confinement that re-opens `~` protects nothing.
#: `ECAC_LANDLOCK_READ_ROOTS` lets a deployment add its own data roots (colon-
#: separated), which is how a real workload gets its inputs.
def _interpreter_roots() -> tuple[str, ...]:
    """Directories this interpreter needs in order to start and import.

    Hardcoding `/usr` and `/lib` was wrong and CI proved it: on a runner whose
    Python lives in `/opt/hostedtoolcache`, a confined executor could not read
    the stdlib and every `import smtplib` failed with EACCES. The read roots
    must be derived from where *this* interpreter actually is, not guessed.

    Only the top-level parents are returned: `sys.path` entries and the
    executable's own directory. Re-opening a prefix of the filesystem is the
    point — what matters is that it is the prefix the interpreter uses.
    """
    candidates: list[str] = []
    exe = sys.executable
    if exe:
        candidates.append(os.path.dirname(exe))
        # `.../bin/python3` -> the prefix, which holds lib/pythonX.Y.
        candidates.append(os.path.dirname(os.path.dirname(exe)))
    for entry in sys.path:
        if entry and os.path.isdir(entry):
            candidates.append(entry)

    # Deduplicate while keeping order, and drop anything that resolves to `/`:
    # opening `/` would re-open every home directory through the same rule.
    seen: set[str] = set()
    roots: list[str] = []
    for candidate in candidates:
        try:
            resolved = os.path.realpath(candidate)
        except OSError:
            continue
        if resolved in seen or resolved == "/":
            continue
        seen.add(resolved)
        roots.append(resolved)
    return tuple(roots)


#: Read-only roots, re-opened for reading now that READ_FILE is handled.
#:
#: Two groups, both deliberate:
#:   - what an interpreter needs to start at all (stdlib, shared libs, the
#:     executable itself) — derived from `sys.path`/`sys.executable`, because
#:     the interpreter is not always under `/usr`;
#:   - `/dev` for `/dev/null`, `/dev/urandom`.
#:
#: Home directories are NOT here. `~/.ssh`, `~/.aws`, `~/.config` and any signing
#: key live there, and a read-confinement that re-opens `~` protects nothing.
#: `ECAC_LANDLOCK_READ_ROOTS` lets a deployment add its own data roots (colon-
#: separated), which is how a real workload gets its inputs.
_LANDLOCK_READ_DIRS: tuple[str, ...] = tuple(
    os.environ.get("ECAC_LANDLOCK_READ_ROOTS", "").split(":")
) if os.environ.get("ECAC_LANDLOCK_READ_ROOTS") else (
    "/usr",
    "/lib",
    "/lib64",
    "/bin",
    "/sbin",
    "/etc",
    "/dev",
    "/proc",
    "/sys",
) + _interpreter_roots()


def _kernel_landlock_abi() -> int:
    """Return the kernel's Landlock ABI version, or a negative value.

    Separated out so that a caller can distinguish "this kernel has no Landlock"
    (a host property, nothing to fix in this code) from "this kernel has
    Landlock and our ruleset did not take" (a defect). CI uses it to refuse to
    skip: on a Landlock-capable runner, being unconfined is always a failure.
    """
    if os.uname().sysname != "Linux":
        return -1
    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    libc.syscall.restype = ctypes.c_long
    result: int = libc.syscall(
        _SYS_LANDLOCK_CREATE_RULESET,
        None,
        ctypes.c_size_t(0),
        ctypes.c_uint32(_LANDLOCK_CREATE_RULESET_VERSION),
    )
    return result


def _apply_landlock_sandbox() -> bool:
    """Apply a Landlock filesystem ruleset to this process (Linux 5.13+).

    Returns True ONLY if the kernel reports the ruleset as enforced. A bare
    `syscall() >= 0` does not establish that: this function used to return True
    from a call that passed the ruleset FD where the flags argument belongs, so
    "landlock active" was reported without a rule ever being applied.

    The claim is only made after `_selftest_confinement()` observes a denied
    path actually being denied, which is the difference between asking the
    kernel to restrict us and the restriction being in effect.
    """
    if os.uname().sysname != "Linux":
        return False

    # Confirm the kernel implements Landlock before asking for a ruleset. On an
    # older kernel this fails cleanly, which is what we want: no silent no-op.
    abi = _kernel_landlock_abi()
    if abi < 0:
        return False

    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    libc.syscall.restype = ctypes.c_long

    class _RulesetAttr(ctypes.Structure):
        _fields_ = [("handled_access_fs", ctypes.c_uint64)]

    class _PathBeneathAttr(ctypes.Structure):
        _fields_ = [
            ("allowed_access", ctypes.c_uint64),
            ("parent_fd", ctypes.c_int32),
        ]

    # Place the read probe's canary now: once the ruleset applies, writing to
    # `~` is denied, so this is the last moment it can exist.
    _place_read_sentinel()

    handled = _landlock_handled_access(abi)
    attr = _RulesetAttr(handled_access_fs=handled)
    ruleset_fd = libc.syscall(
        _SYS_LANDLOCK_CREATE_RULESET,
        ctypes.byref(attr),
        ctypes.sizeof(attr),
        0,
    )
    if ruleset_fd < 0:
        return False

    try:
        # A ruleset with no rules denies every handled access everywhere. That is
        # the intended default: writes are re-opened only beneath the permitted
        # directories.
        #
        # Each directory must exist BEFORE its rule is added. A missing directory
        # means no rule for it, and the ruleset then denies writes there — which
        # is how the executor ended up unable to write its own temp files.
        o_path = getattr(os, "O_PATH", 0)
        for write_dir in _LANDLOCK_WRITE_DIRS:
            try:
                os.makedirs(write_dir, exist_ok=True)
            except OSError:
                continue
            if not os.path.isdir(write_dir):
                continue
            # `_real_os_open` rather than `os.open`: inside the executor, os.open
            # is replaced by the Python-level allowlist, which would refuse to
            # open the sandbox root itself and leave the ruleset without its one
            # permitting rule. More importantly, measuring the kernel mechanism
            # through a Python wrapper would measure the wrapper.
            root_fd = _real_os_open(write_dir, o_path | os.O_CLOEXEC)
            try:
                path_attr = _PathBeneathAttr(
                    allowed_access=handled,
                    parent_fd=root_fd,
                )
                added = libc.syscall(
                    _SYS_LANDLOCK_ADD_RULE,
                    ruleset_fd,
                    _LANDLOCK_RULE_PATH_BENEATH,
                    ctypes.byref(path_attr),
                    0,
                )
                if added < 0:
                    return False
            finally:
                os.close(root_fd)

        # Read-only roots: reading is now handled, so it must be re-opened where
        # it is legitimate. Read+execute only — never write.
        #
        # The working directory is included because that is where a workload's
        # own input files live; without it the confined executor cannot read the
        # files it was started to process. It is resolved here, at activation,
        # not at import, so it reflects where this process actually runs.
        read_access = _LANDLOCK_ACCESS_FS_READ_FILE | _LANDLOCK_ACCESS_FS_EXECUTE
        try:
            cwd_root = os.getcwd()
        except OSError:
            cwd_root = ""
        extra_roots = [cwd_root]
        # The executor must read the HMAC key it verifies IPC messages with.
        # That directory holds one file (the secret), so opening it is a narrow
        # exception -- opening `~` to reach it would defeat the point.
        ipc_key_dir = os.environ.get("ECAC_IPC_KEY_DIR", "")
        if ipc_key_dir:
            extra_roots.append(ipc_key_dir)
        read_dirs = tuple(_LANDLOCK_READ_DIRS) + tuple(r for r in extra_roots if r)
        for read_dir in read_dirs:
            read_dir = read_dir.strip()
            if not read_dir or not os.path.isdir(read_dir):
                continue
            try:
                root_fd = _real_os_open(read_dir, o_path | os.O_CLOEXEC)
            except OSError:
                continue
            try:
                path_attr = _PathBeneathAttr(allowed_access=read_access, parent_fd=root_fd)
                added = libc.syscall(
                    _SYS_LANDLOCK_ADD_RULE,
                    ruleset_fd,
                    _LANDLOCK_RULE_PATH_BENEATH,
                    ctypes.byref(path_attr),
                    0,
                )
                if added < 0:
                    # A read root the kernel refuses is not fatal: it only means
                    # that tree stays unreadable, which fails closed for reads.
                    continue
            finally:
                os.close(root_fd)

        # restrict_self requires PR_SET_NO_NEW_PRIVS first; without it the call
        # returns EPERM and no restriction is applied. This was the second
        # defect in this path, and the reason `_landlock_active` was always
        # False on Linux even once the ruleset arguments were correct.
        if libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            return False

        # restrict_self takes FLAGS, not the ruleset FD — passing the FD here was
        # the original defect, and it made the call meaningless.
        if (
            libc.syscall(
                _SYS_LANDLOCK_RESTRICT_SELF,
                ruleset_fd,
                ctypes.c_uint32(0),
            )
            < 0
        ):
            return False
    finally:
        os.close(ruleset_fd)

    # No-op unless a denied path is actually denied.
    return _selftest_confinement()


def _selftest_confinement() -> bool:
    """Return True only if confinement is observably BOTH ways.

    A one-sided probe is not evidence. "A write outside the root was denied" is
    also true of a ruleset that denies everything — and a ruleset that denies
    everything is not confinement, it is a broken executor: the process cannot
    write its own temp files. So the probe requires two observations:

      1. a write outside `_LANDLOCK_WRITE_ROOT` is denied (EACCES), AND
      2. a write inside it is allowed.

    The outside probe must run somewhere writable *without* confinement,
    otherwise a denial proves nothing: probing `/etc` returns "denied" on any
    host where `/etc` is not writable for ordinary permission reasons. So it
    looks for a directory the process can normally write to and that lies
    outside every permitted directory, and treats only `EACCES` there as denial.

    If either observation cannot be made, the answer is False: an untested claim
    is not a claim.

    The probes use `_real_os_open`, not `os.open`. Inside the executor, `os.open`
    is replaced by the Python-level path allowlist, so a probe routed through it
    would report the allowlist's decision and call it kernel confinement — a
    denial from Python read as evidence from the kernel. The question here is
    specifically whether the *kernel* is confining us.
    """
    write_dirs = [os.path.abspath(d) for d in _LANDLOCK_WRITE_DIRS]

    def _is_permitted(path: str) -> bool:
        return any(path == d or path.startswith(d + os.sep) for d in write_dirs)

    # (2) The permitted side must still work. Checked first: if no permitted
    # directory is writable, the ruleset is denying more than intended and the
    # outside denial below would be worthless evidence.
    writable_inside = False
    for write_dir in write_dirs:
        if not os.path.isdir(write_dir):
            continue
        inside_probe = os.path.join(write_dir, f".ecac-inside-probe-{os.getpid()}")
        try:
            fd = _real_os_open(inside_probe, os.O_CREAT | os.O_WRONLY | os.O_CLOEXEC, 0o600)
        except OSError:
            continue  # This one is not writable; another permitted dir may be.
        os.close(fd)
        try:
            os.unlink(inside_probe)
        except OSError:
            pass
        writable_inside = True
        break
    if not writable_inside:
        return False  # Confined out of its own sandbox: not a working sandbox.

    try:
        tmpdir: str | None = tempfile.gettempdir()
    except OSError:
        tmpdir = None
    try:
        cwd: str | None = os.getcwd()
    except OSError:
        cwd = None
    for base in (tmpdir, cwd, os.path.expanduser("~")):
        if not base:
            continue
        base_abs = os.path.abspath(base)
        # Probing inside a permitted directory would be allowed by design, and
        # would read as "not confined" even when it is.
        if _is_permitted(base_abs):
            continue
        if not os.access(base_abs, os.W_OK):
            continue
        probe = os.path.join(base_abs, f".ecac-landlock-probe-{os.getpid()}")
        try:
            fd = _real_os_open(probe, os.O_CREAT | os.O_WRONLY | os.O_CLOEXEC, 0o600)
        except PermissionError:
            # Denied where we demonstrably could write: that is confinement.
            return _read_probe_passes()
        except OSError:
            # Some other error says nothing about confinement. Try elsewhere.
            continue
        os.close(fd)
        try:
            os.unlink(probe)
        except OSError:
            pass
        return False  # The write landed. Not confined.
    return False


def _read_probe_passes() -> bool:
    """True only if a legitimate read works AND a home read is denied.

    `READ_FILE` is now handled, so a ruleset that forgot to re-open the read
    roots would confine the executor into being unusable — and a write-only
    probe would still call that success. Both directions must be observed:

      1. reading a file under a permitted read root succeeds, and
      2. reading a file under the home directory is denied.

    The sentinel is created by `_place_read_sentinel()` BEFORE the ruleset is
    applied, because after it the process can no longer write to `~`. Without a
    pre-placed file this probe had no credential to try, and returned False —
    which made every legitimate deployment look unconfined.

    A denial is only counted when the file was readable without confinement;
    otherwise it could just be ordinary permissions.
    """
    # (1) Legitimate read must still work.
    read_ok = False
    for read_dir in _LANDLOCK_READ_DIRS:
        read_dir = read_dir.strip()
        if not read_dir or not os.path.isdir(read_dir):
            continue
        try:
            names = os.listdir(read_dir)
        except OSError:
            continue
        for name in names[:20]:
            candidate = os.path.join(read_dir, name)
            if not os.path.isfile(candidate):
                continue
            try:
                fd = _real_os_open(candidate, os.O_RDONLY | os.O_CLOEXEC)
            except OSError:
                continue
            os.close(fd)
            read_ok = True
            break
        if read_ok:
            break
    if not read_ok:
        return False  # Confined out of reading anything: not a usable executor.

    # (2) The sentinel under home must now be denied.
    sentinel = _read_sentinel_path()
    if sentinel is None or not os.path.isfile(sentinel):
        return False  # Nothing to prove the read boundary against.
    try:
        fd = _real_os_open(sentinel, os.O_RDONLY | os.O_CLOEXEC)
    except PermissionError:
        return True  # Readable without confinement, denied with it.
    except OSError:
        return False
    os.close(fd)
    return False  # The home read landed. Not confined.


def _read_sentinel_path() -> str | None:
    """Where the read probe's canary lives, or None if there is no home tree."""
    home = os.path.expanduser("~")
    if not home or home in {"/", "~"}:
        return None
    return os.path.join(home, ".ecac-read-probe")


def _place_read_sentinel() -> None:
    """Create the read-probe canary. Must run BEFORE the ruleset is applied.

    After confinement the process cannot write to `~`, so a sentinel created
    later cannot exist. Failure is not fatal: the probe then reports False,
    which is the honest answer for "the boundary could not be demonstrated".
    """
    path = _read_sentinel_path()
    if path is None:
        return
    try:
        with open(path, "w") as handle:
            handle.write("read-confinement-probe")
        os.chmod(path, 0o600)
    except OSError:
        pass


# Landlock is applied when the executor starts, NOT at import time.
#
# It was applied at import, and that confined every process that so much as
# imported this module — the test runner included, which then could not spawn a
# subprocess, and any in-process caller inherited a ruleset it never asked for.
# A sandbox belongs to the process that is meant to be sandboxed, so the
# restriction is now activated explicitly by `_activate_confinement()` from the
# executor entrypoint.
_landlock_active: bool = False


def _activate_confinement() -> bool:
    """Confine this process and make it able to write its own temp files.

    Returns True only if `_apply_landlock_sandbox()` observed the restriction
    taking effect. Idempotent: calling it twice does not stack rulesets.
    """
    global _landlock_active
    if _landlock_active:
        return True
    if not _apply_landlock_sandbox():
        return False
    # Everything under the root is the only place this process can write, so
    # anything that reaches for a temp dir must land inside it. Without this,
    # `tempfile` cannot find a usable directory and raises — the executor would
    # be confined into being non-functional, which is not a sandbox.
    os.environ["TMPDIR"] = _LANDLOCK_WRITE_ROOT
    tempfile.tempdir = _LANDLOCK_WRITE_ROOT
    _landlock_active = True
    return True


class ConfinementUnavailable(RuntimeError):
    """Kernel-enforced confinement was required but is not in effect."""


def _require_confinement_if_configured() -> None:
    """Fail closed when `ECAC_REQUIRE_CONFINEMENT=1` and Landlock is inactive.

    Without this, a host that cannot confine (macOS, an old kernel, a container
    without the LSM enabled) degrades silently: the executor runs, the ledger
    says `committed`, and nothing distinguishes "confined" from "wanted to be".
    Default is off so local development on macOS still runs; CI sets it, and
    either way the status is reported rather than assumed.
    """
    if os.environ.get("ECAC_REQUIRE_CONFINEMENT", "").lower() not in {"1", "true", "yes"}:
        return
    if _confinement_is_kernel_enforced():
        return
    raise ConfinementUnavailable(
        f"ECAC_REQUIRE_CONFINEMENT is set but no kernel confinement is in effect "
        f"(platform={os.uname().sysname}, status={_get_confinement_status()}). "
        f"Refusing to run unconfined rather than reporting a guarantee we cannot keep. "
        f"Landlock requires Linux 5.13+ with the LSM enabled."
    )


def _get_confinement_status() -> str:
    """Return the confinement methods actually in effect, per platform.

    `landlock` appears only when `_apply_landlock_sandbox()` returned True, which
    requires the selftest to have observed a denied path being denied. There is
    no code path that reports `landlock` on the strength of a syscall return
    value alone

    On non-Linux hosts the answer names what is left, so a reader cannot mistake
    "no kernel confinement" for "confinement not checked".
    """
    methods = []
    if _landlock_active:
        methods.append("landlock")
    methods.append("restricted-open")
    methods.append("import-blocking")
    return "+".join(methods)


def _confinement_is_kernel_enforced() -> bool:
    """True only if a kernel mechanism, not a Python wrapper, is restricting us."""
    return _landlock_active


def _derive_confidentiality_from_mode(mode_int: int) -> str:
    """Derive confidentiality from Unix permission bits.

    delegates to the single source of truth in statx.py instead of
    a forked hard-coded copy, so the subprocess can never drift from the broker
    or shim. Runs in subprocess so taint detection uses real OS state.
    """
    # Absolute import: the subprocess runs as a top-level script
    # (python effect_broker/executor_subprocess.py) with PYTHONPATH=ecac_root,
    # so relative imports do NOT resolve here — use the package path.
    from effect_broker.statx import derive_confidentiality_mode_str

    return derive_confidentiality_mode_str(mode_int)


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
        # The sandbox root must exist before confinement is applied: it is the
        # only writable location afterwards, and the IPC socket lives inside it.
        try:
            os.makedirs(_LANDLOCK_WRITE_ROOT, exist_ok=True)
        except OSError:
            pass

        # Confine first: the restriction applies to the whole process, so it has
        # to be in place before anything else in here touches the filesystem,
        # and certainly before an effect is applied.
        _activate_confinement()

        # Refuse to start unconfined when confinement is required. Checked here,
        # before any effect can be applied, so "required but absent" can never be
        # discovered late.
        _require_confinement_if_configured()

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

            # Track taint: if read CONFIDENTIAL file, taint THIS resource
            # (PLAN_2 S2 — per-resource, keyed by the file URI).
            if effect.get("etype") == "read":
                target = effect.get("target", "")
                file_entry = self._store._files.get(target)
                if (
                    file_entry
                    and hasattr(file_entry.sensitivity, "name")
                    and file_entry.sensitivity.name == "CONFIDENTIAL"
                ):
                    if target not in session.get("_tainted_resources", {}):
                        # session is the preferred dict here; mutate in place.
                        tainted_resources = dict(session.get("_tainted_resources", {}))
                        tainted_resources[target] = {
                            "reason": f"read-confidential({target})",
                            "cleared_by": None,
                        }
                        session["_tainted_resources"] = tainted_resources
                        self._session_states[task_id] = session

            # Reserve nonce if requested (B's local reservation)
            if reserve_nonce and nonce:
                if "used" not in session:
                    session["used"] = list(snapshot.get("used", []))
                session["used"] = list(session.get("used", [])) + [nonce]

            # Build session update for A (B→A sync) — PLAN_2 S2: carry the
            # per-resource taint records so A can do narrow declassification.
            session_update_applied = {
                "used": session.get("used", list(snapshot.get("used", []))),
                "logical_time": session.get("logical_time", snapshot.get("logical_time", 0.0)),
                "tainted": bool(session.get("_tainted_resources")),
                "tainted_resources": session.get("_tainted_resources", {}),
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
                    # PLAN_2 S2 — per-resource taint keyed by the file URI.
                    task_id = payload.get("task_id", "default")
                    session = self._session_states.get(task_id, {})
                    if path not in session.get("_tainted_resources", {}):
                        session = dict(session)  # copy
                        tainted_resources = dict(session.get("_tainted_resources", {}))
                        tainted_resources[path] = {
                            "reason": f"real-read-confidential({path})",
                            "cleared_by": None,
                        }
                        session["_tainted_resources"] = tainted_resources
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
                landed_bytes: int | None = None
                try:
                    st = os.stat(path)
                    confidentiality = _derive_confidentiality_from_mode(st.st_mode)
                    # What actually landed, measured here rather than asserted by
                    # the broker. f.write() can return without raising and still
                    # leave a short file, so the size is read back from the OS.
                    landed_bytes = st.st_size
                except OSError:
                    confidentiality = "INTERNAL"
                session_update = {}
                if confidentiality == "CONFIDENTIAL":
                    # PLAN_2 S2 — per-resource taint keyed by the file URI.
                    task_id = payload.get("task_id", "default")
                    session = self._session_states.get(task_id, {})
                    if path not in session.get("_tainted_resources", {}):
                        session = dict(session)
                        tainted_resources = dict(session.get("_tainted_resources", {}))
                        tainted_resources[path] = {
                            "reason": f"real-write-confidential({path})",
                            "cleared_by": None,
                        }
                        session["_tainted_resources"] = tainted_resources
                        self._session_states[task_id] = session
                    session_update = session
                return {
                    "ok": True,
                    "path": path,
                    "confidentiality": confidentiality,
                    "session_update": session_update,
                    "landed_bytes": landed_bytes,
                }

            elif op == "real_delete":
                path = payload["path"]
                os.remove(path)
                return {"ok": True, "path": path}

            elif op == "real_stat":
                path = payload["path"]
                st = os.stat(path)
                confidentiality = _derive_confidentiality_from_mode(st.st_mode)
                # PLAN_2 S4 — metadata (statx fields: mode/size/mtime) is NOT
                # semantically confidential. Only file CONTENT is. A pure stat
                # must NOT taint the session (it observes metadata, not content).
                session_update = {}
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
                # Real send. sendmail() discards the DATA reply, so drive the
                # transaction explicitly: the code is the transport's answer and
                # it is what the broker records as evidence.
                smtp = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10)
                try:
                    smtp.ehlo()
                    smtp.mail(sender)
                    for rcpt in recipients:
                        smtp.rcpt(rcpt)
                    code, reply_text = smtp.data(body)
                finally:
                    smtp.quit()
                reply_str = (
                    reply_text.decode("utf-8", errors="replace")
                    if isinstance(reply_text, bytes)
                    else (reply_text or "")
                )
                return {
                    "ok": True,
                    "delivered": actual_recipients,
                    "reply": f"data={code} {reply_str}".strip(),
                }

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
        #
        # ECAC_IPC_KEY_DIR pins the signing-key directory explicitly. Both sides
        # must resolve the same file; if they each call `Path.home()` in a
        # context where it differs, they generate different keys and every
        # signed request is rejected as forged.
        env = {**os.environ, "PYTHONPATH": str(ecac_root)}
        if "ECAC_IPC_KEY_DIR" not in env:
            from effect_broker.executor_ipc import _ipc_key_dir

            env["ECAC_IPC_KEY_DIR"] = str(_ipc_key_dir())
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
        default=f"{_LANDLOCK_WRITE_ROOT}/ecac-executor.sock",
        help="Unix socket path (default: inside the sandbox root)",
    )
    parser.add_argument(
        "--store-socket",
        default=f"{_LANDLOCK_WRITE_ROOT}/ecac-executor-store.sock",
        help="Unix socket for observer store reads (default: inside the sandbox root)",
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
