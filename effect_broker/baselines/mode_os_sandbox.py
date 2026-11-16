"""OS sandbox comparator — the kernel actually enforces the boundary.

Unlike `mode_path_allowlist.py`, which compares strings on `effect.target` and
never involves the kernel, this comparator runs the operation in a real OS
sandbox:

- **Linux**: a Landlock ruleset, applied by a throwaway child rather than the
  long-lived executor.
- **macOS**: a seatbelt profile (`sandbox-exec`).

The point of a comparator is to answer "what does a conventional sandbox buy
you, and what does it not?" — so the claim has to be checkable. Every report
carries `mechanism`, naming what was actually in effect, and `verified`, which
is True only after a self-test observed both directions:

  1. a write INSIDE the sandbox root succeeds, and
  2. a write OUTSIDE it is refused by the kernel, and
  3. a read of a planted secret is refused by the kernel.

The refusal code differs by mechanism — seatbelt returns EPERM, Landlock returns
EACCES — so reports name the number that was actually observed rather than
assuming one.

A ruleset that denies everything would satisfy (2) and (3) while being useless,
which is why (1) is not optional. A sandbox that cannot pass its own self-test
is reported as `mechanism="none"` with `verified=False` and blocks nothing:
claimed confinement that was never observed is the defect this file exists to
avoid.

**What a conventional sandbox does not do**, and this comparator therefore does
not either: no capability system, no dataflow tracking, no notion of who the
recipient is, no replay state, no ledger. A write inside the sandbox root is
permitted whether or not it leaks a secret; a send is permitted whether or not
the body was approved. That blindness is the real, measurable finding — it is
not simulated here.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from effect_broker.model import Effect

#: What this comparator actually enforces, quoted into the comparison table.
MECHANISMS: tuple[str, ...] = (
    "kernel-enforced write confinement (Landlock on Linux, seatbelt on macOS)",
    "write INSIDE the sandbox root succeeds (self-test, both directions)",
    "write OUTSIDE the sandbox root refused by the kernel (EPERM or EACCES)",
    "planted-secret read refused by the kernel (EPERM or EACCES)",
)

#: What it deliberately does not do. Documented rather than discovered.
NOT_IMPLEMENTED: tuple[str, ...] = (
    "capability system — any write inside the root is allowed",
    "IFC / dataflow tracking / session taint",
    "recipient (BCC) scoping — a send is a send once the socket is open",
    "content binding — the approved body is not compared with the sent body",
    "freshness / replay check — no state across effects",
    "ledger / independent observation",
    "approval binding across processes",
)

#: Subtree (under the fixture root) the workload may write into.
_WRITABLE_SUBDIR = "ws"

#: Subtree (under the fixture root) holding what the sandbox must protect. Kept
#: beside the writable one so a deny is a genuine cross-directory deny.
_PROTECTED_SUBDIR = "protected"

#: First path component that marks a location as protected. `/secrets` is where
#: the traces put credentials, so it maps into the protected subtree.
_PROTECTED_NAMES = frozenset({"secrets"})

#: Files the fixture places inside the workspace. These are the trace targets a
#: real deployment would treat as the workload's own working files, so a
#: sandbox that denied writes to them would be measuring a misconfigured sandbox
#: rather than a sandbox.
_WORKSPACE_FILES = ("safe.txt", "audit_test.txt", "cross-task.txt")

#: Directories the workspace creates. `reports` is a trace write target.
_WORKSPACE_DIRS = ("reports",)

#: Kernel refusal codes a sandbox returns, by number.
#:
#: The two mechanisms do not refuse alike: seatbelt returns EPERM (1) and
#: Landlock returns EACCES (13). Reporting a fixed "EACCES" would be wrong on
#: macOS, so the name is taken from the observed number instead.
_ERRNO_NAMES: dict[int, str] = {
    1: "EPERM",
    2: "ENOENT",
    13: "EACCES",
    20: "ENOTDIR",
    21: "EISDIR",
    30: "EROFS",
}


def _errno_name(number: object) -> str:
    """Name for a kernel error number, or the number itself when unknown."""
    if isinstance(number, int):
        return _ERRNO_NAMES.get(number, f"errno={number}")
    return "unknown-errno"


#: Memoised self-test result. `None` means "not yet probed". Whether this host
#: can confine does not change within a process, so probing once is enough;
#: `reset_selftest_cache()` exists so a test can force a fresh observation.
_SELFTEST_CACHE: SandboxProbe | None = None


def reset_selftest_cache() -> None:
    """Discard the memoised self-test so the next call re-probes the host."""
    global _SELFTEST_CACHE
    _SELFTEST_CACHE = None


def _build_workspace(root: str) -> str:
    """Materialise the workload's writable directory under `root`.

    Returns the workspace path. A fixture rather than an empty directory because
    a trace writing to `file:///safe.txt` has to land somewhere: without the file
    already present the probe measures directory existence, not confinement.
    """
    workspace = os.path.join(root, _WRITABLE_SUBDIR)
    os.makedirs(workspace, exist_ok=True)
    for name in _WORKSPACE_FILES:
        path = os.path.join(workspace, name)
        if not os.path.exists(path):
            with open(path, "w") as fh:
                fh.write("workspace file\n")
    for name in _WORKSPACE_DIRS:
        os.makedirs(os.path.join(workspace, name), exist_ok=True)
    # The protected area exists and holds a credential. It is created OUTSIDE
    # the writable root so that a deny is a genuine cross-directory deny.
    protected = os.path.join(root, _PROTECTED_SUBDIR)
    os.makedirs(protected, exist_ok=True)
    secret = os.path.join(protected, "id_rsa")
    if not os.path.exists(secret):
        with open(secret, "w") as fh:
            fh.write("planted-credential")
    return workspace


@dataclass
class SandboxProbe:
    """Result of running one operation under the sandbox.

    `mechanism` is what was actually in effect, never what was requested:
    "landlock", "seatbelt", or "none". `verified` is True only when the
    self-test observed the sandbox working in both directions.
    """

    allowed: bool
    mechanism: str
    verified: bool
    errno: int | None = None
    detail: str = ""
    self_test: dict[str, object] = field(default_factory=dict)
    absent: bool = False


def _seatbelt_profile(write_root: str, deny_read_roots: tuple[str, ...]) -> str:
    """Build a seatbelt profile confining writes to `write_root`.

    `deny` clauses win over `allow` regardless of order in seatbelt, so the
    denies are absolute. Paths must go through `realpath`: on macOS `/tmp` is a
    symlink to `/private/tmp` and seatbelt matches the resolved path, which is
    why an unresolved root silently fails to match and the sandbox then appears
    to deny nothing.
    """
    lines = [
        "(version 1)",
        "(allow default)",
        # Writes: deny everywhere, then re-open the sandbox root only. The /dev
        # entries are what a Python child needs in order to start and to print.
        "(deny file-write*)",
        f'(allow file-write* (subpath "{write_root}"))',
        '(allow file-write* (literal "/dev/null"))',
        '(allow file-write* (literal "/dev/stdout"))',
        '(allow file-write* (literal "/dev/stderr"))',
    ]
    for root in deny_read_roots:
        lines.append(f'(deny file-read* (subpath "{root}"))')
    return "\n".join(lines) + "\n"


#: Python source for a child that applies Landlock to itself, then probes.
#:
#: Landlock restricts only the calling process, so a parent cannot apply it on a
#: child's behalf: after fork+exec the restriction belongs to whoever asked for
#: it. The child therefore applies the ruleset and touches the file in the same
#: process.
_LANDLOCK_LAUNCHER = r'''
import ctypes, ctypes.util, json, os, sys

SYS_CREATE_RULESET, SYS_ADD_RULE, SYS_RESTRICT_SELF = 444, 445, 446
CREATE_VERSION_FLAG, RULE_PATH_BENEATH = 1 << 0, 1
FS_WRITE_FILE, FS_READ_FILE, FS_MAKE_REG = 1 << 1, 1 << 2, 1 << 8
PR_SET_NO_NEW_PRIVS = 38


def apply_ruleset(write_root):
    """Return the mechanism name on success, None when the kernel refuses."""
    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    libc.syscall.restype = ctypes.c_long
    abi = libc.syscall(
        SYS_CREATE_RULESET, None, ctypes.c_size_t(0), ctypes.c_uint32(CREATE_VERSION_FLAG)
    )
    if abi < 0:
        return None

    handled = FS_WRITE_FILE | FS_READ_FILE | FS_MAKE_REG

    class RulesetAttr(ctypes.Structure):
        _fields_ = [("handled_access_fs", ctypes.c_uint64)]

    class PathBeneath(ctypes.Structure):
        _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]

    attr = RulesetAttr(handled_access_fs=handled)
    ruleset_fd = libc.syscall(
        SYS_CREATE_RULESET, ctypes.byref(attr), ctypes.sizeof(attr), 0
    )
    if ruleset_fd < 0:
        return None

    o_path = getattr(os, "O_PATH", 0)
    root_fd = os.open(write_root, o_path | os.O_CLOEXEC)
    try:
        pb = PathBeneath(allowed_access=handled, parent_fd=root_fd)
        added = libc.syscall(
            SYS_ADD_RULE, ruleset_fd, RULE_PATH_BENEATH, ctypes.byref(pb), 0
        )
        if added < 0:
            return None
    finally:
        os.close(root_fd)
    os.close(ruleset_fd)

    # restrict_self needs NO_NEW_PRIVS first, else EPERM. It takes FLAGS, not
    # the ruleset fd — passing the fd is the classic form of this bug.
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        return None
    if libc.syscall(SYS_RESTRICT_SELF, 0) != 0:
        return None
    return "landlock"


def main():
    mode, path, root = sys.argv[1], sys.argv[2], sys.argv[3]
    mechanism = apply_ruleset(root)
    if mechanism is None:
        print(json.dumps({"ok": None, "mechanism": "none"}))
        return
    try:
        if mode == "write":
            os.close(os.open(path, os.O_CREAT | os.O_WRONLY | os.O_CLOEXEC, 0o600))
        else:
            open(path, "rb").close()
        print(json.dumps({"ok": True, "mechanism": mechanism}))
    except PermissionError as exc:
        print(json.dumps({"ok": False, "mechanism": mechanism, "errno": exc.errno}))
    except OSError as exc:
        print(json.dumps({"ok": False, "mechanism": mechanism, "errno": exc.errno,
                          "type": type(exc).__name__}))


main()
'''

#: Python source for the seatbelt child. Written to a file rather than passed as
#: `-c` so the profile need not allow the code string through argv.
_SEATBELT_PROBE = r"""
import json, os, sys

mode, path = sys.argv[1], sys.argv[2]
try:
    if mode == "write":
        os.close(os.open(path, os.O_CREAT | os.O_WRONLY, 0o600))
    else:
        open(path, "rb").close()
    print(json.dumps({"ok": True, "mechanism": "seatbelt"}))
except PermissionError as exc:
    print(json.dumps({"ok": False, "mechanism": "seatbelt", "errno": exc.errno}))
except OSError as exc:
    print(json.dumps({"ok": False, "mechanism": "seatbelt", "errno": exc.errno,
                      "type": type(exc).__name__}))
"""


def _parse_last_json(stdout: str, stderr: str) -> dict[str, object]:
    """Return the last JSON object a probe child printed.

    Scanned in reverse because the interpreter or a library may print to stdout
    before the probe's own line; the last object is the probe's answer.
    """
    for line in reversed(stdout.strip().splitlines()):
        candidate = line.strip()
        if not candidate.startswith("{"):
            continue
        try:
            parsed: dict[str, object] = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        return parsed
    return {
        "ok": None,
        "mechanism": "none",
        "detail": f"no-json(stderr={stderr.strip()[:200]})",
    }


def _run_confined(mode: str, path: str, root: str, deny_read: tuple[str, ...]) -> dict[str, object]:
    """Run one probe under the best sandbox this host offers.

    Returns the probe's parsed JSON. A failure to build or start the sandbox
    yields `{"ok": None, "mechanism": "none"}` instead of raising: a comparator
    that raises would be skipped by the caller, and an unevaluated comparator
    silently reads as "no difference found".
    """
    real_root = os.path.realpath(root)
    real_path = os.path.realpath(path)

    if sys.platform == "linux":
        script = os.path.join(real_root, ".landlock_probe.py")
        try:
            with open(script, "w") as fh:
                fh.write(_LANDLOCK_LAUNCHER)
            proc = subprocess.run(
                [sys.executable, script, mode, real_path, real_root],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return {"ok": None, "mechanism": "none", "detail": f"launch-failed:{exc}"}
        finally:
            if os.path.exists(script):
                os.unlink(script)
        return _parse_last_json(proc.stdout, proc.stderr)

    if sys.platform == "darwin":
        if shutil.which("sandbox-exec") is None:
            return {"ok": None, "mechanism": "none", "detail": "sandbox-exec not found"}
        profile_path = os.path.join(real_root, ".seatbelt.sb")
        probe_path = os.path.join(real_root, ".seatbelt_probe.py")
        try:
            with open(profile_path, "w") as fh:
                fh.write(_seatbelt_profile(real_root, deny_read))
            with open(probe_path, "w") as fh:
                fh.write(_SEATBELT_PROBE)
            proc = subprocess.run(
                [
                    "sandbox-exec",
                    "-f",
                    profile_path,
                    sys.executable,
                    probe_path,
                    mode,
                    real_path,
                ],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return {"ok": None, "mechanism": "none", "detail": f"launch-failed:{exc}"}
        finally:
            for leftover in (profile_path, probe_path):
                if os.path.exists(leftover):
                    os.unlink(leftover)
        return _parse_last_json(proc.stdout, proc.stderr)

    return {
        "ok": None,
        "mechanism": "none",
        "detail": f"unsupported-platform:{sys.platform}",
    }


def selftest() -> SandboxProbe:
    """Verify the sandbox confines, in both directions.

    `verified` is True only when all three observations hold: a write inside the
    sandbox root succeeds, a write outside it is denied, and a planted secret is
    unreadable. A profile that denies everything satisfies the last two and is
    useless, which is why the first is not optional.

    Result is memoised: whether this host can confine is a property of the host,
    not of the call, and the comparison table is built repeatedly (once per test
    that reads it). Re-probing would spawn three subprocesses per call and turn
    a table lookup into a multi-second operation without measuring anything new.
    """
    global _SELFTEST_CACHE
    if _SELFTEST_CACHE is not None:
        return _SELFTEST_CACHE
    _SELFTEST_CACHE = _run_selftest()
    return _SELFTEST_CACHE


def _run_selftest() -> SandboxProbe:
    """Uncached body of `selftest()`, kept separate for a clean reset in tests."""
    root = tempfile.mkdtemp(prefix="ecac-sbx-")
    try:
        workspace = _build_workspace(root)
        protected = os.path.join(root, _PROTECTED_SUBDIR)
        inside = os.path.join(workspace, "selftest-inside.txt")
        outside = os.path.join(protected, "selftest-outside.txt")
        secret = os.path.join(protected, "id_rsa")

        # Deny only the protected directory. Denying the whole temp root would
        # also hide the probe scripts the confined child must read in order to
        # start, and then every observation would read as "denied" while nothing
        # was being measured.
        deny_read = (os.path.realpath(protected),)

        write_inside = _run_confined("write", inside, workspace, deny_read)
        write_outside = _run_confined("write", outside, workspace, deny_read)
        read_secret = _run_confined("read", secret, workspace, deny_read)

        mechanism = str(write_inside.get("mechanism") or "none")
        self_test: dict[str, object] = {
            "write_inside_allowed": write_inside.get("ok") is True,
            "write_outside_denied": write_outside.get("ok") is False,
            "secret_read_denied": read_secret.get("ok") is False,
            "mechanism": mechanism,
            "write_inside_detail": write_inside,
            "write_outside_detail": write_outside,
            "secret_read_detail": read_secret,
        }
        verified = (
            mechanism != "none"
            and self_test["write_inside_allowed"] is True
            and self_test["write_outside_denied"] is True
            and self_test["secret_read_denied"] is True
        )
        return SandboxProbe(
            allowed=write_inside.get("ok") is True,
            mechanism=mechanism if verified else "none",
            verified=verified,
            detail="" if verified else "self-test failed (see self_test)",
            self_test=self_test,
        )
    finally:
        shutil.rmtree(root, ignore_errors=True)


def probe_access(
    mode: str,
    target_path: str,
    writable_root: str,
    deny_read: tuple[str, ...] = (),
) -> SandboxProbe:
    """Attempt a real `mode` ("write" or "read") on `target_path` under the sandbox.

    The operation is real: the file is created on a permitted write, and the call
    fails with EACCES when the kernel refuses. `writable_root` is the single
    subtree the profile re-opens for writing; `deny_read` lists subtrees it makes
    unreadable as well.

    A missing file is reported distinctly (`absent=True`) rather than as a
    denial: ENOENT says the target is not there, which is not the sandbox
    refusing anything, and conflating the two would credit the kernel with a
    block it did not make.
    """
    result = _run_confined(mode, target_path, writable_root, deny_read)
    mechanism = str(result.get("mechanism") or "none")
    error_number = result.get("errno")
    return SandboxProbe(
        allowed=result.get("ok") is True,
        mechanism=mechanism,
        verified=mechanism != "none",
        errno=error_number if isinstance(error_number, int) else None,
        detail=str(result.get("detail") or ""),
        self_test=result,
        absent=error_number == 2,  # ENOENT
    )


def probe_write(
    target_path: str,
    writable_root: str,
    deny_read: tuple[str, ...] = (),
) -> SandboxProbe:
    """Attempt a real write to `target_path`. Thin alias over `probe_access`."""
    return probe_access("write", target_path, writable_root, deny_read)


class OSSandboxBroker:
    """A conventional OS sandbox as a comparator: kernel-enforced file boundary.

    The deployment shape modelled here is the ordinary one: a per-workload
    workspace is writable and a credential directory beside it is not. That is
    what a seatbelt profile or a Landlock ruleset is actually configured to do —
    allow the work, deny the secrets — so the comparator answers the real
    question rather than a convenient one.

    Consequences, which is the point of including it:

    - a write to a protected path (`/secrets`) is **denied by the kernel**;
    - a write to an ordinary workspace file is **permitted**, whether it is a
      replay (T4), an undeclared side effect (T8), a cross-task write (T10) or a
      TOCTOU swap (T15) — the sandbox has no state with which to notice any of
      that;
    - every non-file effect (send, network, read of a permitted path) is
      permitted, because a file sandbox holds no opinion about recipients,
      provenance or freshness.

    A comparator that blocked every trace would be trivially correct and would
    measure nothing, so the workspace is genuinely writable. If the host cannot
    confine, the mechanism is "none" and nothing is blocked, which the
    comparison table reports as `NO KERNEL SANDBOX ON THIS HOST` rather than as
    a score.
    """

    def __init__(self, workspace: str | None = None) -> None:
        self._owns_workspace = workspace is None
        self._root = workspace or tempfile.mkdtemp(prefix="ecac-sbx-ws-")
        self._writable = os.path.join(self._root, _WRITABLE_SUBDIR)
        self._protected = os.path.join(self._root, _PROTECTED_SUBDIR)
        os.makedirs(self._writable, exist_ok=True)
        os.makedirs(self._protected, exist_ok=True)
        # The protected area holds a credential at the path `/secrets` maps to.
        # It has to exist: a write to a nonexistent parent fails with ENOENT, and
        # an absence is not a sandbox refusal — the comparison would then credit
        # the kernel for a block it never made.
        for name in ("secrets", "id_rsa"):
            entry = os.path.join(self._protected, name)
            if not os.path.exists(entry):
                with open(entry, "w") as handle:
                    handle.write("planted-credential")
        self._selftest = selftest()

    def close(self) -> None:
        """Remove the temporary workspace, if this broker created it."""
        if self._owns_workspace:
            shutil.rmtree(self._root, ignore_errors=True)

    @property
    def verified(self) -> bool:
        """True only if the sandbox was observed to confine in both directions."""
        return self._selftest.verified

    @property
    def mechanism(self) -> str:
        """What was actually enforced: "landlock", "seatbelt", or "none"."""
        return self._selftest.mechanism

    def _map_target(self, target: str) -> str | None:
        """Resolve an effect target to a path inside this workspace.

        A protected path (`/secrets`, and anything beneath it) maps beside the
        writable subtree so the profile's deny rule covers it. Everything else
        maps into the writable subtree, which is where a workload's own files
        live. Returns None for targets that are not file paths.
        """
        if not target.startswith("file://"):
            return None
        raw = target[len("file://") :]
        if not raw:
            return None
        # Normalise traversal before mapping: resolving `..` after the fact
        # would let an escape out of the writable subtree, and the comparison
        # would then credit the kernel for something it never prevented.
        normalised = os.path.normpath("/" + raw.lstrip("/"))
        parts = [p for p in normalised.split("/") if p and p != "."]
        if not parts:
            return None
        # The leaf is always kept, including for a protected name. Mapping
        # `/secrets` onto the protected DIRECTORY itself would make a write fail
        # with EISDIR, and an EISDIR is not confinement — the comparison would
        # then credit the sandbox with a block that any filesystem would have
        # produced. Keeping the leaf makes the refusal come from the profile.
        if parts[0] in _PROTECTED_NAMES:
            return os.path.join(self._protected, *parts)
        return os.path.join(self._writable, *parts)

    def commit_effect(self, effect: Effect, task_id: str = "default") -> tuple[bool, dict]:
        """Decide by asking the kernel, not by comparing strings."""
        if not self._selftest.verified:
            return True, {
                "blocker": None,
                "reason": "no-kernel-sandbox-on-this-host",
                "policy": "OS_Sandbox",
                "mechanism": "none",
                "verified": False,
            }

        mechanism = self._selftest.mechanism

        # A file sandbox rules on file access, so writes, deletes and reads are
        # inside its competence. Sends and network effects are not: it holds no
        # opinion about recipients, provenance or freshness, and simulating a
        # deny there would make this comparator a strawman in the other
        # direction.
        if effect.etype not in ("write", "delete", "read"):
            return True, {
                "blocker": None,
                "reason": f"{effect.etype}-not-constrained-by-file-sandbox",
                "policy": "OS_Sandbox",
                "mechanism": mechanism,
                "verified": True,
            }

        path = self._map_target(effect.target)
        if path is None:
            return True, {
                "blocker": None,
                "reason": "non-file-target-not-constrained",
                "policy": "OS_Sandbox",
                "mechanism": mechanism,
                "verified": True,
            }

        # Reads are tested as reads and writes as writes. Using a write probe for
        # a read would let a profile that protects confidentiality appear to
        # allow the exfiltration path T17 describes.
        #
        # The protected subtree is denied for reads as well as writes: that is
        # how a real profile protects credentials, not merely by stopping them
        # being modified.
        probe_mode = "read" if effect.etype == "read" else "write"
        probe = probe_access(probe_mode, path, self._writable, (os.path.realpath(self._protected),))

        if probe.mechanism == "none":
            # A probe that could not run is not a denial. Reporting it as a block
            # would manufacture protection that was never observed.
            return True, {
                "blocker": None,
                "reason": f"sandbox-probe-unavailable({probe.detail})",
                "policy": "OS_Sandbox",
                "mechanism": "none",
                "verified": False,
            }
        if probe.absent:
            # Nothing is there. Absence is not confinement, so this is reported
            # as permitted-and-absent rather than as a block.
            return True, {
                "blocker": None,
                "reason": f"target-absent(ENOENT, {probe.mechanism})",
                "policy": "OS_Sandbox",
                "mechanism": probe.mechanism,
                "verified": True,
            }
        if probe.allowed:
            return True, {
                "blocker": None,
                "reason": f"kernel-permitted-{probe_mode}({probe.mechanism})",
                "policy": "OS_Sandbox",
                "mechanism": probe.mechanism,
                "verified": True,
            }
        return False, {
            "blocker": "OS_Sandbox",
            # The refusal code is reported as observed: seatbelt yields EPERM and
            # Landlock yields EACCES, so naming a fixed one would misdescribe the
            # mechanism on one of the two platforms.
            "reason": f"kernel-denied-{probe_mode}({_errno_name(probe.errno)}, {probe.mechanism})",
            "policy": "OS_Sandbox",
            "mechanism": probe.mechanism,
            "verified": True,
            "errno": probe.errno,
        }
