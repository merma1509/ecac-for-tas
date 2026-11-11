"""Confinement is reported only when it is in effect

The defect these tests pin: `_apply_landlock_sandbox()` returned True from a
call that passed the ruleset FD where `restrict_self`'s flags argument belongs.
No rule was ever added, and the return value was ignored, yet the process would
have reported `landlock` as an active layer. The claim was about the intent to
confine, not about confinement.

What is asserted here is behaviour, not syscall return values:

- `landlock` appears in the status string only when confinement is enforced;
- on a host with no Landlock, the status says so and never mentions landlock;
- `ECAC_REQUIRE_CONFINEMENT=1` refuses to run instead of degrading silently;
- the selftest detects an unrestricted process rather than trusting a return
  value.

The Landlock syscall path itself cannot be exercised on macOS, so the tests that
need it are marked `linux`. That is deliberate: a green suite on macOS must not
be readable as evidence that kernel confinement works.
"""

from __future__ import annotations

import os
import sys
from unittest import mock

import pytest

from effect_broker import executor_subprocess as sub


class TestConfinementStatusDoesNotLie:
    """The status string is a claim, and it must match reality."""

    def test_status_omits_landlock_when_not_enforced(self) -> None:
        """No `landlock` in the status unless the selftest proved it."""
        if sub._confinement_is_kernel_enforced():
            pytest.skip("Landlock genuinely active here; the negative case cannot be shown")
        assert "landlock" not in sub._get_confinement_status(), (
            "status advertises landlock while confinement is not in effect"
        )

    def test_status_includes_landlock_when_enforced(self) -> None:
        """When enforcement is reported, the status must say `landlock`."""
        with mock.patch.object(sub, "_landlock_active", True):
            assert "landlock" in sub._get_confinement_status()

    def test_status_always_names_the_python_layers(self) -> None:
        """The Python-level wrappers are named whether or not Landlock is on.

        They are hygiene rather than confinement, but a reader has to be able to
        see that they are what is left when no kernel mechanism exists.
        """
        status = sub._get_confinement_status()
        assert "restricted-open" in status
        assert "import-blocking" in status

    def test_kernel_enforced_matches_the_probe(self) -> None:
        """`_confinement_is_kernel_enforced` is the probe result, not a constant."""
        with mock.patch.object(sub, "_landlock_active", True):
            assert sub._confinement_is_kernel_enforced() is True
        with mock.patch.object(sub, "_landlock_active", False):
            assert sub._confinement_is_kernel_enforced() is False


class TestSelftestDetectsAnUnrestrictedProcess:
    """Confinement must be observed BOTH ways, never from one side alone."""

    @staticmethod
    def _patch_probes(*, inside_writable: bool, outside_writable: bool):
        """Patch the two probes so either side can be made to succeed or fail.

        The selftest checks the permitted side first, so a test that only
        controls the outside probe is controlling the wrong thing.

        `_real_os_open` is patched, not `os.open`: the selftest deliberately
        bypasses the Python-level allowlist so that what it measures is the
        kernel ruleset rather than the wrapper.
        """
        import os as _os

        write_dirs = [str(d) for d in sub._LANDLOCK_WRITE_DIRS]

        def fake_open(path, flags, *args, **kwargs):
            raw = str(path)
            is_inside = any(raw == d or raw.startswith(d + _os.sep) for d in write_dirs)
            writable = inside_writable if is_inside else outside_writable
            if not writable:
                raise PermissionError(13, "denied", raw)
            return 3  # a plausible fd; closed below

        return (
            mock.patch("os.path.isdir", return_value=True),
            mock.patch("os.access", return_value=True),
            mock.patch.object(sub, "_real_os_open", side_effect=fake_open),
            mock.patch("os.close"),
            mock.patch("os.unlink"),
            # This class is about the WRITE probe. The read probe is exercised
            # separately in TestReadConfinement, so stub it to a pass here —
            # otherwise these tests measure the stub, not the write logic.
            mock.patch.object(sub, "_read_probe_passes", return_value=True),
        )

    def test_probe_passes_only_when_outside_denied_and_inside_allowed(self) -> None:
        """Both sides, and in the right direction: that is confinement."""
        patches = self._patch_probes(inside_writable=True, outside_writable=False)
        for p in patches:
            p.start()
        try:
            assert sub._selftest_confinement() is True
        finally:
            for p in patches:
                p.stop()

    def test_probe_fails_when_the_outside_write_succeeds(self) -> None:
        """If the outside write lands, confinement is not in effect."""
        patches = self._patch_probes(inside_writable=True, outside_writable=True)
        for p in patches:
            p.start()
        try:
            assert sub._selftest_confinement() is False
        finally:
            for p in patches:
                p.stop()

    def test_probe_fails_when_its_own_sandbox_is_unwritable(self) -> None:
        """Denying everything is not confinement — it is a broken sandbox.

        This is the failure mode a one-sided probe cannot see: a ruleset with
        no rules denies the outside write too, which would read as success
        while the executor cannot write its own temp files.
        """
        patches = self._patch_probes(inside_writable=False, outside_writable=False)
        for p in patches:
            p.start()
        try:
            assert sub._selftest_confinement() is False, (
                "a process confined out of its own sandbox must not report confinement as working"
            )
        finally:
            for p in patches:
                p.stop()

    def test_probe_ignores_denials_that_are_not_confinement(self) -> None:
        """EACCES at a path the process could not write anyway proves nothing.

        This is the bug the first version of the probe had: it wrote to `/etc`,
        where permission is denied on any ordinary host, and read the denial as
        evidence of Landlock.
        """
        with (
            mock.patch.object(sub, "_LANDLOCK_WRITE_DIRS", ("/tmp/ecac-test-root",)),
            mock.patch("os.path.isdir", return_value=True),
            mock.patch("os.access", return_value=False),
            mock.patch.object(sub, "_real_os_open", return_value=3),
            mock.patch("os.close"),
        ):
            assert sub._selftest_confinement() is False, (
                "a path that is not writable regardless of confinement must not "
                "be treated as proof of confinement"
            )

    def test_probe_is_not_run_inside_the_write_root(self) -> None:
        """Probing inside the permitted root would be allowed by design."""
        observed: list[str] = []
        write_root = "/tmp/ecac-test-root"

        def record_access(path: str, mode: int) -> bool:
            observed.append(path)
            return True

        def fake_open(path, flags, *args, **kwargs):
            is_inside = str(path).startswith(write_root + "/")
            if is_inside:
                return 3
            raise PermissionError(13, "denied", str(path))

        with (
            mock.patch("os.path.isdir", return_value=True),
            mock.patch.object(sub, "_LANDLOCK_WRITE_DIRS", (write_root,)),
            mock.patch("os.access", side_effect=record_access),
            mock.patch.object(sub, "_real_os_open", side_effect=fake_open),
            mock.patch("os.close"),
            mock.patch("os.unlink"),
            mock.patch.object(sub, "_read_probe_passes", return_value=True),
        ):
            assert sub._selftest_confinement() is True
        assert not [p for p in observed if p == write_root or p.startswith(write_root + "/")], (
            f"outside probe looked inside the write root: {observed}"
        )

    def test_probe_leaves_no_file_behind(self, tmp_path) -> None:
        """A probe write that succeeds is cleaned up rather than left on disk."""
        probe_dir = str(tmp_path)
        write_root = str(tmp_path / "root")
        import os as _os

        def fake_open(path, flags, *args, **kwargs):
            is_inside = str(path).startswith(write_root + _os.sep)
            if is_inside:
                return 3
            raise PermissionError(13, "denied", str(path))

        with (
            mock.patch.object(sub, "_LANDLOCK_WRITE_DIRS", (write_root,)),
            mock.patch("os.path.isdir", return_value=True),
            mock.patch.object(sub.tempfile, "gettempdir", return_value=probe_dir),
            mock.patch("os.access", return_value=True),
            mock.patch.object(sub, "_real_os_open", side_effect=fake_open),
            mock.patch("os.close"),
            mock.patch.object(sub, "_read_probe_passes", return_value=True),
        ):
            assert sub._selftest_confinement() is True
        assert list(tmp_path.iterdir()) == [], "probe file was not removed"


class TestRequireConfinementFailsClosed:
    """`ECAC_REQUIRE_CONFINEMENT` turns absence into a refusal (P5-2)."""

    def test_default_is_off(self) -> None:
        """Unset means proceed, so local development on macOS still runs."""
        with mock.patch.dict("os.environ", {}, clear=True):
            sub._require_confinement_if_configured()  # must not raise

    @pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes"])
    def test_required_but_absent_refuses(self, value: str) -> None:
        """Required with no kernel mechanism: refuse, do not degrade."""
        env = {"ECAC_REQUIRE_CONFINEMENT": value}
        with (
            mock.patch.dict("os.environ", env, clear=True),
            mock.patch.object(sub, "_landlock_active", False),
            pytest.raises(sub.ConfinementUnavailable) as exc,
        ):
            sub._require_confinement_if_configured()
        assert "kernel confinement" in str(exc.value)

    def test_required_and_present_proceeds(self) -> None:
        """Required and actually enforced: no reason to refuse."""
        with (
            mock.patch.dict("os.environ", {"ECAC_REQUIRE_CONFINEMENT": "1"}, clear=True),
            mock.patch.object(sub, "_landlock_active", True),
        ):
            sub._require_confinement_if_configured()  # must not raise

    def test_refusal_names_the_platform(self) -> None:
        """The error must say where it ran, so the cause is obvious."""
        with (
            mock.patch.dict("os.environ", {"ECAC_REQUIRE_CONFINEMENT": "1"}, clear=True),
            mock.patch.object(sub, "_landlock_active", False),
            pytest.raises(sub.ConfinementUnavailable) as exc,
        ):
            sub._require_confinement_if_configured()
        assert "platform=" in str(exc.value)


@pytest.mark.skipif(sys.platform != "linux", reason="Landlock is Linux-only")
class TestLandlockOnLinux:
    """The syscall path, exercised only where it can be."""

    def test_apply_returns_false_or_selftests(self) -> None:
        """Activation must never report success the selftest did not observe.

        Run in a child process: applying a Landlock ruleset is irreversible, so
        doing it in the test runner would confine pytest itself and every later
        subprocess spawn would fail with EACCES on the interpreter.
        """
        import os
        import subprocess

        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        code = (
            f"import sys; sys.path.insert(0, {repo_root!r})\n"
            "from effect_broker import executor_subprocess as sub\n"
            "r = sub._activate_confinement()\n"
            "print('ACTIVATED', r, 'ENFORCED', sub._confinement_is_kernel_enforced())\n"
        )
        proc = subprocess.run(
            [sys.executable, "-c", code], capture_output=True, text=True, timeout=120
        )
        assert proc.returncode == 0, proc.stderr
        line = next(ln for ln in proc.stdout.splitlines() if ln.startswith("ACTIVATED"))
        activated = line.split()[1]
        enforced = line.split()[3]
        if activated == "True":
            assert enforced == "True", "reported activated without enforcement"

    def test_rule_beneath_constant_is_distinct(self) -> None:
        """The rule type must be PATH_BENEATH, not the restrict-self command."""
        assert sub._LANDLOCK_RULE_PATH_BENEATH == 1
        assert sub._SYS_LANDLOCK_ADD_RULE != sub._SYS_LANDLOCK_RESTRICT_SELF

    def test_handled_access_filters_by_abi(self) -> None:
        """A flag newer than the kernel's ABI must not be requested."""
        v1 = sub._landlock_handled_access(1)
        assert v1 & sub._LANDLOCK_ACCESS_FS_WRITE_FILE
        assert not (v1 & (1 << 13)), "ABI v1 must not ask for a v2+ flag"

    def test_no_new_privs_is_set_before_restrict_self(self) -> None:
        """`restrict_self` is refused with EPERM unless NO_NEW_PRIVS precedes it.

        This is the defect that kept `_landlock_active` False on a kernel that
        implements Landlock: the ruleset was created and the rule added, then
        `restrict_self` failed silently and no restriction was in effect.
        """
        assert sub._PR_SET_NO_NEW_PRIVS == 38


@pytest.mark.skipif(sys.platform != "linux", reason="Landlock is Linux-only")
class TestConfinementIsProvenNotAssumed:
    """a denied path must fail with EACCES *in the confined process*.

    The claim under test is not "we asked the kernel to restrict us" but "the
    restriction is in effect". That can only be shown by a process that is
    actually restricted, so this runs a real subprocess rather than asserting
    against a mock. When the kernel cannot confine (no Landlock, or a container
    that forbids it), the test skips rather than passing on a weaker claim.
    """

    #: Runs in a child that activates confinement the way the executor's `run()`
    #: does, then tries to write outside and inside the sandbox root and reports
    #: what actually happened. Landlock is NOT applied at import time — a sandbox
    #: belongs to the process meant to be sandboxed, not to every importer.
    _PROBE = """
import ctypes, ctypes.util, os, sys
sys.path.insert(0, {root!r})
from effect_broker import executor_subprocess as sub

# Does the kernel implement Landlock at all? If it does, activation failing is
# a defect in our syscall sequence, not an absent feature — and a skip here
# would hide exactly the regression these tests exist to catch.
try:
    _libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    _libc.syscall.restype = ctypes.c_long
    _abi = _libc.syscall(
        sub._SYS_LANDLOCK_CREATE_RULESET, None,
        ctypes.c_size_t(0), ctypes.c_uint32(sub._LANDLOCK_CREATE_RULESET_VERSION),
    )
except OSError:
    _abi = -1
print("KERNEL_ABI", _abi)

if not sub._activate_confinement():
    print("NOT_CONFINED")
    raise SystemExit(0)

# A permitted directory, per the kernel ruleset, and a path outside every one
# of them. /tmp is permitted by default, so the outside probe must not be there.
permitted = sub._LANDLOCK_WRITE_DIRS[0]
outside = os.path.join({outside_dir!r}, "ecac-p5-1-escape.txt")
result = {{}}
try:
    with open(outside, "w") as f:
        f.write("x")
    result["outside"] = "allowed"
    os.unlink(outside)
except PermissionError as exc:
    result["outside"] = "denied"
    result["errno"] = exc.errno

inside = os.path.join(permitted, "p5-1-inside.txt")
try:
    with open(inside, "w") as f:
        f.write("x")
    result["inside"] = "allowed"
    os.unlink(inside)
except PermissionError:
    result["inside"] = "denied"

print("RESULT", result)
"""

    def _run_probe(self, repo_root: str) -> dict | None:
        import subprocess

        proc = subprocess.run(
            [sys.executable, "-c", self._PROBE.format(root=repo_root, outside_dir=repo_root)],
            capture_output=True,
            text=True,
            timeout=120,
        )
        out = proc.stdout.strip()
        assert proc.returncode == 0, f"probe failed: {out}{proc.stderr}"

        abi_line = next((ln for ln in out.splitlines() if ln.startswith("KERNEL_ABI")), None)
        assert abi_line is not None, f"probe reported no ABI: {out}{proc.stderr}"
        kernel_abi = int(abi_line.split()[1])

        if "NOT_CONFINED" in out:
            if kernel_abi >= 1:
                raise AssertionError(
                    f"the kernel implements Landlock (ABI {kernel_abi}) but "
                    f"`_activate_confinement()` failed. This is a defect in the "
                    f"syscall sequence — most likely a missing PR_SET_NO_NEW_PRIVS "
                    f"before restrict_self, which fails with EPERM and leaves the "
                    f"process unconfined while reporting success nowhere. "
                    f"Output: {out}"
                )
            pytest.skip("kernel has no Landlock; confinement cannot be shown here")

        assert "RESULT" in out, f"probe produced no result: {out}{proc.stderr}"
        return eval(out.split("RESULT", 1)[1].strip())  # noqa: S307 — probe-owned literal

    def test_write_outside_the_root_fails_with_eacces(self) -> None:
        """The denied path, observed in a process that is actually confined."""
        import os

        result = self._run_probe(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        assert result is not None
        assert result["outside"] == "denied", (
            "a confined executor wrote outside its sandbox root; the confinement "
            f"claim is unsupported (probe said {result})"
        )
        assert result.get("errno") == 13, (
            f"denial must be EACCES (13), got errno={result.get('errno')}"
        )

    def test_write_inside_the_root_is_allowed(self) -> None:
        """Confinement that also forbids the sandbox is not a working sandbox."""
        import os

        result = self._run_probe(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        assert result is not None
        assert result["inside"] == "allowed", (
            "the confined executor cannot write inside its own sandbox root: "
            "the ruleset denies everything, which is not confinement"
        )


@pytest.mark.skipif(sys.platform != "linux", reason="Landlock is Linux-only")
class TestReadConfinement:
    """Reading a credential must be denied by the kernel, not by convention.

    `_landlock_handled_access()` used to omit READ_FILE, so reads were not
    confined at all: `~/.ssh/id_rsa` opened fine through the real syscall while
    the status still said "landlock". These tests run in a confined child, since
    applying a ruleset to the test runner is irreversible.
    """

    _PROBE = """
import os, sys
sys.path.insert(0, {root!r})
from effect_broker import executor_subprocess as sub

if not sub._activate_confinement():
    print("NOT_CONFINED")
    raise SystemExit(0)

home = {home!r}
result = {{}}

# (1) A legitimate read under a permitted root must keep working.
for read_dir in sub._LANDLOCK_READ_DIRS:
    if not os.path.isdir(read_dir):
        continue
    for name in os.listdir(read_dir):
        candidate = os.path.join(read_dir, name)
        if not os.path.isfile(candidate):
            continue
        try:
            fd = sub._real_os_open(candidate, os.O_RDONLY)
            os.close(fd)
            result["legit_read"] = "allowed"
        except PermissionError:
            result["legit_read"] = "denied"
        break
    if "legit_read" in result:
        break

# (2) A credential-shaped read under home must be denied.
secret = os.path.join(home, ".ssh", "ecac-test-id-rsa")
if os.path.isfile(secret):
    try:
        fd = sub._real_os_open(secret, os.O_RDONLY)
        os.close(fd)
        result["secret_read"] = "allowed"
    except PermissionError as exc:
        result["secret_read"] = "denied"
        result["errno"] = exc.errno

print("RESULT", result)
"""

    def _run(self, repo_root: str, home: str) -> dict:
        import subprocess

        proc = subprocess.run(
            [sys.executable, "-c", self._PROBE.format(root=repo_root, home=home)],
            capture_output=True,
            text=True,
            timeout=120,
        )
        out = proc.stdout.strip()
        assert proc.returncode == 0, f"probe failed: {out}{proc.stderr}"
        if "NOT_CONFINED" in out:
            pytest.skip("kernel has no Landlock; read confinement cannot be shown")
        return eval(out.split("RESULT", 1)[1].strip())  # noqa: S307

    def test_read_file_is_in_the_handled_mask(self) -> None:
        """Without this bit the kernel ignores reads entirely."""
        handled_v1 = sub._landlock_handled_access(1)
        assert handled_v1 & sub._LANDLOCK_ACCESS_FS_READ_FILE, (
            "READ_FILE missing from the handled set: Landlock does not confine "
            "reads at all, so credentials stay readable"
        )

    def test_read_of_a_credential_is_denied(self) -> None:
        """The property item 2 of the review asks for, observed in a child.

        The child keeps the runner's own HOME and the test plants a canary in
        it, for two reasons: the read roots are resolved from the *child's*
        environment, and a home invented under `/tmp` would sit inside a
        permitted write dir and be readable by design, which would read as "not
        confined" while proving nothing.
        """
        home = os.path.expanduser("~")
        canary = os.path.join(home, ".ssh", "ecac-test-id-rsa")
        created_dir = False
        try:
            if not os.path.isdir(os.path.dirname(canary)):
                os.makedirs(os.path.dirname(canary), exist_ok=True)
                created_dir = True
            with open(canary, "w") as handle:
                handle.write("PRIVATE-KEY-MATERIAL")
            os.chmod(canary, 0o600)
            result = self._run(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))), home
            )
        except OSError as exc:
            pytest.skip(f"cannot plant a canary in $HOME ({exc})")
        finally:
            try:
                os.unlink(canary)
            except OSError:
                pass
            if created_dir:
                try:
                    os.rmdir(os.path.dirname(canary))
                except OSError:
                    pass

        assert result.get("secret_read") == "denied", (
            "a confined executor read a private key; read confinement is not in "
            f"effect (probe said {result})"
        )
        assert result.get("errno") == 13, f"expected EACCES, got {result}"

    def test_legitimate_reads_still_work(self) -> None:
        """Read confinement must not confine the executor out of the stdlib."""
        result = self._run(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        )
        assert result.get("legit_read") == "allowed", (
            f"the confined executor cannot read anything: not a usable sandbox ({result})"
        )
