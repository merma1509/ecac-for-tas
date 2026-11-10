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
    """A ruleset that was accepted but not applied must not read as success."""

    def test_probe_passes_when_a_writable_path_is_denied(self) -> None:
        """Denial at a path we demonstrably could write is the accepted signal."""
        with (
            mock.patch("os.access", return_value=True),
            mock.patch("os.open", side_effect=PermissionError("denied")),
        ):
            assert sub._selftest_confinement() is True

    def test_probe_fails_when_the_write_succeeds(self) -> None:
        """If the probe write lands, confinement is not in effect."""
        assert sub._selftest_confinement() is False

    def test_probe_ignores_denials_that_are_not_confinement(self) -> None:
        """EACCES at a path the process could not write anyway proves nothing.

        This is the bug the first version of the probe had: it wrote to `/etc`,
        where permission is denied on any ordinary host, and read the denial as
        evidence of Landlock.
        """
        with mock.patch("os.access", return_value=False):
            assert sub._selftest_confinement() is False, (
                "a path that is not writable regardless of confinement must not "
                "be treated as proof of confinement"
            )

    def test_probe_is_not_run_inside_the_write_root(self) -> None:
        """Probing inside the permitted root would be allowed by design."""
        observed: list[str] = []

        def record_access(path: str, mode: int) -> bool:
            observed.append(path)
            return True

        with (
            mock.patch.dict("os.environ", {"ECAC_LANDLOCK_WRITE_ROOT": "/tmp"}),
            mock.patch("os.access", side_effect=record_access),
            mock.patch("os.open", side_effect=PermissionError("denied")),
            mock.patch.object(sub, "_LANDLOCK_WRITE_ROOT", "/tmp"),
        ):
            sub._selftest_confinement()
        write_root = sub._LANDLOCK_WRITE_ROOT
        assert not [p for p in observed if p == write_root or p.startswith(write_root + "/")], (
            f"probe looked inside the write root: {observed}"
        )

    def test_probe_leaves_no_file_behind(self, tmp_path) -> None:
        """A successful probe write is cleaned up rather than left on disk."""
        probe_dir = str(tmp_path)
        with (
            mock.patch("os.access", return_value=True),
            mock.patch.object(sub.tempfile, "gettempdir", return_value=probe_dir),
        ):
            assert sub._selftest_confinement() is False
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
        """A True result must be backed by the selftest, never by a bare return."""
        result = sub._apply_landlock_sandbox()
        if result:
            assert sub._confinement_is_kernel_enforced()

    def test_rule_beneath_constant_is_distinct(self) -> None:
        """The rule type must be PATH_BENEATH, not the restrict-self command."""
        assert sub._LANDLOCK_RULE_PATH_BENEATH == 1
        assert sub._SYS_LANDLOCK_ADD_RULE != sub._SYS_LANDLOCK_RESTRICT_SELF

    def test_handled_access_filters_by_abi(self) -> None:
        """A flag newer than the kernel's ABI must not be requested."""
        v1 = sub._landlock_handled_access(1)
        assert v1 & sub._LANDLOCK_ACCESS_FS_WRITE_FILE
        assert not (v1 & (1 << 13)), "ABI v1 must not ask for a v2+ flag"
