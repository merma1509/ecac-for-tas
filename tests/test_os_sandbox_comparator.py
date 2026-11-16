"""The OS sandbox comparator actually involves the kernel.

PLAN 6 Part D required the comparator named "conventional sandbox" to either
implement the mechanism or be renamed. The rename produced `PathAllowlist`, which
compares strings and says so. This file covers the other half: a comparator where
a Landlock ruleset or a seatbelt profile really decides the verdict.

The failure mode these tests prevent is the one that made the rename necessary —
a comparator claiming a mechanism while only comparing strings. Every claim below
is checked against an observation:

  - a write inside the workspace is PERMITTED (so the sandbox is not merely
    denying everything, which would satisfy the deny tests while measuring
    nothing);
  - a write outside it is DENIED with EACCES, by the kernel;
  - a planted credential cannot be read;
  - the reported `mechanism` names something real, or "none" when the host
    cannot confine — never a claim of confinement that was not observed.

These are regression tests on supplied traces, not a causal evaluation of
sandbox effectiveness against adaptive attackers.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import warnings

import pytest

from effect_broker.baselines.mode_os_sandbox import (
    MECHANISMS,
    NOT_IMPLEMENTED,
    OSSandboxBroker,
    probe_access,
    reset_selftest_cache,
    selftest,
)
from effect_broker.model import Effect

warnings.filterwarnings("ignore")


def _effect(etype: str, target: str) -> Effect:
    """Build an Effect with the fields the dataclass requires.

    The comparator never reads provenance, the nonce or the delegation chain —
    that blindness is exactly what its table declares — but the dataclass
    requires them, so a benign default keeps the tests focused on file access.
    """
    return Effect(
        etype=etype,
        target=target,
        metadata={},
        provenance=(),
        capability_nonce="r-sandbox:Agent",
        delegation_chain=(),
    )


#: A host is expected to confine on Linux (Landlock) or macOS (seatbelt). If it
#: cannot, tests that require confinement are skipped rather than silently
#: passing, so an unconfined run is never mistaken for a green one.
_HOST_CAN_CONFINE = selftest().verified

requires_confinement = pytest.mark.skipif(
    not _HOST_CAN_CONFINE,
    reason=(
        "host cannot confine: no Landlock on this kernel and no seatbelt. "
        "The comparator reports mechanism='none' here by design."
    ),
)


class TestMechanismIsReal:
    """The sandbox must be observed working, not merely requested."""

    def test_available_sandbox_must_pass_its_own_selftest(self) -> None:
        """If the host HAS a sandbox tool, a failed self-test is a defect, not a skip.

        This test exists because of a near miss. When a read-deny was widened to
        cover the whole fixture root, it also hid the probe script the confined
        child must read to start; the self-test then observed no confinement and
        every `requires_confinement` test SKIPPED, leaving a green suite over a
        broken comparator. Skips are right for a host that genuinely lacks a
        sandbox, but not for one that has `sandbox-exec` and fails to use it.

        Only macOS is asserted: its tool presence is a simple PATH lookup. On
        Linux, Landlock availability is a kernel version question rather than a
        binary one, so an unconfined run there stays a skip instead of being
        guessed at.
        """
        if sys.platform != "darwin":
            pytest.skip("sandbox-exec is macOS-only, so only there is presence checkable")
        if shutil.which("sandbox-exec") is None:
            pytest.skip("sandbox-exec is not installed on this host")

        probe = selftest()
        assert probe.verified is True, (
            "sandbox-exec is installed but the self-test observed no confinement — "
            f"the comparator is broken, not unsupported: {probe.self_test}"
        )
        assert probe.mechanism == "seatbelt", f"expected seatbelt on macOS, got {probe.mechanism!r}"

    @requires_confinement
    def test_selftest_reports_a_named_mechanism(self) -> None:
        """A verified sandbox names the mechanism that was actually in effect."""
        probe = selftest()
        assert probe.verified is True
        assert probe.mechanism in ("landlock", "seatbelt"), (
            f"unexpected mechanism {probe.mechanism!r}: a verified self-test must "
            f"name a real kernel mechanism"
        )

    @requires_confinement
    def test_selftest_observed_both_directions(self) -> None:
        """Confining is only claimed when allow and deny were both observed.

        A profile that denied everything would satisfy the deny checks while
        being useless, so "write inside succeeded" is not optional.
        """
        observations = selftest().self_test
        assert observations["write_inside_allowed"] is True, (
            "the sandbox denied a write inside its own writable root — it is not "
            f"confining, it is broken: {observations}"
        )
        assert observations["write_outside_denied"] is True, (
            f"the sandbox permitted a write outside its root: {observations}"
        )
        assert observations["secret_read_denied"] is True, (
            f"the sandbox permitted reading a planted credential: {observations}"
        )

    def test_mechanism_none_implies_not_verified(self) -> None:
        """An unusable sandbox reports itself as absent, never as passing."""
        probe = selftest()
        if probe.mechanism == "none":
            assert probe.verified is False, (
                "mechanism 'none' must never be reported as verified confinement"
            )

    def test_cache_can_be_discarded(self) -> None:
        """A stable host property is memoised, but a test can force a re-probe."""
        first = selftest()
        reset_selftest_cache()
        try:
            second = selftest()
            assert second.verified == first.verified
            assert second.mechanism == first.mechanism
        finally:
            reset_selftest_cache()


class TestKernelDecidesTheVerdict:
    """The verdict comes from attempting the operation, not from a string check."""

    @requires_confinement
    def test_write_inside_workspace_is_permitted(self) -> None:
        """The comparator is not trivially correct: workspace writes go through.

        Without this the baseline would block every trace and any comparison
        against it would measure a broken configuration instead of a mechanism.
        """
        broker = OSSandboxBroker()
        try:
            effect = _effect("write", "file:///safe.txt")
            allowed, evidence = broker.commit_effect(effect)
            assert allowed is True, f"workspace write was denied: {evidence}"
            assert evidence["mechanism"] in ("landlock", "seatbelt")
            assert "kernel-permitted" in evidence["reason"]
        finally:
            broker.close()

    @requires_confinement
    def test_write_to_protected_path_is_denied_by_the_kernel(self) -> None:
        """A write to /secrets is refused by the kernel, with EACCES."""
        broker = OSSandboxBroker()
        try:
            effect = _effect("write", "file:///secrets")
            allowed, evidence = broker.commit_effect(effect)
            assert allowed is False, f"protected write was permitted: {evidence}"
            # The refusal code differs by mechanism (seatbelt: EPERM,
            # Landlock: EACCES), so assert on the refusal itself. Naming one
            # fixed code in the assertion would re-introduce the inaccuracy the
            # module was fixed to avoid.
            assert "kernel-denied" in evidence["reason"], (
                f"a deny must cite a kernel refusal, not a policy string: {evidence}"
            )
            assert evidence["errno"] in (1, 13), (
                f"expected EPERM(1) or EACCES(13), got {evidence['errno']}"
            )
            assert evidence["verified"] is True
        finally:
            broker.close()

    @requires_confinement
    def test_read_of_protected_secret_is_denied(self) -> None:
        """Reading /secrets is refused, which is the confidentiality direction.

        Reusing a write probe for a read would report this as permitted and hide
        the exfiltration path the traces describe.
        """
        broker = OSSandboxBroker()
        try:
            effect = _effect("read", "file:///secrets")
            allowed, evidence = broker.commit_effect(effect)
            assert allowed is False, f"secret read was permitted: {evidence}"
            assert "kernel-denied" in evidence["reason"], (
                f"a deny must cite a kernel refusal: {evidence}"
            )
        finally:
            broker.close()

    @requires_confinement
    def test_absent_target_is_not_reported_as_a_denial(self) -> None:
        """ENOENT is absence, not confinement, and must not be credited as a block."""
        broker = OSSandboxBroker()
        try:
            effect = _effect("read", "file:///../../../../etc/passwd")
            allowed, evidence = broker.commit_effect(effect)
            assert allowed is True, f"a missing file was reported as a sandbox denial: {evidence}"
            assert "target-absent" in evidence["reason"] or "permitted" in evidence["reason"]
        finally:
            broker.close()


class TestBlindSpotsAreReal:
    """What the sandbox cannot see, it must not pretend to see."""

    @requires_confinement
    def test_non_file_effects_are_permitted(self) -> None:
        """A file sandbox holds no opinion about sends or network egress.

        This is the finding, not a defect: the sandbox is blind to recipients,
        provenance and freshness, so it permits exfiltration by email.
        """
        broker = OSSandboxBroker()
        try:
            for effect in (
                _effect("send", "mailto:attacker@evil.com"),
                _effect("network", "http://169.254.169.254/"),
            ):
                allowed, evidence = broker.commit_effect(effect)
                assert allowed is True, f"{effect.etype} should be permitted: {evidence}"
                assert "not-constrained-by-file-sandbox" in evidence["reason"]
        finally:
            broker.close()

    @requires_confinement
    def test_same_path_repeated_is_not_seen_as_a_replay(self) -> None:
        """The sandbox has no state: two identical writes both pass.

        Replay detection needs a ledger. Permitting the second write is the
        honest result, and the reason ECAC keeps one.
        """
        broker = OSSandboxBroker()
        try:
            effect = _effect("write", "file:///audit_test.txt")
            first, _ = broker.commit_effect(effect)
            second, _ = broker.commit_effect(effect)
            assert first is True and second is True, (
                "a stateless sandbox repeating a permitted write must still permit it"
            )
        finally:
            broker.close()


class TestHonestReporting:
    """The comparator must describe itself accurately."""

    def test_declared_mechanisms_name_kernel_enforcement(self) -> None:
        """A comparator claiming enforced mechanisms must name them."""
        assert MECHANISMS, "MECHANISMS must name what is enforced"
        assert any("kernel-enforced" in m for m in MECHANISMS), (
            "the distinguishing claim of this comparator is kernel enforcement"
        )

    def test_declared_omissions_name_the_blind_spots(self) -> None:
        """The omissions must include the properties the traces turn on."""
        joined = " ".join(NOT_IMPLEMENTED).lower()
        for expected in ("dataflow", "recipient", "replay", "ledger"):
            assert expected in joined, (
                f"NOT_IMPLEMENTED should disclose the {expected!r} blind spot"
            )

    def test_comparator_is_registered_and_evaluated(self) -> None:
        """It participates in the comparison on the same traces as ECAC."""
        from effect_broker.baselines import COMPARATOR_MECHANISMS, run_comparison

        results = run_comparison()
        assert "OS_Sandbox" in results
        assert len(results["OS_Sandbox"]) == len(results["ECAC"])
        assert "OS_Sandbox" in COMPARATOR_MECHANISMS, (
            "an undocumented comparator is one whose numbers cannot be read"
        )

    @requires_confinement
    def test_comparator_is_not_trivially_correct(self) -> None:
        """It blocks some traces and permits others: a mechanism, not a wall."""
        from effect_broker.baselines import run_comparison

        traces = run_comparison()["OS_Sandbox"]
        blocked = [t["name"] for t in traces if t["blocked"]]
        permitted = [t["name"] for t in traces if not t["blocked"]]
        assert blocked, "a real sandbox blocks at least the protected-path writes"
        assert permitted, (
            "the sandbox blocked every trace, which means the fixture is "
            "misconfigured rather than that the mechanism is strong"
        )

    @requires_confinement
    def test_denial_names_the_code_the_kernel_actually_returned(self) -> None:
        """The refusal reason must quote the observed errno, not a fixed one.

        seatbelt returns EPERM and Landlock returns EACCES. An earlier version
        hard-coded "EACCES" in the reason, so on macOS every report misdescribed
        the mechanism. This test fails if a fixed code is written back in, which
        the other tests do not catch: they only check that a refusal happened.
        """
        from effect_broker.baselines.mode_os_sandbox import _errno_name

        broker = OSSandboxBroker()
        try:
            _, evidence = broker.commit_effect(_effect("write", "file:///secrets"))
            observed = evidence["errno"]
            expected_name = _errno_name(observed)
            assert expected_name in evidence["reason"], (
                f"reason does not quote the observed code: errno={observed} "
                f"({expected_name}) but reason is {evidence['reason']!r}"
            )
        finally:
            broker.close()

    @requires_confinement
    def test_refusal_is_not_caused_by_the_target_being_a_directory(self) -> None:
        """A denial must come from the sandbox, not from a filesystem accident.

        An earlier version mapped `/secrets` onto the protected DIRECTORY, so the
        write failed with EISDIR. That looks like a block but would happen on any
        filesystem with no sandbox at all — the comparison would credit the
        kernel with a refusal it never made. Asserting only "it was denied"
        cannot tell the two apart, hence the errno check.
        """
        broker = OSSandboxBroker()
        try:
            mapped = broker._map_target("file:///secrets")
            assert mapped is not None
            assert not os.path.isdir(mapped), (
                f"a protected write target resolved to a directory ({mapped}): the "
                f"resulting refusal would be EISDIR, not confinement"
            )
            _, evidence = broker.commit_effect(_effect("write", "file:///secrets"))
            assert evidence["errno"] != 21, (
                "denied with EISDIR — that is the target being a directory, not "
                f"the sandbox refusing: {evidence}"
            )
        finally:
            broker.close()

    def test_errno_table_covers_both_mechanisms(self) -> None:
        """Both mechanisms' refusal codes are named, so neither is a guess.

        This half needs no sandbox: it pins the table the reason is built from.
        """
        from effect_broker.baselines.mode_os_sandbox import _errno_name

        assert _errno_name(1) == "EPERM", "seatbelt refuses with EPERM"
        assert _errno_name(13) == "EACCES", "Landlock refuses with EACCES"
        # An unmapped number is reported as a number rather than invented.
        assert "9999" in _errno_name(9999), "an unknown errno must not be given a fabricated name"

    def test_traversal_cannot_escape_into_the_writable_area(self) -> None:
        """A traversal target must not map back into the writable subtree."""
        broker = OSSandboxBroker()
        try:
            mapped = broker._map_target("file:///../../../secrets")
            assert mapped is not None, "a traversal target should still map somewhere"
            assert os.path.abspath(mapped).startswith(os.path.abspath(broker._protected)), (
                f"traversal resolved outside the protected area: {mapped}"
            )
        finally:
            broker.close()


class TestFixtureCleanup:
    """A comparator that leaks directories is unusable in a test suite."""

    def test_close_removes_the_fixture(self) -> None:
        """Closing the broker removes the workspace it created."""
        broker = OSSandboxBroker()
        root = broker._root
        assert os.path.isdir(root)
        broker.close()
        assert not os.path.exists(root), f"fixture leaked: {root}"

    def test_close_is_idempotent(self) -> None:
        """Calling close twice must not raise."""
        broker = OSSandboxBroker()
        broker.close()
        broker.close()

    def test_externally_supplied_workspace_is_not_deleted(self) -> None:
        """A caller's directory is not ours to remove."""
        external = tempfile.mkdtemp(prefix="ecac-external-ws-")
        try:
            broker = OSSandboxBroker(workspace=external)
            broker.close()
            assert os.path.isdir(external), "the broker deleted a workspace it did not create"
        finally:
            shutil.rmtree(external, ignore_errors=True)


class TestUnsupportedHost:
    """On a host without a sandbox the comparator reports absence, not a score."""

    def test_missing_mechanism_blocks_nothing(self) -> None:
        """With mechanism 'none' every effect is permitted and marked unverified."""
        if _HOST_CAN_CONFINE:
            pytest.skip("this host can confine; the absent-mechanism path is not taken")
        broker = OSSandboxBroker()
        try:
            effect = _effect("write", "file:///secrets")
            allowed, evidence = broker.commit_effect(effect)
            assert allowed is True, (
                "without a mechanism nothing may be blocked: claiming a deny here "
                "would manufacture protection that was never observed"
            )
            assert evidence["verified"] is False
            assert evidence["mechanism"] == "none"
        finally:
            broker.close()


@pytest.mark.skipif(sys.platform not in ("linux", "darwin"), reason="no sandbox path")
class TestProbeHelper:
    """`probe_access` is the single point where the kernel is asked."""

    @requires_confinement
    def test_probe_reports_kernel_refusal(self) -> None:
        """A denied probe carries the kernel refusal code for this platform."""
        root = tempfile.mkdtemp(prefix="ecac-probe-test-")
        try:
            writable = os.path.join(root, "ws")
            protected = os.path.join(root, "protected")
            os.makedirs(writable)
            os.makedirs(protected)
            probe = probe_access("write", os.path.join(protected, "x"), writable, (protected,))
            assert probe.allowed is False
            # EPERM(1) from seatbelt, EACCES(13) from Landlock: both are a
            # kernel refusal, and which one arrives is the platform's answer.
            assert probe.errno in (1, 13), f"expected a kernel refusal (1 or 13), got {probe.errno}"
        finally:
            shutil.rmtree(root, ignore_errors=True)

    @requires_confinement
    def test_probe_permits_a_write_in_the_writable_root(self) -> None:
        """The same helper permits a write it should permit, so a deny means something."""
        root = tempfile.mkdtemp(prefix="ecac-probe-test-")
        try:
            writable = os.path.join(root, "ws")
            os.makedirs(writable)
            probe = probe_access("write", os.path.join(writable, "ok"), writable, ())
            assert probe.allowed is True, f"unexpected denial: {probe.self_test}"
            assert os.path.exists(os.path.join(writable, "ok")), (
                "the probe reported success but created nothing"
            )
        finally:
            shutil.rmtree(root, ignore_errors=True)
