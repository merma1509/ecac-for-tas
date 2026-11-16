"""Keep the comparator table honest.

`COMPARATOR_MECHANISMS` claims, per comparator, what is enforced and what is
omitted. A table of claims is worth little if it can drift from the code, so
these tests check it against observed behaviour.

The specific failure they prevent: a comparator described as implementing a
mechanism, but whose `commit_effect` has no reachable deny path. Such a
comparator blocks 0 traces, and
`test_baseline_regressions.test_no_baseline_is_trivially_correct` still passes,
because "fails at least one trace" is trivially true when it fails all of them.
That test was reading as evidence of a real mechanism while proving nothing.
"""

from __future__ import annotations

import warnings

import pytest

from effect_broker.baselines import COMPARATOR_MECHANISMS, run_comparison

warnings.filterwarnings("ignore")

#: Marker used in `COMPARATOR_MECHANISMS` to declare a comparator that cannot
#: deny anything. Kept as a constant so the string cannot drift.
NOTHING_BLOCKED = "NOTHING BLOCKED"


def _blocked_counts() -> dict[str, int]:
    """Number of traces each comparator blocks."""
    results = run_comparison()
    return {name: sum(1 for t in traces if t["blocked"]) for name, traces in results.items()}


def _host_can_confine() -> bool:
    """Whether this host actually has a kernel sandbox the comparator can use.

    Read from the comparator's own self-test rather than inferred from the
    platform: presence of Landlock syscalls in the kernel does not mean they are
    permitted here — a container can expose the syscall number and still refuse
    it, which is exactly what happens inside `python:3.12-slim`.
    """
    from effect_broker.baselines.mode_os_sandbox import selftest

    return selftest().verified


class TestComparatorTableMatchesBehaviour:
    """The table must describe the code that actually runs."""

    def test_every_comparator_is_documented(self) -> None:
        """No comparator may be added to the comparison without a table entry."""
        results = run_comparison()
        undocumented = sorted(set(results) - set(COMPARATOR_MECHANISMS))
        assert not undocumented, (
            f"Comparators with no COMPARATOR_MECHANISMS entry: {undocumented}. "
            f"An undocumented comparator is one whose numbers cannot be read."
        )

    def test_nothing_blocked_claim_matches_reality(self) -> None:
        """A comparator declared as unable to deny must indeed block zero traces."""
        counts = _blocked_counts()
        for name, (_enforces, omits) in COMPARATOR_MECHANISMS.items():
            declared_stub = any(NOTHING_BLOCKED in o for o in omits)
            if not declared_stub:
                continue
            assert counts[name] == 0, (
                f"{name} is declared '{NOTHING_BLOCKED}' but blocked "
                f"{counts[name]} trace(s). Either it grew a deny path (update the "
                f"table) or the declaration is wrong."
            )

    def test_enforcing_comparator_can_actually_deny(self) -> None:
        """A comparator claiming enforced mechanisms must deny at least one trace.

        Otherwise the claim is a description of intent, not of behaviour, and any
        comparative number against it is meaningless.

        One exemption, and it is checked rather than assumed: a comparator whose
        mechanism is enforced *by the host* blocks nothing when the host cannot
        confine. `OS_Sandbox` on a kernel without Landlock (or in a container
        without the syscall) reports `mechanism="none"` and blocks 0 traces by
        design — the module's own self-test says so. Treating that as a false
        claim would push the comparator toward simulating a deny, which is the
        dishonesty this file exists to prevent.

        The exemption is narrow on purpose: it applies only when the self-test
        actually reports no mechanism. On a host that *can* confine, the
        assertion still applies in full, so a comparator that silently lost its
        deny path still fails here.
        """
        counts = _blocked_counts()
        host_confines = _host_can_confine()
        dishonest = [
            name
            for name, (enforces, omits) in COMPARATOR_MECHANISMS.items()
            if enforces
            and not any(NOTHING_BLOCKED in o for o in omits)
            and name != "ECAC"
            and counts[name] == 0
            # Host-dependent enforcement with no mechanism in effect is an
            # absent mechanism, not an unimplemented one.
            and not (name == "OS_Sandbox" and not host_confines)
        ]
        assert not dishonest, (
            f"Comparators that claim enforced mechanisms but block nothing: "
            f"{dishonest}. Mark them '{NOTHING_BLOCKED}' or implement the mechanism."
        )

    def test_host_exemption_is_not_a_blanket_escape(self) -> None:
        """The OS_Sandbox exemption must track the host, not silence the check.

        If this host can confine, `OS_Sandbox` must block something. This is the
        guard that keeps the exemption above from becoming a permanent pass.
        """
        if not _host_can_confine():
            pytest.skip("host cannot confine: OS_Sandbox legitimately blocks nothing")
        counts = _blocked_counts()
        assert counts["OS_Sandbox"] > 0, (
            "OS_Sandbox reports a verified mechanism on this host but blocked no "
            "trace — its deny path is unreachable."
        )

    def test_ecac_claims_no_omissions(self) -> None:
        """ECAC is the subject, not a reduced model: it must declare no omissions."""
        _enforces, omits = COMPARATOR_MECHANISMS["ECAC"]
        assert omits == (), (
            f"ECAC declares omissions {omits}. If ECAC is a reduced model too, "
            f"the comparison is between two reduced models and must say so."
        )


class TestTodaysComparatorReality:
    """Pins the current numbers so a silent change is noticed.

    These are not targets: they record what is true today, including the parts
    that are unflattering. If a comparator starts blocking more traces, this
    test fails and someone has to say why — which is the point.
    """

    #: Observed at the time of writing. Update deliberately, with a reason.
    #:
    #: CaMeL, PACT, ChainCaps, Cordon and ArgProv used to
    #: return True unconditionally — 0/20 was a *stub*, not a measurement, and
    #: every comparative claim resting on it was unsupported. Each now
    #: implements the mechanism its docstring names:
    #:   CaMeL      4 — IFC denies untrusted provenance at a publish sink
    #:   PACT      14 — capability scope covers (etype, target)
    #:   ChainCaps  3 — capability scope, honoring EXPAND (its documented gap)
    #:   Cordon     3 — proposal revalidated: expiry + target match
    #:   ArgProv    6 — broken/untrusted provenance denies
    #: The gaps that remain are exactly the traces each comparator lacks the
    #: mechanism for; they are the honest basis of ECAC's 20/20.
    EXPECTED_BLOCKED = {
        "ECAC": 20,
        "PathAllowlist": 9,
        "FORGE": 9,
        "Allowlist": 2,
        "CaMeL": 4,
        "PACT": 14,
        "ChainCaps": 3,
        "Cordon": 3,
        "ArgProv": 6,
    }

    @pytest.mark.parametrize(("name", "expected"), sorted(EXPECTED_BLOCKED.items()))
    def test_blocked_count_is_unchanged(self, name: str, expected: int) -> None:
        """Each comparator blocks the same number of traces as recorded."""
        counts = _blocked_counts()
        assert counts[name] == expected, (
            f"{name} now blocks {counts[name]} traces, was {expected}. "
            f"If this is intended, update EXPECTED_BLOCKED and say why in the commit."
        )
