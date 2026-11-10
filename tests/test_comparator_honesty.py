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
        """
        counts = _blocked_counts()
        dishonest = [
            name
            for name, (enforces, omits) in COMPARATOR_MECHANISMS.items()
            if enforces
            and not any(NOTHING_BLOCKED in o for o in omits)
            and name != "ECAC"
            and counts[name] == 0
        ]
        assert not dishonest, (
            f"Comparators that claim enforced mechanisms but block nothing: "
            f"{dishonest}. Mark them '{NOTHING_BLOCKED}' or implement the mechanism."
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
    EXPECTED_BLOCKED = {
        "ECAC": 20,
        "PathAllowlist": 9,
        "FORGE": 9,
        "Allowlist": 2,
        "CaMeL": 0,
        "PACT": 0,
        "ChainCaps": 0,
        "Cordon": 0,
        "ArgProv": 0,
    }

    @pytest.mark.parametrize(("name", "expected"), sorted(EXPECTED_BLOCKED.items()))
    def test_blocked_count_is_unchanged(self, name: str, expected: int) -> None:
        """Each comparator blocks the same number of traces as recorded."""
        counts = _blocked_counts()
        assert counts[name] == expected, (
            f"{name} now blocks {counts[name]} traces, was {expected}. "
            f"If this is intended, update EXPECTED_BLOCKED and say why in the commit."
        )
