"""A block count must say WHY it blocked.

`run_comparison()` reports how many traces each baseline blocks. That number
cannot distinguish a comparator that inspected an operation and refused it from
one that was simply never granted the authority to perform it. PACT is the
concrete case: it blocks 14 of 20, but every one of those denials reads
"no capability for (etype, target)" — the capability table in the fixture never
had an entry. The fourteen are a statement about provisioning, not about a check.

`block_basis` makes that distinction machine-readable, so the comparison table
cannot be read as fourteen defences. These tests pin the classification and, in
particular, pin the PACT finding so it cannot drift back into a bare count.
"""

from __future__ import annotations

import warnings

import pytest

from effect_broker.baselines import (
    block_basis,
    run_comparison,
    summarise_basis,
)

warnings.filterwarnings("ignore")


@pytest.fixture(scope="module")
def results() -> dict[str, list[dict]]:
    """One comparison run shared by the tests in this module."""
    return run_comparison()


class TestBlockBasisClassification:
    """The classifier must read the reason it is given, not the baseline name."""

    def test_allowed_is_none(self) -> None:
        assert block_basis("PACT", "anything at all", blocked=False) == "none"

    def test_no_capability_is_coverage(self) -> None:
        """Absence of a grant is a property of the setup, not of a check."""
        assert (
            block_basis("PACT", "PACT: no capability for (send, mailto:x)", True)
            == "coverage"
        )

    def test_flow_violation_is_check(self) -> None:
        assert block_basis("CaMeL", "CaMeL IFC: untrusted value flows to sink", True) == "check"

    def test_expiry_is_check(self) -> None:
        assert block_basis("Cordon", "Cordon: proposal expired at 123", True) == "check"

    def test_kernel_refusal_is_check(self) -> None:
        assert block_basis("OS_Sandbox", "kernel-denied-write(EACCES, landlock)", True) == "check"

    def test_basis_is_derived_not_hardcoded(self) -> None:
        """The same baseline gets different bases for different reasons."""
        assert block_basis("X", "no capability for (send, y)", True) == "coverage"
        assert block_basis("X", "freshness: nonce replayed", True) == "check"


class TestBasisIsReportedForEveryTrace:
    """Every trace carries a basis, so no block is left unclassified."""

    def test_every_trace_has_a_basis(self, results: dict[str, list[dict]]) -> None:
        missing = [
            (name, trace["name"])
            for name, traces in results.items()
            for trace in traces
            if "basis" not in trace
        ]
        assert not missing, f"traces with no block basis: {missing[:5]}"

    def test_basis_is_one_of_the_three_values(self, results: dict[str, list[dict]]) -> None:
        invalid = [
            (name, trace["name"], trace["basis"])
            for name, traces in results.items()
            for trace in traces
            if trace["basis"] not in {"coverage", "check", "none"}
        ]
        assert not invalid, f"unclassified bases: {invalid[:5]}"

    def test_blocked_traces_are_never_basis_none(self, results: dict[str, list[dict]]) -> None:
        """A blocked trace must have a reason; 'none' would hide it."""
        wrong = [
            (name, trace["name"])
            for name, traces in results.items()
            for trace in traces
            if trace["blocked"] and trace["basis"] == "none"
        ]
        assert not wrong, f"blocked traces reported as basis 'none': {wrong[:5]}"


class TestPACTFindingIsPinned:
    """PACT's score is coverage-dominated; that must stay visible."""

    def test_pact_blocks_come_from_coverage_not_checks(
        self, results: dict[str, list[dict]]
    ) -> None:
        """Every PACT block is 'no capability', i.e. a provisioning artefact.

        If this ever fails, PACT grew a real check — good news, but the
        disclosure in VERIFICATION.md must be updated with it rather than
        silently becoming wrong.
        """
        pact = summarise_basis(results)["PACT"]
        assert pact["check"] == 0, (
            f"PACT now blocks {pact['check']} trace(s) by inspection. Update the "
            f"'coverage-dominated' disclosure in VERIFICATION.md."
        )
        assert pact["coverage"] > 0, "PACT blocked nothing at all; the setup changed"

    def test_ecac_blocks_come_from_checks(self, results: dict[str, list[dict]]) -> None:
        """The claim ECAC makes is a check-based one; it must not be coverage."""
        ecac = summarise_basis(results)["ECAC"]
        assert ecac["coverage"] == 0, (
            "ECAC blocked a trace for lack of a grant, which would mean the "
            "comparison measured provisioning rather than enforcement"
        )
        assert ecac["check"] > 0

    def test_no_comparator_blocks_only_by_coverage_except_pact(
        self, results: dict[str, list[dict]]
    ) -> None:
        """A coverage-only score is not evidence of a mechanism."""
        coverage_only = [
            name
            for name, counts in summarise_basis(results).items()
            if name != "ECAC" and counts["coverage"] > 0 and counts["check"] == 0
        ]
        assert coverage_only == ["PACT"], (
            f"Comparators whose entire score is provisioning, not checking: "
            f"{coverage_only}. Document each one."
        )
