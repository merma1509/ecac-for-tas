"""mediation verdicts must be checked, not inferred.

The defect being removed: most experiment sites wrote

    mediation_complete=not actual_allow

i.e. "the effect was blocked, therefore mediation must be complete". Those are
different propositions. A blocked effect says nothing about whether some *other*
effect escaped unmediated, and at several sites nothing was checked at all.

These tests attack the new design from both directions:
  - an unevaluated result must NOT read as a pass;
  - a real hole must NOT be hidden by a successful block.
"""

from __future__ import annotations

import inspect
from typing import Any

import pytest

from effect_broker import experiment
from effect_broker.experiment import ExperimentResult, _mediation_verdict


def _result(**overrides: Any) -> ExperimentResult:
    """Build an ExperimentResult with only the fields under test varied."""
    base: dict[str, Any] = {
        "name": "x",
        "tool_class": object,
        "expected_blocker": "Auth",
        "actual_allow": False,
        "actual_blocker": "Auth",
        "predicates": {},
        "shim_blocked": False,
        "op_log_count": 0,
        "effects_log_count": 0,
    }
    base.update(overrides)
    return ExperimentResult(**base)  # type: ignore[arg-type]


class _FakeBroker:
    """Broker stub whose mediation check can be made to pass, fail or explode."""

    def __init__(self, failures: list[str] | None = None, *, raises: Exception | None = None):
        self._failures = failures or []
        self._raises = raises

    def verify_complete_mediation(self) -> list[str]:
        if self._raises is not None:
            raise self._raises
        return self._failures


# The verdict helper never infers
class TestMediationVerdict:
    def test_clean_check_reports_complete(self) -> None:
        complete, evaluated, failures = _mediation_verdict(_FakeBroker([]))  # type: ignore[arg-type]
        assert (complete, evaluated, failures) == (True, True, ())

    def test_hole_reports_incomplete_with_reasons(self) -> None:
        complete, evaluated, failures = _mediation_verdict(
            _FakeBroker(["UNKNOWN(possible_bypass)"])  # type: ignore[arg-type]
        )
        assert complete is False
        assert evaluated is True
        assert failures == ("UNKNOWN(possible_bypass)",)

    def test_broken_check_is_not_a_pass(self) -> None:
        """If verification cannot run, the answer is 'not evaluated' — never True."""
        complete, evaluated, failures = _mediation_verdict(
            _FakeBroker(raises=RuntimeError("ledger unavailable"))  # type: ignore[arg-type]
        )
        assert complete is None
        assert evaluated is False
        assert any("verification_error" in f for f in failures)


# The result type refuses to represent the false inference
class TestExperimentResultInvariants:
    def test_unevaluated_result_has_no_verdict(self) -> None:
        r = _result()
        assert r.mediation_evaluated is False
        assert r.mediation_complete is None

    def test_verdict_without_evaluation_is_rejected(self) -> None:
        """This is the old `mediation_complete=not actual_allow` in disguise."""
        with pytest.raises(ValueError, match="inference"):
            _result(mediation_complete=True, mediation_evaluated=False)

    def test_evaluation_without_verdict_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="contradictory"):
            _result(mediation_complete=None, mediation_evaluated=True)

    def test_evaluated_pass_is_representable(self) -> None:
        r = _result(mediation_complete=True, mediation_evaluated=True)
        assert r.mediation_complete is True

    def test_evaluated_failure_is_representable(self) -> None:
        r = _result(
            mediation_complete=False,
            mediation_evaluated=True,
            mediation_failures=("UNKNOWN(x)",),
        )
        assert r.mediation_complete is False
        assert r.mediation_failures == ("UNKNOWN(x)",)


# No inference survives in the source
class TestNoInferenceRemains:
    def test_no_mediation_complete_inferred_from_allow(self) -> None:
        """The plan's exit criterion is a grep; this is that grep, as a test."""
        source = inspect.getsource(experiment)
        offenders = [
            line.strip()
            for line in source.splitlines()
            if "mediation_complete=" in line
            and "actual_allow" in line
            and "_mediation_verdict" not in line
        ]
        assert offenders == [], f"inference still present: {offenders}"

    def test_no_mediation_complete_hardcoded_true(self) -> None:
        source = inspect.getsource(experiment)
        offenders = [
            line.strip()
            for line in source.splitlines()
            if "mediation_complete=True" in line
        ]
        assert offenders == [], f"asserted (not checked) verdict: {offenders}"

    def test_every_site_also_declares_evaluated(self) -> None:
        """A verdict field without its evaluated flag would fail __post_init__."""
        source = inspect.getsource(experiment)
        n_complete = source.count("mediation_complete=_mediation_verdict")
        n_evaluated = source.count("mediation_evaluated=_mediation_verdict")
        assert n_complete == n_evaluated, (
            f"{n_complete} mediation_complete vs {n_evaluated} mediation_evaluated"
        )


# The real experiment suite reports honestly
class TestRealExperimentSuite:
    @pytest.fixture(scope="class")
    def results(self) -> dict[str, ExperimentResult]:
        return experiment.run_all_experiments()

    def test_every_result_was_actually_evaluated(
        self, results: dict[str, ExperimentResult]
    ) -> None:
        unevaluated = [n for n, r in results.items() if not r.mediation_evaluated]
        assert unevaluated == [], f"never checked: {unevaluated}"

    def test_every_evaluated_result_carries_a_verdict(
        self, results: dict[str, ExperimentResult]
    ) -> None:
        for name, r in results.items():
            assert r.mediation_complete is not None, name

    def test_a_block_alone_does_not_make_mediation_complete(self) -> None:
        """Belt and braces: the two fields must move independently.

        A blocked result with a real hole must report incomplete. This cannot
        easily be provoked through run_all_experiments (it has no holes), so the
        relationship is asserted structurally instead: the verdict comes from
        the ledger, and `actual_allow` is not an input to it.
        """
        assert "actual_allow" not in inspect.signature(_mediation_verdict).parameters
