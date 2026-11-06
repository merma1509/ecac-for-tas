"""P4-4: the five outcomes are counted, and counted honestly.

The danger here is not that the counters break — it is that they lie
optimistically. An unauthorized effect must not be filed under `denied`
(which implies policy worked), and a report of zero must not be read as
"we checked". Most of these tests pin the pessimistic direction.
"""

from __future__ import annotations

import pytest

from effect_broker.experiment import collect_outcome_counts, run_all_experiments
from effect_broker.ledger import (
    ALL_OUTCOMES,
    OUTCOME_ABANDONED,
    OUTCOME_COMMITTED,
    OUTCOME_DENIED,
    OUTCOME_FAILED,
    OUTCOME_UNKNOWN,
    IndependentEffectLedger,
    OutcomeCounts,
)


@pytest.fixture
def ledger() -> IndependentEffectLedger:
    return IndependentEffectLedger()

# One effect, one outcome
class TestOutcomeOf:
    def test_observed_after_authorization_is_committed(
        self, ledger: IndependentEffectLedger
    ) -> None:
        ledger.record_authorization("t", "n", frozenset({"x"}), source="executor.execute")
        ledger.record_observation("t", "n", frozenset({"x"}), source="executor.apply")
        assert ledger.outcome_of("t", "n") == OUTCOME_COMMITTED

    def test_gate_block_is_denied(self, ledger: IndependentEffectLedger) -> None:
        ledger.record_authorization("t", "n", frozenset({"x"}), source="executor.execute")
        ledger.record_observation("t", "n", None, source="executor.execute:BLOCKED")
        assert ledger.outcome_of("t", "n") == OUTCOME_DENIED

    def test_shim_block_without_authorization_is_denied(
        self, ledger: IndependentEffectLedger
    ) -> None:
        """A shim-level block never reaches the gate; it is still a denial."""
        ledger.record_shim_block("t", "n", reason="bcc")
        assert ledger.outcome_of("t", "n") == OUTCOME_DENIED

    def test_apply_failure_is_failed(self, ledger: IndependentEffectLedger) -> None:
        ledger.record_authorization("t", "n", frozenset({"x"}), source="executor.execute")
        ledger.record_observation("t", "n", None, source="executor.apply:FAILED")
        assert ledger.outcome_of("t", "n") == OUTCOME_FAILED

    def test_dispatched_without_observation_is_unknown(
        self, ledger: IndependentEffectLedger
    ) -> None:
        ledger.record_authorization("t", "n", frozenset({"x"}), source="executor.execute")
        ledger.record_dispatched("t", "n")
        assert ledger.outcome_of("t", "n") == OUTCOME_UNKNOWN

    def test_authorized_without_observation_is_unknown(
        self, ledger: IndependentEffectLedger
    ) -> None:
        ledger.record_authorization("t", "n", frozenset({"x"}), source="executor.execute")
        assert ledger.outcome_of("t", "n") == OUTCOME_UNKNOWN


# The pessimistic direction: never file a mystery as a policy win
class TestUnauthorizedNeverReadsAsDenied:
    def test_observed_without_authorization_is_unknown_not_denied(
        self, ledger: IndependentEffectLedger
    ) -> None:
        """This is a possible bypass. Calling it `denied` would hide the attack."""
        ledger.record_observation("t", "n", frozenset({"secret"}), source="executor.apply")
        assert ledger.outcome_of("t", "n") == OUTCOME_UNKNOWN

    def test_unrecognised_source_is_unknown_not_committed(
        self, ledger: IndependentEffectLedger
    ) -> None:
        """A new source string must not become a commit by default.

        The classifier started life as a deny-list ("anything not obviously a
        block is a commit"), which meant adding a source anywhere in the codebase
        would silently inflate the commit count. An allow-list makes the default
        `unknown` instead: safer, and it fails visibly.
        """
        ledger.record_authorization("t", "n", frozenset({"x"}), source="executor.execute")
        ledger.record_observation("t", "n", frozenset({"x"}), source="something.new")
        assert ledger.outcome_of("t", "n") == OUTCOME_UNKNOWN

    def test_known_committing_sources_are_recognised(
        self, ledger: IndependentEffectLedger
    ) -> None:
        """The allow-list must actually cover both commit paths."""
        for source in ("executor.apply", "subprocess.apply"):
            ledger.record_authorization("t", source, frozenset({"x"}), source="executor.execute")
            ledger.record_observation("t", source, frozenset({"x"}), source=source)
            assert ledger.outcome_of("t", source) == OUTCOME_COMMITTED

    def test_known_denying_sources_are_recognised(
        self, ledger: IndependentEffectLedger
    ) -> None:
        for source in ("executor.execute:BLOCKED", "subprocess.gate:BLOCKED"):
            ledger.record_authorization("t", source, frozenset({"x"}), source="executor.execute")
            ledger.record_observation("t", source, None, source=source)
            assert ledger.outcome_of("t", source) == OUTCOME_DENIED

    def test_idle_ledger_reports_no_effects(self, ledger: IndependentEffectLedger) -> None:
        counts = ledger.outcome_counts()
        assert counts.total == 0


# Counting
class TestOutcomeCounts:
    def test_counts_partition_the_effects(self, ledger: IndependentEffectLedger) -> None:
        """Every effect lands in exactly one bucket; the totals must agree."""
        ledger.record_authorization("t", "ok", frozenset({"x"}), source="executor.execute")
        ledger.record_observation("t", "ok", frozenset({"x"}), source="executor.apply")

        ledger.record_authorization("t", "blocked", frozenset({"x"}), source="executor.execute")
        ledger.record_observation("t", "blocked", None, source="executor.execute:BLOCKED")

        ledger.record_authorization("t", "ghost", frozenset({"x"}), source="executor.execute")
        ledger.record_dispatched("t", "ghost")

        counts = ledger.outcome_counts()
        assert counts.total == 3
        assert counts.committed == 1
        assert counts.denied == 1
        assert counts.unknown == 1

    def test_observed_but_unauthorized_is_included(self, ledger: IndependentEffectLedger) -> None:
        """It must not vanish from the accounting just because nobody authorized it."""
        ledger.record_observation("t", "rogue", frozenset({"x"}), source="executor.apply")
        counts = ledger.outcome_counts()
        assert counts.total == 1
        assert counts.unknown == 1

    def test_unexplained_counts_unknown_and_abandoned(self) -> None:
        assert OutcomeCounts(unknown=2, committed=5).unexplained() == 2
        assert OutcomeCounts(abandoned=1).unexplained() == 1
        assert OutcomeCounts(committed=5, denied=3).unexplained() == 0

    def test_every_outcome_appears_in_as_dict(self) -> None:
        assert set(OutcomeCounts().as_dict()) == set(ALL_OUTCOMES)

    def test_abandoned_has_no_producer_yet(self) -> None:
        """Documented limitation rather than a silent zero.

        No code path currently authorizes an effect and then gives up before
        dispatch -- capability expiry is caught by the gate as a denial, before
        authorization is recorded. So `abandoned` cannot occur, and the printer
        says so beside the number. This test is the tripwire: if somebody adds
        such a path, the set below must grow with it.
        """
        from effect_broker import ledger as ledger_mod

        producible = (
            set(ledger_mod._COMMITTING_SOURCES)
            | set(ledger_mod._FAILED_SOURCES)
            | set(ledger_mod._DENYING_SOURCES)
        )
        # Nothing in the ledger's source tables can yield ABANDONED.
        assert not any(OUTCOME_ABANDONED in s for s in producible)

    def test_abandoned_is_counted_when_set_directly(self) -> None:
        counts = OutcomeCounts(abandoned=3)
        assert counts.as_dict()[OUTCOME_ABANDONED] == 3
        assert counts.unexplained() == 3


# The real suite
class TestSuiteOutcomes:
    @pytest.fixture(scope="class")
    def run(self):
        return collect_outcome_counts()

    def test_every_effect_gets_exactly_one_outcome(self, run) -> None:
        """The sum of the five buckets must equal the number of effects seen."""
        _results, counts = run
        assert counts.total == sum(counts.as_dict().values())

    def test_no_effect_is_unexplained(self, run) -> None:
        """A green suite must not be green because it lost track of effects."""
        _results, counts = run
        assert counts.unexplained() == 0

    def test_suite_produces_both_commits_and_denials(self, run) -> None:
        """If either were zero the accounting would be vacuous."""
        _results, counts = run
        assert counts.committed > 0
        assert counts.denied > 0

    def test_results_and_counts_come_from_one_execution(self, run) -> None:
        """Both must describe the same run, so they are returned together."""
        results, _counts = run
        assert len(results) == 18

    def test_counts_are_not_cumulative_across_runs(self) -> None:
        """A detached registry would make the second run double the first."""
        _r1, first = collect_outcome_counts()
        _r2, second = collect_outcome_counts()
        assert first.as_dict() == second.as_dict()


class TestNoStaleRegistry:
    def test_build_broker_outside_a_run_does_not_register(self) -> None:
        from effect_broker.experiment import _build_broker

        # No run is active, so this must not touch (or create) a registry.
        _build_broker()
        from effect_broker.experiment import _RUN_BROKERS

        assert _RUN_BROKERS is None

    def test_registry_is_cleared_even_if_the_run_is_used_twice(self) -> None:
        from effect_broker.experiment import _RUN_BROKERS

        collect_outcome_counts()
        assert _RUN_BROKERS is None

    def test_run_all_experiments_still_works_alone(self) -> None:
        """The older entry point must not depend on the registry."""
        results = run_all_experiments()
        assert len(results) == 18
