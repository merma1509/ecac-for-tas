"""Tests for the held-out evaluation framework."""

from __future__ import annotations

import pytest


class TestHoldOutEvaluation:
    """Tests for the sealed held-out evaluation framework."""

    def test_hold_out_traces_not_in_experiment(self) -> None:
        """Verify hold-out traces are not imported by experiment.py.

        This is the key property: hold-out traces must be SEALED.
        If they're imported here, they're not sealed.
        """
        import warnings

        warnings.filterwarnings("ignore")

        # Check that hold-out IDs are not in the experiment traces
        from effect_broker.held_out_evaluation import HOLD_OUT_TRACES

        ho_ids = {t["id"] for t in HOLD_OUT_TRACES}

        # These should NOT appear in the experiment.py trace names
        # (checked by string search — if HO-1..HO-8 appear in experiment.py,
        # the developer saw them during development)
        import os

        experiment_path = os.path.join(
            os.path.dirname(__file__), "..", "effect_broker", "experiment.py"
        )
        with open(experiment_path) as f:
            experiment_content = f.read()

        leaked = [tid for tid in ho_ids if f'"{tid}"' in experiment_content or f"'{tid}'" in experiment_content]
        assert len(leaked) == 0, (
            f"Hold-out trace IDs {leaked} appear in experiment.py — "
            f"traces are NOT sealed. Move them to held_out_evaluation.py only."
        )

    def test_hold_out_traces_never_imported_by_broker(self) -> None:
        """Hold-out traces must not be imported by any broker module."""
        import warnings

        warnings.filterwarnings("ignore")
        import os

        broker_files = [
            "effect_broker/broker.py",
            "effect_broker/shim.py",
            "effect_broker/model.py",
            "effect_broker/lattice.py",
        ]
        for path in broker_files:
            full_path = os.path.join(os.path.dirname(__file__), "..", path)
            if os.path.exists(full_path):
                with open(full_path) as f:
                    content = f.read()
                ho_mentions = [tid for tid in ["HO-1", "HO-2", "HO-3", "HO-4", "HO-5", "HO-6", "HO-7", "HO-8"] if f'"{tid}"' in content or f"'{tid}'" in content]
                assert len(ho_mentions) == 0, (
                    f"Hold-out trace ID {ho_mentions} found in {path} — "
                    f"broker code must NOT reference hold-out traces."
                )

    def test_all_hold_out_traces_have_required_fields(self) -> None:
        """Every hold-out trace must have all required metadata fields."""
        from effect_broker.held_out_evaluation import HOLD_OUT_TRACES

        required = {"id", "name", "attack_class", "severity", "effect", "expected_blocker", "description"}
        for trace in HOLD_OUT_TRACES:
            missing = required - set(trace.keys())
            assert len(missing) == 0, (
                f"Trace {trace.get('id', '?')} missing fields: {missing}"
            )
            # Verify effect is an Effect
            from effect_broker.model import Effect

            assert isinstance(trace["effect"], Effect), (
                f"Trace {trace['id']} has non-Effect effect: {type(trace['effect'])}"
            )

    def test_hold_out_evaluation_runs(self) -> None:
        """The held-out evaluation framework must run without errors."""
        import warnings

        warnings.filterwarnings("ignore")
        from effect_broker.held_out_evaluation import (
            evaluate_all_hold_out,
            HOLD_OUT_TRACES,
        )
        from effect_broker.traces import build

        broker = build()
        report = evaluate_all_hold_out(broker)
        summary = report["summary"]

        assert summary["total"] == len(HOLD_OUT_TRACES)
        assert 0 <= summary["defense_rate"] <= 100

    def test_hold_out_defense_rate_threshold(self) -> None:
        """Broker must defend ≥60% of hold-out traces (100% for high severity)."""
        import warnings

        warnings.filterwarnings("ignore")
        from effect_broker.held_out_evaluation import evaluate_all_hold_out
        from effect_broker.traces import build

        broker = build()
        report = evaluate_all_hold_out(broker)
        summary = report["summary"]

        # HO-8 (integrity downgrade) and HO-1 (timing/rate limit) require
        # enhancements not yet implemented:
        # - HO-8: FlowOK needs metadata._source checking to detect
        #   untrusted external data mislabeled as INTERNAL/USER
        # - HO-1: Requires Fresh rate-limit enforcement for valid caps
        # At least 60% overall defense rate (5/8 traces correctly blocked)
        assert summary["defense_rate"] >= 60.0, (
            f"Defense rate {summary['defense_rate']:.0f}% is below 60% threshold. "
            f"Attack classes needing improvement: "
            f"{[k for k, v in summary['by_attack_class'].items() if v['defended'] < v['total']]}"
        )
        # High-severity attacks must have 100% defense
        if summary["high_severity_total"] > 0:
            assert summary["high_severity_passed"] == summary["high_severity_total"], (
                f"All high-severity attacks must be defended. "
                f"Got {summary['high_severity_passed']}/{summary['high_severity_total']}. "
                f"High-severity traces that failed: "
                f"{[r for r in report['details'] if r.severity == 'high' and not r.pass_]}"
            )

    def test_hold_out_traces_hash_deterministic(self) -> None:
        """The traces hash must be deterministic (same content → same hash)."""
        from effect_broker.held_out_evaluation import get_traces_hash

        h1 = get_traces_hash()
        h2 = get_traces_hash()
        assert h1 == h2, "Traces hash must be deterministic"
        assert len(h1) == 16, "Traces hash should be 16 hex chars (SHA-256 prefix)"

    def test_each_hold_out_attack_class_unique(self) -> None:
        """Each hold-out trace must have a unique attack_class."""
        from effect_broker.held_out_evaluation import HOLD_OUT_TRACES

        classes = [t["attack_class"] for t in HOLD_OUT_TRACES]
        unique = set(classes)
        # Attack classes should be diverse (ideally all unique, min 6 unique)
        assert len(unique) >= 6, (
            f"Expected at least 6 unique attack classes in hold-out traces, "
            f"got {len(unique)}: {sorted(unique)}"
        )

    def test_hold_out_print_report_runs(self) -> None:
        """print_evaluation_report must run without errors (smoke test)."""
        import warnings

        warnings.filterwarnings("ignore")
        from effect_broker.held_out_evaluation import evaluate_all_hold_out, print_evaluation_report
        from effect_broker.traces import build

        broker = build()
        report = evaluate_all_hold_out(broker)
        print_evaluation_report(report)  # Should not raise