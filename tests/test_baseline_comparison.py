"""Tests for baseline comparison framework.

Verifies that:
1. ECAC blocks all 20 adversarial traces
2. Each baseline fails at least one trace (proving it's not trivially correct)
3. ECAC's advantage is documented (what ECAC blocks that baselines don't)
"""

from __future__ import annotations

from effect_broker.baselines import run_comparison


class TestBaselineComparison:
    """Baseline comparison: ECAC vs CaMeL/PACT/ChainCaps/Cordon/FORGE."""

    def test_ecac_blocks_all_traces(self) -> None:
        """ECAC should block all 20 adversarial traces."""
        import warnings

        warnings.filterwarnings("ignore")
        results = run_comparison()

        ecac_traces = results["ECAC"]
        all_blocked = all(t["blocked"] for t in ecac_traces)
        failed = [t["name"] for t in ecac_traces if not t["blocked"]]

        assert all_blocked, (
            f"ECAC should block ALL traces but failed on: {failed}. "
            f"ECAC must provide comprehensive protection to be novel."
        )

    def test_no_baseline_is_trivially_correct(self) -> None:
        """Every baseline should fail at least one trace (proving it's not trivial)."""
        import warnings

        warnings.filterwarnings("ignore")
        results = run_comparison()

        # Skip ECAC (it's the target) and the trivially-weak baselines
        # Allowlist and ArgProv are expected to be weak
        for baseline_name in ["CaMeL", "PACT", "ChainCaps", "Cordon", "FORGE"]:
            traces = results[baseline_name]
            failed = [t for t in traces if not t["blocked"]]
            # Each baseline should have at least one trace it doesn't block
            # (proving the baseline is non-trivial and needs improvement)
            assert len(failed) > 0, (
                f"{baseline_name} blocks ALL traces — "
                f"either the baseline is too strong (false positive) "
                f"or the traces are too weak. Review baseline implementation."
            )

    def test_ecac_blocks_traces_pact_does_not(self) -> None:
        """ECAC blocks traces that PACT-style systems miss."""
        import warnings

        warnings.filterwarnings("ignore")
        results = run_comparison()

        # ECAC must block traces that PACT-style systems (PACT, ChainCaps) miss.
        # This is the key kill-criterion: prove ECAC adds something PACT doesn't.
        ecac_blocked = {t["name"]: t["blocked"] for t in results["ECAC"]}
        pact_blocked = {t["name"]: t["blocked"] for t in results["PACT"]}
        chaincaps_blocked = {t["name"]: t["blocked"] for t in results["ChainCaps"]}

        # Find traces ECAC blocks that PACT misses
        pact_gaps = [
            name for name in ecac_blocked
            if ecac_blocked[name] and not pact_blocked.get(name, False)
        ]
        chaincaps_gaps = [
            name for name in ecac_blocked
            if ecac_blocked[name] and not chaincaps_blocked.get(name, False)
        ]

        # The key advantages over PACT-style:
        # 1. Content hash binding (T2)
        # 2. Session taint propagation (T1)
        # 3. Independent ledger (T4)
        # 4. Authority monotonicity / NoAmp (T5, T6)
        assert len(pact_gaps) >= 4, (
            f"ECAC must block ≥4 traces PACT misses. Got {len(pact_gaps)}: {pact_gaps}. "
            f"This proves ECAC's kill-criterion contribution beyond PACT."
        )
        assert len(chaincaps_gaps) >= 4, (
            f"ECAC must block ≥4 traces ChainCaps misses. "
            f"Got {len(chaincaps_gaps)}: {chaincaps_gaps}. "
            f"This proves ECAC's kill-criterion contribution beyond ChainCaps."
        )

    def test_trace_coverage_complete(self) -> None:
        """Verify 20 traces total (T1-T20)."""
        import warnings

        warnings.filterwarnings("ignore")
        results = run_comparison()

        total = len(list(results.values())[0])
        assert total == 20, (
            f"Expected 20 adversarial traces, got {total}. "
            f"Update baselines/traces.py to include T1-T20."
        )

    def test_freshness_trace_blocked_by_ecac_not_camel(self) -> None:
        """T4 (replay) must be blocked by ECAC but NOT by CaMeL."""
        import warnings

        warnings.filterwarnings("ignore")
        results = run_comparison()

        ecac_traces = {t["name"]: t["blocked"] for t in results["ECAC"]}
        camel_traces = {t["name"]: t["blocked"] for t in results["CaMeL"]}

        # Find T4 (replay)
        t4_names = [n for n in ecac_traces if "replay" in n.lower() or "T4" in n]
        if t4_names:
            assert ecac_traces[t4_names[0]], "T4 must be blocked by ECAC"
            assert not camel_traces[t4_names[0]], (
                "T4 must NOT be blocked by CaMeL (proving ledger adds value)"
            )

    def test_all_traces_have_expected_failures_listed(self) -> None:
        """Every trace must list which baselines it fails."""
        from effect_broker.baselines.traces import ADVERSARIAL_TRACES

        for trace in ADVERSARIAL_TRACES:
            assert "what_fails" in trace, f"Trace {trace.get('name')} missing 'what_fails'"
            assert isinstance(trace["what_fails"], list), (
                f"Trace {trace.get('name')}: 'what_fails' must be a list"
            )
            assert len(trace["what_fails"]) > 0, (
                f"Trace {trace.get('name')}: 'what_fails' must list at least one baseline"
            )

    def test_no_duplicate_trace_names(self) -> None:
        """No two traces should have the same name."""
        from effect_broker.baselines.traces import ADVERSARIAL_TRACES

        names = [t["name"] for t in ADVERSARIAL_TRACES]
        unique_names = set(names)
        assert len(names) == len(unique_names), (
            f"Duplicate trace names found: {[n for n in names if names.count(n) > 1]}"
        )

    def test_comparison_table_format(self) -> None:
        """Generate the comparison table for the paper."""
        import warnings

        warnings.filterwarnings("ignore")
        results = run_comparison()

        total = len(list(results.values())[0])
        print("\n=== BASELINE COMPARISON TABLE ===")
        print(f"{'Baseline':<15} {'Blocked':<10} {'Total':<8} {'Coverage'}")
        print("-" * 50)
        for name, traces in results.items():
            blocked = sum(1 for t in traces if t["blocked"])
            coverage = blocked / total * 100
            print(f"{name:<15} {blocked:<10} {total:<8} {coverage:5.1f}%")

        # Key claim for kill criteria: ECAC must have strictly higher coverage
        # than any baseline that's a close comparison (PACT, ChainCaps, CaMeL)
        ecac_blocked = sum(1 for t in results["ECAC"] if t["blocked"])
        for baseline in ["PACT", "ChainCaps", "CaMeL", "Cordon"]:
            baseline_blocked = sum(1 for t in results[baseline] if t["blocked"])
            assert ecac_blocked > baseline_blocked, (
                f"ECAC must block strictly more traces than {baseline}. "
                f"ECAC={ecac_blocked}, {baseline}={baseline_blocked}. "
                f"If ECAC == {baseline}, there is no novelty."
            )
