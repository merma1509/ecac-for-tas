"""Path/host allowlist baseline comparison

This baseline was previously named `mode_conventional_sandbox.py` and claimed to
model a seccomp/landlock/SELinux OS sandbox. It never did — it compares strings
on `effect.target`. PLAN 6 Part D requires a comparator to either implement the
named mechanism or be renamed; this file tests the renamed baseline and records
why the rename happened.

What the baseline is honest about:
  - It DOES block out-of-root writes and egress to non-allowlisted hosts. That
    protection is real at the level an allowlist can provide it.
  - It is structurally blind to the dataflow/recipient/freshness attacks ECAC's
    predicates close (session-taint exfil, hidden BCC, replay).
  - It is NOT a sandbox comparator and must not be cited as one: no syscall
    filter, no kernel-enforced path confinement.

Regression coverage on supplied traces, not a causal evaluation of
effectiveness against adaptive attackers.
"""

from __future__ import annotations

import warnings

from effect_broker.baselines import PathAllowlistBroker, run_comparison

warnings.filterwarnings("ignore")


class TestPathAllowlistBaseline:
    """ECAC vs PathAllowlist (path/host allowlist, NOT an OS sandbox)."""

    def test_sandbox_is_registered_in_comparison(self) -> None:
        """The conventional sandbox participates in the baseline comparison."""
        results = run_comparison()
        assert "PathAllowlist" in results, "PathAllowlist must be a comparison baseline"
        assert len(results["PathAllowlist"]) == len(results["ECAC"]), (
            "Sandbox must be evaluated on the same traces as ECAC"
        )

    def test_sandbox_not_trivially_correct(self) -> None:
        """The sandbox fails at least one trace (it's a real, bounded mechanism)."""
        results = run_comparison()
        traces = results["PathAllowlist"]
        not_blocked = [t["name"] for t in traces if not t["blocked"]]
        assert len(not_blocked) >= 1, (
            f"Conventional sandbox should NOT block every trace (it lacks IFC/taint/BCC/replay). "
            f"Blocked all {len(traces)} — baseline is likely mis-modeled."
        )

    def test_allowlist_blocks_what_path_checks_cover(self) -> None:
        """The allowlist DOES block what a path/host check can see.

        Sufficient for:
          - writes outside the allowlisted roots
          - egress to non-allowlisted hosts
        This proves the baseline provides real (if narrow) protection rather
        than being a strawman that blocks nothing.
        """
        from effect_broker.model import Effect

        allowlist = PathAllowlistBroker()

        # write outside the allowlisted roots -> BLOCKED (prefix allowlist works)
        write_out = Effect(
            etype="write",
            target="file:///etc/passwd",
            metadata={},
            provenance=(),
            capability_nonce="n1",
            delegation_chain=(),
        )
        allowed, _ = allowlist.commit_effect(write_out)
        assert allowed is False, "allowlist must block write outside its roots"

        # network egress to a non-allowlisted host -> BLOCKED (host allowlist works)
        net_out = Effect(
            etype="network",
            target="http://evil.com",
            metadata={},
            provenance=(),
            capability_nonce="n2",
            delegation_chain=(),
        )
        allowed, _ = allowlist.commit_effect(net_out)
        assert allowed is False, "allowlist must block egress to non-allowlisted host"

        # network egress to an allowlisted host -> ALLOWED
        net_in = Effect(
            etype="network",
            target="http://internal.corp.com",
            metadata={},
            provenance=(),
            capability_nonce="n3",
            delegation_chain=(),
        )
        allowed, _ = allowlist.commit_effect(net_in)
        assert allowed is True, "allowlist must allow egress to allowlisted host"

    def test_ecac_blocks_dataflow_traces_allowlist_cannot(self) -> None:
        """ECAC blocks the dataflow/recipient/freshness attacks an allowlist is blind to.

        A path/host allowlist is structurally incapable of:
          - session taint (read CONFIDENTIAL -> send exfil)
          - hidden BCC / recipient scoping
          - nonce replay
        For these traces ECAC blocks and the allowlist does not. This is the
        documented dimension where ECAC adds value over a path/host allowlist.
        """
        results = run_comparison()
        by_name_ecac = {t["name"]: t for t in results["ECAC"]}
        by_name_allowlist = {t["name"]: t for t in results["PathAllowlist"]}

        # Trace classes a path/host allowlist cannot model (send/BCC/replay/taint).
        dataflow_traces = [
            n
            for n in by_name_ecac
            if any(k in n for k in ("Session taint", "BCC", "Replay", "rate limit"))
        ]
        assert dataflow_traces, "Expected dataflow/BCC/replay traces in the comparison set"

        allowlist_blind = [
            n
            for n in dataflow_traces
            if by_name_ecac[n]["blocked"] and not by_name_allowlist[n]["blocked"]
        ]
        assert len(allowlist_blind) >= 1, (
            f"ECAC should block at least one dataflow/BCC/replay trace that the "
            f"path allowlist cannot. ECAC-blocked dataflow traces: {dataflow_traces}; "
            f"per-name ECAC: "
            f"{ {n: by_name_ecac[n]['blocked'] for n in dataflow_traces} }"
        )

    def test_allowlist_and_ecac_agree_on_path_checks(self) -> None:
        """Both block out-of-root writes — ECAC is not weaker here.

        On pure path-check traces (out-of-root write), the allowlist and ECAC
        should agree. This shows ECAC does not REGRESS the narrow protection a
        path allowlist already provides.
        """
        results = run_comparison()
        by_name_ecac = {t["name"]: t for t in results["ECAC"]}

        # Traces the allowlist blocks via its prefix check: ECAC must also block.
        allowlist_blocked_write = [
            t["name"]
            for t in results["PathAllowlist"]
            if t["blocked"] and "write-outside-allowlist-root" in t["reason"]
        ]
        assert allowlist_blocked_write, (
            "Expected out-of-root write traces for the agreement check (non-vacuous)"
        )
        for name in allowlist_blocked_write:
            assert by_name_ecac[name]["blocked"], (
                f"ECAC must also block {name} (out-of-root write) — no regression vs allowlist"
            )
