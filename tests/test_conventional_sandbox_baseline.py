"""Conventional OS-sandbox baseline comparison

Adds the "genuine conventional broker+sandbox" baseline missing from the
comparison: a seccomp/landlock/SELinux-style OS sandbox that confines the tool
process by PATH and SYSCALL but has no capability/IFC/session-taint/BCC/replay
semantics.

This test documents the COMPARISON HONESTLY:
  - The conventional sandbox IS sufficient for what it models: it blocks
    out-of-root writes and network egress to non-allowlisted hosts.
  - ECAC adds value over it for the dataflow/recipient/freshness attacks the
    sandbox is structurally blind to (session-taint exfil, hidden BCC, replay).
  - The sandbox is NOT trivially correct (it fails some traces), and it is NOT
    universally weaker on every dimension (it blocks what ECAC's gate also
    blocks) — so this is a real baseline, not a strawman.

Regression coverage on supplied traces, not a causal evaluation of
effectiveness against adaptive attackers.
"""

from __future__ import annotations

import warnings

from effect_broker.baselines import ConventionalSandboxBroker, run_comparison

warnings.filterwarnings("ignore")


class TestConventionalSandboxBaseline:
    """ECAC vs ConventionalSandbox (seccomp/landlock-style OS confinement)."""

    def test_sandbox_is_registered_in_comparison(self) -> None:
        """The conventional sandbox participates in the baseline comparison."""
        results = run_comparison()
        assert "ConvSandbox" in results, "ConventionalSandbox must be a comparison baseline"
        assert len(results["ConvSandbox"]) == len(results["ECAC"]), (
            "Sandbox must be evaluated on the same traces as ECAC"
        )

    def test_sandbox_not_trivially_correct(self) -> None:
        """The sandbox fails at least one trace (it's a real, bounded mechanism)."""
        results = run_comparison()
        traces = results["ConvSandbox"]
        not_blocked = [t["name"] for t in traces if not t["blocked"]]
        assert len(not_blocked) >= 1, (
            f"Conventional sandbox should NOT block every trace (it lacks IFC/taint/BCC/replay). "
            f"Blocked all {len(traces)} — baseline is likely mis-modeled."
        )

    def test_sandbox_blocks_what_os_confinement_covers(self) -> None:
        """The sandbox DOES block the attacks OS confinement is designed for.

        A conventional sandbox is sufficient for:
          - writes outside the sandbox root (landlock/SELinux path confinement)
          - network egress to non-allowlisted hosts (cgroup/netfilter)
        This proves the baseline provides real protection, not a strawman.
        """
        from effect_broker.model import Effect

        sandbox = ConventionalSandboxBroker()

        # write outside the sandbox root -> BLOCKED (OS path confinement works)
        write_out = Effect(
            etype="write",
            target="file:///etc/passwd",
            metadata={},
            provenance=(),
            capability_nonce="n1",
            delegation_chain=(),
        )
        allowed, _ = sandbox.commit_effect(write_out)
        assert allowed is False, "OS sandbox must block write outside sandbox root"

        # network egress to a non-allowlisted host -> BLOCKED (egress filter works)
        net_out = Effect(
            etype="network",
            target="http://evil.com",
            metadata={},
            provenance=(),
            capability_nonce="n2",
            delegation_chain=(),
        )
        allowed, _ = sandbox.commit_effect(net_out)
        assert allowed is False, "OS sandbox must block egress to non-allowlisted host"

        # network egress to an allowlisted host -> ALLOWED
        net_in = Effect(
            etype="network",
            target="http://internal.corp.com",
            metadata={},
            provenance=(),
            capability_nonce="n3",
            delegation_chain=(),
        )
        allowed, _ = sandbox.commit_effect(net_in)
        assert allowed is True, "OS sandbox must allow egress to allowlisted host"

    def test_ecac_blocks_dataflow_traces_sandbox_cannot(self) -> None:
        """ECAC blocks the dataflow/recipient/freshness attacks the sandbox is blind to.

        The conventional sandbox is structurally incapable of:
          - session taint (read CONFIDENTIAL -> send exfil)
          - hidden BCC / recipient scoping
          - nonce replay
        For these traces ECAC blocks and the sandbox does not. This is the
        documented dimension where ECAC adds value over a conventional sandbox.
        """
        results = run_comparison()
        by_name_ecac = {t["name"]: t for t in results["ECAC"]}
        by_name_sbx = {t["name"]: t for t in results["ConvSandbox"]}

        # Trace classes the OS sandbox cannot model (send/BCC/replay/taint).
        dataflow_traces = [
            n for n in by_name_ecac
            if any(k in n for k in ("Session taint", "BCC", "Replay", "rate limit"))
        ]
        assert dataflow_traces, "Expected dataflow/BCC/replay traces in the comparison set"

        sandbox_blind = [
            n for n in dataflow_traces
            if by_name_ecac[n]["blocked"] and not by_name_sbx[n]["blocked"]
        ]
        assert len(sandbox_blind) >= 1, (
            f"ECAC should block at least one dataflow/BCC/replay trace that the "
            f"conventional sandbox cannot. ECAC-blocked dataflow traces: {dataflow_traces}; "
            f"per-name ECAC: "
            f"{ {n: by_name_ecac[n]['blocked'] for n in dataflow_traces} }"
        )

    def test_sandbox_and_ecac_agree_on_path_confinement(self) -> None:
        """Both block writes the sandbox root forbids — ECAC is not weaker here.

        On pure path-confinement traces (e.g. out-of-root write), the OS sandbox
        and ECAC should agree. This shows ECAC does not REGRESS the protection a
        conventional sandbox already provides.
        """
        results = run_comparison()
        by_name_ecac = {t["name"]: t for t in results["ECAC"]}

        # Traces the sandbox blocks via path confinement: ECAC must also block.
        sandbox_blocked_write = [
            t["name"] for t in results["ConvSandbox"]
            if t["blocked"] and "write-outside-sandbox-root" in t["reason"]
        ]
        assert sandbox_blocked_write, (
            "Expected out-of-root write traces for the agreement check (non-vacuous)"
        )
        for name in sandbox_blocked_write:
            assert by_name_ecac[name]["blocked"], (
                f"ECAC must also block {name} (out-of-root write) — no regression vs OS sandbox"
            )
