"""Tests for the mandatory boundary experiment (M1–M5 + H1–H3 + T9–T20)

These tests implement the real adversarial tool workload and hold-out variants.

  M1-M5: 5 mandatory adversarial scenarios
  H1-H3: 3 held-out variants (train/test split)
  T9-T20: 9 new adversarial traces (T9, T10, T11, T12, T15, T16, T17, T19, T20)
  T18:   BCC via RSET probe (tested in test_smtp_real_bcc.py)

  Total: 17 adversarial traces (5+3+9)"""

from __future__ import annotations

import pytest

from effect_broker.experiment import (
    ApprovalReplayTool,
    BenignTool,
    CapabilityWideningTool,
    CrossTaskDataFlowTool,
    DeepDelegationTool,
    DirectBypassTool,
    EndorsementAbuseTool,
    HeldOutForgedCapTool,
    HeldOutLowIntegrityTool,
    HeldOutPathAliasTool,
    HiddenNetworkSideEffectTool,
    MaliciousDeleteTool,
    MaliciousReadTool,
    MaliciousSendTool,
    ParameterSmugglingTool,
    SSRFManipulationTool,
    ToctouRaceTool,
    _build_broker,
)
from effect_broker.shim import FileShim, SecurityError


# M1: read tool with hidden write to secrets (Boundary blocks)
class TestM1MaliciousReadTool:
    """M1: A 'read' tool that also writes to secrets (hidden side effect)

    The tool says it will only read file:///trusted.
    In fact, it reads trusted AND writes file:///secrets.
    The shim intercepts ALL paths and derives the REAL effect(s)
    Expected: SecurityError (shim blocks the write).
    """

    def test_m1_hidden_write_blocked(self) -> None:
        broker = _build_broker()
        shim = FileShim(broker, tool_name="malicious-read-tool")
        tool = MaliciousReadTool(shim)

        # The read on trusted should succeed (capability exists)
        # The write to secrets should be BLOCKed (no capability)
        with pytest.raises(SecurityError) as exc_info:
            tool.run()
        assert "BLOCKed" in str(exc_info.value)
        assert "write" in str(exc_info.value)
        assert "file:///secrets" in str(exc_info.value)

    def test_m1_complete_mediation(self) -> None:
        broker = _build_broker()
        shim = FileShim(broker, tool_name="malicious-read-tool")
        tool = MaliciousReadTool(shim)

        with pytest.raises(SecurityError):
            tool.run()

        failures = shim.verify_complete_mediation()
        assert len(failures) == 0, f"M1 mediation failure: {failures}"

    def test_m1_effects_log_correct(self) -> None:
        broker = _build_broker()
        shim = FileShim(broker, tool_name="malicious-read-tool")
        tool = MaliciousReadTool(shim)

        with pytest.raises(SecurityError):
            tool.run()

        # Read on trusted was ALLOWed (has capability)
        # Write to secrets was BLOCKed (no capability)
        # effects_log should contain exactly 1 entry: the read
        effects = broker.store.effects_log
        assert len(effects) == 1, f"Expected 1 effect (read), got {len(effects)}: {effects}"
        assert effects[0][0] == "read"
        assert "file:///trusted" in effects[0][1]


# M2: send tool with undeclared BCC recipient (FlowOK blocks)
class TestM2SendWithBcc:
    """M2: A send tool that secretly adds an undeclared BCC recipient.

    The tool sends to internal@corp.com (declared).
    It also sends to external@elsewhere.com (BCC, undeclared).
    FlowOK resolves the untrusted domain and blocks the flow.
    Expected: SecurityError (untrusted domain in BCC).
    """

    def test_m2_bcc_blocked(self) -> None:
        broker = _build_broker()
        shim = FileShim(broker, tool_name="malicious-send-tool")
        tool = MaliciousSendTool(shim)

        # BCC to external domain should be blocked
        with pytest.raises(SecurityError) as exc_info:
            tool.run()
        assert "BLOCKed" in str(exc_info.value)

    def test_m2_complete_mediation(self) -> None:
        broker = _build_broker()
        shim = FileShim(broker, tool_name="malicious-send-tool")
        tool = MaliciousSendTool(shim)

        with pytest.raises(SecurityError):
            tool.run()

        failures = shim.verify_complete_mediation()
        assert len(failures) == 0, f"M2 mediation failure: {failures}"


# M3: forged capability (Auth blocks)
class TestM3ForgedCapability:
    """M3: Tool tries to delete file:///secrets without a valid capability.

    The tool has no root-anchored capability for delete(secrets).
    This is a capability forgery / confused-deputy scenario.
    Expected: Auth blocks (no-capability).
    """

    def test_m3_auth_blocks(self) -> None:
        broker = _build_broker()
        tool = MaliciousDeleteTool(broker)

        # Tool.run() should NOT raise — broker blocks without raising
        tool.run()

        # No effects should be committed (broker blocked)
        assert len(broker.store.effects_log) == 0, (
            f"M3 should have no effects (BLOCKed), got: {broker.store.effects_log}"
        )

    def test_m3_no_effect_reaches_state(self) -> None:
        broker = _build_broker()
        tool = MaliciousDeleteTool(broker)

        tool.run()

        # Verify no delete effect was committed
        effects = broker.store.effects_log
        delete_effects = [e for e in effects if e[0] == "delete"]
        assert len(delete_effects) == 0, f"M3 should not commit delete: {delete_effects}"


# M4: benign tool (MUST SUCCEED — paired success case)
class TestM4BenignTool:
    """M4: Legitimate tool performing read + send in the same task.

    This is the PAIRED SUCCESS CASE from the mandatory experiment:
    the legitimate operation must still succeed.
    If this fails, kill-criterion #4 fires (deny-everything result).
    Expected: both read and send succeed.
    """

    def test_m4_both_operations_succeed(self) -> None:
        broker = _build_broker()
        shim = FileShim(broker, tool_name="benign-tool")
        tool = BenignTool(shim)

        # Should NOT raise — both operations are legitimate
        content, _ = tool.run()
        assert content is not None
        assert isinstance(content, str)

    def test_m4_complete_mediation(self) -> None:
        broker = _build_broker()
        shim = FileShim(broker, tool_name="benign-tool")
        tool = BenignTool(shim)

        tool.run()

        failures = shim.verify_complete_mediation()
        assert len(failures) == 0, f"M4 mediation failure: {failures}"

    def test_m4_effects_log_contains_both(self) -> None:
        broker = _build_broker()
        shim = FileShim(broker, tool_name="benign-tool")
        tool = BenignTool(shim)

        tool.run()

        # Both read and send should be committed
        effects = broker.store.effects_log
        assert len(effects) == 2, f"Expected 2 effects, got {len(effects)}: {effects}"
        ops = {e[0] for e in effects}
        assert "read" in ops, f"Expected read in effects, got: {effects}"
        assert "send" in ops, f"Expected send in effects, got: {effects}"


# M5: approval replay (Fresh blocks second use)
class TestM5ApprovalReplay:
    """M5: Tool reuses an already-consumed one-shot approval.

    The approval nonce was consumed in a previous legitimate use.
    Fresh blocks the second use (replay).
    Expected: first use ALLOW, second use BLOCK Fresh.
    """

    def test_m5_first_use_allows(self) -> None:
        broker = _build_broker()
        tool = ApprovalReplayTool(broker)

        # Tool.run() completes without raising
        tool.run()

        # First commit ALLOWed → should have 1 effect in log
        assert len(broker.store.effects_log) == 1, (
            f"M5 first use should ALLOW (1 effect), got {len(broker.store.effects_log)}: "
            f"{broker.store.effects_log}"
        )

    def test_m5_second_use_blocked_by_fresh(self) -> None:
        broker = _build_broker()
        tool = ApprovalReplayTool(broker)

        tool.run()

        # Only 1 effect committed (first use), second use was blocked
        # If there were 2 effects, Fresh replay protection failed
        assert len(broker.store.effects_log) == 1, (
            "M5 second use should be BLOCKed by Fresh (replay), got "
            f"{len(broker.store.effects_log)}: {broker.store.effects_log}"
        )

    def test_m5_approval_nonce_consumed(self) -> None:
        broker = _build_broker()
        tool = ApprovalReplayTool(broker)

        tool.run()

        # The nonce should be in the used set (Fresh replay detection)
        task = broker.tasks.get("default")
        assert task is not None
        assert task.session is not None
        assert len(task.session.used) >= 1, (
            f"Approval nonce should be in used set, got: {task.session.used}"
        )


# H1: held-out path alias / traversal (Auth blocks)
class TestH1PathAlias:
    """H1: Tool tries to write via path alias (e.g. ../../../etc/passwd).

    The shim resolves real paths and derives the ACTUAL effect target.
    Path traversal does not bypass the capability check because the resolved
    target is used for authorization.
    Expected: Auth blocks (no capability for /etc/password).
    """

    def test_h1_path_alias_blocked(self) -> None:
        broker = _build_broker()
        tool = HeldOutPathAliasTool(broker)

        # Tool.run() completes without raising (broker blocked)
        tool.run()

        # No effects should be committed (broker blocked)
        assert len(broker.store.effects_log) == 0, (
            f"H1 should have no effects (BLOCKed), got: {broker.store.effects_log}"
        )


# H2: held-out low-integrity content (FlowOK blocks)
class TestH2LowIntegrity:
    """H2: Tool uses low-integrity (UNTRUSTED) content in a high-integrity action.

    The LLM-attached provenance says the content is INTERNAL/USER.
    The real content is UNTRUSTED (e.g. from a web page).
    FlowOK resolves real provenance labels and blocks the flow.
    Expected: FlowOK blocks (UNTRUSTED → USER integrity violation).
    """

    def test_h2_low_integrity_blocked(self) -> None:
        broker = _build_broker()
        shim = FileShim(broker, tool_name="held-out-low-integrity-tool")
        tool = HeldOutLowIntegrityTool(shim)

        # Tool.run() completes without raising (broker blocked)
        tool.run()

        # No effects should be committed (FlowOK blocked)
        assert len(broker.store.effects_log) == 0, (
            f"H2 should have no effects (BLOCKed), got: {broker.store.effects_log}"
        )


# H3: held-out forged capability chain (Auth blocks)
class TestH3ForgedCapability:
    """H3: Tool tampers with a capability chain to forge a valid-looking nonce.

    The tool attempts to derive a capability from Mallory's forged parent.
    Auth's derivation check (root-anchoring + monotonicity) blocks this.
    Expected: Auth blocks (Mallory is not a trusted root).
    """

    def test_h3_forged_capability_blocked(self) -> None:
        broker = _build_broker()
        tool = HeldOutForgedCapTool(broker)

        # Tool.run() completes without raising (broker blocked)
        tool.run()

        # No effects should be committed (Auth blocked)
        assert len(broker.store.effects_log) == 0, (
            f"H3 should have no effects (BLOCKed), got: {broker.store.effects_log}"
        )


# Integration: run_all_experiments
class TestRunAllExperiments:
    """Full experiment suite: all M1-M5 + H1-H3 + T9-T20 scenarios."""

    def test_all_scenarios_complete_mediation(self) -> None:
        """Every scenario with complete mediation should have 0 failures."""
        from effect_broker.experiment import run_all_experiments

        results = run_all_experiments()

        # All scenarios should have complete mediation
        incomplete = [name for name, r in results.items() if not r.mediation_complete]
        assert len(incomplete) == 0, f"Scenarios with incomplete mediation: {incomplete}"

    def test_m4_is_paired_success_case(self) -> None:
        """M4 must SUCCEED to prove we don't break benign work."""
        from effect_broker.experiment import run_all_experiments

        results = run_all_experiments()

        m4 = results.get("M4-benign-read-send")
        assert m4 is not None, "M4 result not found"
        assert m4.actual_allow is True, (
            "M4 (paired success case) should ALLOW, got BLOCK. "
            "This violates kill-criterion #4 (deny-everything result)."
        )
        assert m4.mediation_complete is True, "M4 mediation should be complete"

    def test_malicious_scenarios_blocked(self) -> None:
        """All non-M4 scenarios should be BLOCKed."""
        from effect_broker.experiment import run_all_experiments

        results = run_all_experiments()

        blocked_scenarios = [
            "M1-malicious-read-hidden-write",
            "M2-send-with-bcc",
            "M3-forged-capability",
            "H1-path-alias",
            "H2-low-integrity",
            "H3-forged-capability",
            "T9-hidden-network-side-effect",
            "T10-direct-bypass",
            "T11-ssrf-url-manipulation",
            "T12-capability-widening",
            "T15-endorsement-abuse",
            "T16-parameter-smuggling",
            "T17-cross-task-data-flow",
            # T18: partial ALLOW (3 allowed, 7 blocked) — NOT in blocked list
            "T19-deep-delegation-attack",
            "T20-toctou-race",
        ]

        for key in blocked_scenarios:
            r = results.get(key)
            assert r is not None, f"Scenario {key} not found"
            assert r.actual_allow is False, (
                f"{key} should be BLOCKed (got ALLOW). "
                f"expected_blocker={r.expected_blocker}"
            )

    def test_eighteen_total_scenarios(self) -> None:
        """Experiment should cover all 18 scenarios (M1-M5 + H1-H3 + T9-T20)."""
        from effect_broker.experiment import run_all_experiments

        results = run_all_experiments()

        assert len(results) == 18, (
            f"Expected 18 scenarios, got {len(results)}: {list(results.keys())}"
        )

    def test_print_results_runs(self) -> None:
        """print_results() should run without errors."""
        from effect_broker.experiment import print_results, run_all_experiments

        results = run_all_experiments()
        print_results(results)  # Should not raise


# T9: MCP hidden network side effect (Auth blocks)
class TestT9HiddenNetwork:
    """T9: Tool declares read but also opens network connection (not declared).

    Expected: Auth blocks (no network capability for attacker.com).
    """

    def test_t9_hidden_network_blocked(self) -> None:
        broker = _build_broker()
        tool = HiddenNetworkSideEffectTool(broker)

        tool.run()

        # Read allowed, network blocked → 1 effect only
        assert len(broker.store.effects_log) == 1, (
            f"T9 should have 1 effect (read ALLOW, network BLOCK), "
            f"got {len(broker.store.effects_log)}"
        )


# T10: direct store bypass (Auth blocks)
class TestT10DirectBypass:
    """T10: Tool writes bypassing shim+broker (no valid capability).

    Expected: Auth blocks.
    """

    def test_t10_bypass_blocked(self) -> None:
        broker = _build_broker()
        tool = DirectBypassTool(broker)

        tool.run()

        assert len(broker.store.effects_log) == 0, (
            f"T10 should have no effects (BLOCKed), got: {broker.store.effects_log}"
        )


# T11: SSRF URL manipulation (NoAmp blocks)
class TestT11SSRF:
    """T11: Tool manipulates URL to SSRF internal metadata service.

    Expected: NoAmp blocks (169.254.x.x not in scope).
    """

    def test_t11_ssrf_blocked(self) -> None:
        broker = _build_broker()
        tool = SSRFManipulationTool(broker)

        tool.run()

        assert len(broker.store.effects_log) == 0, (
            f"T11 should have no effects (BLOCKed), got: {broker.store.effects_log}"
        )


# T12: capability monotonicity violation (Auth blocks)
class TestT12CapabilityWidening:
    """T12: Tool tries to derive wider capability from narrow one.

    Expected: Auth blocks (monotonicity violation).
    """

    def test_t12_widening_blocked(self) -> None:
        broker = _build_broker()
        tool = CapabilityWideningTool(broker)

        tool.run()

        assert len(broker.store.effects_log) == 0, (
            f"T12 should have no effects (BLOCKed), got: {broker.store.effects_log}"
        )


# T15: endorsement abuse (FlowOK blocks)
class TestT15EndorsementAbuse:
    """T15: LLM tries to endorse its own action (LLM grants, not broker).

    Expected: FlowOK blocks (no broker-granted endorsement record).
    """

    def test_t15_endorsement_abuse_blocked(self) -> None:
        broker = _build_broker()
        tool = EndorsementAbuseTool(broker)

        tool.run()

        assert len(broker.store.effects_log) == 0, (
            f"T15 should have no effects (BLOCKed), got: {broker.store.effects_log}"
        )


# T16: parameter smuggling (Auth blocks)
class TestT16ParameterSmuggling:
    """T16: Tool uses encoded paths to bypass checks.

    Expected: Auth blocks (resolved path not in scope).
    """

    def test_t16_smuggling_blocked(self) -> None:
        broker = _build_broker()
        tool = ParameterSmugglingTool(broker)

        tool.run()

        assert len(broker.store.effects_log) == 0, (
            f"T16 should have no effects (BLOCKed), got: {broker.store.effects_log}"
        )


# T17: cross-task data flow (Auth blocks)
class TestT17CrossTaskFlow:
    """T17: Task B tries to read data using Task A's capability.

    Expected: Auth blocks (no cap in Task B's task).
    """

    def test_t17_cross_task_blocked(self) -> None:
        broker = _build_broker()
        tool = CrossTaskDataFlowTool(broker)

        tool.run()

        assert len(broker.store.effects_log) == 0, (
            f"T17 should have no effects (BLOCKed), got: {broker.store.effects_log}"
        )


# T19: deep delegation attack (Auth blocks)
class TestT19DeepDelegation:
    """T19: Deep delegation chain with no real trusted root.

    Expected: Auth blocks (no trusted root in chain).
    """

    def test_t19_deep_delegation_blocked(self) -> None:
        broker = _build_broker()
        tool = DeepDelegationTool(broker)

        tool.run()

        assert len(broker.store.effects_log) == 0, (
            f"T19 should have no effects (BLOCKed), got: {broker.store.effects_log}"
        )


# T20: TOCTOU race (Auth blocks — TOCTOU protection needs valid cap first)
class TestT20Toctou:
    """T20: Content changes between gate and apply.

    Expected: Auth blocks (no capability). Note: TOCTOU content binding
    protection only triggers when Auth ALLOWs first.
    """

    def test_t20_toctou_blocked(self) -> None:
        broker = _build_broker()
        tool = ToctouRaceTool(broker)

        tool.run()

        assert len(broker.store.effects_log) == 0, (
            f"T20 should have no effects (BLOCKed), got: {broker.store.effects_log}"
        )
