"""Tests for the mandatory boundary experiment (M1–M5 + H1–H3)

These tests implement the real adversarial tool workload and hold-out variants

  M1: read tool performs an extra write to secrets (hidden side effect)
  M2: send tool attaches an undeclared BCC recipient
  M3: tool uses a forged capability (Auth blocks)
  M4: legitimate read + send in same task (MUST SUCCEED — paired success case)
  M5: one-shot approval consumed, second use blocked by Fresh (replay)
  H1: held-out path alias / traversal (Auth blocks)
  H2: held-out low-integrity content in high-integrity action (FlowOK blocks)
  H3: held-out forged capability chain tampering (Auth blocks)

Each test verifies:
  1. The broker's gate correctly blocks/allows based on expected blocker
  2. Complete mediation: every real effect has a broker-authorized entry
     (op_log matches effects_log for shim-based scenarios)
"""

from __future__ import annotations

import pytest

from effect_broker.experiment import (
    ApprovalReplayTool,
    BenignTool,
    HeldOutForgedCapTool,
    HeldOutLowIntegrityTool,
    HeldOutPathAliasTool,
    MaliciousDeleteTool,
    MaliciousReadTool,
    MaliciousSendTool,
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

        # Read should return content
        assert content is not None, "Read should return content"

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
            f"M5 second use should be BLOCKed by Fresh (replay), got {len(broker.store.effects_log)}: "
            f"{broker.store.effects_log}"
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
    """Full experiment suite: all M1-M5 + H1-H3 scenarios."""

    def test_all_scenarios_complete_mediation(self) -> None:
        """Every scenario with complete mediation should have 0 failures."""
        from effect_broker.experiment import run_all_experiments

        results = run_all_experiments()

        # All scenarios should have complete mediation
        incomplete = [
            name for name, r in results.items()
            if not r.mediation_complete
        ]
        assert len(incomplete) == 0, (
            f"Scenarios with incomplete mediation: {incomplete}"
        )

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
        """M1, M2, M3, H1, H2, H3 should all be BLOCKed."""
        from effect_broker.experiment import run_all_experiments

        results = run_all_experiments()

        blocked_scenarios = [
            "M1-malicous-read-hidden-write",  # M1: hidden write blocked
            "M2-send-with-bcc",              # M2: BCC blocked
            "M3-forged-capability",          # M3: forged cap blocked
            "H1-path-alias",                 # H1: path traversal blocked
            "H2-low-integrity",              # H2: low-integrity content blocked
            "H3-forged-capability",          # H3: forged cap blocked
        ]

        for key in blocked_scenarios:
            r = results.get(key)
            assert r is not None, f"Scenario {key} not found"
            assert r.actual_allow is False, (
                f"{key} should be BLOCKed (got ALLOW). "
                f"expected_blocker={r.expected_blocker}"
            )

    def test_eight_total_scenarios(self) -> None:
        """Experiment should cover all 8 scenarios."""
        from effect_broker.experiment import run_all_experiments

        results = run_all_experiments()

        assert len(results) == 8, f"Expected 8 scenarios, got {len(results)}: {list(results.keys())}"

    def test_print_results_runs(self) -> None:
        """print_results() should run without errors."""
        from effect_broker.experiment import print_results, run_all_experiments

        results = run_all_experiments()
        print_results(results)  # Should not raise
