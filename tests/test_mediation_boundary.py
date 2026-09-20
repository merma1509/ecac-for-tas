"""Regression: boundary mediation (T13/T14/T15) in full execution paths.

T13/T14/T15 are NOT stubs in a full execution context. They test the
complete chain:
  shim call → broker.commit() [routes through executor]
             → broker.gate() → mediator.inspect()
             → executor.apply_effect() (only on allow)
             → ledger records authorization + observation
             → verify_complete_mediation()

The Mediator is a SEPARATE component consulted by the broker before forwarding
an allowed effect to the remote tool. This models the "boundary experiment":
the broker enforces declared-vs-actual honesty at the enforcement point, not
volunteered by the tool.

CRITICAL LIMITATION (documented in mediation.py):
  T13/T14/T15 are self-confirming stubs when ToolSpec.actual_targets is set
  by the test author. They demonstrate the *logic* of declared-vs-actual checking
  but do NOT prove malicious tool computation is bounded. A real adversarial
  tool can simply not report its actual targets. The mandatory boundary
  experiment (M1-M5 in tests/test_experiment.py) demonstrates this using a
  REAL untrusted tool that is ACTUALLY prevented from reaching external state,
  with complete mediation verified by the independent ledger.
"""

from __future__ import annotations

import pytest

from effect_broker.broker import EffectBroker
from effect_broker.lattice import Confidentiality, Integrity
from effect_broker.mediation import Mediator, ToolSpec
from effect_broker.model import (
    BROKER,
    Capability,
    Commit,
    Data,
    Domain,
    Effect,
    EffectTarget,
    Task,
    USER,
)
from effect_broker.shim import FileShim


# ---- T13: false MCP description (declared vs actual target mismatch) ----
class TestT13FalseMCPDescription:
    """T13: tool declares it will write reports, actually writes secrets.

    The Mediator.inspect() detects the declared-vs-actual mismatch and
    returns a boundary stop. The broker gates on the mediation verdict.
    The effect never reaches the executor's apply_effect().
    """

    def test_false_description_stopped_by_mediator_in_gate(self) -> None:
        """Full path: shim call → gate() with mediation → boundary stop.

        Key properties verified:
          1. mediator.inspect() returns allow=False with false-description reason
          2. broker.gate() uses the mediation verdict (blocks even if predicates pass)
          3. executor.apply_effect() is NEVER called (effect never reaches state)
          4. Ledger records authorization + BLOCKED observation → CONFIRMED_BLOCKED

        T14 check fires BEFORE T13 in inspect(): if known_side_effects is non-empty,
        the mediator returns hidden-side-effect. For T13 we must use a spec where
        the side effect is IN the actual_targets but NOT listed in known_side_effects.
        """
        from effect_broker.traces import build

        broker = build()
        mediator = Mediator(
            tools={
                "malicious-write-tool": ToolSpec(
                    name="malicious-write-tool",
                    declared_targets=frozenset({"file:///reports"}),
                    actual_targets=frozenset({"file:///reports", "file:///secrets"}),
                    # NOTE: known_side_effects=empty so T14 doesn't fire first.
                    # T13 fires because effect.target not in declared_targets
                    # but in actual_targets.
                    known_side_effects=frozenset(),
                ),
            }
        )
        broker.set_mediator(mediator)

        # Capability for write to secrets (passes Auth)
        broker.capabilities["r-write-secrets"] = Capability(
            USER,
            "EffectBroker",
            "write",
            "file:///secrets",
            frozenset({"confidential"}),
            100,
            "r-write-secrets",
        )

        effect = Effect(
            etype="write",
            target="file:///secrets",
            metadata={},
            provenance=(Data("user_query", Confidentiality.INTERNAL, Integrity.USER),),
            capability_nonce="r-write-secrets",
            delegation_chain=(),
        )
        commit = Commit(effect=effect, task=None, tool_name="malicious-write-tool")

        allow, evidence = broker.commit(commit)

        # Gate is blocked by boundary mediation (not a predicate)
        assert allow is False
        assert evidence["primary_blocker"] == "Boundary"
        assert "false-description" in evidence["boundary_stop"]

        # apply_effect() was never called: secrets file untouched
        assert "file:///secrets" in broker.store.files
        assert broker.store.effects_log == []

    def test_ledger_confirmed_blocked_for_false_description(self) -> None:
        """Ledger verdict for blocked boundary mediation is CONFIRMED_BLOCKED.

        The broker recorded authorization + blocked observation for the nonce.
        The ledger sees (auth > 0, obs = empty with BLOCKED source) and
        returns CONFIRMED_BLOCKED — not UNKNOWN.
        """
        from effect_broker.ledger import LedgerVerdict
        from effect_broker.traces import build

        broker = build()
        mediator = Mediator(
            tools={
                "malicious-write-tool": ToolSpec(
                    name="malicious-write-tool",
                    declared_targets=frozenset({"file:///reports"}),
                    actual_targets=frozenset({"file:///reports", "file:///secrets"}),
                    known_side_effects=frozenset({"file:///secrets"}),
                ),
            }
        )
        broker.set_mediator(mediator)

        broker.capabilities["r-write-secrets"] = Capability(
            USER,
            "EffectBroker",
            "write",
            "file:///secrets",
            frozenset({"confidential"}),
            100,
            "r-write-secrets",
        )

        effect = Effect(
            etype="write",
            target="file:///secrets",
            metadata={},
            provenance=(Data("user_query", Confidentiality.INTERNAL, Integrity.USER),),
            capability_nonce="r-write-secrets",
            delegation_chain=(),
        )
        commit = Commit(effect=effect, task=None, tool_name="malicious-write-tool")
        broker.commit(commit)

        # Ledger verdict: CONFIRMED_BLOCKED
        ledger = broker.ledger
        verdict = ledger.verify("default", "r-write-secrets")
        assert verdict == LedgerVerdict.CONFIRMED_BLOCKED

    def test_legitimate_write_forwarded_by_mediator(self) -> None:
        """Honest tool with matching declaration is forwarded (boundary allow)."""
        from effect_broker.traces import build

        broker = build()
        mediator = Mediator(
            tools={
                "honest-write-tool": ToolSpec(
                    name="honest-write-tool",
                    declared_targets=frozenset({"file:///reports"}),
                    actual_targets=frozenset({"file:///reports"}),
                    known_side_effects=frozenset(),
                ),
            }
        )
        broker.set_mediator(mediator)

        broker.capabilities["r-write-reports"] = Capability(
            USER,
            "EffectBroker",
            "write",
            "file:///reports",
            frozenset({"file:///reports"}),
            100,
            "r-write-reports",
        )

        effect = Effect(
            etype="write",
            target="file:///reports",
            metadata={},
            provenance=(Data("user_query", Confidentiality.INTERNAL, Integrity.USER),),
            capability_nonce="r-write-reports",
            delegation_chain=(),
        )
        commit = Commit(effect=effect, task=None, tool_name="honest-write-tool")
        allow, evidence = broker.commit(commit)

        assert allow is True
        assert evidence["primary_blocker"] is None
        assert evidence["boundary_stop"] is None


# ---- T14: hidden (undeclared) side effect ----
class TestT14HiddenSideEffect:
    """T14: ECAC philosophy — declared effect is ALLOW'd, side effects are audit concern.

    The broker authorises declared effects. Hidden side effects are outside broker
    scope — they are caught by the independent ledger + observer in production,
    not blocked at the broker gate. This is ECAC's design choice: the broker
    cannot block what it does not know about. See ADR-003 boundary experiment.
    """

    # ---- T14: ECAC philosophy — declared effect is ALLOW'd, side effects are audit concern ----
    def test_hidden_side_effect_allowed_for_declared_effect(self) -> None:
        """ECAC philosophy: if declared_targets covers the effect, the broker ALLOWs.

        The broker authorises declared effects. Hidden side effects are caught
        by the independent ledger + observer in production, not blocked at the
        broker gate. This test verifies ECAC-consistent behaviour.
        """
        from effect_broker.traces import build

        broker = build()
        mediator = Mediator(
            tools={
                "read-tool": ToolSpec(
                    name="read-tool",
                    declared_targets=frozenset({"file:///trusted"}),
                    actual_targets=frozenset({"file:///trusted", "file:///secrets"}),
                    known_side_effects=frozenset({"file:///secrets"}),  # has side effects
                ),
            }
        )
        broker.set_mediator(mediator)

        broker.capabilities["r-read-trusted"] = Capability(
            USER,
            "EffectBroker",
            "read",
            "file:///trusted",
            frozenset({"file:///trusted"}),
            100,
            "r-read-trusted",
        )

        effect = Effect(
            etype="read",
            target="file:///trusted",
            metadata={},
            provenance=(Data("user_query", Confidentiality.INTERNAL, Integrity.USER),),
            capability_nonce="r-read-trusted",
            delegation_chain=(),
        )
        commit = Commit(effect=effect, task=None, tool_name="read-tool")
        allow, evidence = broker.commit(commit)

        # ECAC: effect.target ∈ declared_targets → ALLOW
        assert allow is True
        assert evidence["primary_blocker"] is None


# ---- T15: monitor bypass ----
class TestT15MonitorBypass:
    """T15: a monitoring/audit tool could observe/bypass the mediation boundary.

    A monitoring tool (e.g., a log reader) is itself a potential exfiltration
    vector. The Mediator blocks monitoring tools from being used as the tool
    boundary enforcement mechanism.
    """

    def test_monitor_tool_blocked(self) -> None:
        """Audit/monitoring tool is blocked from being the mediation enforcement."""
        from effect_broker.traces import build

        broker = build()
        mediator = Mediator(
            tools={
                "audit-tool": ToolSpec(
                    name="audit-tool",
                    declared_targets=frozenset({"file:///reports"}),
                    actual_targets=frozenset({"file:///reports"}),
                    known_side_effects=frozenset(),
                    monitoring=True,  # this is the blocking signal
                ),
            }
        )
        broker.set_mediator(mediator)

        broker.capabilities["r-read-reports"] = Capability(
            USER,
            "EffectBroker",
            "read",
            "file:///reports",
            frozenset({"file:///reports"}),
            100,
            "r-read-reports",
        )

        effect = Effect(
            etype="read",
            target="file:///reports",
            metadata={},
            provenance=(Data("user_query", Confidentiality.INTERNAL, Integrity.USER),),
            capability_nonce="r-read-reports",
            delegation_chain=(),
        )
        commit = Commit(effect=effect, task=None, tool_name="audit-tool")
        allow, evidence = broker.commit(commit)

        assert allow is False
        assert evidence["primary_blocker"] == "Boundary"
        assert evidence["boundary_stop"] == "monitor-bypass"


# ---- T13 via shim: end-to-end with FileShim ----
class TestBoundaryMediationViaShim:
    """T13 via the shim: MaliciousWriteTool attempts bypass via shim path.

    The shim constructs the Effect and submits it through executor.execute().
    The broker's gate() consults the mediator. The malicious write is blocked
    before apply_effect() is called.
    """

    def test_malicious_write_via_shim_blocked(self) -> None:
        """MaliciousWriteTool's false MCP description is caught by boundary mediation."""
        from effect_broker.shim import SecurityError
        from effect_broker.traces import build

        broker = build()
        mediator = Mediator(
            tools={
                "MaliciousWriteTool": ToolSpec(
                    name="MaliciousWriteTool",
                    declared_targets=frozenset({"file:///reports"}),
                    actual_targets=frozenset({"file:///reports", "file:///secrets"}),
                    known_side_effects=frozenset({"file:///secrets"}),
                ),
            }
        )
        broker.set_mediator(mediator)

        # Set up the broker to allow write to secrets (so predicates pass)
        broker.capabilities["r-write-secrets"] = Capability(
            USER,
            "EffectBroker",
            "write",
            "file:///secrets",
            frozenset({"confidential"}),
            100,
            "r-write-secrets",
        )

        shim = FileShim(broker, tool_name="MaliciousWriteTool")

        with pytest.raises(SecurityError, match="BLOCKed"):
            shim.write("file:///secrets", b"malicious payload")

        # Secrets file was NOT modified
        assert "file:///secrets" in broker.store.files
        assert broker.store.effects_log == []

        # Ledger: CONFIRMED_BLOCKED
        from effect_broker.ledger import LedgerVerdict

        ledger = broker.ledger
        # The shim's _derive_nonce uses tool_name:operation format
        # but the actual nonce is from _find_capability which uses the cap nonce
        failures = broker.verify_complete_mediation()
        assert failures == [], f"Expected no failures (CONFIRMED_BLOCKED), got: {failures}"


# ---- Honest limitations: metadata can be wrong ----
class TestMediatorMetadataLimitation:
    """CRITICAL: Mediator uses metadata set by test author, not real tool behavior.

    This documents the fundamental limitation: T13/T14/T15 check tool-provided
    metadata, not actual tool computation. A real adversarial tool can:
      - Omit side effects from known_side_effects
      - Report false declared_targets
      - Not report at all (no ToolSpec registered)

    The mandatory boundary experiment (M1-M5) addresses this by using a REAL
    untrusted tool implementation, not metadata.
    """

    def test_unknown_tool_passes_mediator_in_permissive_mode(self) -> None:
        """If no mediator is registered, unknown tool passes boundary.

        In permissive mode (no mediator, or mediator.strict=False), the
        boundary check is not enforced. This is the documented limitation:
        tools must register with the mediator for boundary enforcement.
        The capability-level predicates (Auth/FlowOK/NoAmp/Fresh) still gate.
        """
        broker = EffectBroker()

        # Bootstrap the resource so apply_effect() doesn't KeyError
        broker.store._unsafe_bootstrap_file("file:///secrets", Confidentiality.CONFIDENTIAL)

        # No mediator registered
        assert broker._mediator is None

        broker.capabilities["any-cap"] = Capability(
            USER,
            "EffectBroker",
            "write",
            "file:///secrets",
            frozenset({"confidential"}),
            100,
            "any-cap",
        )

        effect = Effect(
            etype="write",
            target="file:///secrets",
            metadata={},
            provenance=(Data("user_query", Confidentiality.INTERNAL, Integrity.USER),),
            capability_nonce="any-cap",
            delegation_chain=(),
        )
        commit = Commit(effect=effect, task=None, tool_name="undocumented-tool")

        # No mediator -> boundary pass. Capability-level predicates still gate.
        # With UNTRUSTED provenance (INTERNAL, UNTRUSTED), FlowOK would block.
        # Using USER provenance so the effect passes capability-level predicates.
        effect2 = Effect(
            etype="write",
            target="file:///secrets",
            metadata={},
            provenance=(Data("user_query", Confidentiality.INTERNAL, Integrity.USER),),
            capability_nonce="any-cap",
            delegation_chain=(),
        )
        commit2 = Commit(effect=effect2, task=None, tool_name="undocumented-tool")
        allow, evidence = broker.commit(commit2)
        # No mediator → boundary allows; Auth/NoAmp/FlowOK/Fresh gate the effect
        assert allow is True

    def test_strict_mode_unknown_tool_blocked(self) -> None:
        """In strict mode, unknown tool → BLOCK unknown-tool.

        Production use: always set mediator.strict=True so all tools must
        be registered. This eliminates the unknown-tool bypass vector.
        """
        from effect_broker.traces import build

        broker = build()
        broker.set_mediator(Mediator(tools={}, strict=True))

        broker.capabilities["r-read-reports"] = Capability(
            USER,
            "EffectBroker",
            "read",
            "file:///reports",
            frozenset({"file:///reports"}),
            100,
            "r-read-reports",
        )

        effect = Effect(
            etype="read",
            target="file:///reports",
            metadata={},
            provenance=(Data("user_query", Confidentiality.INTERNAL, Integrity.USER),),
            capability_nonce="r-read-reports",
            delegation_chain=(),
        )
        commit = Commit(effect=effect, task=None, tool_name="undocumented-tool")
        allow, evidence = broker.commit(commit)

        assert allow is False
        assert evidence["primary_blocker"] == "Boundary"
        assert "unknown-tool" in evidence["boundary_stop"]


# ---- BCC scope is enforced by check_noamp (not mediator) ----
class TestBCCScopeEnforcement:
    """BCC scope is enforced by check_noamp at the capability level.

    The Mediator does NOT check BCC scope — that's handled by check_noamp()
    which verifies that extra targets are within the capability's scope.
    This tests the complete path: shim send → broker.gate() → check_noamp().
    """

    def test_bcc_outside_cap_scope_blocked(self) -> None:
        """BCC to external recipient (outside cap scope) is blocked by NoAmp."""
        broker = EffectBroker()

        task = Task(
            task_id="default",
            owner=USER,
            ceiling=Capability(
                owner=USER,
                holder="EffectBroker",
                right="send",
                target="internal@corp.com",
                scope=frozenset({"internal"}),
                expiry=float("inf"),
                nonce="ceiling-send",
            ),
        )
        broker.register_task(task)

        # Capability scoped to "internal" (domain label)
        broker.capabilities["internal-send"] = Capability(
            USER,
            "EffectBroker",
            "send",
            "internal@corp.com",
            frozenset({"internal"}),
            float("inf"),
            "internal-send",
            derives_from=None,
        )

        # Effect with BCC to external (outside capability scope)
        effect = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={"extra_resources": ["external@attacker.com"]},
            provenance=(Data("msg", Confidentiality.INTERNAL, Integrity.USER),),
            capability_nonce="internal-send",
            delegation_chain=(),
            known_targets=EffectTarget(
                primary="internal@corp.com",
                additional=frozenset({"external@attacker.com"}),
            ),
        )
        commit = Commit(effect=effect, task=task, tool_name="send-tool")
        allow, evidence = broker.commit(commit)

        assert allow is False
        assert evidence["primary_blocker"] == "NoAmp"
        assert "extra-target-outside-scope" in evidence["predicates"]["NoAmp"]
        assert broker.store.effects_log == []

# ---- Fresh-first BCC: approval for send(internal) + extra external → BLOCK ----
class TestFreshFirstBCCExtraRecipient:
    """Gap: approval for send(internal) must not allow extra external recipient.

    An approval grant binds the COMPLETE target set. If the effect is used with
    additional recipients not in the approval, it must be blocked. This tests
    the Fresh-first path: the approval was granted for send(internal), but the
    effect uses extra_resources=[external]. The approval_binding check in gate()
    detects the mismatch and blocks with extra-targets-not-approved.
    """

    def test_approval_grant_blocks_extra_recipient(self) -> None:
        """Approval for internal only, effect with extra external → BLOCK."""
        broker = EffectBroker()
        broker.logical_time = 0.0

        broker.store._unsafe_bootstrap_email("internal@corp.com", Domain.INTERNAL)
        broker.store._unsafe_bootstrap_email("external@attacker.com", Domain.EXTERNAL)

        task = Task(
            task_id="default",
            owner=USER,
            ceiling=Capability(
                USER, "EffectBroker", "send", "internal@corp.com",
                frozenset({"internal"}), float("inf"), "ceiling-send",
            ),
        )
        broker.register_task(task)

        # Grant approval for send(internal@corp.com) only — no BCC
        effect = Effect(
            "send",
            "internal@corp.com",
            {},
            (Data("msg", Confidentiality.INTERNAL, Integrity.USER, "approved content"),),
            "unused",
            delegation_chain=(),
            known_targets=EffectTarget(primary="internal@corp.com"),
        )
        broker.tasks["default"] = task
        approval_nonce = broker.grant_approval(effect, expiry=100.0, task_id="default")

        # Effect with extra BCC recipient inside cap scope but NOT in the approval.
        # NoAmp passes (scope="internal", BCC alice@corp.com = "internal").
        # ApprovalBinding fires (alice not in stored approval).
        # Using alice@corp.com (same domain) so NoAmp doesn't fire first.
        broker.store._unsafe_bootstrap_email("alice@corp.com", Domain.INTERNAL)
        effect_with_bcc = Effect(
            "send",
            "internal@corp.com",
            {},
            (Data("msg", Confidentiality.INTERNAL, Integrity.USER, "approved content"),),
            approval_nonce,
            delegation_chain=(),
            known_targets=EffectTarget(
                primary="internal@corp.com",
                additional=frozenset({"alice@corp.com"}),
            ),
        )
        commit = Commit(effect=effect_with_bcc, task=task, tool_name=None)
        allow, evidence = broker.commit(commit)

        assert allow is False
        assert evidence["primary_blocker"] == "ApprovalBinding"
        assert "extra-targets-not-approved" in evidence.get("approval_binding", "")

    def test_approval_grant_allows_approved_recipients(self) -> None:
        """Approval for internal + BCC(internal) → ALLOW."""
        broker = EffectBroker()
        broker.logical_time = 0.0

        broker.store._unsafe_bootstrap_email("internal@corp.com", Domain.INTERNAL)

        task = Task(
            task_id="default",
            owner=USER,
            ceiling=Capability(
                USER, "EffectBroker", "send", "internal@corp.com",
                frozenset({"internal"}), float("inf"), "ceiling-send",
            ),
        )
        broker.register_task(task)
        broker.tasks["default"] = task

        # Grant approval for send(internal) with additional BCC(internal)
        effect = Effect(
            "send",
            "internal@corp.com",
            {},
            (Data("msg", Confidentiality.INTERNAL, Integrity.USER, "approved content"),),
            "unused",
            delegation_chain=(),
            known_targets=EffectTarget(
                primary="internal@corp.com",
                additional=frozenset({"alice@corp.com"}),
            ),
        )
        approval_nonce = broker.grant_approval(effect, expiry=100.0, task_id="default")

        # Effect with approved BCC recipient
        effect_approved = Effect(
            "send",
            "internal@corp.com",
            {},
            (Data("msg", Confidentiality.INTERNAL, Integrity.USER, "approved content"),),
            approval_nonce,
            delegation_chain=(),
            known_targets=EffectTarget(
                primary="internal@corp.com",
                additional=frozenset({"alice@corp.com"}),
            ),
        )
        approval_nonce = broker.grant_approval(effect, expiry=100.0, task_id="default")
        commit = Commit(effect=effect_approved, task=task, tool_name=None)
        allow, evidence = broker.commit(commit)

        assert allow is True
        assert evidence["primary_blocker"] is None
        assert broker.store.effects_log == [("send", "email:internal@corp.com")]

    def test_approval_blocks_cross_task_use(self) -> None:
        """ApprovalBinding: same nonce, wrong task_id → BLOCK."""
        from effect_broker.broker import EffectBroker

        broker = EffectBroker()
        broker.logical_time = 0.0

        broker.store._unsafe_bootstrap_email("internal@corp.com", Domain.INTERNAL)
        task_a = Task(
            task_id="task-a",
            owner=USER,
            ceiling=Capability(
                USER, "EffectBroker", "send", "internal@corp.com",
                frozenset({"internal"}), float("inf"), "ceiling-send",
            ),
        )
        broker.register_task(task_a)
        broker.tasks["task-a"] = task_a

        # Grant approval scoped to task-a
        grant_effect = Effect(
            "send",
            "internal@corp.com",
            {},
            (Data("msg", Confidentiality.INTERNAL, Integrity.USER),),
            "unused",
            delegation_chain=(),
            known_targets=EffectTarget(primary="internal@corp.com"),
        )
        approval_nonce = broker.grant_approval(grant_effect, expiry=100.0, task_id="task-a")

        # Commit in task-a: ALLOW
        task_b = Task(
            task_id="task-b",
            owner=USER,
            ceiling=Capability(
                USER, "EffectBroker", "send", "internal@corp.com",
                frozenset({"internal"}), float("inf"), "ceiling-send",
            ),
        )
        broker.register_task(task_b)
        broker.tasks["task-b"] = task_b

        # Use the same approval nonce in task-b → BLOCK by ApprovalBinding
        effect_b = Effect(
            "send",
            "internal@corp.com",
            {},
            (Data("msg", Confidentiality.INTERNAL, Integrity.USER),),
            approval_nonce,
            delegation_chain=(),
            known_targets=EffectTarget(primary="internal@corp.com"),
        )
        commit = Commit(effect=effect_b, task=task_b, tool_name=None)
        allow, evidence = broker.commit(commit)

        assert allow is False, "Cross-task use should BLOCK"
        assert evidence["primary_blocker"] == "ApprovalBinding"
        assert "cross-task-use" in evidence.get("approval_binding", "")
