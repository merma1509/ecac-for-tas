"""Tool Registry: structural enforcement tests.

Tests the ToolRegistry integration with FileShim for T14 (hidden side effect)
and T13 (false MCP description) prevention via structural constraints, not
just metadata-based mediation.

T14 is prevented structurally: a tool that only declared "read" cannot perform
"write" — the ToolRegistry blocks at the shim level before the Effect is built.
The ledger then has no effect to observe, so T14 cannot succeed.

This is the key improvement over the ECAC philosophy (ledger detects after commit):
with ToolRegistry, T14 is prevented before commit.
"""

from __future__ import annotations

import pytest

from effect_broker.broker import EffectBroker
from effect_broker.lattice import Confidentiality
from effect_broker.model import Capability
from effect_broker.shim import FileShim, SecurityError
from effect_broker.tool_registry import ToolDeclaration, ToolRegistry
from effect_broker.traces import build


def _make_broker_and_shim(
    tool_name: str = "default-tool",
    strict: bool = False,
) -> tuple[EffectBroker, FileShim, ToolRegistry]:
    """Create a broker, tool registry, and shim for testing.

    The broker is given capabilities for the test file/email targets so that
    the broker gate can evaluate Auth/FlowOK/NoAmp/Fresh — the structural
    enforcement (ToolRegistry) is tested independently.

    IMPORTANT: _find_capability looks up by (holder, right, target).
    The shim's holder is the tool_name, but broker capabilities use holder="EffectBroker".
    """

    broker = build()
    broker.store._unsafe_bootstrap_file("file:///reports", Confidentiality.INTERNAL)
    broker.store._unsafe_bootstrap_file("file:///secrets", Confidentiality.CONFIDENTIAL)
    broker.store._unsafe_bootstrap_email("internal@corp.com", "INTERNAL")
    broker.store._unsafe_bootstrap_email("team@corp.com", "INTERNAL")

    # Give broker capabilities for test targets.
    # holder="EffectBroker" is the shim's effective holder (the shim acts on behalf of the tool).
    # _find_capability searches by (holder, right, target) → holder="EffectBroker" matches.
    broker.capabilities["r-read:reports"] = Capability(
        owner="User", holder="EffectBroker", right="read", target="file:///reports",
        scope=frozenset({"file:///reports"}), expiry=float("inf"),
        nonce="r-read:reports", derives_from=None,
    )
    broker.capabilities["r-write:reports"] = Capability(
        owner="User", holder="EffectBroker", right="write", target="file:///reports",
        scope=frozenset({"file:///reports"}), expiry=float("inf"),
        nonce="r-write:reports", derives_from=None,
    )
    broker.capabilities["r-write:secrets"] = Capability(
        owner="User", holder="EffectBroker", right="write", target="file:///secrets",
        scope=frozenset({"file:///secrets"}), expiry=float("inf"),
        nonce="r-write:secrets", derives_from=None,
    )
    broker.capabilities["r-send:corp"] = Capability(
        owner="User", holder="EffectBroker", right="send", target="*",
        # Domain-level scope: covers ALL internal email recipients.
        # This is the correct pattern for email capabilities: capability scope
        # is at the domain level, so BCC to team@corp.com passes NoAmp
        # (both "internal@corp.com" and "team@corp.com" → domain label "internal").
        scope=frozenset({"internal"}), expiry=float("inf"),
        nonce="r-send:corp", derives_from=None,
    )
    # Note: r-send:team is not needed for this test. The domain-level
    # r-send:corp covers all internal.com recipients.
    broker.capabilities["r-read:secrets"] = Capability(
        owner="User", holder="EffectBroker", right="read", target="file:///secrets",
        scope=frozenset({"file:///secrets"}), expiry=float("inf"),
        nonce="r-read:secrets", derives_from=None,
    )

    registry = ToolRegistry(strict=strict)
    shim = FileShim(broker, tool_name=tool_name, registry=registry)

    return broker, shim, registry


class TestToolRegistryStructuralEnforcement:
    """Structural enforcement: undeclared rights blocked BEFORE broker.gate()."""

    def test_declared_read_allows_read(self) -> None:
        """A tool that declared read may read."""
        broker, shim, registry = _make_broker_and_shim("read-tool")
        registry.declare(
            ToolDeclaration("read-tool", declared_rights=frozenset({"read"}), declared_targets=frozenset({"file:///reports"}))
        )

        content = shim.read("file:///reports")
        assert "simulated" in content  # shim returns content

    def test_declared_read_blocks_write(self) -> None:
        """T14: A tool that declared only read cannot write (structural enforcement).

        Without ToolRegistry: the write would reach broker.gate() where Auth
        might block (if no write capability), but if tool somehow had write
        capability, the write would succeed.

        With ToolRegistry: the write is blocked at the shim level BEFORE the
        Effect is built → SecurityError → no effect reaches broker.gate().
        This is T14 prevention, not detection.
        """
        broker, shim, registry = _make_broker_and_shim("read-only-tool")
        registry.declare(
            ToolDeclaration("read-only-tool", declared_rights=frozenset({"read"}), declared_targets=frozenset({"file:///reports"}))
        )

        with pytest.raises(SecurityError, match="undeclared-right"):
            shim.write("file:///reports", b"secret data")

    def test_declared_targets_restricts_access(self) -> None:
        """A tool may only access its declared targets."""
        broker, shim, registry = _make_broker_and_shim("reports-tool")
        registry.declare(
            ToolDeclaration("reports-tool", declared_rights=frozenset({"read", "write"}), declared_targets=frozenset({"file:///reports"}))
        )

        # Read on declared target → OK
        content = shim.read("file:///reports")
        assert "simulated" in content

        # Read on undeclared target → BLOCK
        with pytest.raises(SecurityError, match="undeclared-target"):
            shim.read("file:///secrets")

    def test_strict_mode_blocks_unknown_tool(self) -> None:
        """In strict mode, an unknown tool raises SecurityError."""
        broker, shim, registry = _make_broker_and_shim("unknown-tool", strict=True)
        # No declaration for "unknown-tool" → strict mode blocks

        with pytest.raises(SecurityError, match="undeclared-tool"):
            shim.read("file:///reports")

    def test_permissive_mode_allows_unknown_tool(self) -> None:
        """In permissive mode, unknown tools are allowed (documented limitation)."""
        broker, shim, registry = _make_broker_and_shim("unknown-tool", strict=False)
        # No declaration for "unknown-tool" → permissive mode allows (limitation)

        # Should NOT raise — permissive allows unknown tools
        content = shim.read("file:///reports")
        assert "simulated" in content

    def test_extra_targets_must_be_declared(self) -> None:
        """BCC recipients outside declared targets → SecurityError."""
        broker, shim, registry = _make_broker_and_shim("send-tool")
        registry.declare(
            ToolDeclaration(
                "send-tool",
                declared_rights=frozenset({"send"}),
                declared_targets=frozenset({"internal@corp.com"}),
            )
        )

        # BCC to undeclared target → BLOCK before effect is built
        with pytest.raises(SecurityError, match="undeclared-extra-target"):
            shim.send("internal@corp.com", "hello", bcc_1="attacker@elsewhere.com")

    def test_extra_targets_in_scope_allows(self) -> None:
        """BCC to declared target → allowed (structural + broker gate pass).

        Two enforcement layers:
          1. ToolRegistry: checks target ∈ declared_targets → PASSES
          2. broker.gate() (Auth + NoAmp): checks cap scope covers domain → PASSES

        For layer 2 to pass: BCC email must be classified as "internal"
        (matching the capability's scope). We register team@corp.com in
        the store so _domain_for_email("team@corp.com") → "internal".
        """
        from effect_broker.model import Domain

        broker, shim, registry = _make_broker_and_shim("send-team-tool")
        # Register BCC recipient so its domain is "internal"
        broker.store._unsafe_bootstrap_email("team@corp.com", Domain.INTERNAL)

        registry.declare(
            ToolDeclaration(
                "send-team-tool",
                declared_rights=frozenset({"send"}),
                declared_targets=frozenset({"internal@corp.com", "team@corp.com"}),
            )
        )

        # BCC to declared target → OK (both layers pass)
        shim.send("internal@corp.com", "hello", bcc_1="team@corp.com")

    def test_read_and_write_declared_allows_both(self) -> None:
        """A tool that declared both read and write may perform both."""
        broker, shim, registry = _make_broker_and_shim("读写-tool")
        registry.declare(
            ToolDeclaration("读写-tool", declared_rights=frozenset({"read", "write"}), declared_targets=frozenset({"file:///reports"}))
        )

        shim.read("file:///reports")
        shim.write("file:///reports", b"updated")

    def test_mismatched_right_and_target(self) -> None:
        """T13: tool declares "read reports" but attempts "write secrets"."""
        broker, shim, registry = _make_broker_and_shim("reports-reader")
        registry.declare(
            ToolDeclaration("reports-reader", declared_rights=frozenset({"read"}), declared_targets=frozenset({"file:///reports"}))
        )

        # Even if the tool tries to write to a different file, it's blocked
        with pytest.raises(SecurityError, match="undeclared-right"):
            shim.write("file:///secrets", b"stolen")

    def test_no_effect_reaches_broker_on_undeclared_right(self) -> None:
        """Undeclared right: no Effect is built → no ledger entry → complete mediation."""
        broker, shim, registry = _make_broker_and_shim("safe-tool")
        registry.declare(
            ToolDeclaration("safe-tool", declared_rights=frozenset({"read"}), declared_targets=frozenset({"file:///reports"}))
        )

        initial_log_len = len(broker.store.effects_log)

        try:
            shim.write("file:///reports", b"data")
        except SecurityError:
            pass

        # No effect was applied (blocked before Effect was built)
        assert len(broker.store.effects_log) == initial_log_len

    def test_broker_gate_runs_after_structural_check(self) -> None:
        """A declared operation goes through broker.gate() after structural check.

        Two layers: (1) ToolRegistry structural check, (2) broker.gate() semantic check.
        ToolRegistry PASSES → broker.gate() RUNS.
        broker.gate() evaluates Auth/FlowOK/NoAmp/Fresh.
        In this test: capability exists → Auth PASSES.
        """
        broker, shim, registry = _make_broker_and_shim("send-tool")

        registry.declare(
            ToolDeclaration(
                "send-tool",
                declared_rights=frozenset({"send"}),
                declared_targets=frozenset({"internal@corp.com"}),
            )
        )

        # Structural check passes → broker.gate() runs.
        # With a valid capability in broker: Auth passes.
        # NoAmp: "internal" in {"internal"} → PASS.
        # Result: ALLOW (tool could send)
        #
        # To test broker BLOCKING on declared ops, we'd need a capability
        # that fails Auth/FlowOK/NoAmp/Fresh. The key point is that
        # ToolRegistry is a FILTER, not a replacement — broker gate is still
        # evaluated for ALL declared operations.
        shim.send("internal@corp.com", "hello")  # no raise → structural check passed

    def test_dual_defense_layers(self) -> None:
        """ToolRegistry (structural) + broker.gate() (semantic) = complete enforcement.

        Two layers of defense:
          1. ToolRegistry: checks if tool DECLARED this (right, target) → PASSES
          2. broker.gate(): checks if capability EXISTS and is VALID → RUNS

        In this test: tool declared read+write, capability EXISTS → both pass.
        To observe broker blocking on declared ops, we would need a capability
        that fails Auth/FlowOK/NoAmp/Fresh (e.g., expired capability, wrong
        provenance, wrong domain scope).
        """
        broker, shim, registry = _make_broker_and_shim("full-access-tool")

        registry.declare(
            ToolDeclaration(
                "full-access-tool",
                declared_rights=frozenset({"read", "write"}),
                declared_targets=frozenset({"file:///reports"}),
            )
        )

        # Structural check passes (read declared) → broker.gate() runs
        # With valid capability: Auth PASSES
        shim.read("file:///reports")  # no raise

        # Structural check passes (write declared) → broker.gate() runs
        shim.write("file:///reports", b"data")  # no raise

    def test_check_operation_by_name(self) -> None:
        """ToolRegistry.check_operation_by_name() for pre-Effect validation."""
        registry = ToolRegistry()
        registry.declare(
            ToolDeclaration("test-tool", declared_rights=frozenset({"read", "send"}), declared_targets=frozenset({"file:///a", "internal@corp.com"}))  # noqa: E501
        )

        ok, reason = registry.check_operation_by_name("test-tool", "read", "file:///a")
        assert ok, reason

        ok, reason = registry.check_operation_by_name("test-tool", "write", "file:///a")
        assert not ok
        assert "undeclared-right" in reason

        ok, reason = registry.check_operation_by_name("test-tool", "read", "file:///secrets")
        assert not ok
        assert "undeclared-target" in reason

        ok, reason = registry.check_operation_by_name("test-tool", "send", "internal@corp.com", frozenset({"external@evil.com"}))  # noqa: E501
        assert not ok
        assert "undeclared-extra-target" in reason

    def test_t14_hidden_write_prevented(self) -> None:
        """T14: A read-only tool that secretly tries to write is blocked.

        This is the key T14 fix: tool declares only "read" on reports.
        Even if the tool has a write capability (from broker setup),
        ToolRegistry blocks the write attempt BEFORE the Effect is built.
        The ledger never sees a write effect — T14 is prevented.
        """
        broker, shim, registry = _make_broker_and_shim("reports-reader-tool")
        registry.declare(
            ToolDeclaration(
                "reports-reader-tool",
                declared_rights=frozenset({"read"}),
                declared_targets=frozenset({"file:///reports"}),
            )
        )

        # The tool's hidden agenda: write to reports (audit log injection)
        # ToolRegistry blocks this structurally — no Effect reaches the broker.
        with pytest.raises(SecurityError, match="undeclared-right"):
            shim.write("file:///reports", b"injected audit log entry")
