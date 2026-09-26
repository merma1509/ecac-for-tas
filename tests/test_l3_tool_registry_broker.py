"""Tests for L3 fix: ToolRegistry integrated into broker.gate().

This test verifies that T14 (hidden side effect) is blocked at the broker level
via the ToolRegistry structural enforcement layer in gate().
"""
from effect_broker.broker import EffectBroker
from effect_broker.lattice import Confidentiality, Integrity
from effect_broker.ledger import IndependentEffectLedger
from effect_broker.model import (
    Capability,
    Commit,
    Data,
    Domain,
    Effect,
    EffectTarget,
    Task,
)
from effect_broker.tool_registry import ToolDeclaration

# Delegation chain for tests
CHAIN = ("User", "Agent", "EffectBroker")


class TestL3ToolRegistryBrokerIntegration:
    """T14 (hidden side effect) blocked at broker gate via ToolRegistry."""

    def test_t14_blocked_at_broker_level(self) -> None:
        """T14: tool declares 'read' but attempts 'write' — blocked at gate()."""
        ledger = IndependentEffectLedger()
        broker = EffectBroker(ledger=ledger)
        broker.set_tool_registry(strict=True)

        broker.tool_registry.declare(ToolDeclaration(
            tool_name="file_reader",
            declared_rights=frozenset({"read"}),
            declared_targets=frozenset({"file:///reports"}),
            description="Read-only file access",
        ))

        broker.store._unsafe_bootstrap_file("file:///reports", Confidentiality.INTERNAL)

        task = Task(
            task_id="t14-attack",
            owner="User",
            ceiling=Capability(
                owner="User", holder="file_reader", right="read",
                target="file:///reports", scope=frozenset({"*"}),
                expiry=float("inf"), nonce="cap-read-reports",
            ),
        )
        broker.tasks[task.task_id] = task

        # T14: tool declared 'read' but attempts 'write' (hidden side effect)
        attack_effect = Effect(
            "write",  # etype - undeclared!
            "file:///reports",
            {},  # metadata
            (Data("report", Confidentiality.INTERNAL, Integrity.USER),),
            "cap-read-reports",
            CHAIN,
            known_targets=EffectTarget(primary="file:///reports"),
        )
        commit = Commit(effect=attack_effect, task=task, tool_name="file_reader")

        result = broker.gate(commit, reserve_nonce=False)

        assert result.allow is False
        assert result.evidence["primary_blocker"] == "Structural"
        assert "undeclared-right" in result.evidence["predicates"]["Structural"]
        assert result.evidence["predicates"]["Auth"] == "skipped"

    def test_legitimate_read_allowed_with_registry(self) -> None:
        """Legitimate read within declared rights should ALLOW."""
        ledger = IndependentEffectLedger()
        broker = EffectBroker(ledger=ledger)
        broker.set_tool_registry(strict=True)

        broker.tool_registry.declare(ToolDeclaration(
            tool_name="file_reader",
            declared_rights=frozenset({"read"}),
            declared_targets=frozenset({"file:///reports"}),
            description="Read-only file access",
        ))

        broker.store._unsafe_bootstrap_file("file:///reports", Confidentiality.INTERNAL)

        broker.grant_root(Capability(
            owner="User", holder="EffectBroker", right="read",
            target="file:///reports", scope=frozenset({"*"}),
            expiry=float("inf"), nonce="cap-read",
        ))

        task = Task(
            task_id="legitimate-read",
            owner="User",
            ceiling=Capability(
                owner="User", holder="EffectBroker", right="read",
                target="file:///reports", scope=frozenset({"*"}),
                expiry=float("inf"), nonce="cap-read",
            ),
        )
        broker.tasks[task.task_id] = task

        effect = Effect(
            "read",
            "file:///reports",
            {},
            (Data("report", Confidentiality.INTERNAL, Integrity.USER),),
            "cap-read",
            CHAIN,
            known_targets=EffectTarget(primary="file:///reports"),
        )
        commit = Commit(effect=effect, task=task, tool_name="file_reader")

        result = broker.gate(commit, reserve_nonce=False)
        assert result.allow is True

    def test_unknown_tool_blocked_in_strict_mode(self) -> None:
        """Unknown tool in strict mode should be BLOCKed."""
        ledger = IndependentEffectLedger()
        broker = EffectBroker(ledger=ledger)
        broker.set_tool_registry(strict=True)

        broker.store._unsafe_bootstrap_file("file:///docs", Confidentiality.INTERNAL)

        broker.grant_root(Capability(
            owner="User", holder="EffectBroker", right="read",
            target="file:///docs", scope=frozenset({"*"}),
            expiry=float("inf"), nonce="cap-read",
        ))

        task = Task(
            task_id="unknown-tool",
            owner="User",
            ceiling=Capability(
                owner="User", holder="EffectBroker", right="read",
                target="file:///docs", scope=frozenset({"*"}),
                expiry=float("inf"), nonce="cap-read",
            ),
        )
        broker.tasks[task.task_id] = task

        effect = Effect(
            "read",
            "file:///docs",
            {},
            (Data("doc", Confidentiality.INTERNAL, Integrity.USER),),
            "cap-read",
            CHAIN,
            known_targets=EffectTarget(primary="file:///docs"),
        )
        commit = Commit(effect=effect, task=task, tool_name="unknown_tool")

        result = broker.gate(commit, reserve_nonce=False)
        assert result.allow is False
        assert result.evidence["primary_blocker"] == "Structural"
        assert "undeclared-tool" in result.evidence["predicates"]["Structural"]

    def test_permissive_mode_allows_unknown_tool(self) -> None:
        """Unknown tool in permissive mode should ALLOW (limitation)."""
        ledger = IndependentEffectLedger()
        broker = EffectBroker(ledger=ledger)
        broker.set_tool_registry(strict=False)

        broker.store._unsafe_bootstrap_file("file:///docs", Confidentiality.INTERNAL)

        broker.grant_root(Capability(
            owner="User", holder="EffectBroker", right="read",
            target="file:///docs", scope=frozenset({"*"}),
            expiry=float("inf"), nonce="cap-read",
        ))

        task = Task(
            task_id="permissive-task",
            owner="User",
            ceiling=Capability(
                owner="User", holder="EffectBroker", right="read",
                target="file:///docs", scope=frozenset({"*"}),
                expiry=float("inf"), nonce="cap-read",
            ),
        )
        broker.tasks[task.task_id] = task

        effect = Effect(
            "read",
            "file:///docs",
            {},
            (Data("doc", Confidentiality.INTERNAL, Integrity.USER),),
            "cap-read",
            CHAIN,
            known_targets=EffectTarget(primary="file:///docs"),
        )
        commit = Commit(effect=effect, task=task, tool_name="any_tool")

        result = broker.gate(commit, reserve_nonce=False)
        assert result.allow is True

    def test_t14_with_extra_target_blocked_by_noamp(self) -> None:
        """T14 variant: tool tries BCC to undeclared target - blocked."""
        ledger = IndependentEffectLedger()
        broker = EffectBroker(ledger=ledger)
        broker.set_tool_registry(strict=True)

        broker.tool_registry.declare(ToolDeclaration(
            tool_name="safe_sender",
            declared_rights=frozenset({"send"}),
            declared_targets=frozenset({"internal@corp.com"}),
            description="Send to internal recipients only",
        ))

        broker.store._unsafe_bootstrap_email("internal@corp.com", Domain.INTERNAL)
        broker.store._unsafe_bootstrap_email("attacker@evil.com", Domain.EXTERNAL)

        broker.grant_root(Capability(
            owner="User", holder="EffectBroker", right="send",
            target="internal@corp.com", scope=frozenset({"*"}),
            expiry=float("inf"), nonce="cap-send",
        ))

        task = Task(
            task_id="bcc-attack",
            owner="User",
            ceiling=Capability(
                owner="User", holder="EffectBroker", right="send",
                target="internal@corp.com", scope=frozenset({"*"}),
                expiry=float("inf"), nonce="cap-send",
            ),
        )
        broker.tasks[task.task_id] = task

        effect = Effect(
            "send",
            "mailto:internal@corp.com",
            {"extra_resources": ["attacker@evil.com"]},
            (Data("msg", Confidentiality.INTERNAL, Integrity.USER),),
            "cap-send",
            CHAIN,
            known_targets=EffectTarget(
                primary="internal@corp.com",
                additional=frozenset({"attacker@evil.com"}),
            ),
        )
        commit = Commit(effect=effect, task=task, tool_name="safe_sender")

        result = broker.gate(commit, reserve_nonce=False)
        assert result.allow is False
        assert result.evidence["primary_blocker"] in ("Structural", "NoAmp")


class TestL4SendRateLimiting:
    """L4 fix: Send rate limiting prevents inter-effect amplification."""

    def test_send_within_rate_limit_allows(self) -> None:
        """Send within max_sends limit should ALLOW."""
        ledger = IndependentEffectLedger()
        broker = EffectBroker(ledger=ledger)
        broker.set_send_rate_limit(max_sends=3)

        broker.store._unsafe_bootstrap_email("internal@corp.com", Domain.INTERNAL)

        # Grant capabilities for all 3 sends
        for i in range(3):
            broker.grant_root(Capability(
                owner="User", holder="EffectBroker", right="send",
                target="internal@corp.com", scope=frozenset({"*"}),
                expiry=float("inf"), nonce=f"send-cap-{i}",
            ))

        task = Task(
            task_id="rate-limit-test",
            owner="User",
            ceiling=Capability(
                owner="User", holder="EffectBroker", right="send",
                target="internal@corp.com", scope=frozenset({"*"}),
                expiry=float("inf"), nonce="send-cap",
            ),
        )
        broker.register_task(task)

        # First 3 sends should ALLOW (each needs unique nonce for Fresh)
        for i in range(3):
            # Grant capability for each send (or use unique nonce)
            cap_nonce = f"send-cap-{i}"
            broker.grant_root(Capability(
                owner="User", holder="EffectBroker", right="send",
                target="internal@corp.com", scope=frozenset({"*"}),
                expiry=float("inf"), nonce=cap_nonce,
            ))
            task.ceiling = Capability(
                owner="User", holder="EffectBroker", right="send",
                target="internal@corp.com", scope=frozenset({"*"}),
                expiry=float("inf"), nonce=cap_nonce,
            )
            effect = Effect(
                "send",
                "internal@corp.com",
                {},
                (Data(f"msg{i}", Confidentiality.INTERNAL, Integrity.USER),),
                cap_nonce,
                CHAIN,
            )
            commit = Commit(effect, task)
            allow, _ = broker.commit(commit)
            assert allow is True, f"Send {i+1} should ALLOW"

    def test_send_exceeding_rate_limit_blocks(self) -> None:
        """Send exceeding max_sends limit should BLOCK."""
        ledger = IndependentEffectLedger()
        broker = EffectBroker(ledger=ledger)
        broker.set_send_rate_limit(max_sends=2)

        broker.store._unsafe_bootstrap_email("internal@corp.com", Domain.INTERNAL)

        # Grant capabilities for all 3 sends
        for i in range(3):
            broker.grant_root(Capability(
                owner="User", holder="EffectBroker", right="send",
                target="internal@corp.com", scope=frozenset({"*"}),
                expiry=float("inf"), nonce=f"send-cap-{i}",
            ))

        task = Task(
            task_id="rate-limit-block",
            owner="User",
            ceiling=Capability(
                owner="User", holder="EffectBroker", right="send",
                target="internal@corp.com", scope=frozenset({"*"}),
                expiry=float("inf"), nonce="send-cap-0",
            ),
        )
        broker.register_task(task)

        # First 2 sends should ALLOW (each needs unique nonce for Fresh)
        for i in range(2):
            cap_nonce = f"send-cap-{i}"
            task.ceiling = Capability(
                owner="User", holder="EffectBroker", right="send",
                target="internal@corp.com", scope=frozenset({"*"}),
                expiry=float("inf"), nonce=cap_nonce,
            )
            effect = Effect(
                "send",
                "internal@corp.com",
                {},
                (Data(f"msg{i}", Confidentiality.INTERNAL, Integrity.USER),),
                cap_nonce,
                CHAIN,
            )
            commit = Commit(effect, task)
            allow, _ = broker.commit(commit)
            assert allow is True, f"Send {i+1} should ALLOW"

        # 3rd send: update ceiling for fresh nonce, use separate nonce for rate limit
        broker.grant_root(Capability(
            owner="User", holder="EffectBroker", right="send",
            target="internal@corp.com", scope=frozenset({"*"}),
            expiry=float("inf"), nonce="send-cap-limit",
        ))

        # 3rd send should BLOCK by rate limit (capability already granted)
        effect = Effect(
            "send",
            "internal@corp.com",
            {},
            (Data("msg2", Confidentiality.INTERNAL, Integrity.USER),),
            "send-cap-limit",
            CHAIN,
        )
        commit = Commit(effect, task)
        allow, evidence = broker.commit(commit)
        assert allow is False, f"3rd send should be BLOCKed by rate limit, got: {evidence}"
        assert "send-rate-limit" in evidence["predicates"]["NoAmp"]

    def test_each_session_has_own_rate_limit(self) -> None:
        """Different sessions have separate send counts."""
        ledger = IndependentEffectLedger()
        broker = EffectBroker(ledger=ledger)
        broker.set_send_rate_limit(max_sends=1)

        broker.store._unsafe_bootstrap_email("internal@corp.com", Domain.INTERNAL)

        broker.grant_root(Capability(
            owner="User", holder="EffectBroker", right="send",
            target="internal@corp.com", scope=frozenset({"*"}),
            expiry=float("inf"), nonce="send-cap",
        ))

        # Task 1: max 1 send
        task1 = Task(
            task_id="session-1",
            owner="User",
            ceiling=Capability(
                owner="User", holder="EffectBroker", right="send",
                target="internal@corp.com", scope=frozenset({"*"}),
                expiry=float("inf"), nonce="send-cap",
            ),
        )
        broker.register_task(task1)

        # Task 2: separate session, also max 1 send
        task2 = Task(
            task_id="session-2",
            owner="User",
            ceiling=Capability(
                owner="User", holder="EffectBroker", right="send",
                target="internal@corp.com", scope=frozenset({"*"}),
                expiry=float("inf"), nonce="send-cap",
            ),
        )
        broker.register_task(task2)

        # Task 1: 1 send OK, 2nd BLOCKed
        broker.grant_root(Capability(
            owner="User", holder="EffectBroker", right="send",
            target="internal@corp.com", scope=frozenset({"*"}),
            expiry=float("inf"), nonce="task1-send-1",
        ))
        broker.grant_root(Capability(
            owner="User", holder="EffectBroker", right="send",
            target="internal@corp.com", scope=frozenset({"*"}),
            expiry=float("inf"), nonce="task1-send-2",
        ))
        effect1 = Effect("send", "internal@corp.com", {},
                       (Data("msg1", Confidentiality.INTERNAL, Integrity.USER),),
                       "task1-send-1", CHAIN)
        effect2 = Effect("send", "internal@corp.com", {},
                       (Data("msg2", Confidentiality.INTERNAL, Integrity.USER),),
                       "task1-send-2", CHAIN)
        allow1, _ = broker.commit(Commit(effect1, task1))
        allow2, _ = broker.commit(Commit(effect2, task1))
        assert allow1 is True
        assert allow2 is False

        # Task 2: fresh session, starts fresh
        broker.grant_root(Capability(
            owner="User", holder="EffectBroker", right="send",
            target="internal@corp.com", scope=frozenset({"*"}),
            expiry=float("inf"), nonce="task2-send-1",
        ))
        effect3 = Effect("send", "internal@corp.com", {},
                       (Data("msg3", Confidentiality.INTERNAL, Integrity.USER),),
                       "task2-send-1", CHAIN)
        allow3, _ = broker.commit(Commit(effect3, task2))
        assert allow3 is True, "Task 2 should have fresh send count"

    def test_rate_limit_zero_means_unlimited(self) -> None:
        """max_sends=0 means unlimited sends."""
        ledger = IndependentEffectLedger()
        broker = EffectBroker(ledger=ledger)
        broker.set_send_rate_limit(max_sends=0)  # unlimited

        broker.store._unsafe_bootstrap_email("internal@corp.com", Domain.INTERNAL)

        # Grant capabilities for all 3 sends
        for i in range(3):
            broker.grant_root(Capability(
                owner="User", holder="EffectBroker", right="send",
                target="internal@corp.com", scope=frozenset({"*"}),
                expiry=float("inf"), nonce=f"send-cap-{i}",
            ))

        task = Task(
            task_id="unlimited-test",
            owner="User",
            ceiling=Capability(
                owner="User", holder="EffectBroker", right="send",
                target="internal@corp.com", scope=frozenset({"*"}),
                expiry=float("inf"), nonce="send-cap",
            ),
        )
        broker.register_task(task)

        # Many sends should all ALLOW (each needs unique nonce for Fresh)
        for i in range(10):
            cap_nonce = f"send-cap-{i}"
            broker.grant_root(Capability(
                owner="User", holder="EffectBroker", right="send",
                target="internal@corp.com", scope=frozenset({"*"}),
                expiry=float("inf"), nonce=cap_nonce,
            ))
            effect = Effect(
                "send",
                "internal@corp.com",
                {},
                (Data(f"msg{i}", Confidentiality.INTERNAL, Integrity.USER),),
                cap_nonce,
                CHAIN,
            )
            commit = Commit(effect, task)
            allow, _ = broker.commit(commit)
            assert allow is True, f"Send {i+1} should ALLOW with unlimited rate"
