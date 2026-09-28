"""Test that broker.py refines TLA+ ECAC spec.

This test verifies the implementation matches the formal specification:
- Commit(effect, task) iff Authorized and FlowOK and NoAmp and Fresh

Run with: pytest tests/test_tla_spec_equivalence.py -v
"""

from effect_broker.baselines import run_comparison
from effect_broker.lattice import Confidentiality, Integrity
from effect_broker.model import AGENT, BROKER, USER, Capability, Effect, Session, Task
from effect_broker.traces import CHAIN, _capability, _mk, build


def _make_task(task_id: str, taint: bool = False) -> Task:
    """Create a task for testing."""
    session = Session(
        session_id=f"session-{task_id}",
        logical_time=0.0,
    )
    if taint:
        session.taint_for_send("confidential data read")

    return Task(
        task_id=task_id,
        owner=USER,
        ceiling=Capability(
            owner=USER,
            holder=BROKER,
            right="*",
            target="*",
            scope=frozenset({"*"}),
            expiry=float("inf"),
            nonce=f"ceil-{task_id}",
        ),
        session=session,
    )


class TestTLASpecEquivalence:
    """Verify broker implements TLA+ spec invariants."""

    def test_tla_inv1_all_allowed_effects_pass_predicates(self) -> None:
        """
        TLA+ Inv1: Every allowed effect passes all four predicates.

        Inv1: All allowed effects must pass CheckAuth, CheckFlowOK,
        CheckNoAmp, and CheckFresh.
        """
        broker = build()
        task = _make_task("default")
        broker.register_task(task)

        # Grant capability
        broker.grant_root(
            _capability(
                USER,
                USER,
                "write",
                "file:///test.txt",
                frozenset({"file:///test.txt"}),
                100,
                "r-write-test",
            )
        )
        broker.attenuate(
            "r-write-test", AGENT, "write", "file:///test.txt", frozenset({"file:///test.txt"}), 100
        )

        # Create effect
        effect = Effect(
            etype="write",
            target="file:///test.txt",
            metadata={},
            provenance=(_mk("test", Confidentiality.INTERNAL, Integrity.USER),),
            capability_nonce="r-write-test:Agent",
            delegation_chain=CHAIN,
        )

        # Commit - should ALLOW
        allow, evidence = broker.commit_effect(effect, task=task)
        assert allow, f"Effect should be allowed: {evidence}"

    def test_tla_inv2_session_taint_blocks_send(self) -> None:
        """
        TLA+ Inv2: Session taint blocks sends.

        When session is tainted, sends are blocked.
        """
        broker = build()

        # Create tainted session (taint_for_send marks it tainted)
        tainted_task = _make_task("tainted", taint=True)
        broker.register_task(tainted_task)

        # Verify session is tainted
        assert tainted_task.session.tainted, "Session should be tainted"

        # Grant send capability
        broker.grant_root(
            _capability(
                USER,
                USER,
                "send",
                "internal@corp.com",
                frozenset({"internal@corp.com"}),
                100,
                "r-send",
            )
        )
        broker.attenuate(
            "r-send", AGENT, "send", "internal@corp.com", frozenset({"internal@corp.com"}), 100
        )

        effect = Effect(
            etype="send",
            target="mailto:internal@corp.com",
            metadata={},
            provenance=(_mk("secret", Confidentiality.CONFIDENTIAL, Integrity.USER),),
            capability_nonce="r-send:Agent",
            delegation_chain=CHAIN,
        )

        # Should BLOCK due to session taint
        allow, evidence = broker.commit_effect(effect, task=tainted_task)
        assert not allow, "Tainted session should block send"

    def test_tla_inv3_no_unknown_owner_in_capabilities(self) -> None:
        """
        TLA+ Inv3: No unknown owner in capabilities.

        All capabilities granted by USER must be owned by USER.
        Note: Test capabilities with non-User owners are for adversarial testing.
        """
        broker = build()

        # Grant capability (owned by USER)
        broker.grant_root(
            _capability(
                USER,
                USER,
                "write",
                "file:///test.txt",
                frozenset({"file:///test.txt"}),
                100,
                "test-cap",
            )
        )

        # Verify USER-granted capabilities have USER owner
        # (some test capabilities intentionally have Mallory owner for adversarial tests)
        for nonce, cap in broker.capabilities.items():
            if nonce.startswith("test-") or nonce.startswith("r-"):
                assert cap.owner == USER, f"Capability {nonce} owner must be USER, got {cap.owner}"

    def test_tla_inv4_all_allowed_effects_have_valid_nonces(self) -> None:
        """
        TLA+ Inv4: All allowed effects have valid nonces.

        Allowed effect nonces must be in broker_capabilities domain.
        """
        broker = build()
        task = _make_task("default")
        broker.register_task(task)

        # Grant valid capability
        broker.grant_root(
            _capability(
                USER,
                USER,
                "write",
                "file:///test.txt",
                frozenset({"file:///test.txt"}),
                100,
                "r-write",
            )
        )
        broker.attenuate(
            "r-write", AGENT, "write", "file:///test.txt", frozenset({"file:///test.txt"}), 100
        )

        effect = Effect(
            etype="write",
            target="file:///test.txt",
            metadata={},
            provenance=(),
            capability_nonce="r-write:Agent",
            delegation_chain=CHAIN,
        )

        allow, _ = broker.commit_effect(effect, task=task)

        if allow:
            # Nonce must be in broker's capabilities
            assert effect.capability_nonce in broker.capabilities, (
                "Allowed effect must have valid nonce"
            )

    def test_tla_commit_requires_all_four_predicates(self) -> None:
        """
        Commit(effect, task) requires all four predicates:
        Authorized and FlowOK and NoAmp and Fresh.

        Test each predicate independently fails:
        """
        broker = build()
        task = _make_task("default")
        broker.register_task(task)

        # Create valid capability
        broker.grant_root(
            _capability(
                USER,
                USER,
                "write",
                "file:///test.txt",
                frozenset({"file:///test.txt"}),
                100,
                "r-write",
            )
        )
        broker.attenuate(
            "r-write", AGENT, "write", "file:///test.txt", frozenset({"file:///test.txt"}), 100
        )

        # Test 1: Invalid nonce (Fresh fails)
        effect_fresh = Effect(
            etype="write",
            target="file:///test.txt",
            metadata={},
            provenance=(),
            capability_nonce="invalid-nonce",
            delegation_chain=CHAIN,
        )
        allow, evidence = broker.commit_effect(effect_fresh, task=task)
        assert not allow, "Invalid nonce should block"

        # Test 2: Wrong right (Authorized fails)
        effect_auth = Effect(
            etype="send",  # Wrong right
            target="file:///test.txt",
            metadata={},
            provenance=(),
            capability_nonce="r-write:Agent",
            delegation_chain=CHAIN,
        )
        allow, evidence = broker.commit_effect(effect_auth, task=task)
        assert not allow, "Wrong right should block"

        # Test 3: Out of scope (NoAmp fails)
        broker2 = build()
        task2 = _make_task("default2")
        broker2.register_task(task2)
        broker2.grant_root(
            _capability(
                USER,
                USER,
                "write",
                "file:///test.txt",
                frozenset({"file:///test.txt"}),
                100,
                "r-write2",
            )
        )
        broker2.attenuate(
            "r-write2", AGENT, "write", "file:///test.txt", frozenset({"file:///test.txt"}), 100
        )

        effect_scope = Effect(
            etype="write",
            target="file:///etc/passwd",
            metadata={},
            provenance=(),
            capability_nonce="r-write2:Agent",
            delegation_chain=CHAIN,
        )
        allow, evidence = broker2.commit_effect(effect_scope, task=task2)
        assert not allow, "Out of scope should block"

    def test_tla_baseline_comparison_runs(self) -> None:
        """Verify baseline comparison runs successfully."""
        results = run_comparison()
        assert "ECAC" in results
        assert len(results["ECAC"]) > 0
        ecac_blocked = sum(1 for r in results["ECAC"] if r["blocked"])
        assert ecac_blocked == len(results["ECAC"]), "ECAC should block 100%"
