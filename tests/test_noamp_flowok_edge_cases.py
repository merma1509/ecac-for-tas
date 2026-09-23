"""Regression: NoAmp and FlowOK edge cases not covered by existing tests.

These fill coverage gaps for predicates that are tested via traces but
lacked isolated unit tests.
"""

from __future__ import annotations

from effect_broker.broker import EffectBroker
from effect_broker.lattice import Confidentiality, Integrity
from effect_broker.model import (
    Capability,
    Commit,
    Data,
    Effect,
    LabelException,
    Task,
    USER,
    APPROVER,
    BROKER,
)
from effect_broker.traces import build


def _build() -> EffectBroker:
    """Build a fresh broker with default task and wildcard ceiling."""
    broker = build()
    task = broker.tasks.get("default")
    if task is None:
        ceiling = Capability(
            owner=USER,
            holder=BROKER,
            right="*",
            target="*",
            scope=frozenset({"*"}),
            expiry=float("inf"),
            nonce="default-ceiling",
        )
        task = Task(task_id="default", owner=USER, ceiling=ceiling)
        broker.tasks["default"] = task
    return broker


def _make_task(task_id: str, scope: frozenset[str] | None = None) -> Task:
    """Build a task with a permissive capability (used to pass Auth/FlowOK/NoAmp)."""
    ceiling = Capability(
        owner=USER,
        holder=BROKER,
        right="*",
        target="*",
        scope=scope or frozenset({"*"}),
        expiry=float("inf"),
        nonce=f"ceiling-{task_id}",
    )
    return Task(task_id=task_id, owner=USER, ceiling=ceiling)


class TestNoAmpDerivationEdgeCases:
    """NoAmp: derivation chain edge cases beyond monotonicity."""

    def test_cycle_in_chain_blocked(self) -> None:
        """Capability whose derivation chain contains a cycle → BLOCK cycle-in-chain.

        A cycle means the chain never terminates at a trusted root. This is
        impossible to produce via normal attenuate() (acyclic), but can be
        constructed via direct store manipulation to test the guard.
        """
        broker = _build()

        # Build a cycle: A→B→C→B (B appears twice)
        broker.capabilities["cap-cycle-A"] = Capability(
            owner=USER,
            holder=BROKER,
            right="read",
            target="file:///reports",
            scope=frozenset({"*"}),
            expiry=float("inf"),
            nonce="cap-cycle-A",
            derives_from="cap-cycle-B",  # points to B
        )
        broker.capabilities["cap-cycle-B"] = Capability(
            owner=USER,
            holder=BROKER,
            right="read",
            target="file:///reports",
            scope=frozenset({"*"}),
            expiry=float("inf"),
            nonce="cap-cycle-B",
            derives_from="cap-cycle-C",  # points to C
        )
        broker.capabilities["cap-cycle-C"] = Capability(
            owner=USER,
            holder=BROKER,
            right="read",
            target="file:///reports",
            scope=frozenset({"*"}),
            expiry=float("inf"),
            nonce="cap-cycle-C",
            derives_from="cap-cycle-B",  # ← cycle: B→C→B
        )

        effect = Effect(
            etype="read",
            target="file:///reports",
            metadata={},
            provenance=(),
            capability_nonce="cap-cycle-A",
            delegation_chain=(),
        )
        task = broker.tasks["default"]
        commit = Commit(effect, task)
        allow, ev = broker.commit(commit)

        assert allow is False
        assert ev["primary_blocker"] == "Auth"
        assert "cycle-in-chain" in ev["predicates"]["Auth"]

    def test_mallory_non_root_owner_blocked(self) -> None:
        """Capability with owner=Mallory (non-trusted root) → BLOCK owner-not-trusted.

        Mallory can forge a capability with owner="Mallory" and pass it to the
        broker. NoAmp's derivation check rejects it: owner not in TRUSTED_ROOTS.
        """
        broker = _build()

        # Mallory forges a capability — passes through broker.capabilities[]
        # (in real attack, Mallory sets broker.capabilities[forge] directly or
        # via a compromised shim). The capability has owner=Mallory.
        broker.capabilities["mallory-forged"] = Capability(
            owner="Mallory",  # ← NOT a trusted root
            holder=BROKER,
            right="read",
            target="file:///secrets",
            scope=frozenset({"*"}),
            expiry=float("inf"),
            nonce="mallory-forged",
            derives_from=None,  # Mallory claims it's a root grant
        )

        effect = Effect(
            etype="read",
            target="file:///secrets",
            metadata={},
            provenance=(Data("s", Confidentiality.CONFIDENTIAL, Integrity.USER),),
            capability_nonce="mallory-forged",
            delegation_chain=(),
        )
        task = broker.tasks["default"]
        commit = Commit(effect, task)
        allow, ev = broker.commit(commit)

        # Auth blocks: Mallory not in TRUSTED_ROOTS
        assert allow is False
        assert ev["primary_blocker"] == "Auth"
        assert "owner-not-trusted" in ev["predicates"]["Auth"]

    def test_broken_chain_blocked(self) -> None:
        """Capability whose derives_from points to a missing nonce → BLOCK broken-chain.

        The parent nonce referenced in derives_from does not exist in capabilities.
        This means the chain is broken and cannot be verified.
        """
        broker = _build()

        broker.capabilities["orphaned-cap"] = Capability(
            owner=USER,
            holder=BROKER,
            right="read",
            target="file:///reports",
            scope=frozenset({"*"}),
            expiry=float("inf"),
            nonce="orphaned-cap",
            derives_from="this-nonce-does-not-exist",  # ← parent missing
        )

        effect = Effect(
            etype="read",
            target="file:///reports",
            metadata={},
            provenance=(),
            capability_nonce="orphaned-cap",
            delegation_chain=(),
        )
        task = broker.tasks["default"]
        commit = Commit(effect, task)
        allow, ev = broker.commit(commit)

        assert allow is False
        assert ev["primary_blocker"] == "Auth"
        assert "broken-chain" in ev["predicates"]["Auth"]

    def test_widened_scope_blocked_in_check_derivation(self) -> None:
        """Non-monotonic child scope: child.scope > parent.scope → BLOCK non-monotonic.

        attempt_wide() creates a widened capability (non-monotonic). The derivation
        chain check (Auth sub-check 2) detects that child.scope !<= parent.scope.
        """
        broker = _build()

        # Normal parent cap
        parent = Capability(
            owner=USER,
            holder=BROKER,
            right="read",
            target="file:///reports",
            scope=frozenset({"reports", "internal"}),
            expiry=float("inf"),
            nonce="parent-cap",
        )
        broker.capabilities["parent-cap"] = parent

        # Widened child: scope larger than parent
        # parent.scope = {"reports", "internal"}, child.scope = {"*"} ⊄ parent
        broker.capabilities["wide-child"] = Capability(
            owner=USER,
            holder="SubAgent",
            right="read",
            target="file:///reports",
            scope=frozenset({"*"}),  # ← widens scope (non-monotonic)
            expiry=float("inf"),
            nonce="wide-child",
            derives_from="parent-cap",
        )

        effect = Effect(
            etype="read",
            target="file:///reports",
            metadata={},
            provenance=(),
            capability_nonce="wide-child",
            delegation_chain=(),
        )
        task = broker.tasks["default"]
        commit = Commit(effect, task)
        allow, ev = broker.commit(commit)

        # Auth blocks: non-monotonic scope
        assert allow is False
        assert ev["primary_blocker"] == "Auth"
        assert "non-monotonic" in ev["predicates"]["Auth"]


class TestNoAmpSSRFContainment:
    """NoAmp: SSRF containment for network effects."""

    def test_network_effect_outside_cap_scope_blocked(self) -> None:
        """Network effect to internal URL with cap scoped to external → BLOCK.

        The capability scope {"external"} does not cover "http://internal.corp.com".
        NoAmp's SSRF containment check fails: cap-scope not subset of url-scope.
        Auth passes: capability grants right="network" and target="*" (wildcard),
        which covers any effect target. The SSRF block happens in NoAmp.
        """
        broker = _build()

        # Capability scoped to external only — capability.right="network" matches
        # etype and target matches the effect target (so Auth sub-check 5 passes).
        # NoAmp SSRF containment fails: cap-scope {"external"} is not a subset
        # of url-scope {"http://internal.corp.com"}.
        cap = Capability(
            owner=USER,
            holder=BROKER,
            right="network",
            target="http://internal.corp.com/admin",  # must match effect.target
            scope=frozenset({"external"}),
            expiry=float("inf"),
            nonce="ssrf-cap",
            derives_from=None,
        )
        broker.capabilities["ssrf-cap"] = cap

        # Try to reach internal network target
        effect = Effect(
            etype="network",
            target="http://internal.corp.com/admin",
            metadata={},
            provenance=(),
            capability_nonce="ssrf-cap",
            delegation_chain=(),
        )
        task = broker.tasks["default"]
        commit = Commit(effect, task)
        allow, ev = broker.commit(commit)

        # NoAmp blocks: SSRF containment fails
        assert allow is False
        assert ev["primary_blocker"] == "NoAmp"
        assert "ssrf containment" in ev["predicates"]["NoAmp"]

    def test_network_effect_within_cap_scope_allowed(self) -> None:
        """Network effect to matching URL scope → ALLOW.

        The capability scope {"http://internal.corp.com"} exactly matches the
        URL domain scope. SSRF containment passes in NoAmp.
        Auth also passes: right="network" matches etype, target="*" wildcard.
        """
        broker = _build()

        cap = Capability(
            owner=USER,
            holder=BROKER,
            right="network",
            target="http://internal.corp.com/admin",  # must match effect.target
            scope=frozenset({"http://internal.corp.com"}),
            expiry=float("inf"),
            nonce="safe-network-cap",
            derives_from=None,
        )
        broker.capabilities["safe-network-cap"] = cap

        effect = Effect(
            etype="network",
            target="http://internal.corp.com/admin",
            metadata={},
            provenance=(),
            capability_nonce="safe-network-cap",
            delegation_chain=(),
        )
        task = broker.tasks["default"]
        commit = Commit(effect, task)
        allow, ev = broker.commit(commit)
        assert allow is True


class TestFlowOKEndorseEdgeCases:
    """FlowOK: endorse exception edge cases."""

    def test_wrong_from_label_endorse_still_blocked(self) -> None:
        """Endorse exception with wrong from_label → FlowOK still blocks.

        An UNTRUSTED datum has integrity=UNTRUSTED. An endorse exception
        for from_label=HIGH does NOT cover UNTRUSTED data.
        Only an exception with from_label=UNTRUSTED would apply.
        """
        broker = _build()

        # Endorse exception for the WRONG from_label (HIGH, not UNTRUSTED)
        wrong_exception = LabelException(
            kind="endorse",
            match_target="file:///reports",
            additional_targets=frozenset(),
            etype="write",
            from_label=Integrity.HIGH.name,  # ← wrong: datum is UNTRUSTED
            to_label=Integrity.USER.name,
            granted_by=APPROVER,
            nonce="wrong-endorse",
        )
        broker.grant_label_exception(wrong_exception)

        task = Task(
            task_id="endorse-test",
            owner="USER",
            ceiling=Capability(
                owner=USER,
                holder=BROKER,
                right="*",
                target="*",
                scope=frozenset({"*"}),
                expiry=float("inf"),
                nonce="endorse-ceiling",
            ),
        )
        broker.tasks["endorse-test"] = task
        broker.capabilities["endorse-cap"] = Capability(
            owner=USER,
            holder=BROKER,
            right="write",
            target="file:///reports",
            scope=frozenset({"*"}),
            expiry=float("inf"),
            nonce="endorse-cap",
        )

        # UNTRUSTED datum — violates sink integrity floor
        # Pass label_exception via constructor (not frozen field mutation)
        effect = Effect(
            etype="write",
            target="file:///reports",
            metadata={},
            provenance=(Data("poisoned", Confidentiality.INTERNAL, Integrity.UNTRUSTED),),
            capability_nonce="endorse-cap",
            delegation_chain=(),
            label_exceptions=(wrong_exception,),  # ← wrong exception
        )
        commit = Commit(effect, task)
        allow, ev = broker.commit(commit)

        # FlowOK blocks: the endorse exception is for from_label=HIGH,
        # but the datum is UNTRUSTED — exception doesn't apply
        assert allow is False
        assert ev["primary_blocker"] == "FlowOK"
        assert "low-integrity" in ev["predicates"]["FlowOK"]

    def test_correct_endorse_allows_untrusted_to_user(self) -> None:
        """Endorse with correct from_label=UNTRUSTED → ALLOW.

        The exception sanctions the UNTRUSTED→USER integrity flow.
        """
        broker = _build()

        correct_exception = LabelException(
            kind="endorse",
            match_target="file:///reports",
            additional_targets=frozenset(),
            etype="write",
            from_label=Integrity.UNTRUSTED.name,  # ← correct: matches datum
            to_label=Integrity.USER.name,
            granted_by=APPROVER,
            nonce="correct-endorse",
        )
        broker.grant_label_exception(correct_exception)

        task = Task(
            task_id="endorse-ok",
            owner="USER",
            ceiling=Capability(
                owner=USER,
                holder=BROKER,
                right="*",
                target="*",
                scope=frozenset({"*"}),
                expiry=float("inf"),
                nonce="ceiling",
            ),
        )
        broker.tasks["endorse-ok"] = task
        broker.capabilities["endorse-ok-cap"] = Capability(
            owner=USER,
            holder=BROKER,
            right="write",
            target="file:///reports",
            scope=frozenset({"*"}),
            expiry=float("inf"),
            nonce="endorse-ok-cap",
        )

        effect = Effect(
            etype="write",
            target="file:///reports",
            metadata={},
            provenance=(Data("untrusted", Confidentiality.INTERNAL, Integrity.UNTRUSTED),),
            capability_nonce="endorse-ok-cap",
            delegation_chain=(),
            label_exceptions=(correct_exception,),
        )
        commit = Commit(effect, task)
        allow, ev = broker.commit(commit)

        # FlowOK allows: UNTRUSTED→USER exception applies
        assert allow is True

# =============================================================================
# Session Taint (inter-effect composition)
# =============================================================================
class TestSessionTaintInterEffectComposition:
    """Session Taint Mode: prevents read-secrets→send-exfil without declass.

    Inter-effect composition attack:
      1. Effect A: read(secrets) — ALLOW (has read capability)
      2. Effect B: send(internal, body=secrets_data) — ALLOW (cap + FlowOK)

    Before session taint: Both pass individually. The sequence is an exfiltration
    attack that NoAmp cannot detect (effect-level only).

    After session taint:
      - When read(CONFIDENTIAL file) commits → session.tainted = True
      - When send() commits → FlowOK checks session.tainted
        → BLOCKs with "session-taint" (unless declass exception exists)
    """

    def test_read_confidential_taints_session(self) -> None:
        """Step 1: reading a CONFIDENTIAL file marks session as tainted."""
        from effect_broker.broker import EffectBroker
        from effect_broker.lattice import Confidentiality, Integrity
        from effect_broker.model import (
            Capability,
            Commit,
            Data,
            Effect,
            Task,
        )

        broker = EffectBroker()
        task = Task(
            task_id="taint-test",
            owner=USER,
            ceiling=Capability(
                owner=USER, holder=BROKER, right="read",
                target="file:///secrets", scope=frozenset({"*"}),
                expiry=float("inf"), nonce="cap",
            ),
            flow_boundary=(Confidentiality.CONFIDENTIAL, Integrity.USER),
        )
        broker.tasks["taint-test"] = task
        broker.capabilities["cap"] = Capability(
            owner=USER, holder=BROKER, right="read",
            target="file:///secrets", scope=frozenset({"*"}),
            expiry=float("inf"), nonce="cap",
        )

        # Bootstrap the file with CONFIDENTIAL sensitivity
        broker.store._unsafe_bootstrap_file(
            "file:///secrets", Confidentiality.CONFIDENTIAL
        )

        effect = Effect(
            etype="read",
            target="file:///secrets",
            metadata={},
            provenance=(Data("file", Confidentiality.CONFIDENTIAL, Integrity.USER),),
            capability_nonce="cap",
            delegation_chain=(BROKER,),
        )
        commit = Commit(effect, task)
        allow, _ = broker.commit(commit)

        assert allow is True
        assert task.session is not None
        assert task.session.tainted is True, "Session should be tainted after CONFIDENTIAL read"
        assert "read-confidential" in task.session._taint_reason

    def test_send_blocked_after_confidential_read(self) -> None:
        """Step 2: send is BLOCKed by session taint (no declass yet)."""
        from effect_broker.broker import EffectBroker
        from effect_broker.lattice import Confidentiality, Integrity
        from effect_broker.model import (
            Capability,
            Commit,
            Data,
            Effect,
            Task,
        )

        broker = EffectBroker()
        task = Task(
            task_id="taint-test",
            owner=USER,
            ceiling=Capability(
                owner=USER, holder=BROKER, right="send",
                target="internal@corp.com", scope=frozenset({"internal"}),
                expiry=float("inf"), nonce="send-cap",
            ),
            flow_boundary=(Confidentiality.INTERNAL, Integrity.USER),
        )
        broker.tasks["taint-test"] = task
        broker.capabilities["send-cap"] = Capability(
            owner=USER, holder=BROKER, right="send",
            target="internal@corp.com", scope=frozenset({"internal"}),
            expiry=float("inf"), nonce="send-cap",
        )

        # Bootstrap the file and mark session as taint-forced
        broker.store._unsafe_bootstrap_file("file:///secrets", Confidentiality.CONFIDENTIAL)
        task.session.taint_for_send("test: read-confidential already happened")

        # Now try to send — should be BLOCKed by session taint
        effect = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={},
            provenance=(Data("body", Confidentiality.INTERNAL, Integrity.USER),),
            capability_nonce="send-cap",
            delegation_chain=(BROKER,),
        )
        commit = Commit(effect, task)
        allow, ev = broker.commit(commit)

        assert allow is False
        assert "session-taint" in ev["predicates"]["FlowOK"]

    def test_declass_clears_session_taint(self) -> None:
        """Step 3: broker-recorded declass clears session taint."""
        from effect_broker.broker import EffectBroker
        from effect_broker.lattice import Confidentiality, Integrity
        from effect_broker.model import (
            Capability,
            Commit,
            Data,
            Effect,
            Task,
        )

        broker = EffectBroker()
        task = Task(
            task_id="declass-test",
            owner=USER,
            ceiling=Capability(
                owner=USER, holder=BROKER, right="send",
                target="internal@corp.com", scope=frozenset({"internal"}),
                expiry=float("inf"), nonce="send-cap",
            ),
            flow_boundary=(Confidentiality.INTERNAL, Integrity.USER),
        )
        broker.tasks["declass-test"] = task
        broker.capabilities["send-cap"] = Capability(
            owner=USER, holder=BROKER, right="send",
            target="internal@corp.com", scope=frozenset({"internal"}),
            expiry=float("inf"), nonce="send-cap",
        )

        # Session is taint-forced (read-secrets happened)
        task.session.taint_for_send("read-confidential(file:///secrets)")
        assert task.session.tainted is True

        # Broker records a declass exception (user approved)
        declass = EffectBroker.request_label_exception(
            kind="declass",
            target="internal@corp.com",
            from_label="CONFIDENTIAL",
            to_label="INTERNAL",
            etype="send",
            task_id="declass-test",
            additional_targets=frozenset(),
        )

        # NOTE: nonce must be unique for grant_label_exception
        from effect_broker.model import LabelException
        grant = LabelException(
            kind="declass",
            match_target="internal@corp.com",
            from_label="CONFIDENTIAL",
            to_label="INTERNAL",
            granted_by="User",
            nonce="declass-1",
            additional_targets=frozenset(),
            etype="send",
            task_id="declass-test",
        )

        # Bootstrap the email (required for send effect to be valid)
        from effect_broker.model import Domain
        broker.store._unsafe_bootstrap_email("internal@corp.com", Domain.INTERNAL)

        # Broker grants: this should clear the session taint
        broker.grant_label_exception(grant, task_id="declass-test")
        assert task.session.tainted is False, "Session taint should be cleared after declass grant"

        # Now send should ALLOW (declass + declass exception checked)
        effect = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={},
            provenance=(Data("body", Confidentiality.INTERNAL, Integrity.USER),),
            capability_nonce="send-cap",
            delegation_chain=(BROKER,),
            label_exceptions=(grant,),
        )
        commit = Commit(effect, task)
        allow, ev = broker.commit(commit)

        assert allow is True, f"Send should ALLOW after declass: {ev}"

    def test_send_without_prior_confidential_read_allows(self) -> None:
        """Baseline: send is ALLOW when session is NOT tainted (no prior CONFIDENTIAL read)."""
        from effect_broker.broker import EffectBroker
        from effect_broker.lattice import Confidentiality, Integrity
        from effect_broker.model import (
            Capability,
            Commit,
            Data,
            Effect,
            Task,
        )

        broker = EffectBroker()
        task = Task(
            task_id="clean-task",
            owner=USER,
            ceiling=Capability(
                owner=USER, holder=BROKER, right="send",
                target="internal@corp.com", scope=frozenset({"internal"}),
                expiry=float("inf"), nonce="send-cap",
            ),
            flow_boundary=(Confidentiality.INTERNAL, Integrity.USER),
        )
        broker.tasks["clean-task"] = task
        broker.capabilities["send-cap"] = Capability(
            owner=USER, holder=BROKER, right="send",
            target="internal@corp.com", scope=frozenset({"internal"}),
            expiry=float("inf"), nonce="send-cap",
        )

        # Session is NOT tainted (no CONFIDENTIAL read happened)
        assert task.session.tainted is False

        # Bootstrap the email (required for send effect to be valid)
        from effect_broker.model import Domain
        broker.store._unsafe_bootstrap_email("internal@corp.com", Domain.INTERNAL)

        # Send should ALLOW
        effect = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={},
            provenance=(Data("body", Confidentiality.INTERNAL, Integrity.USER),),
            capability_nonce="send-cap",
            delegation_chain=(BROKER,),
        )
        commit = Commit(effect, task)
        allow, ev = broker.commit(commit)

        assert allow is True, f"Send should ALLOW (session not tainted): {ev}"

    def test_read_internal_does_not_taint_session(self) -> None:
        """Only CONFIDENTIAL reads taint the session. INTERNAL reads are fine."""
        from effect_broker.broker import EffectBroker
        from effect_broker.lattice import Confidentiality, Integrity
        from effect_broker.model import (
            Capability,
            Commit,
            Data,
            Effect,
            Task,
        )

        broker = EffectBroker()
        task = Task(
            task_id="internal-read",
            owner=USER,
            ceiling=Capability(
                owner=USER, holder=BROKER, right="read",
                target="file:///reports", scope=frozenset({"*"}),
                expiry=float("inf"), nonce="read-cap",
            ),
            flow_boundary=(Confidentiality.INTERNAL, Integrity.USER),
        )
        broker.tasks["internal-read"] = task
        broker.capabilities["read-cap"] = Capability(
            owner=USER, holder=BROKER, right="read",
            target="file:///reports", scope=frozenset({"*"}),
            expiry=float("inf"), nonce="read-cap",
        )

        # Bootstrap with INTERNAL sensitivity
        broker.store._unsafe_bootstrap_file("file:///reports", Confidentiality.INTERNAL)

        effect = Effect(
            etype="read",
            target="file:///reports",
            metadata={},
            provenance=(Data("file", Confidentiality.INTERNAL, Integrity.USER),),
            capability_nonce="read-cap",
            delegation_chain=(BROKER,),
        )
        commit = Commit(effect, task)
        allow, ev = broker.commit(commit)

        assert allow is True
        assert task.session.tainted is False, "INTERNAL read should NOT taint session"

    def test_session_taint_clear_requires_correct_task_id(self) -> None:
        """Declass for wrong task_id does NOT clear taint (cross-task isolation)."""
        from effect_broker.broker import EffectBroker
        from effect_broker.lattice import Confidentiality, Integrity
        from effect_broker.model import (
            Capability,
            Task,
        )

        broker = EffectBroker()
        task_a = Task(
            task_id="task-A",
            owner=USER,
            ceiling=Capability(
                owner=USER, holder=BROKER, right="send",
                target="internal@corp.com", scope=frozenset({"internal"}),
                expiry=float("inf"), nonce="send-cap",
            ),
            flow_boundary=(Confidentiality.INTERNAL, Integrity.USER),
        )
        broker.tasks["task-A"] = task_a
        broker.capabilities["send-cap"] = Capability(
            owner=USER, holder=BROKER, right="send",
            target="internal@corp.com", scope=frozenset({"internal"}),
            expiry=float("inf"), nonce="send-cap",
        )

        # Session A is tainted
        task_a.session.taint_for_send("read-confidential in task-A")

        from effect_broker.model import LabelException
        # Declass is granted for task-B (different task)
        grant = LabelException(
            kind="declass",
            match_target="internal@corp.com",
            from_label="CONFIDENTIAL",
            to_label="INTERNAL",
            granted_by="User",
            nonce="declass-wrong-task",
            etype="send",
            task_id="task-B",  # WRONG TASK
        )

        # Grant to task-B should NOT clear task-A's taint
        broker.grant_label_exception(grant, task_id="task-B")
        assert task_a.session.tainted is True, (
            "Taint should NOT be cleared — declass was for wrong task"
        )


class TestProvenanceDerivation:
    """ProvenanceDeriver: derive labels from real path patterns, not hand-assigned.

    BEFORE: provenance labels were hand-assigned by the test code, assuming
    the LLM would always label correctly.
    AFTER: labels are derived from path patterns (simulating OS-level metadata),
    removing reliance on LLM honesty for the source of truth.
    """

    def test_secrets_file_is_confidential(self) -> None:
        """file:///secrets → CONFIDENTIAL/USER (derived, not hand-assigned)."""
        from effect_broker.broker import derive_file_provenance
        from effect_broker.lattice import Confidentiality, Integrity

        conf, integ = derive_file_provenance("file:///secrets")
        assert conf == Confidentiality.CONFIDENTIAL, f"Expected CONFIDENTIAL, got {conf}"
        assert integ == Integrity.USER

    def test_reports_file_is_internal(self) -> None:
        """file:///reports → INTERNAL/USER (derived from path keyword)."""
        from effect_broker.broker import derive_file_provenance
        from effect_broker.lattice import Confidentiality, Integrity

        conf, integ = derive_file_provenance("file:///reports")
        assert conf == Confidentiality.INTERNAL, f"Expected INTERNAL, got {conf}"
        assert integ == Integrity.USER

    def test_unknown_file_defaults_to_internal(self) -> None:
        """Unrecognized path → INTERNAL/USER (safe default, not over-classified)."""
        from effect_broker.broker import derive_file_provenance
        from effect_broker.lattice import Confidentiality, Integrity

        conf, integ = derive_file_provenance("file:///random-file-123")
        assert conf == Confidentiality.INTERNAL, f"Expected safe default INTERNAL, got {conf}"
        assert integ == Integrity.USER

    def test_public_file_is_public(self) -> None:
        """file:///tmp/file → PUBLIC/USER (explicitly public path)."""
        from effect_broker.broker import derive_file_provenance
        from effect_broker.lattice import Confidentiality, Integrity

        conf, integ = derive_file_provenance("/tmp/some-temp-file")
        assert conf == Confidentiality.PUBLIC, f"Expected PUBLIC, got {conf}"
        assert integ == Integrity.USER

    def test_internal_path_is_internal(self) -> None:
        """file:///internal/doc → INTERNAL/USER (keyword "internal" in path)."""
        from effect_broker.broker import derive_file_provenance
        from effect_broker.lattice import Confidentiality, Integrity

        conf, integ = derive_file_provenance("file:///internal/strategy-2025")
        assert conf == Confidentiality.INTERNAL, f"Expected INTERNAL, got {conf}"

    def test_password_in_path_is_confidential(self) -> None:
        """Path containing 'password' → CONFIDENTIAL (regardless of other keywords)."""
        from effect_broker.broker import derive_file_provenance
        from effect_broker.lattice import Confidentiality

        conf, _ = derive_file_provenance("file:///users/alice/passwords.csv")
        assert conf == Confidentiality.CONFIDENTIAL, f"Expected CONFIDENTIAL, got {conf}"

    def test_confidential_subdirectory_is_confidential(self) -> None:
        """Path with 'secret' subdirectory → CONFIDENTIAL (recursive keyword match)."""
        from effect_broker.broker import derive_file_provenance
        from effect_broker.lattice import Confidentiality

        conf, _ = derive_file_provenance("file:///projects/app/secret-keys/config.json")
        assert conf == Confidentiality.CONFIDENTIAL, f"Expected CONFIDENTIAL, got {conf}"

    def test_email_internal_domain_is_internal(self) -> None:
        """Email with internal domain → INTERNAL (domain-based, not path keyword)."""
        from effect_broker.broker import EffectBroker

        broker = EffectBroker()
        # email target: checked by _ProvenanceResolver, not derive_file_provenance
        resolver = broker._provenance_resolver
        conf, integ = resolver.resolve("alice@corp.com")
        # corp.com is in TRUSTED_DOMAINS → internal domain → INTERNAL
        assert conf == Confidentiality.INTERNAL, f"Expected INTERNAL for corp.com domain, got {conf}"
        assert integ == Integrity.USER

    def test_email_external_domain_is_public(self) -> None:
        """Email with external domain → PUBLIC (external = lower sensitivity)."""
        from effect_broker.broker import EffectBroker

        broker = EffectBroker()
        resolver = broker._provenance_resolver
        conf, integ = resolver.resolve("alice@external.com")
        assert conf == Confidentiality.PUBLIC, f"Expected PUBLIC for external domain, got {conf}"
        assert integ == Integrity.USER
