"""Regression: email domain scope — target must match against domain label, not raw address.

BEFORE the fix: check_auth() and check_noamp() compared effect.target (a full email
address like "internal@corp.com") directly against the ceiling scope (a set of domain
labels like {"internal"}). The comparison:
    "internal@corp.com" in {"internal"} = False  ← WRONG (masks the bug)

AFTER the fix: _scope_label_for_target() extracts the domain label from email targets:
    _scope_label_for_target("internal@corp.com") = "internal"
    "internal" in {"internal"} = True  ← CORRECT

This fix ensures:
  1. Domain-scoped capabilities (scope={"internal"}) work for email targets
  2. Different domains within the same email host are correctly distinguished
  3. BCC recipients from the same domain pass NoAmp's extra-target check

Also fixed: test_concurrent_replay.py, test_approval_binding_new.py, and other test
files that used scope={raw_email} instead of scope={domain_label}.
"""

from __future__ import annotations

from effect_broker.broker import EffectBroker
from effect_broker.model import (
    Capability,
    Commit,
    Data,
    Effect,
    EffectTarget,
    Task,
)
from effect_broker.traces import build


def _provenance(name: str, content: str = "") -> tuple[Data, ...]:
    from effect_broker.lattice import Confidentiality, Integrity
    return (Data(name, Confidentiality.INTERNAL, Integrity.USER, content=content),)


def _make_domain_task(task_id: str, domain_scope: frozenset[str]) -> Task:
    """Create a task with domain-level scope (not wildcard)."""
    return Task(
        task_id=task_id,
        owner="User",
        ceiling=Capability(
            owner="User",
            holder="EffectBroker",
            right="send",
            target="internal@corp.com",
            scope=domain_scope,
            expiry=float("inf"),
            nonce=f"ceiling-{task_id}",
        ),
    )


def _grant_domain_cap(broker: EffectBroker, task_id: str, domain_scope: frozenset[str]) -> str:
    """Grant a capability with domain-level scope matching the task's ceiling."""
    nonce = f"domain-send-{task_id}"
    broker.capabilities[nonce] = Capability(
        owner="User",
        holder="EffectBroker",
        right="send",
        target="internal@corp.com",
        scope=domain_scope,
        expiry=100,
        nonce=nonce,
        derives_from=None,
    )
    return nonce


class TestEmailDomainScopeFix:
    """Regression: email targets must use domain labels in scope comparison."""

    def test_email_target_with_domain_scope_allows(self) -> None:
        """Email target \"internal@corp.com\" with scope={\"internal\"} → ALLOW.

        This was the core bug: before _scope_label_for_target(), this would
        BLOCK because "internal@corp.com" in {"internal"} = False.
        After the fix: "internal" in {"internal"} = True → ALLOW.
        """
        broker = build()
        task = _make_domain_task("email-scope-test", frozenset({"internal"}))
        broker.register_task(task)
        nonce = _grant_domain_cap(broker, "email-scope-test", frozenset({"internal"}))

        effect = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={},
            provenance=_provenance("domain-test"),
            capability_nonce=nonce,
            delegation_chain=(),
        )
        allow, ev = broker.commit(Commit(effect, task))

        assert allow is True, (
            f"Email target with domain scope should ALLOW. "
            f"Evidence: {ev} "
            f"(scope_label='internal' should be in {{'internal'}})"
        )
        assert ev["primary_blocker"] is None
        assert "auth-ok" in ev["predicates"]["Auth"]
        assert "composition-ok" in ev["predicates"]["NoAmp"]

    def test_email_target_cross_domain_blocked(self) -> None:
        """Email target \"external@corp.com\" with scope={\"internal\"} → BLOCK.

        The domain label for "external@corp.com" is "external".
        "external" not in {"internal"} → NoAmp composition-fail.
        """
        broker = build()
        broker.store._unsafe_bootstrap_email("external@corp.com", "EXTERNAL")

        task = _make_domain_task("cross-domain-test", frozenset({"internal"}))
        broker.register_task(task)
        nonce = _grant_domain_cap(broker, "cross-domain-test", frozenset({"internal"}))

        effect = Effect(
            etype="send",
            target="external@corp.com",
            metadata={},
            provenance=_provenance("cross-domain"),
            capability_nonce=nonce,
            delegation_chain=(),
        )
        allow, ev = broker.commit(Commit(effect, task))

        assert allow is False, "Cross-domain email should BLOCK"
        assert ev["primary_blocker"] in ("Auth", "NoAmp")
        # The blocker should show the scope label mismatch
        evidence_str = str(ev["predicates"])
        assert "scope-label=external" in evidence_str or "external" in evidence_str

    def test_bcc_same_domain_in_scope_allows(self) -> None:
        """BCC to \"team@corp.com\" with scope={\"internal\"} → ALLOW.

        The domain label for "team@corp.com" is "internal".
        "internal" in {"internal"} → passes both primary check and BCC extra-target check.
        """
        broker = build()
        task = _make_domain_task("bcc-same-domain", frozenset({"internal"}))
        broker.register_task(task)
        nonce = _grant_domain_cap(broker, "bcc-same-domain", frozenset({"internal"}))

        effect = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={},
            provenance=_provenance("bcc-test"),
            capability_nonce=nonce,
            delegation_chain=(),
            known_targets=EffectTarget(
                primary="internal@corp.com",
                additional=frozenset({"team@corp.com"}),  # also internal domain
            ),
        )
        allow, ev = broker.commit(Commit(effect, task))

        assert allow is True, (
            f"BCC to same-domain recipient should ALLOW. Evidence: {ev}"
        )
        assert ev["primary_blocker"] is None

    def test_bcc_different_domain_outside_scope_blocked(self) -> None:
        """BCC to \"attacker@elsewhere.com\" with scope={\"internal\"} → BLOCK NoAmp.

        The domain label for "attacker@elsewhere.com" is "external".
        "external" not in {"internal"} → NoAmp extra-target-outside-scope.
        """
        broker = build()
        task = _make_domain_task("bcc-external", frozenset({"internal"}))
        broker.register_task(task)
        nonce = _grant_domain_cap(broker, "bcc-external", frozenset({"internal"}))

        effect = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={},
            provenance=_provenance("bcc-external"),
            capability_nonce=nonce,
            delegation_chain=(),
            known_targets=EffectTarget(
                primary="internal@corp.com",
                additional=frozenset({"attacker@elsewhere.com"}),  # external domain
            ),
        )
        allow, ev = broker.commit(Commit(effect, task))

        assert allow is False, "BCC to external domain should BLOCK"
        assert ev["primary_blocker"] == "NoAmp"
        assert "extra-target-outside-scope" in ev["predicates"]["NoAmp"]

    def test_scope_label_for_target_extracts_domain_from_email(self) -> None:
        """_scope_label_for_target() returns domain label for email targets.

        Domain classification uses a TWO-LEVEL check:
          1. ResourceStore bootstrap data (authoritative for registered emails)
          2. TRUSTED_DOMAINS allowlist (for known corporate domains like corp.com)

        This prevents attacker-controlled lookalike domains from being classified
        as "internal". Only explicitly registered or explicitly allowlisted domains
        get "internal" status — all others get "external" (safe by default).
        """
        from effect_broker.model import Domain

        broker = build()

        # Level 1: registered in ResourceStore (authoritative for that address)
        # internal@corp.com IS bootstrap'd by build() → "internal"
        assert broker._scope_label_for_target("internal@corp.com") == "internal"
        # Register additional addresses explicitly
        broker.store._unsafe_bootstrap_email("alice@internal.corp.com", Domain.INTERNAL)
        assert broker._scope_label_for_target("alice@internal.corp.com") == "internal"

        # Level 2: TRUSTED_DOMAINS allowlist (for generic corporate domain)
        # "corp.com" is in TRUSTED_DOMAINS → "internal"
        assert broker._scope_label_for_target("team@corp.com") == "internal"
        assert broker._scope_label_for_target("bob@corp.com") == "internal"

        # NOT internal: unknown/external domains → "external" (safe by default)
        assert broker._scope_label_for_target("attacker@elsewhere.com") == "external"
        assert broker._scope_label_for_target(" Mallory @ gmail.com ") == "external"
        # "internal.corp.net" is NOT in TRUSTED_DOMAINS (only corp.com is)
        assert broker._scope_label_for_target("alice@internal.corp.net") == "external"
        # "attacker.com" is in EXTERNAL_DOMAINS → "external"
        assert broker._scope_label_for_target("attacker@attacker.com") == "external"
        # Notcorp.com: not in any allowlist → "external" (safe by default)
        assert broker._scope_label_for_target("alice@notcorp.com") == "external"

        # Non-email targets pass through unchanged
        assert broker._scope_label_for_target("file:///reports") == "file:///reports"
        assert broker._scope_label_for_target("http://internal.corp.com") == "http://internal.corp.com"

        # Plain target (no @) → pass through
        assert broker._scope_label_for_target("secret-key") == "secret-key"

    def test_concurrent_email_commits_work_with_domain_scope(self) -> None:
        """Concurrent commits to email with domain-scoped capabilities work correctly.

        This is the regression test for test_concurrent_replay.py failing after
        the domain scope fix (tests were using scope={raw_email} instead of
        scope={domain_label}).
        """
        import threading
        from concurrent.futures import ThreadPoolExecutor, as_completed

        broker = build()
        task = _make_domain_task("concurrent-email", frozenset({"internal"}))
        broker.register_task(task)
        nonce = _grant_domain_cap(broker, "concurrent-email", frozenset({"internal"}))

        effect = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={},
            provenance=_provenance("concurrent-email"),
            capability_nonce=nonce,
            delegation_chain=(),
        )

        results: list[tuple[int, bool, str | None]] = []
        barrier = threading.Barrier(5)

        def commit_task(task_num: int) -> None:
            barrier.wait()
            commit = broker._make_commit(effect, task_id="concurrent-email")
            allow, evidence = broker.commit(commit)
            results.append((task_num, allow, evidence.get("primary_blocker")))

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(commit_task, i) for i in range(5)]
            for f in as_completed(futures):
                f.result()

        allow_count = sum(1 for _, allow, _ in results if allow)
        assert allow_count == 1, (
            f"Expected exactly 1 ALLOW, got {allow_count}. "
            f"Domain scope fix broke concurrent commits! Results: {results}"
        )

        fresh_blocked = sum(
            1 for _, allow, blocker in results if not allow and blocker == "Fresh"
        )
        assert fresh_blocked == 4, f"Expected 4 Fresh blocks, got {fresh_blocked}"

    def test_approval_with_email_and_domain_scope(self) -> None:
        """Approval for email effect with domain-scoped capability works.

        grant_approval() derives the scope from the email domain.
        The approved capability uses the domain label in its scope.
        """
        broker = build()
        task = _make_domain_task("approval-domain", frozenset({"internal"}))
        broker.register_task(task)

        # Grant approval for a send effect
        approval_effect = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={},
            provenance=_provenance("approval-msg", content="test body"),
            capability_nonce="r-send:Agent:EffectBroker",
            delegation_chain=(),
        )

        nonce = broker.grant_approval(approval_effect, expiry=100.0, task_id="approval-domain")

        # Verify the capability has domain-level scope
        cap = broker.capabilities.get(nonce)
        assert cap is not None
        assert cap.scope == frozenset({"internal"}), (
            f"Approval capability scope should be domain-level {{'internal'}}, "
            f"got {cap.scope}"
        )

        # Commit the approved effect
        approved_effect = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={},
            provenance=_provenance("approval-msg", content="test body"),
            capability_nonce=nonce,
            delegation_chain=(),
        )
        stored = broker._approved_requests[nonce]
        commit = Commit(effect=approved_effect, task=task, approved_request=stored)
        allow, ev = broker.commit(commit)

        assert allow is True, f"Approved email commit should ALLOW. Evidence: {ev}"
        assert ev["primary_blocker"] is None

    def test_approval_with_extra_bcc_same_domain(self) -> None:
        """Approval for email with same-domain BCC recipients works."""
        broker = build()
        task = _make_domain_task("approval-bcc", frozenset({"internal"}))
        broker.register_task(task)

        approval_effect = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={"extra_resources": ["team@corp.com"]},
            provenance=_provenance("bcc-approval"),
            capability_nonce="r-send:Agent:EffectBroker",
            delegation_chain=(),
            known_targets=EffectTarget(
                primary="internal@corp.com",
                additional=frozenset({"team@corp.com"}),
            ),
        )

        nonce = broker.grant_approval(approval_effect, expiry=100.0, task_id="approval-bcc")
        stored = broker._approved_requests[nonce]

        # Exact match: same BCC
        effect_with_bcc = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={"extra_resources": ["team@corp.com"]},
            provenance=_provenance("bcc-approval"),
            capability_nonce=nonce,
            delegation_chain=(),
            known_targets=EffectTarget(
                primary="internal@corp.com",
                additional=frozenset({"team@corp.com"}),
            ),
        )

        commit = Commit(effect=effect_with_bcc, task=task, approved_request=stored)
        allow, ev = broker.commit(commit)

        assert allow is True, f"Exact BCC match should ALLOW. Evidence: {ev}"

    def test_approval_blocks_extra_bcc_different_domain(self) -> None:
        """Approval for email blocks extra BCC recipients from different domains."""
        broker = build()
        task = _make_domain_task("approval-bcc-ext", frozenset({"internal"}))
        broker.register_task(task)

        # Approval granted for internal@corp.com only (no BCC)
        approval_effect = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={},
            provenance=_provenance("no-bcc-approval"),
            capability_nonce="r-send:Agent:EffectBroker",
            delegation_chain=(),
        )

        nonce = broker.grant_approval(approval_effect, expiry=100.0, task_id="approval-bcc-ext")
        stored = broker._approved_requests[nonce]

        # Try to add a BCC to an external domain
        effect_with_external_bcc = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={},
            provenance=_provenance("no-bcc-approval"),
            capability_nonce=nonce,
            delegation_chain=(),
            known_targets=EffectTarget(
                primary="internal@corp.com",
                additional=frozenset({"attacker@external.com"}),  # external domain
            ),
        )

        commit = Commit(effect=effect_with_external_bcc, task=task, approved_request=stored)
        allow, ev = broker.commit(commit)

        # NoAmp blocks (extra target outside scope) or ApprovalBinding (extra not approved)
        assert allow is False, "Extra BCC to external domain should BLOCK"
        assert ev["primary_blocker"] in ("NoAmp", "ApprovalBinding")
