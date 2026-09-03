"""The EffectBroker: the only principal that can commit an effect

Evaluates the four predicates at commit time and returns machine-checkable
evidence for every allow/deny decision

NoAmp is path-based, not set-based: an effect is non-amplifying iff every
capability backing its delegation chain is root-anchored (owner is a trusted
root) and produced by monotonic attenuation. This correctly rejects forged or
widened capabilities that merely happen to be present in the broker's store
"""

from __future__ import annotations

from typing import TypedDict

from .lattice import Confidentiality, Integrity
from .mediation import MediationVerdict
from .model import APPROVER, BROKER, USER, Capability, Commit, Effect, LabelException
from .resources import ResourceStore

# Trusted roots: only these principals may seed NEW authority. Everything else
# must attenuate an existing root-anchored capability (monotonic, no widening)
TRUSTED_ROOTS: frozenset[str] = frozenset({USER})

# Type aliases
PredicateResult = tuple[bool, str]


class Evidence(TypedDict):
    """Machine-checkable record emitted for every commit decision"""

    allow: bool
    primary_blocker: str | None
    predicates: dict[str, str]
    boundary_stop: str | None  # tool-boundary mediation reason, if the commit
    # was allowed by the gate but stopped before forwarding to the remote tool


def _provides(auth_capability: Capability, right: str, target: str) -> bool:
    """True if the capability's right+target covers this (right, target)"""
    return auth_capability.right == right and auth_capability.target == target


class EffectBroker:
    def __init__(self) -> None:
        self.capabilities: dict[str, Capability] = {}  # nonce -> Capability
        self.revoked: set[str] = set()  # revoked nonces
        self.used: set[str] = set()  # committed (replay-prevention) nonces
        self.logical_time: float = 0.0  # logical time counter
        self.store: ResourceStore = ResourceStore()  # external state (R = F ∪ E ∪ M)
        # Validated declass/endorse grants. Only the broker writes here (LLM may
        # only request). keyed by nonce
        self.label_exceptions: dict[str, LabelException] = {}
        # One-shot approvals granted by an Approver after risk escalation
        # nonce -> expiry; a one-shot capability used once is then consumed
        self.approvals: dict[str, float] = {}
        # Risk model (sample): a learned risk_theta classifier may route an
        # effect to an Approver, but it is NOT part of the formal allow rule
        self.risk_override: float = 0.0  # > 0 triggers escalation for testing

    # ---- capability management (monotonic, root-anchored) ----
    def grant_root(self, capability: Capability) -> None:
        """Seed NEW authority. Only a trusted root may do this"""
        assert capability.owner in TRUSTED_ROOTS, (
            f"non-root principal {capability.owner} cannot seed authority (NoAmp)"
        )
        assert capability.derives_from is None, "root grant must not have a parent"
        self.capabilities[capability.nonce] = capability

    def attenuate(
        self,
        parent_nonce: str,
        holder: str,
        right: str,
        target: str,
        scope: frozenset[str],
        expiry: float,
    ) -> Capability:
        """Derive a child capability from a parent. Must not widen authority.

        Requires:
          - parent exists,
          - child scope is a subset of parent scope (monotonic),
          - the parent actually authorizes this (right, target) — i.e. the child
            asks for no more than the parent granted.
        """
        parent = self.capabilities[parent_nonce]
        assert scope <= parent.scope, f"attenuation must narrow scope ({scope} !<= {parent.scope})"
        assert _provides(parent, right, target), "cannot widen authority beyond parent grant"

        # Capabilities may be forwarded (standard object-capability transitivity);
        # NoAmp safety comes from *monotonic narrowing* + *root-anchoring* (the
        # child still carries the root owner via derives_from), not from banning
        # delegation. A holder may pass a capability on subject to monotonicity
        child = Capability(
            owner=parent.owner,
            holder=holder,
            right=right,
            target=target,
            scope=scope,
            expiry=expiry,
            nonce=f"{parent.nonce}:{holder}",
            derives_from=parent.nonce,
        )
        self.capabilities[child.nonce] = child
        return child

    def revoke(self, nonce: str) -> None:
        """Revoke a capability by nonce (freshness check rejects revoked caps)"""
        capability = self.capabilities.get(nonce)
        if capability is None:
            raise KeyError(f"cannot revoke unknown capability: {nonce}")
        self.revoked.add(nonce)

    def attempt_wide(
        self,
        parent_nonce: str,
        holder: str,
        right: str,
        target: str,
        scope: frozenset[str],
        expiry: float,
    ) -> Capability:
        """Deliberately create a NON-monotonic (widened) capability.

        This models "delegation widening" (T6): an agent tries to hand a
        sub-agent a capability that is NOT a monotonic narrowing of its own —
        either a wider scope or a right/target the parent never granted. The
        capability is still *root-anchored* in the sense that it carries the
        parent's owner, so it will PASS Auth (right+target match, holder=broker)
        but will be rejected by NoAmp because the derivation is non-monotonic.

        Unlike `attenuate`, this deliberately violates the monotonic rule on
        purpose — it is used ONLY to build an adversarial widening trace so the
        gate can reject it at commit time with machine-checkable NoAmp evidence,
        rather than the restricted path crashing.
        """
        parent = self.capabilities[parent_nonce]
        child = Capability(
            owner=parent.owner,
            holder=holder,
            right=right,
            target=target,
            scope=scope,
            expiry=expiry,
            nonce=f"{parent.nonce}:{holder}:wide",
            derives_from=parent.nonce,
        )
        self.capabilities[child.nonce] = child
        return child

    # ---- declass/endorse (broker-only privileged operations) ----
    def grant_label_exception(self, exception: LabelException) -> None:
        """Record a validated declass/endorse grant. BROKER-ONLY

        declass/endorse are privileged operations performed ONLY
        by the EffectBroker on explicit User Policy or a validated approval.
        The LLM may request (see request_label_exception), never perform. This
        is the single trusted spot where an otherwise-forbidden flow may be
        explicitly allowed (T3): the label reclassification is explicit and
        attributable to a trusted grantor
        """
        if exception.granted_by not in (USER, APPROVER):
            raise ValueError(
                f"label exception must be granted by a trusted principal "
                f"(User or Approver), got {exception.granted_by}"
            )
        if exception.nonce in self.label_exceptions:
            raise ValueError(f"duplicate label exception nonce {exception.nonce}")
        self.label_exceptions[exception.nonce] = exception

    @staticmethod
    def request_label_exception(
        *, kind: str, target: str, from_label: str, to_label: str
    ) -> LabelException:
        """LLM/agent-side REQUEST for a declass/endorse

        Important: this only builds the *request*; it does NOT grant anything
        The broker must later record it via grant_label_exception after checking
        policy. This enforces "LLM may request, never perform".
        """
        return LabelException(kind, target, from_label, to_label, "?", "?")

    # ---- risk model placement: escalation, NOT in the allow rule ----
    def assess_risk(self, effect: Effect) -> float:
        """Learned/stub risk classifier. May route to an Approver for review

        This is deliberately NOT part of the formal allow rule: the four
        predicates decide allow/deny regardless of this score. If the score is
        high, the effect is *routed* to an Approver; approval grants a fresh,
        one-shot capability which must STILL pass Auth ^ FlowOK ^ NoAmp ^ Fresh
        at commit. The theorem holds even if this classifier is wrong
        """
        # Minimal stub: escalate sensitive-target effects unless overridden
        score = 0.0
        if effect.target.endswith("/secrets") or effect.target.startswith("http://"):
            score = 0.9
        # test override lets us force a high/low risk deterministically
        return max(score, self.risk_override)

    def needs_review(self, effect: Effect) -> bool:
        """True if the risk model wants human review before commit."""
        return self.assess_risk(effect) >= 0.8

    def grant_approval(self, effect: Effect, expiry: float) -> str:
        """Approver grants a FRESH, ONE-SHOT capability for `effect`

        Called after the risk model routes the effect to an Approver and the
        Approver approves it. The approved capability is fresh (expiry>now) and
        single-use (consumed on first successful commit). It grants the exact
        right+target of the effect — it does not widen anything. The resulting
        capability still must pass Auth ^ FlowOK ^ NoAmp ^ Fresh at commit
        """
        nonce = f"approval:{effect.etype}:{effect.target}:{len(self.approvals)}"
        cap = Capability(
            owner=USER,
            holder=BROKER,
            right=effect.etype,
            target=effect.target,
            scope=frozenset({effect.target}),
            expiry=expiry,
            nonce=nonce,
            derives_from=None,
        )
        self.capabilities[nonce] = cap
        self.approvals[nonce] = expiry  # one-shot: consumed after first commit
        return nonce

    def _has_validated_exception(self, effect: Effect, kind: str, datum_label_name: str) -> bool:
        """True if a broker-recorded, validated exception sanctions this override

        An exception applies only if:
          - it targets this effect's sink (or "*")
          - its `from_label` names the label currently violating the flow
          - the grant was actually recorded by the broker (nonce known)
        This makes declass/endorse explicit, attributable, and broker-validated
        """
        for exception in effect.label_exceptions:
            grant = self.label_exceptions.get(exception.nonce)
            if grant is None:
                continue  # not yet broker-validated
            if grant.kind != kind:
                continue
            if grant.match_target != "*" and grant.match_target != effect.target:
                continue
            if grant.from_label != datum_label_name:
                continue
            return True
        return False

    # ---- root-anchored derivation check (helper for NoAmp) ----
    def _is_legitimate(self, capability: Capability) -> bool:
        """Root-anchored AND monotonic: owner is a trusted root and the whole
        chain down to `capability` was produced only by monotonic attenuation"""
        if capability.owner not in TRUSTED_ROOTS:
            return False
        seen: set[str] = set()
        chain_node: Capability | None = capability
        while chain_node is not None:
            if chain_node.nonce in seen:  # cycle guard (paranoid)
                return False
            seen.add(chain_node.nonce)
            if chain_node.derives_from is None:
                # root grants are legitimate iff owner is trusted.
                return chain_node.owner in TRUSTED_ROOTS
            parent = self.capabilities.get(chain_node.derives_from)
            if parent is None:
                return False
            # monotonicity: derived cap may not widen scope or request a target
            # outside the parent's granted authority
            if not (
                chain_node.scope <= parent.scope
                and _provides(parent, chain_node.right, chain_node.target)
            ):
                return False
            chain_node = parent
        return True

    # ---- the four predicates ----
    def check_auth(self, effect: Effect) -> PredicateResult:
        capability = self.capabilities.get(effect.capability_nonce)
        if capability is None:
            return False, "no-capability"
        if capability.holder != BROKER:
            return False, "holder-not-broker"
        if capability.right != effect.etype:
            return False, f"right-mismatch({capability.right}!={effect.etype})"
        if capability.target != effect.target:
            return False, f"target-mismatch({capability.target}!={effect.target})"
        if capability.revoked:
            return False, "revoked"
        return True, "auth-ok"

    def check_flow(self, effect: Effect) -> PredicateResult:
        # Sink labels per effect type. read/delete have no outgoing sink so
        # confine only; send/write/network leak to a sink.
        if effect.etype in ("read", "delete"):
            sink_confidentiality = Confidentiality.CONFIDENTIAL  # safe upper bound (no leakage)
            sink_integrity = Integrity.UNTRUSTED  # no integrity floor for read/delete
        else:  # send | write | network
            sink_confidentiality = Confidentiality.INTERNAL
            sink_integrity = Integrity.USER  # privileged actions need user trust
        for datum in effect.provenance:
            if datum.confidentiality > sink_confidentiality and not self._has_validated_exception(
                effect, "declass", datum.confidentiality.name
            ):
                return False, (
                    f"conf-leak({datum.name}:"
                    f"{datum.confidentiality.name}>{sink_confidentiality.name})"
                )
            if datum.integrity < sink_integrity and not self._has_validated_exception(
                effect, "endorse", datum.integrity.name
            ):
                return False, (
                    f"low-integrity({datum.name}:{datum.integrity.name}<{sink_integrity.name})"
                )
        return True, "flow-ok"

    def check_noamp(self, effect: Effect) -> PredicateResult:
        """Path-based NoAmp.

        Every capability backing the delegation chain of `effect` must be a
        legitimate root-anchored derivation, and the chain must not widen
        authority. Returns (ok, evidence) where evidence lists the reason.
        """
        # The capability that authorizes this effect.
        capability = self.capabilities.get(effect.capability_nonce)
        if capability is None:
            return False, "no-capability"
        if not self._is_legitimate(capability):
            return (
                False,
                f"not-root-anchored(owner={capability.owner},derives={capability.derives_from})",
            )
        # Every principal along the chain must also be backed by legit authority.
        # (In this minimal model the chain is the attenuation path already, so
        #  checking the committing capability's root-anchoring covers it; we still
        #  verify there is no widened authority among chain principals.)
        chain_authority: set[tuple[str, str]] = set()
        for principal in effect.chain:
            for chain_capability in self.capabilities.values():
                if (
                    chain_capability.holder == principal
                    and chain_capability.derives_from is None
                    and chain_capability.owner in TRUSTED_ROOTS
                ):
                    chain_authority.add((chain_capability.right, chain_capability.target))
        effect_authority: set[tuple[str, str]] = {(effect.etype, effect.target)}
        if not (effect_authority <= chain_authority):
            return False, f"effect={effect_authority}!<=root-chain={chain_authority}"
        return True, f"mastered(owner={capability.owner},root-chain={chain_authority})"

    def check_fresh(self, effect: Effect) -> PredicateResult:
        capability = self.capabilities.get(effect.capability_nonce)
        if capability is None:
            return False, "no-capability"
        if capability.expiry <= self.logical_time:
            return False, f"expired(t={self.logical_time},exp={capability.expiry})"
        if capability.nonce in self.revoked:
            return False, "revoked"
        if effect.capability_nonce in self.used:
            return False, "replay"
        return True, "fresh"

    # ---- commit gate (the ONLY way external state changes) ----
    def commit(
        self, commit: Commit, mediation: MediationVerdict | None = None
    ) -> tuple[bool, Evidence]:
        """Evaluate the four-predicate gate over the COMMIT primitive

        read/write/send/delete/network are prepared (staged, non-mutating);
        only COMMIT changes external state, and only the EffectBroker may
        invoke it. `commit` performs the predicate gate on the wrapped prepared
        `Effect`. If allowed, the prepared effect is applied
        (and its capability nonce marked used, playing replay prevention)

        `mediation` (optional) models the broker->tool boundary (remote-boundary
        mode). Even if all four predicates pass, a mediating verdict that stops
        the boundary prevents the effect from being forwarded to the remote
        tool — so no side effect occurs (T13/T14/T15)
        """
        effect = commit.effect
        predicate_results: dict[str, PredicateResult] = {
            "Auth": self.check_auth(effect),
            "FlowOK": self.check_flow(effect),
            "NoAmp": self.check_noamp(effect),
            "Fresh": self.check_fresh(effect),
        }
        allow = all(predicate_result[0] for predicate_result in predicate_results.values())
        # primary blocker: first predicate that failed, in a stable order
        predicate_order = ("Auth", "FlowOK", "NoAmp", "Fresh")
        blocking_predicate = next(
            (predicate for predicate in predicate_order if not predicate_results[predicate][0]),
            None,
        )
        # If a mediating verdict stops the boundary, the forward is blocked even
        # though the gate allowed it (tool/MCP-semantics-honesty).
        boundary_stop: str | None = None
        if allow and mediation is not None and not mediation.allow:
            allow = False
            boundary_stop = mediation.boundary_stop

        evidence: Evidence = {
            "allow": allow,
            "primary_blocker": blocking_predicate,
            "predicates": {
                predicate: predicate_result[1]
                for predicate, predicate_result in predicate_results.items()
            },
            "boundary_stop": boundary_stop,
        }
        if allow:
            self.used.add(effect.capability_nonce)
            self.store.apply_effect(effect)  # prepared effect becomes a real side effect
        return allow, evidence

    # backward-compatible convenience: commit a prepared Effect directly
    def commit_effect(self, effect: Effect) -> tuple[bool, Evidence]:
        """Convenience wrapper: commit(Commit(effect))

        Kept so callers can stage an effect and commit it in one step; the
        semantic is identical to wrapping it as a Commit primitive. The broker
        remains the only principal that can commit and thus mutate external state
        """
        return self.commit(Commit(effect))
