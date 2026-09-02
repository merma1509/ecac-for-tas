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
from .model import BROKER, USER, Capability, Effect

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


def _provides(auth_capability: Capability, right: str, target: str) -> bool:
    """True if the capability's right+target covers this (right, target)"""
    return auth_capability.right == right and auth_capability.target == target


class EffectBroker:
    def __init__(self) -> None:
        self.capabilities: dict[str, Capability] = {}  # nonce -> Capability
        self.revoked: set[str] = set()  # revoked nonces
        self.used: set[str] = set()  # committed (replay-prevention) nonces
        self.logical_time: float = 0.0  # logical time counter

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
        # delegation. A holder may pass a capability on subject to monotonicity.
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
        self.revoked.add(nonce)

    # ---- root-anchored derivation check (helper for NoAmp) ----
    def _is_legitimate(self, capability: Capability) -> bool:
        """Root-anchored AND monotonic: owner is a trusted root and the whole
        chain down to `capability` was produced only by monotonic attenuation."""
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
            if datum.confidentiality > sink_confidentiality:
                return False, (
                    f"conf-leak({datum.name}:"
                    f"{datum.confidentiality.name}>{sink_confidentiality.name})"
                )
            if datum.integrity < sink_integrity:
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

    # ---- commit gate ----
    def commit(self, effect: Effect) -> tuple[bool, Evidence]:
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
        if allow:
            self.used.add(effect.capability_nonce)
        return allow, {
            "allow": allow,
            "primary_blocker": blocking_predicate,
            "predicates": {
                predicate: predicate_result[1]
                for predicate, predicate_result in predicate_results.items()
            },
        }
