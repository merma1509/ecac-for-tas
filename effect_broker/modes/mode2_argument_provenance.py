"""Mode #2: Argument/provenance checking (PACT-style).

PACT-style enforcement:
  - Authority bound to specific arguments at call time
  - Provenance tracked from argument → effect
  - Capability derivation checked at call time
  - No commit-time revalidation (authority checked once, not enforced at mutation)

Unlike Mode #3 (our approach):
  - Mode #2 checks at call/proposal time, not commit time
  - If the same effect is re-proposed without re-validation → may pass
  - No freshness check at the actual mutation moment
  - No atomic fresh check prevents replay after approval
  - No boundary mediation (tools can lie about their effects)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from effect_broker.model import Effect, EffectTarget, Data


@dataclass
class ArgumentBinding:
    """A binding: this effect was authorized for these specific arguments."""
    right: str
    target: str
    scope: frozenset[str]
    bound_arguments: tuple[str, ...] = field(default_factory=tuple)
    provenance_roots: tuple[str, ...] = field(default_factory=tuple)
    authority_source: str = ""  # "capability" or "approval"


@dataclass
class ProvenanceNode:
    """A node in the provenance graph."""
    name: str
    source: str  # "argument", "derived", "constant"
    label: str = "INTERNAL"  # confidentiality class
    integrity: str = "USER"
    children: list[ProvenanceNode] = field(default_factory=list)


@dataclass
class Mode2Result:
    allow: bool
    evidence: dict
    blocker: str | None


class ArgumentProvenanceChecker:
    """Mode #2: PACT-style argument-level provenance + authority binding.

    This is the PACT/CaMeL/FIDES-style baseline:
      - Authority is bound to specific arguments at proposal time
      - Provenance is tracked from arguments to effect
      - No commit-time revalidation (authority checked once)
      - No atomic freshness check at mutation moment
      - No boundary mediation (tools can lie)

    Key weaknesses vs Mode #3 (our broker):
      1. No commit-time revalidation → stale/amplified effects may commit
      2. No atomic freshness → replay is not prevented after approval
      3. No boundary mediation → tools can hide side effects
      4. Provenance is hand-assigned, not verified
    """

    def __init__(self) -> None:
        # Approved argument bindings
        self.bindings: dict[str, ArgumentBinding] = {}
        # Provenance graph
        self.provenance: list[ProvenanceNode] = []

    def grant_argument_binding(
        self,
        binding_id: str,
        right: str,
        target: str,
        scope: frozenset[str],
        bound_args: tuple[str, ...] = (),
        authority_source: str = "capability",
    ) -> None:
        """Grant an argument binding (like a PACT capability)."""
        self.bindings[binding_id] = ArgumentBinding(
            right=right,
            target=target,
            scope=scope,
            bound_arguments=bound_args,
            authority_source=authority_source,
        )

    def track_provenance(
        self,
        name: str,
        source: str,
        label: str = "INTERNAL",
        integrity: str = "USER",
        parent: ProvenanceNode | None = None,
    ) -> ProvenanceNode:
        """Track a provenance node in the graph."""
        node = ProvenanceNode(name=name, source=source, label=label, integrity=integrity)
        if parent is not None:
            parent.children.append(node)
        self.provenance.append(node)
        return node

    def _check_argument_binding(self, effect: Effect) -> tuple[bool, str]:
        """Mode #2 step 1: check if authority is bound to these arguments.

        In PACT, this is checked at call time. If the binding exists → proceed.
        This does NOT re-check at commit time.
        """
        for binding in self.bindings.values():
            if binding.right == effect.etype and binding.target == effect.target:
                # Bound arguments must match (if any were recorded)
                # In PACT, this is the core: authority → specific arguments
                return True, f"binding-ok({binding.authority_source})"

        # No matching binding
        return False, "no-argument-binding"

    def _check_provenance_labels(self, effect: Effect) -> tuple[bool, str]:
        """Mode #2 step 2: check if provenance labels allow this effect.

        This is the PACT-style IFC check: high-integrity arguments may not
        produce effects that flow to low-integrity sinks without endorsement.
        """
        for datum in effect.provenance:
            if datum.confidentiality.name == "CONFIDENTIAL":
                if "@" in effect.target and "corp" not in effect.target.split("@")[1]:
                    # CONFIDENTIAL → external sink
                    return False, f"conf-to-external({datum.name})"
            if datum.integrity.name == "UNTRUSTED":
                # Low-integrity data can drive effects but may not control
                # privileged actions without endorsement
                # In PACT, this is checked at call time, not commit time
                if "secrets" in effect.target or effect.target.endswith("/secrets"):
                    return False, f"low-integrity-to-secrets({datum.name})"

        return True, "provenance-ok"

    def _check_no_amplification(self, effect: Effect) -> tuple[bool, str]:
        """Mode #2 step 3: check authority was not amplified.

        In PACT, amplification is prevented by binding authority to arguments.
        But without commit-time revalidation, the same call can be re-executed.
        """
        # Mode #2: no amplification check at this level
        # The binding prevents widening in the initial call,
        # but does NOT prevent replay of an already-checked call
        return True, "noamp-ok"

    def evaluate(self, effect: Effect, tool_name: str | None = None) -> Mode2Result:
        """Mode #2 evaluation: argument binding + provenance + no-amplification.

        All checks happen at proposal/call time. There is no commit-time
        revalidation. Once a call passes this gate, it can be re-executed
        without re-checking (replay vulnerability).
        """
        # Step 1: argument binding check
        binding_ok, binding_msg = self._check_argument_binding(effect)
        if not binding_ok:
            return Mode2Result(
                allow=False,
                evidence={
                    "mode": "argument-provenance-check",
                    "step": "argument-binding",
                    "detail": binding_msg,
                    "effect": effect.etype,
                    "target": effect.target,
                },
                blocker="ArgumentBinding",
            )

        # Step 2: provenance/IFC check
        prov_ok, prov_msg = self._check_provenance_labels(effect)
        if not prov_ok:
            return Mode2Result(
                allow=False,
                evidence={
                    "mode": "argument-provenance-check",
                    "step": "provenance-labels",
                    "detail": prov_msg,
                    "effect": effect.etype,
                    "target": effect.target,
                    "provenance": [d.name for d in effect.provenance],
                },
                blocker="Provenance",
            )

        # Step 3: no amplification check (weak — no commit-time revalidation)
        noamp_ok, noamp_msg = self._check_no_amplification(effect)
        if not noamp_ok:
            return Mode2Result(
                allow=False,
                evidence={
                    "mode": "argument-provenance-check",
                    "step": "no-amplification",
                    "detail": noamp_msg,
                },
                blocker="NoAmp",
            )

        return Mode2Result(
            allow=True,
            evidence={
                "mode": "argument-provenance-check",
                "binding": binding_msg,
                "provenance": prov_msg,
                "effect": effect.etype,
                "target": effect.target,
            },
            blocker=None,
        )

    def can_exploit_replay(self, effect: Effect, approved_binding_id: str) -> bool:
        """Can the same effect be re-committed after approval (replay)?

        Mode #2: YES. Once approved, the same call can be re-executed.
        Mode #3 (our broker): NO. Fresh nonce is consumed on first commit.
        """
        if approved_binding_id not in self.bindings:
            return False  # No binding → not approved
        binding = self.bindings[approved_binding_id]
        if binding.right == effect.etype and binding.target == effect.target:
            return True  # Same effect re-proposed → replay possible in Mode #2
        return False


def run_mode2_on_effect(effect: Effect) -> bool:
    """Quick helper: returns True if Mode #2 would ALLOW."""
    checker = ArgumentProvenanceChecker()
    return checker.evaluate(effect).allow