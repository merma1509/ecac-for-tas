"""PACT-style capability system (property attestation + capabilities).

What PACT/ChainCaps provides:
- Capability attenuation (narrowing scope)
- Provenance tracking
- Property attestation

What ECAC adds:
- Content hash binding (ApprovedRequest)
- Session taint propagation
- Independent ledger verification
- NoAmp predicate (authority monotonicity)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from effect_broker.model import Effect

from effect_broker.lattice import Confidentiality


@dataclass
class PACTActivity:
    """PACT-style activity record."""

    etype: str
    target: str
    holder: str
    holder_conf: Confidentiality
    scope: frozenset


class PACTBroker:
    """PACT-style broker: capability scope enforced, provenance recorded.

    What PACT actually does, in one sentence: an effect may proceed only if a
    capability held by the caller covers the effect's (etype, target). The
    capability's scope is the authority boundary; provenance is recorded for
    audit but does not itself deny.

    Deliberately absent (each is a trace this comparator does not block *by the
    named mechanism*; several are still denied by missing coverage — see below):

    - No content-hash binding: T2 passes (modify after approval).
    - No session taint: T1 passes.
    - No replay prevention: T4 passes.
    - No recipient completeness: T3 passes (hidden BCC outside scope is not
      checked, because PACT scopes by the declared target only).

    Coverage, not mechanism. T5, T6, T9, T10, T15 and T16 are reported BLOCKED,
    but each with `no capability for (etype, target)` — they are denied because
    `setup_baseline()` issues no grant covering their target, not because PACT
    verifies delegation chains, staleness or content. Counting those as
    "PACT catches it" would overstate the comparator, so the module keeps them
    out of the list above while `run_comparison()` still reports the block.
    """

    def __init__(self) -> None:
        self.activities: list[PACTActivity] = []
        #: holder -> {(right, target)}. In a real PACT deployment this is the
        #: capability store; here it is populated by `grant`.
        self.capabilities: dict[str, set[tuple[str, str]]] = {}

    def grant(self, holder: str, right: str, target: str) -> None:
        """Issue a capability. Attenuation only narrows (no widening path)."""
        self.capabilities.setdefault(holder, set()).add((right, target))

    def commit_effect(self, effect: Effect, task_id: str = "default") -> tuple[bool, dict]:
        """Deny when no capability covers (etype, target); record provenance."""
        holder = effect.capability_nonce
        held = self.capabilities.get(holder, set())

        authorized = any(
            (right == effect.etype or right == "*") and (tgt == effect.target or tgt == "*")
            for right, tgt in held
        )

        self.activities.append(
            PACTActivity(
                etype=effect.etype,
                target=effect.target,
                holder=holder,
                holder_conf=(
                    effect.provenance[0].confidentiality
                    if effect.provenance
                    else Confidentiality.INTERNAL
                ),
                scope=frozenset({effect.target}),
            )
        )

        if not authorized:
            return False, {
                "blocker": "Auth",
                "reason": f"PACT: no capability for ({effect.etype}, {effect.target})",
                "policy": "PACT",
            }

        return True, {
            "blocker": None,
            "reason": "PACT: capability covers effect",
            "policy": "PACT",
        }
