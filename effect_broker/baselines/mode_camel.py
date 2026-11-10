"""CaMeL-style IFC enforcement (without FIDES taint tracking).

What CaMeL/FIDES provides:
- Information Flow Control (IFC) at commit time
- Integrity: values from untrusted sources must not reach a sink unendorsed
- LLM outside TCB

What ECAC adds (and this comparator deliberately lacks):
- Session taint propagation
- Capability nonce with replay prevention
- Ledger-based audit trail
- NoAmp predicate (authority monotonicity)
- Recipient (BCC) completeness

The IFC check below is the mechanism CaMeL actually names: a data policy
attached to a value's provenance decides whether that value may flow to the
effect's sink. An untrusted value reaching a send/write sink is denied. This
is a real deny path — before it, `commit_effect` returned True unconditionally
and could not reject any trace.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from effect_broker.model import Effect

from effect_broker.lattice import Confidentiality, Integrity

#: Effect types that publish data outside the agent's trust domain.
_SINKS = frozenset({"send", "write", "network"})


class CaMeLBroker:
    """CaMeL-style broker: IFC only — no capabilities, no ledger, no taint.

    Deliberately absent (each is a trace this comparator does not block):

    - No session taint: T1 passes (send after a CONFIDENTIAL read).
    - No ledger: T4 passes (replay).
    - No capability/scope: T5 passes (scope widening).
    - No delegation check: T6 passes.
    - No recipient completeness: T3 passes (hidden BCC).
    - No content binding: T2, T15 pass.
    """

    def commit_effect(self, effect: Effect, task_id: str = "default") -> tuple[bool, dict]:
        """IFC check: deny untrusted values flowing to a publish sink.

        CaMeL's rule is per-value: the value carries a policy, and the policy
        must permit the flow. Confidentiality alone is NOT a block — CaMeL
        permits reading confidential data and acting on it; what it forbids is
        an *unendorsed* value reaching a sink. That is why T1 (confidential
        flow within the session) passes, while T7 (PUBLIC/UNTRUSTED injection)
        is denied.
        """
        if effect.etype in _SINKS:
            for datum in effect.provenance:
                if datum.integrity == Integrity.UNTRUSTED:
                    return False, {
                        "blocker": "IFC",
                        "reason": (
                            f"CaMeL IFC: untrusted value {datum.name!r} "
                            f"flows to {effect.etype} sink"
                        ),
                        "policy": "CaMeL",
                    }

        return True, {
            "blocker": None,
            "reason": "CaMeL: IFC OK",
            "policy": "CaMeL",
        }


# ---- Simpler, more honest weak baseline for comparison ----
class CaMeLWeakBaseline:
    """
    Simplified CaMeL: checks confidentiality labels, no other security.

    This is the BASE CASE - no security beyond basic label checking.
    We use this to show our ECAC's improvement over label-only approaches.
    """

    def commit_effect(self, effect: Effect, task_id: str = "default") -> tuple[bool, dict]:
        """Allow all effects with INTERNAL or lower confidentiality."""
        # Only check that provenance doesn't exceed PUBLIC
        for d in effect.provenance:
            if d.confidentiality.value > Confidentiality.INTERNAL.value:
                return False, {
                    "blocker": "CONFIDENTIAL-flow",
                    "reason": "CaMeLWeak: CONFIDENTIAL not allowed without taint check",
                    "policy": "CaMeL-Weak",
                }

        return True, {
            "blocker": None,
            "reason": "CaMeLWeak: label OK",
            "policy": "CaMeL-Weak",
        }
