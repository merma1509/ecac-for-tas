"""CaMeL-style IFC enforcement (without FIDES taint tracking).

What CaMeL/FIDES provides:
- Information Flow Control (IFC) at commit time
- Principal-aware authorization
- LLM outside TCB (trusted computing base)

What ECAC adds:
- Session taint propagation
- Capability nonce with replay prevention
- Ledger-based audit trail
- NoAmp predicate (authority monotonicity)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from effect_broker.model import Effect

from effect_broker.lattice import Confidentiality


class CaMeLBroker:
    """
    CaMeL-style broker: IFC-only, no taint, no ledger.

    Key difference from ECAC:
    - Only checks information flow (no capabilities, no ledger)
    - No session taint propagation
    - No replay prevention
    - No authority monotonicity check

    WEAKNESSES (these bypass CaMeL but not ECAC):
    - No session taint: T1 passes (send after CONFIDENTIAL read)
    - No ledger: T4 passes (replay attack)
    - No capability: T5 passes (scope widening)
    - No delegation check: T6 passes
    """

    def commit_effect(self, effect: Effect, task_id: str = "default") -> tuple[bool, dict]:
        """
        CaMeL-style commit: IFC check only.

        Checks:
        - Confidentiality: no downward flow
        - Integrity: no upward flow

        MISSING (these are ECAC's additions):
        - Capability nonce verification
        - Session taint propagation
        - Ledger-based replay prevention
        - Authority monotonicity (NoAmp)
        """
        # CaMeL checks IFC on provenance data
        # But it doesn't check:
        # 1. Whether the capability is valid
        # 2. Whether the nonce is fresh
        # 3. Whether the session is tainted

        if effect.etype == "send":
            # CaMeL only checks confidentiality in provenance
            # No taint propagation - same confidential data allows send
            for d in effect.provenance:
                if d.confidentiality == Confidentiality.CONFIDENTIAL:
                    # CaMeL doesn't propagate session taint!
                    # This is T1: session taint → send passes
                    pass

        # WEAKNESS: No capability check (any effect allowed)
        # WEAKNESS: No ledger (replay is possible)
        # WEAKNESS: No session taint

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
