"""Tool allowlist baseline - simple pattern matching."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from effect_broker.model import Effect


ALLOWED_TOOLS = {
    "send_email": "mailto:",
    "write_file": "file:///",
    "read_file": "file:///",
}


class AllowlistBroker:
    """
    Simple tool allowlist: checks tool name + target pattern.

    Key difference from ECAC:
    - Pattern matching only (no formal semantics)
    - No provenance tracking
    - No session taint
    - No ledger
    - No capability system

    WEAKNESSES (these bypass allowlist but not ECAC):
    - T1: No session taint (send after CONFIDENTIAL read)
    - T2: No content hash (modify after approval)
    - T4: No ledger (replay)
    - T6: No delegation chain check
    - T7: No provenance integrity check
    - T9: No freshness check
    """

    def commit_effect(self, effect: Effect, task_id: str = "default") -> tuple[bool, dict]:
        """
        Allowlist commit: pattern matching only.

        WEAKNESSES:
        - No capability check
        - No session taint
        - No provenance
        - No ledger
        """
        # Simple pattern check
        tool_map = {
            "send": "mailto:",
            "write": "file:///",
            "read": "file:///",
        }

        prefix = tool_map.get(effect.etype, "")
        if prefix and effect.target.startswith(prefix):
            return True, {
                "blocker": None,
                "reason": "Allowlist: pattern match",
                "policy": "Allowlist",
            }

        return False, {"blocker": "Allowlist", "reason": "pattern-mismatch"}
