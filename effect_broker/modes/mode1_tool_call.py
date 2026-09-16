"""Mode #1: Tool-call checking — the simplest baseline.

Enforcement only at the tool-invocation boundary:
  - If a tool call is made → ALLOW
  - If no tool call → deny (but this means no operation at all)

No capability checking, no IFC, no provenance tracking.
This is the simplest possible defense: a call-level allowlist.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from effect_broker.model import Effect, EffectTarget, Data


@dataclass
class ToolCallCheckResult:
    allow: bool
    evidence: dict
    blocker: str | None


class ToolCallChecker:
    """Mode #1: call-level allowlist enforcement.

    Only checks whether the effect was proposed via a known tool.
    No capability, no IFC, no provenance, no freshness.
    """

    def __init__(self) -> None:
        # Allowlist of known tools (the TCB for this mode)
        # Any tool not in this set is blocked
        self.known_tools: set[str] = {
            "read_file",
            "write_file",
            "send_email",
            "delete_file",
            "http_get",
        }

    def _effect_type_to_tool(self, etype: str) -> str | None:
        """Map effect type to the tool that would produce it."""
        mapping = {
            "read": "read_file",
            "write": "write_file",
            "send": "send_email",
            "delete": "delete_file",
            "network": "http_get",
        }
        return mapping.get(etype)

    def evaluate(self, effect: Effect, tool_name: str | None = None) -> ToolCallCheckResult:
        """Mode #1 evaluation: if tool is known → ALLOW.

        This is trivially exploitable:
          - Any adversarial tool can call itself "read_file" and get ALLOW
          - No capability check means attacker controls the target
          - No IFC means confidential data flows anywhere
          - No freshness means replay is free
        """
        # No tool context → no operation possible
        if tool_name is None:
            return ToolCallCheckResult(
                allow=False,
                evidence={"mode": "tool-call-allowlist", "reason": "no_tool_context"},
                blocker="ToolCall",
            )

        # Known tool → ALLOW (the entire Mode #1 defense)
        if tool_name in self.known_tools:
            return ToolCallCheckResult(
                allow=True,
                evidence={
                    "mode": "tool-call-allowlist",
                    "tool": tool_name,
                    "effect": effect.etype,
                    "target": effect.target,
                },
                blocker=None,
            )

        # Unknown tool → BLOCK
        return ToolCallCheckResult(
            allow=False,
            evidence={
                "mode": "tool-call-allowlist",
                "reason": "unknown_tool",
                "tool": tool_name,
            },
            blocker="ToolCall",
        )

    def can_exploit_via_name_spoofing(self, adversarial_tool_name: str) -> bool:
        """Can an adversarial tool get ALLOW by spoofing a known tool name?"""
        return adversarial_tool_name in self.known_tools


def run_mode1_on_effect(effect: Effect, tool_name: str | None = None) -> bool:
    """Quick helper: returns True if Mode #1 would ALLOW."""
    checker = ToolCallChecker()
    return checker.evaluate(effect, tool_name).allow