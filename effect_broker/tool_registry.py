"""Tool Registry: structural enforcement of tool-declared capabilities.

This module provides STRUCTURAL enforcement for the tool boundary:
every tool MUST declare its capabilities upfront, and the broker checks
that each effect only uses declared rights/targets.

Architecture:
  tool_declares(rights=[read], targets=[file:///reports])
  → ToolDeclaration stored in ToolRegistry
  → FileShim/RealFileShim checks: each effect's (right, target) ∈ declared
  → Effect NOT in declared rights → BLOCK before broker.gate()

This closes the T14 (hidden side effect) and T13 (false MCP description)
gaps by making tool capability declarations STRUCTURAL constraints, not
just metadata. A tool cannot perform a write if it only declared read.

Key distinction from Mediator:
  - Mediator: tool's declared_targets vs effect.target (T13 boundary check)
  - ToolRegistry: tool's declared (right, target) pairs (T14 structural check)

Both are enforcement, not just detection. The ledger catches post-commit
discrepancies (for T14 on declared targets); the registry prevents
un-declared operations from even reaching the broker gate.

Usage:
    registry = ToolRegistry()
    registry.declare("read-reports-tool", declared_rights=["read"], declared_targets=["file:///reports"])

    shim = FileShim(broker, tool_name="read-reports-tool")
    shim._set_registry(registry)  # shim enforces at construction time

    # If tool calls write → SecurityError BEFORE broker.gate()
    shim.write("file:///reports", b"x")  # SecurityError: undeclared right "write"

For T14 (hidden side effect on declared target):
  - Tool declares read(file:///reports)
  - Tool secretly also writes to file:///reports (audit log)
  → ToolRegistry blocks write as "undeclared right"
  → T14 is prevented structurally, not just detected by ledger
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .model import Effect


@dataclass(frozen=True)
class ToolDeclaration:
    """A tool's declared capabilities: which rights it may perform on which targets.

    This is the STRUCTURAL constraint: a tool MUST only perform operations
    that are explicitly declared. Undeclared operations raise SecurityError
    at the shim level, before reaching the broker gate.

    Design rationale:
      - Declared rights: which effect types ("read", "write", "send", etc.)
      - Declared targets: which resources the tool may touch
      - Both must match for the operation to be allowed

    This is NOT the same as capability authorization (Auth predicate).
    Auth checks whether the capability EXISTS and is valid. ToolDeclaration
    checks whether the tool is AUTHORIZED to use that capability — a tool
    that declares only "read" cannot perform "write" even if it somehow
    has a write capability.
    """

    tool_name: str
    declared_rights: frozenset[str]
    declared_targets: frozenset[str]
    description: str = ""


class ToolRegistry:
    """Registry of declared tool capabilities for structural enforcement.

    All tools MUST be registered (strict mode) or are treated as having
    all rights (permissive mode). This is the STRUCTURAL enforcement layer
    above the broker's four-predicate gate.

    In production, this registry would be populated from a trusted
    tool manifest (e.g., MCP tool schema verified by the system administrator),
    not from tool self-descriptions.
    """

    def __init__(self, strict: bool = False) -> None:
        """Create a tool registry.

        Args:
            strict: if True, any tool NOT in the registry raises SecurityError.
                    If False, unknown tools are allowed (documented limitation).
        """
        self._declarations: dict[str, ToolDeclaration] = {}
        self.strict = strict

    def declare(self, declaration: ToolDeclaration) -> None:
        """Register a tool's declared capabilities."""
        self._declarations[declaration.tool_name] = declaration

    def get(self, tool_name: str) -> ToolDeclaration | None:
        """Get a tool's declaration, or None if not registered."""
        return self._declarations.get(tool_name)

    def check_operation(
        self,
        tool_name: str,
        effect: Effect,
    ) -> tuple[bool, str]:
        """Check if a tool's effect is within its declared capabilities.

        Returns (ok, reason). If ok=False, the operation should raise
        SecurityError at the shim level.

        Checks:
          1. Tool is registered (in strict mode)
          2. Effect's etype (right) is in declared_rights
          3. Effect's target is in declared_targets
          4. Extra targets (BCC/CC) are in declared_targets

        This is called by the FileShim before constructing the Effect
        and submitting to the broker. Structural enforcement happens
        BEFORE the broker gate, not AFTER.
        """
        declaration = self._declarations.get(tool_name)

        if declaration is None:
            if self.strict:
                return False, (
                    f"undeclared-tool(tool={tool_name}): "
                    f"tool is not registered in the ToolRegistry (strict mode). "
                    f"All tools must register their declared capabilities upfront."
                )
            # Permissive: unknown tool → allow (documented limitation)
            return True, "permissive-unknown-tool"

        # Check: right (etype) must be declared
        if effect.etype not in declaration.declared_rights:
            return False, (
                f"undeclared-right(tool={tool_name}, right={effect.etype}, "
                f"declared={declaration.declared_rights}): "
                f"tool declared only {declaration.declared_rights} but attempted {effect.etype}"
            )

        # Check: primary target must be declared
        if effect.target not in declaration.declared_targets:
            return False, (
                f"undeclared-target(tool={tool_name}, target={effect.target}, "
                f"declared={declaration.declared_targets}): "
                f"tool attempted to access target outside its declared scope"
            )

        # Check: extra targets (BCC/CC) must be declared
        if effect.known_targets is not None and effect.known_targets.additional:
            for extra in effect.known_targets.additional:
                if extra not in declaration.declared_targets:
                    return False, (
                        f"undeclared-extra-target(tool={tool_name}, extra={extra}, "
                        f"declared={declaration.declared_targets}): "
                        f"tool attempted BCC/CC to target outside declared scope"
                    )

        return (
            True,
            f"declared-right(tool={tool_name}, right={effect.etype}, target={effect.target})",
        )

    def check_operation_by_name(
        self,
        tool_name: str,
        operation: str,
        target: str,
        extra_targets: frozenset[str] = frozenset(),
    ) -> tuple[bool, str]:
        """Check operation without constructing an Effect.

        Convenience method for FileShim: checks (operation, target) before
        building the Effect object.
        """
        declaration = self._declarations.get(tool_name)

        if declaration is None:
            if self.strict:
                return False, f"undeclared-tool(tool={tool_name})"
            return True, "permissive-unknown-tool"

        if operation not in declaration.declared_rights:
            return False, (
                f"undeclared-right(tool={tool_name}, right={operation}, "
                f"declared={declaration.declared_rights})"
            )

        if target not in declaration.declared_targets:
            return False, f"undeclared-target(tool={tool_name}, target={target})"

        for extra in extra_targets:
            if extra not in declaration.declared_targets:
                return False, f"undeclared-extra-target(tool={tool_name}, extra={extra})"

        return True, f"declared-right(tool={tool_name}, right={operation})"
