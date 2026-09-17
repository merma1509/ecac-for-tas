"""Tool/MCP-semantics-honesty mediation at the broker -> tool boundary

The four-predicate gate decides *effects proposed to the broker*. It cannot see
the *actual* remote-tool behaviour that the MCP/tool layer will perform from
the effect's *declared* shape. This module provides the mediation step that
decides whether a prepared effect may be *forwarded* to the remote tool,
mirroring the three MCP-semantics-honesty failures:

  - false MCP description (T13): the tool's declared write target differs from
    the actual target it would touch
  - hidden side effect (T14):   the tool performs an undeclared side effect
  - monitor bypass (T15):       the effect is itself a monitoring/validation
    action that could bypass the mediation boundary

The verdict is a mediation decision (`BoundaryStop`), not a predicate blocker
The EffectBroker refuses to *forward* the effect when the boundary stops;
that is distinct from the four-predicate gate over the commit
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .model import Effect


@dataclass(frozen=True)
class MediationVerdict:
    """Machine-checkable outcome of the broker → tool mediation step."""

    allow: bool
    boundary_stop: str | None  # reason the effect is not forwarded, if blocked


@dataclass(frozen=True)
class ToolSpec:
    """A tool's declared vs. actual behaviour, used by the Mediator.

    - declared_targets: what the MCP tool's schema says it will touch
    - actual_targets:   what it actually touches (may differ → false description)
    - known_side_effects: undeclared side effects the tool actually performs
    - monitoring: True if the tool itself is a monitoring/audit tool
    """

    name: str
    declared_targets: frozenset[str]
    actual_targets: frozenset[str]
    known_side_effects: frozenset[str]
    monitoring: bool = False


@dataclass
class Mediator:
    """MCP/tool adapter that detects declared-vs-actual mismatches.

    The mediator is a SEPARATE component from the broker. The broker consults
    it before forwarding an allowed effect to the remote tool. This models the
    "boundary experiment": the broker enforces declared-vs-actual honesty
    at the enforcement point, not volunteered by the tool.

    ECAC philosophy:
      The broker authorizes declared effects. Side effects (resources touched
      by the tool that are NOT in declared_targets) are outside broker scope —
      the ledger/observer catches them in production. The broker does NOT
      try to infer what side effects a tool might perform.

      This means:
      - T13 (false description): broker tries to touch a target NOT in
        declared_targets → BLOCK (clear mismatch)
      - T14 (hidden side effect): the declared target IS declared → ALLOW.
        Hidden side effects on other resources are caught by the ledger,
        not blocked at the broker gate.

    Production enforcement:
      In production, the mediator's ToolSpec must be enforced by the MCP
      runtime — the tool is only allowed to touch resources in its
      declared_targets. This is structural enforcement, not metadata-based.
      The test model uses metadata because it's an executable specification,
      not a production enforcement mechanism.

    .. note::
        T13/T14/T15 (false-description / hidden-side-effect / monitor-bypass)
        are self-confirming stubs when ToolSpec.actual_targets is set by the
        test author. They demonstrate the *logic* of declared-vs-actual checking
        but do NOT prove malicious tool computation is bounded — a real tool
        can simply not report its actual targets. The mandatory boundary
        experiment (M1-M5 in tests/test_experiment.py) demonstrates this using a
        real untrusted tool that is ACTUALLY prevented from reaching external
        state, with complete mediation verified by an independent observer
    """

    tools: dict[str, ToolSpec] = field(default_factory=dict)
    # When True, any tool_name without a ToolSpec raises SecurityError.
    # In production, all tools must be registered. Default: False (permissive
    # for direct REPL use, where no tool_name is used).
    strict: bool = False

    def inspect(self, effect: Effect, tool_name: str | None) -> MediationVerdict:
        """Decide if the effect can be forwarded to the named tool.

        Runs AFTER the four-predicate gate (so the gate already proved the
        effect is authorised — the question now is whether the tool honours
        the declared shape or deviates).

        Returns:
          - MediationVerdict(allow=True): tool honours declared shape → forward
          - MediationVerdict(allow=False, boundary_stop=...): tool deviates

        ECAC philosophy: the broker only blocks when the EFFECT ITSELF
        touches a resource NOT in declared_targets (T13 false-description).
        Side effects on declared resources (T14) are allowed — the ledger
        catches the discrepancy. A tool declaring a read target gets the
        broker's authorization for that target; if the tool secretly also
        writes elsewhere, that's caught by the independent observer, not
        blocked at the broker gate.

        .. note::
            This uses tool-provided metadata (ToolSpec.declared_targets,
            ToolSpec.actual_targets) set by the test author. A real adversarial
            tool can lie about its actual targets here. The mandatory boundary
            experiment (test_experiment.py, M1-M5) uses a REAL untrusted tool
            — not metadata — to demonstrate that computation is bounded.
        """
        if tool_name is None:
            # No tool_name: direct broker.commit() (REPL use) — no boundary
            return MediationVerdict(True, None)

        if tool_name not in self.tools:
            if self.strict:
                return MediationVerdict(
                    False,
                    f"unknown-tool(tool={tool_name}, no ToolSpec registered — "
                    "mediator.strict=True requires all tools to register)",
                )
            # In permissive mode, unknown tool passes boundary (documented limitation)
            # The capability-level predicates still gate the effect.
            return MediationVerdict(True, None)

        spec = self.tools[tool_name]

        # T15: monitoring/audit tool could observe/bypass the mediation boundary
        if spec.monitoring:
            return MediationVerdict(False, "monitor-bypass")

        # T13: false description — the effect TARGET is NOT in declared_targets.
        # The broker is trying to touch a resource the tool never claimed to touch.
        # This is a clear declared-vs-actual mismatch → BLOCK.
        if effect.target not in spec.declared_targets:
            return MediationVerdict(
                False,
                f"false-description(effect.target={effect.target} not in "
                f"declared_targets={spec.declared_targets})",
            )

        # ECAC: target IS in declared_targets → ALLOW.
        # The broker authorized this effect. Hidden side effects on OTHER
        # resources are caught by the ledger/observer, not blocked here.
        # known_side_effects does NOT block when the target is declared —
        # that would contradict ECAC's scope boundary.
        return MediationVerdict(True, None)

    def register_tool(self, spec: ToolSpec) -> None:
        """Register a tool spec with this mediator."""
        self.tools[spec.name] = spec
