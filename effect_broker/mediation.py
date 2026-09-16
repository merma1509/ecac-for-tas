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

    def inspect(self, effect: Effect, tool_name: str | None) -> MediationVerdict:
        """Decide if the effect can be forwarded to the named tool.

        Runs AFTER the four-predicate gate (so the gate already proved the
        effect is authorised — the question now is whether the tool honours
        the declared shape or deviates).

        Returns:
          - MediationVerdict(allow=True): tool honours declared shape → forward
          - MediationVerdict(allow=False, boundary_stop=...): tool deviates

        .. note::
            This uses tool-provided metadata (ToolSpec.declared_targets,
            ToolSpec.actual_targets) set by the test author. A real adversarial
            tool can lie about its actual targets here. The mandatory boundary
            experiment (test_experiment.py, M1-M5) uses a REAL untrusted tool
            — not metadata — to demonstrate that computation is bounded.
        """
        if tool_name is None or tool_name not in self.tools:
            return MediationVerdict(True, None)

        spec = self.tools[tool_name]

        # T15: monitoring/audit tool could observe/bypass the mediation boundary
        if spec.monitoring:
            return MediationVerdict(False, "monitor-bypass")

        # T13 vs T14: check declared_targets FIRST, then side_effects
        #
        # T14 (ECAC philosophy): declared effect is ALLOW'd
        #   effect.target ∈ declared_targets → broker ALLOWs the declared effect.
        #   Side effects are outside broker scope → audit/observer concern.
        if effect.target in spec.declared_targets:
            return MediationVerdict(True, None)

        # Effect target is NOT in declared_targets. Check if the tool actually
        # knows about this target (in known_side_effects → T13 or actual_targets → T13).
        if effect.target in spec.known_side_effects:
            # T13: tool listed this target in known_side_effects but didn't declare it.
            # The tool has actual knowledge of this resource — BLOCK as false description.
            return MediationVerdict(False, "hidden-side-effect")

        if effect.target in spec.actual_targets:
            # T13: tool's actual_targets includes this target, but not in declared_targets.
            # Clear false description: tool claims X, broker effect is Y.
            return MediationVerdict(
                False,
                f"false-description(declared={spec.declared_targets},"
                f"actual={spec.actual_targets})",
            )

        return MediationVerdict(False, "unknown-tool-target")

    def register_tool(self, spec: ToolSpec) -> None:
        """Register a tool spec with this mediator."""
        self.tools[spec.name] = spec
