"""Tool/MCP-semantics-honesty mediation at the broker -> tool boundary

The four-predicate gate decides *effects proposed to the broker*. It cannot see
the *actual* remote-tool behavior that the MCP/tool layer will perform from the
effect's *declared* shape. This module models the mediation step that decides
whether a prepared effect may be *forwarded* to the remote tool (remote
boundary mode from the brief), mirroring the three MCP-semantics-honesty
failures:

  - false MCP description (T13): the tool's declared write target differs from
    the actual target it would touch
  - hidden side effect (T14):   the tool performs an undeclared side effect
  - monitor bypass (T15):       the effect is itself a monitoring/validation
    action that could bypass the mediation boundary

The verdict is a mediation decision (`BoundaryStop`), not a predicate blocker.
The EffectBroker refuses to *forward* the effect when the boundary stops; that
is distinct from the four-predicate gate over the commit.
"""

from __future__ import annotations

from dataclasses import dataclass

from .model import Effect


@dataclass(frozen=True)
class MediationVerdict:
    """Machine-checkable outcome of the broker -> tool mediation step."""

    allow: bool
    boundary_stop: str | None  # reason the effect is not forwarded, if blocked


def mediate(
    effect: Effect,
    *,
    declared_write_target: str | None = None,
    hidden_side_effect: bool = False,
    monitoring_bypass: bool = False,
) -> MediationVerdict:
    """Decide whether to forward a prepared effect to the remote tool.

    Mirrors the three MCP-semantics-honesty failures from the brief:
      - a tool whose *declared* write target (from its MCP description) differs
        from the actual target it would touch  -> false description (T13)
      - a tool that performs a side effect it does not declare          -> T14
      - an effect that monitors/validates the system but could bypass the
        mediation itself                                                -> T15
    Any such mismatch stops at the boundary: the effect is not forwarded.
    """
    if monitoring_bypass:
        return MediationVerdict(False, "monitor-bypass")
    if hidden_side_effect:
        return MediationVerdict(False, "hidden-side-effect")
    if declared_write_target is not None and declared_write_target != effect.target:
        return MediationVerdict(
            False, f"false-description(declared={declared_write_target},actual={effect.target})"
        )
    return MediationVerdict(True, None)
