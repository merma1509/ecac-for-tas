"""FORGE-style policy DSL + runtime authorization."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from effect_broker.model import Effect


@dataclass
class PolicyRule:
    """FORGE-style policy rule."""

    effect_type: str | None
    target_pattern: str | None
    action: str
    priority: int = 0


@dataclass
class Policy:
    """FORGE-style policy containing rules."""

    name: str
    rules: list[PolicyRule]


class ForgeBroker:
    """
    FORGE-style broker: policy DSL + runtime authorization.

    WEAKNESSES (these bypass FORGE but not ECAC):
    - Policy DSL requires trusted policy generation
    - No formal invariant (T1-T4 not enforced)
    - No commit-time revalidation
    - No session taint propagation
    - No independent ledger
    """

    def __init__(self) -> None:
        self.policies: dict[str, Policy] = {}
        self._setup_default_policies()

    def _setup_default_policies(self) -> None:
        send_policy = Policy(
            "send",
            [
                PolicyRule("send", r"internal@corp\.com$", "allow", 1),
                PolicyRule("send", None, "deny", 0),
            ],
        )
        self.policies["send"] = send_policy

        write_policy = Policy(
            "write",
            [
                PolicyRule("write", None, "allow", 0),
            ],
        )
        self.policies["write"] = write_policy

    def commit_effect(self, effect: Effect, task_id: str = "default") -> tuple[bool, dict]:
        """
        FORGE-style commit: policy evaluation at runtime.

        WEAKNESSES (these bypass FORGE but not ECAC):
        - "write" policy allows all writes
        - No session taint
        - No content hash
        - No freshness check
        """
        policy = self.policies.get(effect.etype)
        if not policy:
            return True, {"blocker": None, "reason": "FORGE: no policy (default allow)"}

        for rule in sorted(policy.rules, key=lambda r: r.priority, reverse=True):
            if rule.effect_type and rule.effect_type != effect.etype:
                continue
            if rule.target_pattern:
                if not re.match(rule.target_pattern, effect.target):
                    continue
            return (
                (True, {"blocker": None, "reason": f"FORGE: {policy.name}"})
                if rule.action == "allow"
                else (False, {"blocker": "FORGE-Policy", "reason": "denied"})
            )

        return True, {"blocker": None, "reason": "FORGE: no match (default allow)"}
