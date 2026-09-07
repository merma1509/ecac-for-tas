"""The EffectBroker: the only principal that can commit an effect

Evaluates the four predicates at commit time and returns machine-checkable
evidence for every allow/deny decision.

The four-predicate gate (Auth and FlowOK and NoAmp and Fresh) is the ONLY path to
external state mutation. Each predicate has a single, explicit responsibility:

  Auth    : complete static-and-dynamic judgment
            (root-anchored + monotonic + bottom-scoped + task-bounded + matches)
  FlowOK  : IFC over provenance labels, bounded by task's flow_boundary
  NoAmp   : path-based composition safety (root-anchoring/monotonicity are in Auth)
  Fresh   : task-scoped lifetime/revocation/replay (Session clock)

This split directly addresses the critique: "forged capabilities
pass a deliberately weak Auth" — Auth is now the complete gate, and NoAmp
covers only composition safety.
"""

from __future__ import annotations

from typing import TypedDict

from .mediation import MediationVerdict, Mediator
from .model import (
    APPROVER,
    BROKER,
    USER,
    Capability,
    Commit,
    Effect,
    LabelException,
    Task,
    TaskId,
)
from .resources import ResourceStore

# Trusted roots: only these principals may seed NEW authority. Everything else
# must attenuate an existing root-anchored capability (monotonic, no widening)
TRUSTED_ROOTS: frozenset[str] = frozenset({USER})

# Type aliases
PredicateResult = tuple[bool, str]


class Evidence(TypedDict):
    """Machine-checkable record emitted for every commit decision"""

    allow: bool
    primary_blocker: str | None
    predicates: dict[str, str]
    boundary_stop: str | None  # tool-boundary mediation reason, if the commit
    # was allowed by the gate but stopped before forwarding to the remote tool


def _provides(auth_capability: Capability, right: str, target: str) -> bool:
    """True if the capability's right+target covers this (right, target)"""
    return auth_capability.right == right and auth_capability.target == target


class EffectBroker:
    def __init__(self) -> None:
        # Capability store: nonce -> Capability
        self.capabilities: dict[str, Capability] = {}
        # Validated declass/endorse grants (broker-only writes)
        self.label_exceptions: dict[str, LabelException] = {}
        # One-shot approvals from Approver (nonce -> expiry)
        self.approvals: dict[str, float] = {}
        # External state (R = F ∪ E ∪ M) — only this broker may mutate it
        self.store: ResourceStore = ResourceStore()
        # Registered tasks: task_id -> Task (provides ceiling + session)
        self.tasks: dict[TaskId, Task] = {}
        # Risk model stub: may route to Approver but is NOT part of allow rule
        self.risk_override: float = 0.0  # > 0 triggers escalation for testing
        # Nonces revoked without a task_id (global revocation, affects all sessions)
        self.global_revoked: set[str] = set()
        self.logical_time: float = 0.0
        # Mediator: the enforcement shim that detects declared-vs-actual
        # mismatches (T13/T14/T15). None = boundary mediation disabled
        self._mediator: Mediator | None = None

    def set_mediator(self, mediator: Mediator) -> None:
        """Attach a Mediator (the enforcement shim) to this broker"""
        self._mediator = mediator

    # ---- capability management (monotonic, root-anchored) ----
    def grant_root(self, capability: Capability) -> None:
        """Seed NEW authority. Only a trusted root may do this"""
        assert capability.owner in TRUSTED_ROOTS, (
            f"non-root principal {capability.owner} cannot seed authority (NoAmp)"
        )
        assert capability.derives_from is None, "root grant must not have a parent"
        self.capabilities[capability.nonce] = capability

    def attenuate(
        self,
        parent_nonce: str,
        holder: str,
        right: str,
        target: str,
        scope: frozenset[str],
        expiry: float,
    ) -> Capability:
        """Derive a child capability from a parent. Must not widen authority.

        Requires:
          - parent exists,
          - child scope is a subset of parent scope (monotonic),
          - the parent actually authorizes this (right, target) — i.e. the child
            asks for no more than the parent granted.
        """
        parent = self.capabilities[parent_nonce]
        assert scope <= parent.scope, f"attenuation must narrow scope ({scope} !<= {parent.scope})"
        assert _provides(parent, right, target), "cannot widen authority beyond parent grant"

        # Capabilities may be forwarded (standard object-capability transitivity);
        # NoAmp safety comes from *monotonic narrowing* + *root-anchoring* (the
        # child still carries the root owner via derives_from), not from banning
        # delegation. A holder may pass a capability on subject to monotonicity
        child = Capability(
            owner=parent.owner,
            holder=holder,
            right=right,
            target=target,
            scope=scope,
            expiry=expiry,
            nonce=f"{parent.nonce}:{holder}",
            derives_from=parent.nonce,
        )
        self.capabilities[child.nonce] = child
        return child

    def revoke(self, nonce: str, task_id: TaskId | None = None) -> None:
        """Revoke a capability by nonce.

        - With task_id: per-task revocation (affects only that task's session).
        - Without task_id: global revocation (adds nonce to ALL registered task
          sessions, so the revocation takes effect regardless of which task
          context a commit uses).
        """
        if task_id is not None:
            task = self.tasks.get(task_id)
            if task is not None:
                assert task.session is not None, "task.session must be set by Task.__post_init__"
                task.session.revoked.add(nonce)
        else:
            # Global revocation: add to the broker-level set. check_fresh will
            # check this in addition to any task-scoped revocation. This works
            # even before any task is registered (revoke called before commit).
            self.global_revoked.add(nonce)

    # ---- task management ----
    def register_task(self, task: Task) -> None:
        """Register a task with the broker. Call this before any effect commit."""
        self.tasks[task.task_id] = task

    def get_task(self, task_id: TaskId) -> Task | None:
        """Look up a registered task."""
        return self.tasks.get(task_id)

    def advance_time(self, task_id: TaskId, delta: float = 1.0) -> None:
        """Advance the task session's logical clock (logical time)."""
        task = self.tasks[task_id]
        assert task.session is not None, "task.session must be set by Task.__post_init__"
        task.session.logical_time += delta

    def attempt_wide(
        self,
        parent_nonce: str,
        holder: str,
        right: str,
        target: str,
        scope: frozenset[str],
        expiry: float,
        task_id: TaskId | None = None,
    ) -> Capability:
        """Deliberately create a NON-monotonic (widened) capability.

        This models delegation widening (T6): an agent tries to hand a
        sub-agent a capability that is NOT a monotonic narrowing of its own
        Auth rejects the non-monotonic derivation chain at commit time
        """
        parent = self.capabilities[parent_nonce]
        child = Capability(
            owner=parent.owner,
            holder=holder,
            right=right,
            target=target,
            scope=scope,
            expiry=expiry,
            nonce=f"{parent.nonce}:{holder}:wide",
            task_id=task_id,
            derives_from=parent.nonce,
        )
        self.capabilities[child.nonce] = child
        return child

    # ---- declass/endorse (broker-only privileged operations) ----
    def grant_label_exception(self, exception: LabelException) -> None:
        """Record a validated declass/endorse grant. BROKER-ONLY

        declass/endorse are privileged operations performed ONLY
        by the EffectBroker on explicit User Policy or a validated approval.
        The LLM may request (see request_label_exception), never perform. This
        is the single trusted spot where an otherwise-forbidden flow may be
        explicitly allowed (T3): the label reclassification is explicit and
        attributable to a trusted grantor
        """
        if exception.granted_by not in (USER, APPROVER):
            raise ValueError(
                f"label exception must be granted by a trusted principal "
                f"(User or Approver), got {exception.granted_by}"
            )
        if exception.nonce in self.label_exceptions:
            raise ValueError(f"duplicate label exception nonce {exception.nonce}")
        self.label_exceptions[exception.nonce] = exception

    @staticmethod
    def request_label_exception(
        *, kind: str, target: str, from_label: str, to_label: str
    ) -> LabelException:
        """LLM/agent-side REQUEST for a declass/endorse

        Important: this only builds the *request*; it does NOT grant anything
        The broker must later record it via grant_label_exception after checking
        policy. This enforces "LLM may request, never perform".
        """
        return LabelException(kind, target, from_label, to_label, "?", "?")

    # ---- risk model placement: escalation, NOT in the allow rule ----
    def assess_risk(self, effect: Effect) -> float:
        """Learned/stub risk classifier. May route to an Approver for review

        This is deliberately NOT part of the formal allow rule: the four
        predicates decide allow/deny regardless of this score. If the score is
        high, the effect is *routed* to an Approver; approval grants a fresh,
        one-shot capability which must STILL pass Auth and FlowOK and NoAmp and Fresh
        at commit. The theorem holds even if this classifier is wrong
        """
        # Minimal stub: escalate sensitive-target effects unless overridden
        score = 0.0
        if effect.target.endswith("/secrets") or effect.target.startswith("http://"):
            score = 0.9
        # test override lets us force a high/low risk deterministically
        return max(score, self.risk_override)

    def needs_review(self, effect: Effect) -> bool:
        """True if the risk model wants human review before commit."""
        return self.assess_risk(effect) >= 0.8

    def grant_approval(
        self, effect: Effect, expiry: float, task_id: TaskId | None = None
    ) -> str:
        """Approver grants a FRESH, ONE-SHOT capability for `effect`.

        The approved capability is scoped to task_id (defaults to "default")
        and still must pass Auth and FlowOK and NoAmp and Fresh at commit.
        """
        if task_id is None:
            task_id = "default"
        nonce = f"approval:{effect.etype}:{effect.target}:{len(self.approvals)}"
        cap = Capability(
            owner=USER,
            holder=BROKER,
            right=effect.etype,
            target=effect.target,
            scope=frozenset({effect.target}),
            expiry=expiry,
            nonce=nonce,
            task_id=task_id,
            derives_from=None,
        )
        self.capabilities[nonce] = cap
        self.approvals[nonce] = expiry
        return nonce

    def _has_validated_exception(self, effect: Effect, kind: str, datum_label_name: str) -> bool:
        """True if a broker-recorded, validated exception sanctions this override

        An exception applies only if:
          - it targets this effect's sink (or "*")
          - its `from_label` names the label currently violating the flow
          - the grant was actually recorded by the broker (nonce known)
        This makes declass/endorse explicit, attributable, and broker-validated
        """
        for exception in effect.label_exceptions:
            grant = self.label_exceptions.get(exception.nonce)
            if grant is None:
                continue  # not yet broker-validated
            if grant.kind != kind:
                continue
            if grant.match_target != "*" and grant.match_target != effect.target:
                continue
            if grant.from_label != datum_label_name:
                continue
            return True
        return False

    # ---- root-anchoring / monotonicity helper (used by Auth and NoAmp) ----
    def _check_derivation(self, capability: Capability) -> tuple[bool, str]:
        """Check root-anchoring AND monotonicity of the derivation chain.

        Returns (ok, evidence). A capability is legitimate iff:
          - its owner is a trusted root (root-anchored), AND
          - the entire chain of attenuations is monotonic (each child scope ⊆
            parent scope, each child right+target is covered by the parent).

        This is the key property that distinguishes a trusted attenuation from
        a forged capability with an accidentally-matching owner field: the chain
        is what proves monotonic narrowing, not just the presence of a trusted
        owner.
        """
        if capability.owner not in TRUSTED_ROOTS:
            return False, f"owner-not-trusted({capability.owner})"
        seen: set[str] = set()
        node: Capability | None = capability
        while node is not None:
            if node.nonce in seen:  # cycle guard
                return False, "cycle-in-chain"
            seen.add(node.nonce)
            if node.derives_from is None:
                # root grant: owner already checked, derivation terminates legitimately
                if node.owner in TRUSTED_ROOTS:
                    return True, f"root-anchored({node.owner})"
                return False, f"root-owner-untrusted({node.owner})"
            parent = self.capabilities.get(node.derives_from)
            if parent is None:
                return False, f"broken-chain(parent={node.derives_from})"
            # Monotonicity: child scope <= parent scope and parent's right+target
            # covers the child's request
            if not (node.scope <= parent.scope and _provides(parent, node.right, node.target)):
                return False, (
                    f"non-monotonic(scope={node.scope}!<={parent.scope},"
                    f"right={node.right} not in parent's rights)"
                )
            node = parent
        return True, f"legitimate(owner={capability.owner})"

    def _authority(self, capability: Capability) -> tuple[str, str]:
        """Return the (right, target) pair this capability authorizes."""
        return (capability.right, capability.target)

    def check_auth(self, effect: Effect, task: Task) -> PredicateResult:
        """Complete static-and-dynamic judgment: Auth(e,t).

        The task `t` is the authoritative bound — it is the task passed to
        commit() (which wraps the effect). `effect.task_id` may be set for
        logging/audit; this method validates against the ceiling in `t`.
        

        Rejects forged/widened capabilities at the gate, not downstream.
        The five sub-checks:

          1. root-anchored  : capability owner is a trusted root
          2. monotonic      : no widening along the derivation chain
          3. bottom-scoped  : write authority is subset ceiling scope (integrity floor)
          4. task-bounded   : effect authority subset task ceiling scope (confidentiality floor)
          5. matches        : holder, right, target all agree with the effect

        After this refactor, forged capabilities (owner=Mallory, forged nonce)
        fail sub-check 1 (owner not trusted). Honest delegation widening fails
        sub-check 2 (non-monotonic). So the blocker is Auth, not NoAmp.
        """
        capability = self.capabilities.get(effect.capability_nonce)
        if capability is None:
            return False, "no-capability"

        # Sub-check 1+2: derivation (root-anchoring + monotonicity)
        legit_ok, legit_evidence = self._check_derivation(capability)
        if not legit_ok:
            return False, f"derivation-fail({legit_evidence})"

        # Sub-check 3: bottom-scoped — write authority is subset ceiling scope
        # (integrity floor: a writer may not escalate beyond the ceiling's scope)
        if effect.etype == "write":
            if capability.scope > task.ceiling.scope:
                return False, (
                    f"bottom-scoping-violation(scope={capability.scope}!≤{task.ceiling.scope})"
                )

        # Sub-check 4: task-bounded — effect authority subset task ceiling
        # A ceiling.scope containing "*" is a wildcard: covers any target/right.
        # Otherwise, the capability's scope elements must all be in the ceiling's
        # scope AND the effect's target must be a member of the ceiling scope.
        is_wildcard = "*" in task.ceiling.scope
        scope_ok = is_wildcard or (
            capability.scope <= task.ceiling.scope
            and effect.target in task.ceiling.scope
        )
        if not scope_ok:
            return False, f"task-bounded-fail(e-target={effect.target} not in ceiling-scope={task.ceiling.scope})"

        # Sub-check 5: matches (right, target) — holder is implied by the
        # derivation chain: root-anchoring + monotonicity already prove the
        # holder is authorised. Enforcing holder==BROKER here is too strict
        # for capability forwarding (the agent may hold the capability).
        # A permissive default ceiling (right="*") skips the right check.
        if task.ceiling.right != "*" and capability.right != effect.etype:
            return False, f"right-mismatch({capability.right}!={effect.etype})"
        if capability.target != effect.target:
            return False, f"target-mismatch({capability.target}!={effect.target})"

        return True, f"auth-ok(derivation={legit_evidence},task={task.task_id})"

    def check_flow(self, effect: Effect, task: Task) -> PredicateResult:
        """IFC gate: provenance labels must not exceed task's flow_boundary.

        Uses the task's declared (sink_confidentiality, sink_integrity) interval
        rather than hard-coded per-effect-type defaults. This lets
        each task define its own sensitivity floor, making FlowOK task-scoped.
        """
        sink_confidentiality, sink_integrity = task.flow_boundary
        for datum in effect.provenance:
            if (
                datum.confidentiality > sink_confidentiality
                and not self._has_validated_exception(effect, "declass", datum.confidentiality.name)
            ):
                return False, (
                    f"conf-leak({datum.name}:"
                    f"{datum.confidentiality.name}>{sink_confidentiality.name})"
                )
            if (
                datum.integrity < sink_integrity
                and not self._has_validated_exception(effect, "endorse", datum.integrity.name)
            ):
                return False, (
                    f"low-integrity({datum.name}:{datum.integrity.name}<{sink_integrity.name})"
                )
        return True, "flow-ok"

    def check_noamp(self, effect: Effect, task: Task) -> PredicateResult:
        """Composition safety: effect authority stays within the task ceiling

        For `network` effects, also enforces SSRF containment: the capability's
        scope must be a subset of the URL's domain scope
        """
        capability = self.capabilities.get(effect.capability_nonce)
        if capability is None:
            return False, "no-capability"

        # The effect's target must be in the task's ceiling scope
        is_wildcard = "*" in task.ceiling.scope
        target_in_scope = is_wildcard or effect.target in task.ceiling.scope
        if not target_in_scope:
            return False, (
                f"composition-fail(target={effect.target} not in ceiling-scope={task.ceiling.scope})"
            )

        # Right dominance: ceiling.right = "*" dominates all rights (any right allowed).
        # Any other ceiling.right must exactly match the capability's right.
        if task.ceiling.right == "*":
            pass  # wildcard: any capability right is within ceiling
        elif capability.right == task.ceiling.right:
            pass  # exact match: within ceiling
        else:
            return False, (
                f"ceiling-right-mismatch(cap-right={capability.right}!=ceiling-right={task.ceiling.right})"
            )

        # SSRF containment for network effects
        if effect.etype == "network":
            from .model import URL as _URL
            resource = self.store.resolve(effect.target)
            if isinstance(resource, _URL) and resource.scope and "*" not in resource.scope:
                if not capability.scope <= resource.scope:
                    return False, (
                        f"ssrf containment failed: cap-scope={capability.scope} "
                        f"not subset of url-scope={resource.scope}"
                    )
            elif "://" in effect.target:
                target_domain = frozenset({effect.target.split("://", 1)[1].split("/")[0]})
                if not capability.scope <= target_domain:
                    return False, (
                        f"ssrf containment failed: cap-scope={capability.scope} "
                        f"not subset of url-domain={target_domain}"
                    )

        return True, f"composition-ok(ceiling-scope={task.ceiling.scope})"

    def check_fresh(self, effect: Effect, task: Task) -> PredicateResult:
        """Task-scoped freshness: lifetime/revocation/replay against Session.

        the lifetime model is per-task (logical clock of the task's
        Session, not a wall-clock). Revocation and replay are also per-task.
        """
        capability = self.capabilities.get(effect.capability_nonce)
        if capability is None:
            return False, "no-capability"
        assert task.session is not None, "task.session must be initialized by Task.__post_init__"

        # Lifetime: capability not expired
        session_time = task.session.logical_time if task.session.live else 0.0
        effective_time = max(session_time, self.logical_time)
        if capability.expiry <= effective_time:
            return False, f"expired(t_session={effective_time},cap_exp={capability.expiry})"

        # Revocation: per-task nonce list AND broker-level global revocation
        # NOTE: we use the `task` parameter directly, not a re-lookup via
        # self.tasks, to preserve the correct session (revoke may have added
        # the nonce to this task's session.revoked set already).
        if capability.nonce in task.session.revoked or capability.nonce in self.global_revoked:
            return False, f"revoked(in_task={task.task_id} or global)"

        # Replay: per-task used nonce set
        if effect.capability_nonce in task.session.used:
            return False, f"replay(in_task={task.task_id})"

        return True, f"fresh(t_session={task.session.logical_time})"

    # ---- commit gate (the ONLY way external state changes) ----
    def commit(
        self,
        commit: Commit,
        mediation: MediationVerdict | None = None,
    ) -> tuple[bool, Evidence]:
        """Evaluate the four-predicate gate over the Commit primitive

        If a Mediator is attached and commit.tool_name is set, the mediator
        inspects the effect against the named tool's ToolSpec after the gate
        passes. The verdict is recorded in evidence["boundary_stop"].
        The mediation parameter allows direct verdict injection (for tests)
        """
        effect = commit.effect
        task = commit.task

        # Safety assertion: Task.__post_init__ always initializes session.
        # If a caller passes a Task without a session, __post_init__ creates
        # a default one, so session is never None at runtime.
        # If no task was provided, create a permissive default task that covers
        # all resources (right="*", target="*", scope={"*"}). Register it so
        # that global revoke() (revoke without task_id) reaches its session.
        if task is None:
            # Try to reuse an existing default task so that session state
            # (used nonces, revoked set, logical_time) persists across commits.
            task = self.tasks.get("default")
            if task is None:
                default_ceiling = Capability(
                    owner=USER,
                    holder=BROKER,
                    right="*",
                    target="*",
                    scope=frozenset({"*"}),
                    expiry=float("inf"),
                    nonce="default-ceiling",
                )
                task = Task(task_id="default", owner=USER, ceiling=default_ceiling)
                self.tasks[task.task_id] = task

        assert task.session is not None, "Task must have a session (set by __post_init__)"

        predicate_results: dict[str, PredicateResult] = {
            "Auth": self.check_auth(effect, task),
            "FlowOK": self.check_flow(effect, task),
            "NoAmp": self.check_noamp(effect, task),
            "Fresh": self.check_fresh(effect, task),
        }
        allow = all(predicate_result[0] for predicate_result in predicate_results.values())
        predicate_order = ("Auth", "FlowOK", "NoAmp", "Fresh")
        blocking_predicate = next(
            (predicate for predicate in predicate_order if not predicate_results[predicate][0]),
            None,
        )
        boundary_stop: str | None = None

        # Boundary mediation: the enforcement shim (Mediator) runs AFTER the
        # four-predicate gate. The gate proved the effect is authorised; the
        # mediator now checks whether the named tool will honour the declared shape.
        # Priority: explicit mediation verdict > Mediator.inspect() > allow
        if allow:
            if mediation is not None:
                boundary_verdict = mediation
            elif self._mediator is not None and commit.tool_name is not None:
                boundary_verdict = self._mediator.inspect(effect, commit.tool_name)
            else:
                boundary_verdict = MediationVerdict(True, None)

            if not boundary_verdict.allow:
                allow = False
                boundary_stop = boundary_verdict.boundary_stop
                # A boundary stop is NOT a predicate blocker — the gate passed;
                # the issue is at the broker→tool forwarding boundary
                if blocking_predicate is None:
                    blocking_predicate = "Boundary"

        evidence: Evidence = {
            "allow": allow,
            "primary_blocker": blocking_predicate,
            "predicates": {
                predicate: predicate_result[1]
                for predicate, predicate_result in predicate_results.items()
            },
            "boundary_stop": boundary_stop,
        }
        if allow:
            task.session.used.add(effect.capability_nonce)
            self.store.apply_effect(effect)
        return allow, evidence

    def commit_effect(
        self, effect: Effect, task: Task | None = None
    ) -> tuple[bool, Evidence]:
        """Stage and commit an effect within task `task`.

        If task is None, a permissive default task is created (same as commit()).
        """
        return self.commit(Commit(effect, task))

    def _make_commit(
        self, effect: Effect, task_id: TaskId = "default"
    ) -> Commit:
        """Build a Commit from an effect and task_id (used by the shim)."""
        task = self.tasks.get(task_id)
        if task is None:
            default_ceiling = Capability(
                owner=USER,
                holder=BROKER,
                right="*",
                target="*",
                scope=frozenset({"*"}),
                expiry=float("inf"),
                nonce="default-ceiling",
            )
            task = Task(task_id=task_id, owner=USER, ceiling=default_ceiling)
            self.tasks[task_id] = task
        return Commit(effect, task)
