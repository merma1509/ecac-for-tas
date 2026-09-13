"""The EffectBroker: the only principal that can commit an effect.

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

ARCHITECTURE:
  ┌──────────────────────────────────────────────────────────┐
  │  IndependentEffectLedger (EXTERNAL, not owned by broker) │
  │  - Created outside broker + executor                     │
  │  - Passed to both components                             │
  │  - Records authorization (from broker.gate)              │
  │  - Records observation (from executor + store)           │
  │  - Makes UNAMBIGUOUS verdicts: COMMITTED/BLOCKED/UNKNOWN │
  └──────────────────────────────────────────────────────────┘
                       ↑                    ↑
              broker.gate()          executor.apply()
                   │                        │
                   └──────────┬─────────────┘
                              ↓
                   IndependentEffectLedger

DELEGATION: broker.commit() handles gate() + _apply_effect() for direct callers
For the shim/executor path, the executor calls broker.gate() then applies
via broker._apply_effect() — the observer records from both paths.

THREAD SAFETY: Fresh replay-check + nonce-reservation is atomic (locked)
If gate() fails after the nonce is reserved, the nonce is RELEASED (so a
blocked effect does not consume a valid one-shot capability)

KNOWN LIMITATIONS:
  - Provenance labels are assigned by the shim, not derived from real dataflow
  - Direct ResourceStore mutation is untracked (same-process assumption)
  - Declass/endorse grants are matched by kind+target+from_label without
    exact effect identity verification (only ApprovedRequest enforces full binding)
"""

from __future__ import annotations

import threading
from typing import cast

from .ipc import LedgerBackend, LocalLedgerBackend
from .ledger import IndependentEffectLedger
from .mediation import MediationVerdict, Mediator
from .model import (
    APPROVER,
    BROKER,
    USER,
    ApprovedRequest,
    Capability,
    Commit,
    CommitGateResult,
    Effect,
    EffectTarget,
    Evidence,
    LabelException,
    Task,
    TaskId,
)
from .restricted_store import RestrictedResourceStore as ResourceStore

# Union of types that can be passed as the `ledger` argument.
# Local: IndependentEffectLedger (wrapped in LocalLedgerBackend internally).
# Remote: ProcessLedgerClient or any LedgerBackend implementation.
LedgerSource = IndependentEffectLedger | LedgerBackend | None


def _wrap_ledger(
    ledger: LedgerSource,
) -> tuple[LedgerBackend, IndependentEffectLedger | None]:
    """Convert LedgerSource to (LedgerBackend, local_ledger_or_None)."""
    if ledger is None:
        local = IndependentEffectLedger()
        return LocalLedgerBackend(local), local
    if isinstance(ledger, IndependentEffectLedger):
        return LocalLedgerBackend(ledger), ledger
    return ledger, None


__all__ = [
    "EffectBroker", "Evidence", "CommitGateResult",
    "LabelException",  "Task", "TaskId",
    "ApprovedRequest",
    "Capability",
    "Effect",
    "Commit",
]

# Trusted roots: only these principals may seed NEW authority. Everything else
# must attenuate an existing root-anchored capability (monotonic, no widening)
TRUSTED_ROOTS: frozenset[str] = frozenset({USER})

# Type aliases
PredicateResult = tuple[bool, str]


def _provides(auth_capability: Capability, right: str, target: str) -> bool:
    """True if the capability's right+target covers this (right, target)"""
    return auth_capability.right == right and auth_capability.target == target


class EffectBroker:
    def __init__(self, ledger: LedgerSource = None) -> None:
        # Ledger backend (local or remote IPC).
        # Both broker.commit() (direct) and executor.execute() (via-shim)
        # record to THIS ledger. This is the key to "unknown, not safe":
        # the ledger observes independently from both paths, with equal
        # authority to verify. Neither broker nor executor owns the ledger.
        # Supports:
        #   - None: creates LocalLedgerBackend + IndependentEffectLedger (same-process)
        #   - IndependentEffectLedger: wraps it in LocalLedgerBackend
        #   - ProcessLedgerClient: forwards over IPC to a separate ledger process
        self._ledger_backend, self._local_ledger = _wrap_ledger(ledger)
        # Capability store: nonce -> Capability
        self.capabilities: dict[str, Capability] = {}
        # Validated declass/endorse grants (broker-only writes)
        self.label_exceptions: dict[str, LabelException] = {}
        # One-shot approvals from Approver (nonce -> expiry)
        self.approvals: dict[str, float] = {}
        # External state (R = F ∪ E ∪ M) — only apply_effect() may mutate it
        # RestrictedResourceStore uses read-only proxies for files/emails/mailboxes
        # Direct mutation attempts (store.files[key] = X) raise TypeError
        # In a real deployment, store lives in an isolated process with only
        # the apply_effect primitive as its write path
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
        # Per-task locks for atomic replay-check + nonce-reservation.
        # Each task gets its own lock so concurrent commits in DIFFERENT tasks
        # are not serialized unnecessarily. This closes the race:
        #   Thread 1: gate() reads used=∅ -> Fresh PASS
        #   Thread 2: gate() reads used=∅ -> Fresh PASS
        #   Thread 1: _apply_effect() adds nonce -> used={nonce}
        #   Thread 2: _apply_effect() adds nonce -> used={nonce}  <- DOUBLE COMMIT!
        # With per-task locks, only one thread can check-and-reserve at a time.
        self._task_locks: dict[TaskId, threading.Lock] = {}

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
        *,
        kind: str,
        target: str,
        additional_targets: frozenset[str] = frozenset(),
        etype: str | None = None,
        from_label: str,
        to_label: str,
    ) -> LabelException:
        """LLM/agent-side REQUEST for a declass/endorse.

        The returned LabelException is a REQUEST only — the broker must later
        record it via grant_label_exception after checking policy. This enforces
        "LLM may request, never perform".

        The exact effect identity check is deferred to the broker's
        matches_effect() method at grant time. The request includes
        additional_targets and etype so the broker can verify the complete
        effect identity at grant time (not just at commit time).
        """
        return LabelException(
            kind=kind,
            match_target=target,
            additional_targets=additional_targets,
            etype=etype,
            from_label=from_label,
            to_label=to_label,
            granted_by="?",
            nonce="?",
        )

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
        self,
        effect: Effect,
        expiry: float,
        task_id: TaskId | None = None,
    ) -> str:
        """Approver grants a FRESH, ONE-SHOT capability for `effect`.

        The approved capability is scoped to task_id (defaults to "default")
        and still must pass Auth and FlowOK and NoAmp and Fresh at commit.

        Returns the capability nonce. The ApprovedRequest (full identity binding)
        is stored separately for exact verification in EffectObserver.verify().
        """
        if task_id is None:
            task_id = "default"
        nonce = f"approval:{effect.etype}:{effect.target}:{len(self.approvals)}"

        # FIXED: approval scope must be domain-level so BCC recipients from the
        # same domain pass NoAmp's scope check. _domain_for_email() returns
        # "internal" or "external" from the email address; use that as the scope
        # element so that any BCC recipient from the same domain is in scope.
        if effect.etype == "send" and "@" in effect.target:
            # Derive domain from primary address for scope
            domain_label = self._domain_for_email(effect.target)
            cap_scope = frozenset({domain_label} if domain_label else {effect.target})
        else:
            cap_scope = frozenset({effect.target})

        cap = Capability(
            owner=USER,
            holder=BROKER,
            right=effect.etype,
            target=effect.target,
            scope=cap_scope,
            expiry=expiry,
            nonce=nonce,
            task_id=task_id,
            derives_from=None,
        )
        self.capabilities[nonce] = cap
        self.approvals[nonce] = expiry

        # Also store the ApprovedRequest for exact immutable request binding
        # (kill-criterion #5: complete identity must match)
        # CRITICAL: use canonical complete_targets() — same source as commit()
        # and executor. This ensures authorized_targets are identical everywhere.
        authorized_targets = effect.complete_targets()
        # Targets for ApprovedRequest: primary + additional, excluding primary
        all_targets = authorized_targets

        # FIXED: approval scope must be domain-level (matching what check_noamp
        # uses via _domain_for_email), not the raw email address. This ensures
        # BCC recipients from the same domain pass NoAmp scope check.
        # approval_scope is used only for building the ApprovedRequest targets
        # (for the binding check, not for NoAmp — NoAmp uses the original cap).

        # FIXED: content_hash includes Data.content for immutable request binding.
        # This ensures that any modification to the content after approval
        # (e.g., changing the message body) produces a different hash.
        # FIXED: provenance elements are SORTED before hashing — tuple is unordered,
        # so (A, B) and (B, A) would produce different hashes without sorting.
        # Sorting by (name, confidentiality, integrity, content) ensures determinism:
        # the same effect always produces the same hash regardless of insertion order.
        from hashlib import sha256

        content_parts: list[str] = []
        for d in effect.provenance:
            # Include the actual content value in the hash
            content_parts.append(
                f"{d.name}:{d.confidentiality.name}:{d.integrity.name}:{d.content}"
            )
        content_parts.sort()  # deterministic order regardless of tuple insertion
        content_hash = sha256("|".join(content_parts).encode()).hexdigest()[:16]

        approved_req = ApprovedRequest(
            nonce=nonce,
            etype=effect.etype,
            targets=EffectTarget(
                primary=effect.target, additional=all_targets - {effect.target}
            ),
            content_hash=content_hash,
            expiry=expiry,
            task_id=task_id,
            granted_by=APPROVER,
        )
        self._approved_requests: dict[str, ApprovedRequest] = getattr(
            self, "_approved_requests", {}
        )
        self._approved_requests[nonce] = approved_req

        return nonce

    def _has_validated_exception(self, effect: Effect, kind: str, datum_label_name: str) -> bool:
        """True if a broker-recorded, validated exception sanctions this override

        An exception applies only if:
          - it targets this effect (matches_effect checks target set exactly)
          - its `from_label` names the label currently violating the flow
          - the grant was actually recorded by the broker (nonce known)
          - kind matches (declass vs endorse)

        This makes declass/endorse explicit, attributable, and broker-validated.
        The key fix: matches_effect() checks exact effect identity, including
        BCC/extra_targets and etype — a grant for "send to internal" does NOT
        authorize "send to internal with BCC to external" unless explicit.
        """
        for exception in effect.label_exceptions:
            grant = self.label_exceptions.get(exception.nonce)
            if grant is None:
                continue  # not yet broker-validated
            if grant.kind != kind:
                continue
            if not grant.matches_effect(effect):
                # Target set mismatch: grant doesn't cover this effect's complete identity
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
        # scope AND the effect's target (or its domain, for email targets) must be
        # a member of the ceiling scope.
        # CRITICAL FIX: for email targets (addr@domain), compare the DOMAIN LABEL
        # against the ceiling scope, not the raw email address. Otherwise:
        #   "internal@corp.com" in {"internal"} = False <- WRONG (masks the bug)
        #   _domain_for_email("internal@corp.com") = "internal"
        #   "internal" in {"internal"} = True <- CORRECT
        is_wildcard = "*" in task.ceiling.scope
        target_for_scope_check = self._scope_label_for_target(effect.target)
        scope_ok = is_wildcard or (
            capability.scope <= task.ceiling.scope
            and target_for_scope_check in task.ceiling.scope
        )
        if not scope_ok:
            return (
                False,
                "task-bounded-fail("
                f"e-target={effect.target} (scope-label={target_for_scope_check}) "
                f"not in ceiling-scope={task.ceiling.scope})",
            )

        # Sub-check 5: right must match (FIXED: no wildcard skip).
        # A capability grants exactly one right. An approval for read cannot
        # authorize write — right="*" on a default ceiling was the bypass path.
        # Strict ceiling.right must match capability.right must match effect.etype.
        if capability.right != effect.etype:
            return False, f"right-mismatch(cap_right={capability.right}!=etype={effect.etype})"
        if capability.target != effect.target:
            return False, f"target-mismatch(cap_target={capability.target}!={effect.target})"

        return True, f"auth-ok(derivation={legit_evidence},task={task.task_id})"

    def check_flow(self, effect: Effect, task: Task) -> PredicateResult:
        """IFC gate: provenance labels must not exceed task's flow_boundary.

        Uses the task's declared (sink_confidentiality, sink_integrity) interval
        rather than hard-coded per-effect-type defaults. This lets
        each task define its own sensitivity floor, making FlowOK task-scoped.
        """
        sink_confidentiality, sink_integrity = task.flow_boundary
        for datum in effect.provenance:
            if datum.confidentiality > sink_confidentiality and not self._has_validated_exception(
                effect, "declass", datum.confidentiality.name
            ):
                return False, (
                    f"conf-leak({datum.name}:"
                    f"{datum.confidentiality.name}>{sink_confidentiality.name})"
                )
            if datum.integrity < sink_integrity and not self._has_validated_exception(
                effect, "endorse", datum.integrity.name
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

        # The effect's target must be in the task's ceiling scope.
        # CRITICAL FIX: for email targets, compare the domain label, not the
        # raw email address. This is the same fix as in check_auth().
        is_wildcard = "*" in task.ceiling.scope
        target_for_scope_check = self._scope_label_for_target(effect.target)
        target_in_scope = is_wildcard or target_for_scope_check in task.ceiling.scope
        if not target_in_scope:
            return (
                False,
                "composition-fail("
                f"target={effect.target} (scope-label={target_for_scope_check}) "
                f"not in ceiling-scope={task.ceiling.scope})",
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

        # Extra-target scope check for BCC/CC recipients
        # The capability scope defines which domains (scopes) the capability covers.
        # Extra targets outside this scope are not authorized — for both email
        # (domain label check) AND non-email targets (scope inclusion check).
        if effect.known_targets is not None and effect.known_targets.additional:
            for extra_target in effect.known_targets.additional:
                if "@" in extra_target:
                    # Email extra target: check domain label against cap scope
                    extra_domain = self._domain_for_email(extra_target)
                    if extra_domain is not None and extra_domain not in capability.scope:
                        return False, (
                            f"extra-target-outside-scope("
                            f"{extra_target} (domain={extra_domain}) "
                            f"not in cap-scope={capability.scope})"
                        )
                else:
                    # Non-email extra target: check if target is in cap scope
                    # (e.g. "file:///../../etc/password" must be in scope)
                    target_label = self._scope_label_for_target(extra_target)
                    if target_label not in capability.scope:
                        return False, (
                            f"extra-target-outside-scope("
                            f"{extra_target} (scope-label={target_label}) "
                            f"not in cap-scope={capability.scope})"
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

    def _scope_label_for_target(self, target: str) -> str:
        """Extract the scope-relevant label from a target for scope comparison.

        For email targets (addr@domain), returns the domain label so that:
          - "internal@corp.com" -> "internal" (matches ceiling scope {"internal"})
          - "external@attacker.com" -> "external" (matches ceiling scope {"external"})

        For non-email targets (files, URLs), returns the target as-is:
          - "file:///reports" -> "file:///reports"
          - "http://internal.corp.com" -> "http://internal.corp.com"

        This ensures domain-scoped capabilities work correctly for email,
        which is the CRITICAL FIX for the email-domain-scope bug.
        """
        if "@" in target:
            domain = self._domain_for_email(target)
            return domain if domain is not None else target
        return target

    def _domain_for_email(self, addr: str) -> str | None:
        """Derive the domain label from an email address for scope checking."""
        if "@" not in addr:
            return None
        domain_part = addr.split("@")[1]
        if "corp" in domain_part or "internal" in domain_part:
            return "internal"
        return "external"

    def check_fresh(self, effect: Effect, task: Task) -> PredicateResult:
        """Task-scoped freshness: lifetime/revocation/replay against Session.

        the lifetime model is per-task (logical clock of the task's
        Session, not a wall-clock). Revocation and replay are also per-task.

        FIXED: Session.live=False now BLOCKs commit. A dead session has no
        authoritative clock, so no effect can be committed in its name —
        the task's authority ceiling is invalid until the session is reopened.

        NOTE: This method does NOT reserve the nonce. For thread-safe commits
        (preventing double-commit with the same nonce under concurrency), use
        _atomic_fresh_check() instead, which checks AND reserves atomically.
        """
        capability = self.capabilities.get(effect.capability_nonce)
        if capability is None:
            return False, "no-capability"
        assert task.session is not None, "task.session must be initialized by Task.__post_init__"

        # FIXED: closed/dead session blocks all commits in this task.
        # The session's authority ceiling is no longer authoritative.
        if not task.session.live:
            return False, f"session-closed(task={task.task_id})"

        # Lifetime: capability not expired against the task's logical clock
        effective_time = max(task.session.logical_time, self.logical_time)
        if capability.expiry <= effective_time:
            return False, f"expired(t_session={effective_time},cap_exp={capability.expiry})"

        # Revocation: per-task nonce list AND broker-level global revocation
        if capability.nonce in task.session.revoked or capability.nonce in self.global_revoked:
            return False, f"revoked(in_task={task.task_id} or global)"

        # Replay: per-task used nonce set
        if effect.capability_nonce in task.session.used:
            return False, f"replay(in_task={task.task_id})"

        return True, f"fresh(t_session={task.session.logical_time})"

    def _atomic_fresh_check(self, effect: Effect, task: Task) -> tuple[PredicateResult, bool]:
        """Thread-safe Fresh check: atomically checks and RESERVES the nonce.

        Returns ((ok, evidence), nonce_reserved). If the caller (gate()) fails
        after reservation, it MUST call _release_fresh_reservation() to roll back.

        This closes the race:
          Thread 1: check_fresh() reads used=∅ -> PASS
          Thread 2: check_fresh() reads used=∅ -> PASS
          Thread 1: _apply_effect() adds nonce
          Thread 2: _apply_effect() adds nonce  <- double-commit with same nonce!

        With per-task locks:
          Thread 1: lock(task) -> check -> reserve -> unlock
          Thread 2: lock(task) -> check -> BLOCKED until T1 releases
          T2 sees nonce is used -> Fresh rejects -> correct.
        """
        lock = self._task_locks.setdefault(task.task_id, threading.Lock())
        with lock:
            result = self.check_fresh(effect, task)
            if result[0]:
                # Atomic reservation: add nonce while holding the lock.
                # No other thread can check or reserve this nonce until we release.
                # session is always set: Task.__post_init__ creates a default one.
                task.session.used.add(effect.capability_nonce)  # type: ignore[union-attr]
                return result, True
            return result, False

    def _release_fresh_reservation(self, effect: Effect, task: Task) -> None:
        """Roll back a nonce reservation when gate() fails after atomic reservation.

        Called ONLY when _atomic_fresh_check() returned nonce_reserved=True but
        gate() subsequently failed (e.g. Auth blocked, boundary mediation stopped).
        This ensures a failed effect does not consume a valid one-shot capability.
        """
        lock = self._task_locks.get(task.task_id)
        if lock is None:
            return
        with lock:
            task.session.used.discard(effect.capability_nonce)  # type: ignore[union-attr]

    # ---- commit gate (the ONLY way external state changes) ----
    def commit(
        self,
        commit: Commit,
        mediation: MediationVerdict | None = None,
    ) -> tuple[bool, Evidence]:
        """Evaluate the four-predicate gate and return result.

        This is the DIRECT path (no executor). It records to broker._observer
        so that verify_complete_mediation() works from BOTH direct commits
        and shim/executor commits.

        The two-phase pattern:
          1. gate() evaluates predicates (read-only)
          2. _apply_effect() applies state mutation (only on can_apply=True)
        """
        effect = commit.effect
        task = commit.task

        # Get or create task (same logic as gate())
        if task is None:
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

        # Determine authorized targets for observer record.
        # CRITICAL: use canonical complete_targets() — same source as executor
        # and grant_approval. Never re-extract from metadata independently.
        authorized_targets = effect.complete_targets()

        # Phase 1: gate evaluation (read-only)
        gate_result = self.gate(commit, mediation)
        allow = gate_result.allow
        evidence = gate_result.evidence

        # Record authorization in the independent ledger
        # task_id comes from gate_result.task, not the raw commit.task
        task_id = gate_result.task.task_id
        nonce = effect.capability_nonce
        self._ledger_backend.record_authorization(
            task_id, nonce, authorized_targets, source="broker.gate"
        )

        if allow:
            # Phase 2: apply state mutation (sole mutation point)
            self._apply_effect(gate_result.effect, gate_result.task)

            # Record observation: read the complete target set from identity_log
            identity_entries = self.store.identity_log
            if identity_entries:
                last_entry = identity_entries[-1]
                self._ledger_backend.record_observation(
                task_id, nonce, last_entry, source="broker.commit"
            )
        else:
            # BLOCKed effect: record explicit blocked observation.
            # auth > 0, obs = frozenset() -> CONFIRMED_BLOCKED (observer saw attempt)
            # This is distinct from no observation record -> UNKNOWN (possible bypass).
            self._ledger_backend.record_observation(
                task_id, nonce, None, source="broker.commit:BLOCKED"
            )

        return allow, evidence

    def commit_effect(self, effect: Effect, task: Task | None = None) -> tuple[bool, Evidence]:
        """Stage and commit an effect within task `task`.

        If task is None, a permissive default task is created (same as commit()).
        """
        return self.commit(Commit(effect, task))

    def _make_commit(self, effect: Effect, task_id: TaskId = "default") -> Commit:
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

    # ---- Split commit gate (evaluation) from apply (state mutation) ----
    # This is the key separation for independent observer verification.
    # The executor calls gate() then (on can_apply=True) apply_effect().

    def gate(
        self,
        commit: Commit,
        mediation: MediationVerdict | None = None,
    ) -> CommitGateResult:
        """Phase 1: Evaluate the four-predicate gate. No state mutation.

        Returns CommitGateResult with allow/evidence. Does NOT apply any effect.
        The executor calls this, then calls apply_effect() on can_apply=True.

        This split enables independent observer verification:
        - observer records authorized effects from gate result
        - executor calls apply_effect() which records observed effects
        - verifier compares authorized vs. observed (independent of broker)
        """
        effect = commit.effect
        task = commit.task

        # Get or create task (same logic as commit())
        if task is None:
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

        # Atomic Fresh check: check AND reserve the nonce atomically.
        # This prevents double-commit with the same nonce under concurrency.
        # nonce_reserved = True means Fresh passed AND the nonce is now in used.
        # If we fail the gate AFTER reserving, we MUST release (see rollback below).
        fresh_result, nonce_reserved = self._atomic_fresh_check(effect, task)

        predicate_results: dict[str, PredicateResult] = {
            "Auth": self.check_auth(effect, task),
            "FlowOK": self.check_flow(effect, task),
            "NoAmp": self.check_noamp(effect, task),
            "Fresh": fresh_result,
        }
        allow = all(predicate_result[0] for predicate_result in predicate_results.values())
        predicate_order = ("Auth", "FlowOK", "NoAmp", "Fresh")
        blocking_predicate = next(
            (predicate for predicate in predicate_order if not predicate_results[predicate][0]),
            None,
        )
        boundary_stop: str | None = None
        approval_binding_ok = True
        approval_binding_msg = ""

        # Approval binding: verify exact immutable request binding
        if allow and commit.approved_request is not None:
            stored = self._approved_requests.get(commit.approved_request.nonce)

            if stored is None or stored.nonce != commit.approved_request.nonce:
                approval_binding_ok = False
                approval_binding_msg = f"approval-nonce-unknown({commit.approved_request.nonce})"
            else:
                # FIXED: content_hash includes Data.content, not just names+labels
                from hashlib import sha256

                current_content_parts: list[str] = []
                for d in effect.provenance:
                    # Hash the actual content, not just name
                    current_content_parts.append(
                        f"{d.name}:{d.confidentiality.name}:{d.integrity.name}:{d.content}"
                    )
                current_content_parts.sort()  # deterministic — same order as grant_approval
                current_content_hash = sha256("|".join(current_content_parts).encode()).hexdigest()[
                    :16
                ]

                # CRITICAL: use canonical complete_targets() — authoritative
                # source for target set. Must match what grant_approval() stored.
                current_additional = effect.complete_targets() - {effect.target}

                if effect.etype != stored.etype:
                    approval_binding_ok = False
                    approval_binding_msg = (
                   f"etype-mismatch(approved={stored.etype},got={effect.etype})"
                    )
                elif effect.target != stored.targets.primary:
                    approval_binding_ok = False
                    approval_binding_msg = (
                        f"primary-target-mismatch(approved={stored.targets.primary},"
                        f"got={effect.target})"
                    )
                elif not (current_additional <= stored.targets.additional):
                    extra = current_additional - stored.targets.additional
                    approval_binding_ok = False
                    approval_binding_msg = f"extra-targets-not-approved({extra})"
                elif current_content_hash != stored.content_hash:
                    approval_binding_ok = False
                    approval_binding_msg = "content-modified-after-approval"
                elif task.task_id != stored.task_id:
                    approval_binding_ok = False
                    approval_binding_msg = f"cross-task-use({task.task_id}!={stored.task_id})"

            if not approval_binding_ok:
                allow = False
                if blocking_predicate is None:
                    blocking_predicate = "ApprovalBinding"

        # Boundary mediation
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
            "approval_binding": (
                approval_binding_msg if commit.approved_request is not None else None
            ),
        }

        # Rollback: if the gate failed AFTER reserving the nonce, release it.
        # This ensures a blocked effect does NOT consume a valid one-shot
        # capability. Without this, a failed gate would permanently burn the
        # nonce (approval nonce for a modified-content effect would be unusable
        # even though the effect was correctly blocked).
        if not allow and nonce_reserved:
            self._release_fresh_reservation(effect, task)

        return CommitGateResult(
            allow=allow,
            evidence=evidence,
            effect=effect,
            task=task,
            can_apply=allow,
        )

    def _apply_effect(self, effect: Effect, task: Task) -> None:
        """Apply an effect to external state. Broker-internal.

        NOTE: The nonce is ALREADY reserved by _atomic_fresh_check() in gate().
        We do NOT add it again here — that would be a no-op (set semantics) but
        would also re-add a nonce that was rolled back after a failed gate.
        Since this is called ONLY when gate() succeeded, the nonce is in used
        and the add is a harmless no-op. If gate() failed, _release_fresh_reservation()
        removed the nonce — this method is never called.
        """
        self.store.apply_effect(effect)

    def apply_effect(self, commit_or_effect: Commit | Effect, task: Task | None = None) -> None:
        """Apply an effect to external state. CALLER must verify gate first.

        This is the SECOND phase of commit, called by the IsolatedExecutor
        AFTER gate() returns can_apply=True. It:
          1. Marks the nonce as used (replay prevention)
          2. Applies the effect to the store (identity_log + effects_log)

        IMPORTANT: This method does NOT check predicates. The caller is
        responsible for calling gate() first and checking can_apply=True.
        This separation enables independent observer verification.

        Args:
            commit_or_effect: Either a Commit (for backwards compat) or a raw
                Effect. If Commit, task is ignored (taken from commit.task).
                If Effect, task must be provided.
        """
        if isinstance(commit_or_effect, Commit):
            effect = commit_or_effect.effect
            effective_task = commit_or_effect.task
            if effective_task is None:
                effective_task = self.tasks.get("default")
                if effective_task is None:
                    raise ValueError("No task for commit and no default task registered")
        else:
            effect = commit_or_effect
            if task is None:
                effective_task = self.tasks.get("default")
                if effective_task is None:
                    raise ValueError("No task provided and no default task registered")
            else:
                effective_task = task
        self._apply_effect(effect, effective_task)

    # ---- Independent ledger: the single source of truth ----
    # The ledger is EXTERNAL (passed in via constructor), not owned by broker.
    # Both broker.commit() (direct) and executor.execute() (via-shim) record to it.
    # The ledger is the ONLY entity that can say "confirmed-committed" or "unknown".

    @property
    def ledger(self) -> IndependentEffectLedger:
        """The independent effect ledger for complete mediation verification.

        This ledger is the single source of truth for authorized vs. observed
        effects. Both broker.commit() (direct) and executor.execute() (via-shim)
        record to this ledger. Call verify_complete_mediation() to check.

        Returns the local IndependentEffectLedger if in same-process mode.
        In multi-process mode (ProcessLedgerClient), this returns the local
        client wrapper and direct attribute access may not reflect remote state.
        Prefer verify_complete_mediation() for multi-process verification.
        """
        return (
            self._local_ledger
            if self._local_ledger is not None
            else cast(IndependentEffectLedger, self._ledger_backend)
        )

    @property
    def observer(self) -> IndependentEffectLedger:
        """Alias for ledger (backwards compatibility). Prefer ledger()."""
        return self.ledger

    def verify_complete_mediation(self) -> list[str]:
        """Verify complete mediation across all authorized effects.

        Uses the independent ledger to compare authorized vs. observed effects.
        Returns list of failure strings (empty = complete mediation).

        Works from BOTH paths:
          - Direct: broker.commit() records authorization + observation
          - Via-shim: executor.execute() records authorization + observation
        """
        # Build the authorized records dict that ledger.verify_all() expects.
        # Keys are (task_id, nonce) tuples; values are authorized targets frozensets.
        authorized_records: dict[tuple[str, str], frozenset[str]] = {}

        # Merge all authorized targets from all authorization entries for each nonce
        for (tid, nonce), entries in self._ledger_backend.get_authorization_entries().items():
            targets: frozenset[str] = frozenset()
            for entry in entries:
                targets |= entry.authorized_targets
            authorized_records[(tid, nonce)] = targets

        return self._ledger_backend.verify_all(authorized_records)
