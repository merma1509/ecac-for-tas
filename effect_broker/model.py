"""Core data types: principals, resources, data values, capabilities, effects"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TypedDict

from .lattice import Confidentiality, Integrity


class Evidence(TypedDict):
    """Machine-checkable record emitted for every commit decision."""

    allow: bool
    primary_blocker: str | None
    predicates: dict[str, str]
    boundary_stop: str | None
    approval_binding: str | None

# Principals
USER = "User"  # sole root of authority
AGENT = "Agent"  # untrusted LLM proposer
TOOL = "ToolAdapter"  # untrusted third-party code
BROKER = "EffectBroker"  # trusted core, the only committer
APPROVER = "Approver"  # human escalation


# Alias for task identifiers (future-proof for typed IDs)
TaskId = str


class Domain(Enum):
    """Email domain class (dom ∈ {internal, external})

    We read email as the email domain, which naturally bundles messages and their mailboxes
    (inbox/outbox) — an email is delivered into a mailbox — plus the address's
    domain class. Mailboxes are therefore part of the email domain
    """

    INTERNAL = "internal"
    EXTERNAL = "external"


# ---- Task / Session types ----
# Task authority ceiling: every effect's authority must be a subset of ceiling(t)
# Session clock: per-task logical time, revocation set, and replay set


@dataclass(frozen=True)
class CommitGateResult:
    """Result of the four-predicate gate evaluation (commit phase 1).

    This is returned by broker.commit() BEFORE any state is applied.
    The executor uses this to decide whether to call apply_effect().
    Separating gate evaluation from state application is the key to
    independent observer verification: the observer can check that
    every applied effect corresponds to a gate pass.

    Fields:
      allow: True if ALL predicates pass AND approval binding is valid
      evidence: machine-checkable record of every predicate verdict
      effect: the committed effect (for applying by the executor)
      task: the task whose session tracks used nonces
      can_apply: True if the effect should be applied to state
    """

    allow: bool
    evidence: Evidence
    effect: Effect
    task: Task
    can_apply: bool  # True if allow AND no boundary stop


@dataclass
class Session:
    """A task's logical clock and per-task revocation/replay state.

    FIXED: Session.live=False now BLOCKs all commits in check_fresh().
    Closing a session explicitly revokes the task's authority ceiling.
    Once live=False, the session CANNOT be reopened — setting live=True
    after it has been False raises ValueError. This enforces that "closed"
    is terminal: the task's authority ceiling is invalidated until explicitly
    re-registered with a new session by the broker (not by directly setting live).

    NOTE: `live` is a property wrapping a private _live field. Direct assignment
    (task.session.live = False) goes through the setter, which enforces the
    terminal-closure invariant. The _ever_closed flag is per-instance state that
    persists once the session has been closed.
    """

    session_id: str
    logical_time: float = 0.0
    revoked: set[str] = field(default_factory=set)  # revoked capability nonces
    used: set[str] = field(default_factory=set)  # replay-prevention nonce set

    # Private state
    _live: bool = True
    _ever_closed: bool = field(default=False, repr=False)

    @property
    def live(self) -> bool:
        """Read-only view of the session live state."""
        return self._live

    @live.setter
    def live(self, value: bool) -> None:
        """Set the live flag. Once False, cannot be set back to True.

        Raises ValueError if attempting to reopen a closed session.
        """
        if self._ever_closed and value is True:
            raise ValueError(
                f"Session {self.session_id} has been closed and cannot be reopened. "
                "To resume this task, register a new Task with a fresh Session."
            )
        self._live = value
        if value is False:
            self._ever_closed = True


@dataclass(frozen=True)
class Capability:
    """Object-capability style capability. Issued only by monotonic attenuation

    owner         : the root principal that seeded the authority (only a root
                    may seed a new grant; everything else attenuates an existing capability)
    holder        : the principal currently holding the capability
    right         : one of read|write|send|delete|commit
    target        : the specific resource the capability authorizes
    scope         : the allowed target scope (must narrow monotonically on attenuation)
    expiry        : unix/logical time after which the capability is stale
    nonce         : unique identifier (also used for replay detection)
    task_id       : the task this capability is scoped to; None = any task
    derives_from   : nonce of the parent this was attenuated from, or None if
                    this is a root grant. Used by NoAmp to prove root-anchored, monotonic derivation
    revoked       : True if the capability has been explicitly revoked
    """

    owner: str
    holder: str
    right: str
    target: str
    scope: frozenset[str]
    expiry: float
    nonce: str
    task_id: TaskId | None = None
    derives_from: str | None = None
    revoked: bool = False


@dataclass
class Task:
    """A task carrying an authority ceiling and per-task policy bounds

    The commit rule requires authority(e) ⊆ ceiling(t) for every effect
    committed within this task. FlowOK uses the task's flow_boundary rather
    than a global lattice. The Session carries the per-task
    clock/revocation/replay model
    """

    task_id: TaskId
    owner: str  # the user this task belongs to
    ceiling: Capability  # widest authority this task may exercise
    flow_boundary: tuple[Confidentiality, Integrity] = (Confidentiality.INTERNAL, Integrity.USER)
    session: Session | None = None

    def __post_init__(self) -> None:
        # Lazily create a default session so callers can construct a Task
        # without explicitly constructing a Session
        if self.session is None:
            self.session = Session(session_id=self.task_id)


@dataclass(frozen=True)
class File:
    """A file resource (F). Sensitivity uses the confidentiality lattice"""

    path: str
    sensitivity: Confidentiality


@dataclass(frozen=True)
class Email:
    """An email resource (E): target address + domain class"""

    address: str
    domain: Domain


@dataclass
class Mailbox:
    """A mailbox resource (M): belongs to one user, holds inbox/outbox messages

    Inbox holds incoming messages; outbox holds messages this user sent. A
    `send` effect appends to the sender's outbox; a `read` effect retrieves a
    message from a mailbox. The address -> owning-user association is maintained
    by the ResourceStore (see `mailbox_for`)
    """

    user: str
    inbox: list[str] = field(default_factory=list)
    outbox: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class URL:
    """A network resource (N), identified by URI string

    The scope is a frozenset of allowed domain strings (e.g. {"internal.corp.com"})
    used by NoAmp/Auth for SSRF containment: a network effect whose URL domain
    is not within the capability's scope is rejected by the gate
    """

    uri: str
    scope: frozenset[str]


# Union of all resource kinds — R = F ∪ E ∪ M ∪ N (files, emails, mailboxes, URLs)
Resource = File | Email | Mailbox | URL


@dataclass(frozen=True)
class EffectTarget:
    """Complete identity of an effect's resource targets.

    Unlike a single `target` string, this captures ALL resources an effect
    actually touches. This is the key for full-effect-identity matching:
    the observer must verify that the authorized target set exactly matches
    the observed resource set — not just the declared primary target.

    For a simple write to a file, this is just {target}. For a send with
    BCC/CC recipients, this is {primary, bcc1, bcc2, ...}. For a send with
    attachments, it includes those too. For a read, it covers the file plus
    any side-channel writes (T14 hidden exfil).
    """

    primary: str  # the target submitted to the broker gate
    additional: frozenset[str] = frozenset()  # extra resources touched (e.g. BCC recipients)


@dataclass(frozen=True)
class ApprovedRequest:
    """An immutable authorization binding: exact (etype, targets, content_hash).

    Approvals are one-shot: they may authorize exactly the effect they were
    granted for, and NO variation. The binding covers:

    - etype:       operation type (read/write/send/delete/network)
    - targets:     complete set of resources this authorizes (including BCC)
    - provenance:  hash of the provenance data that was approved
    - expiry:      time after which this approval is invalid
    - task_id:     the task this approval is scoped to

    Killing criterion #5: exact immutable request binding.
    Using this approval for a different target, different recipients, or
    modified content is blocked as Fresh (replay of a nonce that was already
    consumed) and/or Auth (target-mismatch on the capability right+target).
    """

    nonce: str  # unique one-shot token (consumed after first use)
    etype: str  # operation type this was approved for
    targets: EffectTarget  # complete authorized target set (primary + additional)
    # Content hash: a stable fingerprint of the approved content (e.g. hash of
    # message body). An effect with different content has a different identity.
    content_hash: str
    expiry: float  # time after which this approval is invalid
    task_id: TaskId  # task scope: this approval is ONLY valid in this task
    granted_by: str  # who granted it (USER or APPROVER)


@dataclass(frozen=True)
class Data:
    """A data value carrying confidentiality and integrity labels.

    The `content` field holds the actual value that will be hashed for
    immutable request binding (ApprovedRequest.content_hash). This ensures
    that modified content after approval is detected.

    Provenance labels (confidentiality/integrity) are assigned based on
    the data's source, not derived from real dataflow in this same-process
    model. The key invariant: content is included in the hash, so any
    modification after approval is detectable.
    """

    name: str
    confidentiality: Confidentiality
    integrity: Integrity
    content: str = ""  # actual value, hashed for immutable request binding


@dataclass(frozen=True)
class LabelException:
    """A validated declass/endorse grant (broker-only privilege)

    declass/endorse are privileged operations performed ONLY by the EffectBroker
    on explicit User Policy or a validated approval. The LLM may request such
    an exception, but may never perform it — only the broker records one here
    after checking policy

    - kind:              "declass" | "endorse"
    - match_target:      primary resource/effect target this applies to ("*" = any)
    - from_label:        source confidentiality/integrity label
    - to_label:          target label the flow is (re)classified to
    - granted_by:        the principal that authorized it (USER or APPROVER)
    - nonce:             unique id (single-use if tracked)
    - additional_targets: frozenset of extra targets this applies to (BCC recipients,
                          etc.). If empty, the exception applies ONLY to the
                          primary target. An empty set means no extra targets.
    - etype:             operation type this applies to ("*" = any). If None, the
                          exception applies to any etype.
    """

    kind: str  # "declass" | "endorse"
    match_target: str
    from_label: str
    to_label: str
    granted_by: str
    nonce: str
    additional_targets: frozenset[str] = frozenset()  # extra targets (BCC, etc.)
    etype: str | None = None  # operation type, or None for any

    def matches_effect(self, effect: Effect) -> bool:
        """True if this exception applies to the given effect.

        Checks:
          - etype matches (if set)
          - from_label matches the violating datum's label
          - target set is contained in the exception's authorized target set
            (i.e., the effect's complete_targets() ⊆ authorized_targets)
            EXCEPTION: match_target="*" matches ANY target set (wildcard)

        This is the "exact effect identity" check for declass/endorse grants.
        A grant for "send to internal@corp.com" does NOT also authorize
        "send to internal@corp.com with BCC to external@attacker.com" unless
        additional_targets explicitly includes external@attacker.com.
        """
        # Check etype
        if self.etype is not None and effect.etype != self.etype:
            return False

        # Wildcard match_target="*" matches any target set
        if self.match_target == "*":
            return True

        # Build the authorized target set
        authorized_targets = frozenset({self.match_target}) | self.additional_targets

        # Check complete_targets() ⊆ authorized_targets
        effect_targets = effect.complete_targets()
        if not (effect_targets <= authorized_targets):
            return False

        return True


@dataclass(frozen=True)
class Effect:
    """A PREPARED (staged, non-mutating) effect.

    read|write|send|delete are prepared. They never touch external state
    on their own — only a `Commit` (invoked by the broker) does. Note: `commit`
    is NOT an etype here; it is the separate `Commit` primitive the broker performs.

    `known_targets` captures the complete set of resources this effect touches.
    For a simple write to a file this is just {target}. For a send with BCC/CC
    recipients, this is {primary, bcc1, bcc2, ...}. The EffectObserver uses
    this to verify complete effect identity — not just the declared primary target.

    `task_id` binds this effect to the task whose ceiling bounds its authority
    (authority(e) <= ceiling(t) is enforced by Auth at commit time).
    """

    etype: str  # read|write|send|delete  (prepared only)
    target: str  # primary resource target
    metadata: dict[str, object]  # extra context (BCC recipients, etc.)
    provenance: tuple[Data, ...]  # values influencing the effect
    capability_nonce: str
    delegation_chain: tuple[str, ...]  # principals in the delegation chain
    # Optional validated declass/endorse exceptions attached to this effect
    # Only the broker fills this; the LLM may only request them
    label_exceptions: tuple[LabelException, ...] = ()
    task_id: TaskId | None = None  # task whose ceiling bounds authority; validated at commit
    # Complete set of resources this effect actually touches (for effect identity matching).
    # The EffectObserver verifies: observed_resources ⊆ authorized_targets ⊆ observed_resources.
    # For send with BCC: this includes all BCC recipients. For hidden-write: includes secrets.
    known_targets: EffectTarget | None = None

    def complete_targets(self) -> frozenset[str]:
        """Canonical source: complete set of resources this effect touches

        Priority:
          1. known_targets.additional  — authoritative (set by shim or builder)
          2. metadata["extra_resources"] as list  — BCC recipients fallback
          3. metadata["bcc_*"] keys  — legacy BCC metadata
          4. metadata["extra_resources"] as str  — single string fallback

        Returns: frozenset {primary} ∪ {additional recipients}.
        All three call-sites (broker.commit, executor.execute, grant_approval)
        MUST use this method — never re-extract from metadata independently
        """
        targets: set[str] = {self.target}

        if self.known_targets is not None:
            # Authoritative: known_targets is set by the shim/executor builder
            targets |= self.known_targets.additional
        else:
            # Fallback for direct Effect construction (no known_targets):
            # extract extra targets from metadata
            extra = self.metadata.get("extra_resources", [])
            if isinstance(extra, list):
                targets |= set(extra)
            elif isinstance(extra, str):
                targets.add(extra)

            # Legacy BCC metadata keys (e.g. bcc_1, bcc_2, ...)
            for key, val in self.metadata.items():
                if key.startswith("bcc"):
                    if isinstance(val, list):
                        targets |= set(val)
                    elif isinstance(val, str):
                        targets.add(val)

        return frozenset(targets)


@dataclass(frozen=True)
class Commit:
    """The commit primitive that changes external state.

    read/write/send/delete are PREPARED; only COMMIT changes external state,
    and only the EffectBroker may invoke it. A Commit wraps a prepared Effect;
    the broker applies it only after the four-predicate gate
    (Auth and FlowOK and NoAmp and Fresh) passes at commit time.

    `task` carries the authority ceiling and session state needed by the
    predicates. `tool_name` optionally names the MCP tool performing this effect
    — the broker's Mediator consults its ToolSpec to detect declared-vs-actual
    mismatches (T13/T14/T15 boundary failures).

    `approved_request` captures the immutable authorization binding from an
    approval grant (if this effect was approved). The EffectObserver uses
    approved_request.targets and approved_request.content_hash to verify the
    effect's complete identity — preventing modifications after approval.
    """

    effect: Effect
    task: Task | None = None  # None → broker creates a permissive default Task
    tool_name: str | None = None  # MCP tool name for boundary mediation
    # Immutable authorization binding from an approval grant.
    # When set, the effect's complete identity must match this binding:
    #   - etype must match
    #   - known_targets must be ⊆ approved_request.targets
    #   - content_hash must match
    approved_request: ApprovedRequest | None = None
