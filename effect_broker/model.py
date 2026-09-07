"""Core data types: principals, resources, data values, capabilities, effects"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .lattice import Confidentiality, Integrity

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

@dataclass
class Session:
    """A task's logical clock and per-task revocation/replay state

    Lifetime is logical (task-scoped), NOT wall-clock
    Revocation is per-task: revoking in one task does NOT globally invalidate
    capabilities of an unrelated task
    Replay is per-task nonce set: the same nonce cannot be replayed within
    the task window
    """

    session_id: str
    logical_time: float = 0.0
    live: bool = True  # False when task is ended/revoked
    revoked: set[str] = field(default_factory=set)  # revoked capability nonces
    used: set[str] = field(default_factory=set)  # replay-prevention nonce set


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

    The commit rule requires authority(e) to be a subset of the task's ceiling for every effect committed
    within this task. FlowOK uses the task's flow_boundary rather than a global
    lattice. The Session carries the per-task clock/revocation/replay model
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
class Data:
    """A data value carrying confidentiality and integrity labels"""

    name: str
    confidentiality: Confidentiality
    integrity: Integrity


@dataclass(frozen=True)
class LabelException:
    """A validated declass/endorse grant (broker-only privilege)

    declass/endorse are privileged operations performed ONLY by the EffectBroker
    on explicit User Policy or a validated approval. The LLM may request such
    an exception, but may never perform it — only the broker records one here
    after checking policy

    - kind:         "declass" | "endorse"
    - match_target: resource/effect target this applies to ("*" = any)
    - from_label:   source confidentiality/integrity label
    - to_label:     target label the flow is (re)classified to
    - granted_by:   the principal that authorized it (USER or APPROVER)
    - nonce:        unique id (single-use if tracked)
    """

    kind: str  # "declass" | "endorse"
    match_target: str
    from_label: str
    to_label: str
    granted_by: str
    nonce: str


@dataclass(frozen=True)
class Effect:
    """A PREPARED (staged, non-mutating) effect

    read|write|send|delete are prepared. They never touch external state
    on their own — only a `Commit` (invoked by the broker) does. Note: `commit`
    is NOT an etype here; it is the separate `Commit` primitive the broker performs

    `task_id` binds this effect to the task whose ceiling bounds its authority
    (authority(e) <= ceiling(t) is enforced by Auth at commit time)
    """

    etype: str  # read|write|send|delete  (prepared only)
    target: str
    metadata: dict[str, object]  # extra context (resource extras, etc.)
    provenance: tuple[Data, ...]  # values influencing the effect
    capability_nonce: str
    delegation_chain: tuple[str, ...]  # principals in the delegation chain
    # Optional validated declass/endorse exceptions attached to this effect
    # Only the broker fills this; the LLM may only request them
    label_exceptions: tuple[LabelException, ...] = ()
    task_id: TaskId | None = None  # task whose ceiling bounds authority; validated at commit


@dataclass(frozen=True)
class Commit:
    """The commit primitive that changes external state

    read/write/send/delete are PREPARED; only COMMIT changes external state,
    and only the EffectBroker may invoke it. A Commit wraps a prepared Effect;
    the broker applies it only after the four-predicate gate
    (Auth and FlowOK and NoAmp and Fresh) passes at commit time

    `task` carries the authority ceiling and session state needed by the
    predicates. `tool_name` optionally names the MCP tool performing this effect
    — the broker's Mediator consults its ToolSpec to detect declared-vs-actual
    mismatches (T13/T14/T15 boundary failures)
    """

    effect: Effect
    task: Task | None = None  # None → broker creates a permissive default Task
    tool_name: str | None = None  # MCP tool name for boundary mediation
