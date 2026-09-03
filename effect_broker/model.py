"""Core data types: principals, resources, data values, capabilities, effects"""

from dataclasses import dataclass
from enum import Enum

from .lattice import Confidentiality, Integrity

# Principals
USER = "User"  # sole root of authority
AGENT = "Agent"  # untrusted LLM proposer
TOOL = "ToolAdapter"  # untrusted third-party code
BROKER = "EffectBroker"  # trusted core, the only committer
APPROVER = "Approver"  # human escalation


class Domain(Enum):
    """Email domain class (dom ∈ {internal, external})

    We read "email" as the email domain, which naturally bundles messages and their mailboxes
    (inbox/outbox) — an email is delivered into a mailbox — plus the address's
    domain class. Mailboxes are therefore part of the email domain
    """

    INTERNAL = "internal"
    EXTERNAL = "external"


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


@dataclass(frozen=True)
class Mailbox:
    """A mailbox resource (M): belongs to one user (inbox/outbox style)"""

    user: str


# Union of all resource kinds — R = F ∪ E ∪ M
Resource = File | Email | Mailbox


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
class Capability:
    """Object-capability style capability. Issued only by monotonic attenuation

    owner         : the root principal that seeded the authority (only a root
                    may seed a new grant; everything else attenuates an existing capability)
    holder        : the principal currently holding the capability
    right         : one of read|write|send|delete|network|commit
    target        : the specific resource the capability authorizes
    scope         : the allowed target scope (must narrow monotonically on attenuation)
    expiry        : unix/logical time after which the capability is stale.
    nonce         : unique identifier (also used for replay detection).
    derives_from  : nonce of the parent this was attenuated from, or None if
                    this is a root grant. Used by NoAmp to prove root-anchored, monotonic derivation
    revoked       : True if the capability has been revoked (freshness check)
    """

    owner: str
    holder: str
    right: str
    target: str
    scope: frozenset[str]
    expiry: float
    nonce: str
    derives_from: str | None = None
    revoked: bool = False


@dataclass(frozen=True)
class Effect:
    """A PREPARED (staged, non-mutating) effect

    read|write|send|delete|network are prepared. They never touch external state
    on their own — only a `Commit` (invoked by the broker) does. Note: `commit`
    is NOT an etype here; it is the separate `Commit` primitive the broker performs
    """

    etype: str  # read|write|send|delete|network  (prepared only)
    target: str
    args: dict[str, object]
    provenance: tuple[Data, ...]  # values influencing the effect
    capability_nonce: str
    chain: tuple[str, ...]  # principals in the delegation chain
    # Optional validated declass/endorse exceptions attached to this effect
    # Only the broker fills this; the LLM may only request them
    label_exceptions: tuple[LabelException, ...] = ()


@dataclass(frozen=True)
class Commit:
    """The commit primitive that changes external state

    read/write/send/delete/network are PREPARED; only COMMIT
    changes external state, and only the EffectBroker may invoke it. A Commit
    wraps a prepared Effect; the broker applies it only after the four-predicate
    gate (Auth ∧ FlowOK ∧ NoAmp ∧ Fresh) passes at commit time
    """

    effect: Effect
