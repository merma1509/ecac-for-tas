"""Core data types: principals, data values, capabilities, effects"""

from dataclasses import dataclass

from .lattice import Confidentiality, Integrity

# Principals
USER = "User"  # sole root of authority
AGENT = "Agent"  # untrusted LLM proposer
TOOL = "ToolAdapter"  # untrusted third-party code
BROKER = "EffectBroker"  # trusted core, the only committer
APPROVER = "Approver"  # human escalation


@dataclass(frozen=True)
class Data:
    """A data value carrying confidentiality and integrity labels"""

    name: str
    confidentiality: Confidentiality
    integrity: Integrity


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
    """A prepared effect proposed for commit. Only the broker may commit it"""

    etype: str  # read|write|send|delete|network|commit
    target: str
    args: dict[str, object]
    provenance: tuple[Data, ...]  # values influencing the effect
    capability_nonce: str
    chain: tuple[str, ...]  # principals in the delegation chain
