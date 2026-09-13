"""Effect-Complete Authority Confinement for Tool Agents

Tiny executable model of the core invariant:
    Commit(e,t) => Auth(e,t) and FlowOK(e,t) and NoAmp(e,t) and Fresh(e,t)

The EffectBroker is the only principal that can commit an effect. The LLM and
tool code are outside this model
"""

from .broker import EffectBroker, Evidence
from .executor import (
    IsolatedExecutor,
    make_content_hash,
)
from .lattice import Confidentiality, Integrity
from .ledger import (
    EffectObserverVerdict,
    IndependentEffectLedger,
    UnknownObserverResult,
)
from .mediation import MediationVerdict, Mediator, ToolSpec
from .model import (
    AGENT,
    APPROVER,
    BROKER,
    TOOL,
    URL,
    USER,
    ApprovedRequest,
    Capability,
    Commit,
    Data,
    Domain,
    Effect,
    Email,
    File,
    Mailbox,
    Resource,
    Session,
    Task,
    TaskId,
)
from .restricted_store import RestrictedResourceStore as ResourceStore

__all__ = [
    # Core types
    "Confidentiality",
    "Integrity",
    "Data",
    "Capability",
    "Effect",
    "ApprovedRequest",
    "Commit",
    "Session",
    "Task",
    "TaskId",
    "Evidence",
    # Principals
    "USER",
    "AGENT",
    "TOOL",
    "BROKER",
    "APPROVER",
    # Broker (predicate gate only — no direct resource access)
    "EffectBroker",
    # Executor (isolated, independent observer)
    "IsolatedExecutor",
    "make_content_hash",
    # Ledger (independent observer)
    "IndependentEffectLedger",
    "EffectObserverVerdict",
    "UnknownObserverResult",
    # Resources
    "Domain",
    "Email",
    "File",
    "Mailbox",
    "Resource",
    "ResourceStore",
    "URL",
    # Mediation
    "ToolSpec",
    "Mediator",
    "MediationVerdict",
]
