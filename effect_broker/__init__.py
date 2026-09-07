"""Effect-Complete Authority Confinement for Tool Agents

Tiny executable model of the core invariant:
    Commit(e,t) => Auth(e,t) and FlowOK(e,t) and NoAmp(e,t) and Fresh(e,t)

The EffectBroker is the only principal that can commit an effect. The LLM and
tool code are outside this model
"""

from .broker import EffectBroker
from .lattice import Confidentiality, Integrity
from .mediation import MediationVerdict, Mediator, ToolSpec
from .model import (
    AGENT,
    APPROVER,
    BROKER,
    TOOL,
    URL,
    USER,
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
from .resources import ResourceStore

__all__ = [
    "Confidentiality", "Integrity", "Data", "Capability", "Effect",
    "Commit", "Session", "Task", "TaskId", "USER", "AGENT", "TOOL",
    "BROKER", "APPROVER", "EffectBroker", "Domain", "Email",
    "File", "Mailbox", "Resource", "ResourceStore",
    "URL", "ToolSpec", "Mediator", "MediationVerdict",
]
