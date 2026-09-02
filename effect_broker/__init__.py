"""Effect-Complete Authority Confinement for Tool Agents

Tiny executable model of the core invariant:
    Commit(e,t) => Auth(e,t) and FlowOK(e,t) and NoAmp(e,t) and Fresh(e,t)

The EffectBroker is the only principal that can commit an effect. The LLM and
tool code are outside this model
"""

from .broker import EffectBroker
from .lattice import Confidentiality, Integrity
from .model import AGENT, APPROVER, BROKER, TOOL, USER, Capability, Data, Effect

__all__ = [
    "Confidentiality",
    "Integrity",
    "Data",
    "Capability",
    "Effect",
    "USER",
    "AGENT",
    "TOOL",
    "BROKER",
    "APPROVER",
    "EffectBroker",
]
