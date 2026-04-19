"""
Internal event bus.

The bus carries typed envelopes, execution events, tool results, memory
writes, and coordination signals between BlackFox subsystems. The initial
implementation is synchronous and in-memory so later runtime layers can
wire against stable contracts before transport complexity is introduced.
"""

from ix_blackfox.bus.messages import EventEnvelope, EventTopic
from ix_blackfox.bus.runtime import EventDispatchResult, InMemoryEventBus

__all__ = [
    "EventDispatchResult",
    "EventEnvelope",
    "EventTopic",
    "InMemoryEventBus",
]
