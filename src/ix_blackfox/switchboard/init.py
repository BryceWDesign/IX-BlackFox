"""
Switchboard subsystem.

The switchboard routes work across internal capabilities using explicit
routes, deterministic scoring, and policy-aware arbitration. The initial
implementation establishes a transparent base router before richer
semantic selection layers are introduced.
"""

from ix_blackfox.switchboard.models import (
    CapabilityRoute,
    RoutingDecision,
    RoutingDecisionReason,
    score_route,
)
from ix_blackfox.switchboard.runtime import CapabilitySwitchboard, SwitchboardSnapshot

__all__ = [
    "CapabilityRoute",
    "CapabilitySwitchboard",
    "RoutingDecision",
    "RoutingDecisionReason",
    "SwitchboardSnapshot",
    "score_route",
]
