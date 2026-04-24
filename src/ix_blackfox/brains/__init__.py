from __future__ import annotations

"""
Multi-brain runtime contracts for IX-BlackFox.

This package defines provider-agnostic cognitive-plane primitives that
sit underneath pack execution and above concrete inference backends.

Only normalized contracts, manifests, and registries live here.
Routing policy and provider adapters arrive in later commits.
"""

from ix_blackfox.brains.contracts import (
    BrainCapability,
    BrainFailure,
    BrainFailureKind,
    BrainInvocationRequest,
    BrainInvocationResult,
    BrainInvocationStatus,
    BrainMessage,
    BrainModality,
    BrainRole,
)
from ix_blackfox.brains.manifest import BrainManifest, BrainManifestSnapshot
from ix_blackfox.brains.policy import (
    BrainRoutingPolicy,
    BrainRoutingRequest,
    BrainScoreBreakdown,
)
from ix_blackfox.brains.models import (
    BrainContextWindow,
    BrainExecutionLimits,
    BrainModelProfile,
    BrainModalityProfile,
)
from ix_blackfox.brains.registry import BrainManifestRegistry
from ix_blackfox.brains.router import BrainRouteCandidate, BrainRouter, BrainRoutingDecision

__all__ = [
    "BrainCapability",
    "BrainContextWindow",
    "BrainExecutionLimits",
    "BrainFailure",
    "BrainFailureKind",
    "BrainInvocationRequest",
    "BrainInvocationResult",
    "BrainInvocationStatus",
    "BrainManifest",
    "BrainManifestRegistry",
    "BrainRouteCandidate",
    "BrainRouter",
    "BrainRoutingDecision",
    "BrainRoutingPolicy",
    "BrainRoutingRequest",
    "BrainScoreBreakdown",
    "BrainManifestSnapshot",
    "BrainMessage",
    "BrainModality",
    "BrainModalityProfile",
    "BrainModelProfile",
    "BrainRole",
]
