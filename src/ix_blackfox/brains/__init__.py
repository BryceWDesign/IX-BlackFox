from __future__ import annotations

"""
Multi-brain runtime contracts for IX-BlackFox.

This package defines provider-agnostic cognitive-plane primitives that
sit underneath pack execution and above concrete inference backends.

Only normalized contracts live here. Manifest registration, provider
adapters, and routing policy arrive in later commits.
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
from ix_blackfox.brains.models import (
    BrainContextWindow,
    BrainExecutionLimits,
    BrainModelProfile,
    BrainModalityProfile,
)

__all__ = [
    "BrainCapability",
    "BrainContextWindow",
    "BrainExecutionLimits",
    "BrainFailure",
    "BrainFailureKind",
    "BrainInvocationRequest",
    "BrainInvocationResult",
    "BrainInvocationStatus",
    "BrainMessage",
    "BrainModality",
    "BrainModalityProfile",
    "BrainModelProfile",
    "BrainRole",
]
