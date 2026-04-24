from __future__ import annotations

"""
Multi-brain runtime contracts for IX-BlackFox.

This package defines provider-agnostic cognitive-plane primitives that
sit underneath pack execution and above concrete inference backends.

Only normalized contracts, manifests, registries, routing policy, and
execution-profile primitives live here. Provider adapters arrive later.
"""

from ix_blackfox.brains.budgets import (
    BrainContextBudget,
    BrainCostClass,
    BrainEscalationBudget,
    BrainInferenceBudget,
    BrainLatencyClass,
    BrainLatencyBudget,
)
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
from ix_blackfox.brains.models import (
    BrainContextWindow,
    BrainExecutionLimits,
    BrainModelProfile,
    BrainModalityProfile,
)
from ix_blackfox.brains.policy import (
    BrainRoutingPolicy,
    BrainRoutingRequest,
    BrainScoreBreakdown,
)
from ix_blackfox.brains.profiles import BrainExecutionMode, BrainExecutionProfile
from ix_blackfox.brains.receipts import (
    BrainInvocationReceipt,
    BrainInvocationReceiptLedger,
    BrainInvocationReceiptSnapshot,
)
from ix_blackfox.brains.registry import BrainManifestRegistry
from ix_blackfox.brains.renderers import (
    BrainMessageNormalizer,
    HarmonyRenderConfig,
    HarmonyRenderer,
    NormalizedConversation,
    PlainTranscriptRenderer,
)
from ix_blackfox.brains.router import BrainRouteCandidate, BrainRouter, BrainRoutingDecision

__all__ = [
    "BrainCapability",
    "BrainContextBudget",
    "BrainContextWindow",
    "BrainCostClass",
    "BrainEscalationBudget",
    "BrainExecutionLimits",
    "BrainExecutionMode",
    "BrainExecutionProfile",
    "BrainFailure",
    "BrainFailureKind",
    "BrainInferenceBudget",
    "BrainInvocationReceipt",
    "BrainInvocationReceiptLedger",
    "BrainInvocationReceiptSnapshot",
    "BrainInvocationRequest",
    "BrainInvocationResult",
    "BrainInvocationStatus",
    "BrainLatencyBudget",
    "BrainLatencyClass",
    "BrainManifest",
    "BrainManifestRegistry",
    "BrainManifestSnapshot",
    "BrainMessage",
    "BrainMessageNormalizer",
    "BrainModality",
    "BrainModalityProfile",
    "BrainModelProfile",
    "BrainRole",
    "BrainRouteCandidate",
    "BrainRouter",
    "BrainRoutingDecision",
    "BrainRoutingPolicy",
    "BrainRoutingRequest",
    "BrainScoreBreakdown",
    "HarmonyRenderConfig",
    "HarmonyRenderer",
    "NormalizedConversation",
    "PlainTranscriptRenderer",
]
