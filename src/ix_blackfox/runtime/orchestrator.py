from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field, replace
from datetime import UTC, datetime
from enum import StrEnum, auto
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

from ix_blackfox.brains import (
    BrainEscalationDecision,
    BrainEscalationPolicy,
    BrainInvocationReceiptLedger,
    SafeguardAssessment,
)
from ix_blackfox.bus import InMemoryEventBus
from ix_blackfox.config import RuntimeConfig, load_runtime_config
from ix_blackfox.eval import (
    EvaluationContext,
    EvaluationFinding,
    EvaluationResult,
    EvaluationSeverity,
    EvaluationStatus,
    EvidenceRecorder,
    OutputVerifier,
    VerificationContext,
    VerificationReport,
)
from ix_blackfox.governance import GovernanceReceiptLedger, PolicyAdvisoryAssessment
from ix_blackfox.kernel import (
    BlackFoxKernel,
    SharedStateStore,
    TaskKind,
    TaskPriority,
    TaskRecord,
    TaskRequest,
    TaskState,
)
from ix_blackfox.memory import (
    ArtifactMemoryStore,
    EpisodicMemoryStore,
    SemanticMemoryStore,
    TraceMemoryStore,
)
from ix_blackfox.observability import JsonlStructuredLogger
from ix_blackfox.packs import (
    BasePack,
    PackBrainContext,
    PackContext,
    PackLoader,
    PackManifest,
    PackManifestRegistry,
)
from ix_blackfox.packs.architecture import build_architecture_manifest
from ix_blackfox.packs.programming import build_programming_manifest
from ix_blackfox.runtime.approval import (
    RuntimeApprovalResolution,
    RuntimeApprovalResolver,
)
from ix_blackfox.runtime.governance import (
    RuntimeGovernancePreflightEngine,
    RuntimeGovernancePreflightResult,
)
from ix_blackfox.runtime.inference import (
    DeterministicTaskClassifier,
    PrimaryBrainRuntime,
    TaskInference,
)
from ix_blackfox.runtime.policy_reasoning import (
    PolicyReasoningOutcome,
    PolicyReasoningRuntime,
)
from ix_blackfox.runtime.readiness import (
    RuntimeReadinessInspector,
    RuntimeReadinessReport,
    RuntimeReadinessStatus,
)
from ix_blackfox.runtime.reasoning import (
    EscalatedReasoningOutcome,
    EscalatedReasoningRuntime,
)
from ix_blackfox.runtime.receipts import (
    RuntimeGovernanceReceiptRecorder,
    RuntimeGovernanceReceiptReport,
)
from ix_blackfox.runtime.replay import ReplayObservation, TaskReplayGuard
from ix_blackfox.runtime.safeguard import SafeguardRuntime
from ix_blackfox.runtime.vision import VisionOutcome, VisionRuntime
from ix_blackfox.sentinel import (
    SentinelContext,
    SentinelReport,
    SentinelRuntime,
    SentinelSeverity,
    register_default_sentinel_checks,
)
from ix_blackfox.switchboard import (
    CapabilityRoute,
    CapabilitySwitchboard,
    RoutingDecision,
)
from ix_blackfox.vault import (
    ProvenanceLedger,
    VaultStateStore,
)
