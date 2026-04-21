"""
End-to-end runtime orchestration for IX-BlackFox.

This package fuses routing, pack execution, sentinel checks, evaluation,
artifact persistence, replay observation, and audit capture into one
explicit execution spine.
"""

from ix_blackfox.runtime.inference import (
    DeterministicTaskClassifier,
    TaskInference,
    TaskInferenceReason,
)
from ix_blackfox.runtime.orchestrator import (
    BlackFoxRuntime,
    RuntimeRunReport,
    RuntimeRunStatus,
)
from ix_blackfox.runtime.replay import (
    ReplayObservation,
    TaskReplayGuard,
    fingerprint_task_request,
)

__all__ = [
    "BlackFoxRuntime",
    "DeterministicTaskClassifier",
    "ReplayObservation",
    "RuntimeRunReport",
    "RuntimeRunStatus",
    "TaskInference",
    "TaskInferenceReason",
    "TaskReplayGuard",
    "fingerprint_task_request",
]
