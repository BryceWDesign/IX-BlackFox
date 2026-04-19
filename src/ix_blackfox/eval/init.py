"""
Evaluation subsystem.

Eval scores task outcomes, verifies claims, records benchmark results,
and supports regression checks so BlackFox can measure whether its work
is actually correct. The first concrete layers provide a deterministic
evaluation model for findings, scores, rule-based checks, benchmark
suite schemas for repeatable task validation, and evidence recording for
auditable verification.
"""

from ix_blackfox.eval.benchmark import (
    BenchmarkCase,
    BenchmarkSuite,
    BenchmarkSuiteRegistry,
    BenchmarkSuiteSnapshot,
)
from ix_blackfox.eval.core import (
    BaseEvaluator,
    EvaluationContext,
    EvaluationFinding,
    EvaluationResult,
    EvaluationSeverity,
    EvaluationStatus,
    RuleBasedEvaluator,
)
from ix_blackfox.eval.evidence import (
    EvidenceRecord,
    EvidenceRecorder,
    EvidenceSnapshot,
)

__all__ = [
    "BaseEvaluator",
    "BenchmarkCase",
    "BenchmarkSuite",
    "BenchmarkSuiteRegistry",
    "BenchmarkSuiteSnapshot",
    "EvaluationContext",
    "EvaluationFinding",
    "EvaluationResult",
    "EvaluationSeverity",
    "EvaluationStatus",
    "EvidenceRecord",
    "EvidenceRecorder",
    "EvidenceSnapshot",
    "RuleBasedEvaluator",
]
