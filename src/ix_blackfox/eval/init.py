"""
Evaluation subsystem.

Eval scores task outcomes, verifies claims, records benchmark results,
and supports regression checks so BlackFox can measure whether its work
is actually correct. The first concrete layers provide a deterministic
evaluation model for findings, scores, rule-based checks, and benchmark
suite schemas for repeatable task validation.
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
    "RuleBasedEvaluator",
]
