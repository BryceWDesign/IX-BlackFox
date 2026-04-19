"""
Evaluation subsystem.

Eval scores task outcomes, verifies claims, records benchmark results,
and supports regression checks so BlackFox can measure whether its work
is actually correct. The first concrete layer provides a deterministic
evaluation model for findings, scores, and rule-based checks.
"""

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
    "EvaluationContext",
    "EvaluationFinding",
    "EvaluationResult",
    "EvaluationSeverity",
    "EvaluationStatus",
    "RuleBasedEvaluator",
]
