from __future__ import annotations

import pytest

from ix_blackfox.eval import (
    EvaluationContext,
    EvaluationFinding,
    EvaluationSeverity,
    EvaluationStatus,
    RuleBasedEvaluator,
)


def test_evaluation_finding_normalizes_fields() -> None:
    finding = EvaluationFinding(
        code=" Output.Mismatch ",
        severity=EvaluationSeverity.ERROR,
        summary="  Output does not match expected value.  ",
        details="  expected=1 actual=2  ",
    )

    assert finding.code == "output.mismatch"
    assert finding.summary == "Output does not match expected value."
    assert finding.details == "expected=1 actual=2"


def test_rule_based_evaluator_passes_without_findings() -> None:
    def clean_rule(context: EvaluationContext):
        _ = context
        return None

    evaluator = RuleBasedEvaluator(
        evaluator_name="output_quality",
        rules=(clean_rule,),
    )

    result = evaluator.evaluate(EvaluationContext(artifacts=("report.json",)))

    assert result.evaluator_name == "output_quality"
    assert result.status == EvaluationStatus.PASSED
    assert result.score == 1.0
    assert result.findings == ()
    assert result.passed() is True


def test_rule_based_evaluator_requires_review_on_warning() -> None:
    def warning_rule(context: EvaluationContext):
        _ = context
        return EvaluationFinding(
            code="output.partial",
            severity=EvaluationSeverity.WARNING,
            summary="Output is incomplete.",
        )

    evaluator = RuleBasedEvaluator(
        evaluator_name="output_quality",
        rules=(warning_rule,),
        passing_score=0.9,
        review_score=0.6,
        failing_score=0.1,
    )

    result = evaluator.evaluate(EvaluationContext())

    assert result.status == EvaluationStatus.NEEDS_REVIEW
    assert result.score == 0.6
    assert result.filter_by_severity(EvaluationSeverity.WARNING)[0].code == (
        "output.partial"
    )


def test_rule_based_evaluator_fails_on_error() -> None:
    def error_rule(context: EvaluationContext):
        _ = context
        return EvaluationFinding(
            code="output.invalid",
            severity=EvaluationSeverity.ERROR,
            summary="Output failed validation.",
        )

    evaluator = RuleBasedEvaluator(
        evaluator_name="output_quality",
        rules=(error_rule,),
    )

    result = evaluator.evaluate(EvaluationContext())

    assert result.status == EvaluationStatus.FAILED
    assert result.score == 0.0
    assert result.passed() is False


@pytest.mark.parametrize(
    ("builder", "message"),
    [
        (
            lambda: EvaluationFinding(
                code="   ",
                severity=EvaluationSeverity.INFO,
                summary="ok",
            ),
            "Evaluation finding code must not be empty",
        ),
        (
            lambda: EvaluationFinding(
                code="valid.code",
                severity=EvaluationSeverity.INFO,
                summary="   ",
            ),
            "Evaluation finding summary must not be empty",
        ),
        (
            lambda: RuleBasedEvaluator(
                evaluator_name="   ",
                rules=(lambda context: None,),
            ),
            "Evaluation evaluator name must not be empty",
        ),
        (
            lambda: RuleBasedEvaluator(
                evaluator_name="output_quality",
                rules=(),
            ),
            "must define at least one rule",
        ),
    ],
)
def test_evaluation_models_reject_invalid_inputs(builder, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        builder()
