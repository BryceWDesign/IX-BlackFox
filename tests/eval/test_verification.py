from __future__ import annotations

from pathlib import Path

from ix_blackfox.config import load_runtime_config
from ix_blackfox.eval import (
    EvaluationContext,
    EvaluationFinding,
    EvaluationSeverity,
    EvaluationStatus,
    OutputVerifier,
    RuleBasedEvaluator,
    VerificationContext,
    VerificationStatus,
)
from ix_blackfox.forge import (
    ForgeRegressionCollector,
    ForgeTestRunner,
    ForgeWorkspaceManager,
)


def test_output_verifier_passes_with_artifacts_evaluations_and_regression(
    tmp_path: Path,
) -> None:
    config = load_runtime_config(root_dir=tmp_path, env={})
    manager = ForgeWorkspaceManager(config)
    workspace = manager.reserve(prefix="verify-pass")

    manager.materialize_file(
        workspace=workspace,
        relative_path="input/tests/test_ok.py",
        content="""def test_ok() -> None:
    assert True
""",
    )

    regression = ForgeRegressionCollector().collect(
        ForgeTestRunner().run(workspace=workspace)
    )

    evaluator = RuleBasedEvaluator(
        evaluator_name="artifact_quality",
        rules=(lambda context: None,),
    )
    evaluation = evaluator.evaluate(
        EvaluationContext(
            artifacts=("report.json",),
        )
    )

    report = OutputVerifier().verify(
        VerificationContext(
            subject_id="task-001",
            expected_artifacts=("report.json",),
            produced_artifacts=("report.json",),
            evaluation_results=(evaluation,),
            regression_report=regression,
        )
    )

    assert report.subject_id == "task-001"
    assert report.status == VerificationStatus.PASSED
    assert report.passed() is True
    assert report.issues == ()


def test_output_verifier_fails_for_missing_artifacts_and_failed_evaluation() -> None:
    def failing_rule(context: EvaluationContext):
        _ = context
        return EvaluationFinding(
            code="output.invalid",
            severity=EvaluationSeverity.ERROR,
            summary="Output failed validation.",
        )

    evaluation = RuleBasedEvaluator(
        evaluator_name="artifact_quality",
        rules=(failing_rule,),
    ).evaluate(EvaluationContext())

    report = OutputVerifier().verify(
        VerificationContext(
            subject_id="task-002",
            expected_artifacts=("report.json", "trace.log"),
            produced_artifacts=("trace.log",),
            evaluation_results=(evaluation,),
        )
    )

    assert report.status == VerificationStatus.FAILED
    assert report.passed() is False
    assert tuple(issue.code for issue in report.issues) == (
        "verification.missing_artifact",
        "verification.evaluation_failed",
    )


def test_output_verifier_needs_review_when_evaluation_is_missing_or_warning() -> None:
    def warning_rule(context: EvaluationContext):
        _ = context
        return EvaluationFinding(
            code="output.partial",
            severity=EvaluationSeverity.WARNING,
            summary="Output is incomplete.",
        )

    warning_evaluation = RuleBasedEvaluator(
        evaluator_name="artifact_quality",
        rules=(warning_rule,),
    ).evaluate(EvaluationContext())

    missing_eval_report = OutputVerifier().verify(
        VerificationContext(
            subject_id="task-003",
            produced_artifacts=("report.json",),
        )
    )
    warning_eval_report = OutputVerifier().verify(
        VerificationContext(
            subject_id="task-004",
            produced_artifacts=("report.json",),
            evaluation_results=(warning_evaluation,),
        )
    )

    assert missing_eval_report.status == VerificationStatus.NEEDS_REVIEW
    assert missing_eval_report.issues[0].code == "verification.no_evaluations"
    assert warning_eval_report.status == VerificationStatus.NEEDS_REVIEW
    assert warning_eval_report.issues[0].code == (
        "verification.evaluation_needs_review"
    )


def test_output_verifier_fails_when_regression_report_fails(tmp_path: Path) -> None:
    config = load_runtime_config(root_dir=tmp_path, env={})
    manager = ForgeWorkspaceManager(config)
    workspace = manager.reserve(prefix="verify-fail")

    manager.materialize_file(
        workspace=workspace,
        relative_path="input/tests/test_fail.py",
        content="""def test_fail() -> None:
    assert False
""",
    )

    regression = ForgeRegressionCollector().collect(
        ForgeTestRunner().run(workspace=workspace)
    )
    evaluation = RuleBasedEvaluator(
        evaluator_name="artifact_quality",
        rules=(lambda context: None,),
    ).evaluate(EvaluationContext())

    report = OutputVerifier().verify(
        VerificationContext(
            subject_id="task-005",
            produced_artifacts=("report.json",),
            evaluation_results=(evaluation,),
            regression_report=regression,
        )
    )

    assert report.status == VerificationStatus.FAILED
    assert report.issues[0].code == "verification.regression_failed"
