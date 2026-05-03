from __future__ import annotations

import hashlib

import pytest

from ix_blackfox.authoring import (
    AuthoringContext,
    AuthoringContextFile,
    AuthoringEvidence,
    AuthoringEvidenceStrength,
    AuthoringFinding,
    AuthoringFindingSeverity,
    AuthoringRequest,
    AuthoringRiskLevel,
    RepairFailureClass,
    RepairHypothesis,
    RepairHypothesisEngine,
    RepairHypothesisEngineConfig,
    RepairHypothesisReport,
    RepairShape,
    RepairTaskDecomposer,
)


def test_hypothesis_engine_detects_import_error_from_evidence() -> None:
    request = AuthoringRequest.create(
        task_id="task-import",
        objective="Repair failing import test.",
    )
    evidence = AuthoringEvidence.create(
        source="pytest",
        strength=AuthoringEvidenceStrength.DIRECT,
        summary="ModuleNotFoundError: No module named 'ix_blackfox.missing'",
        raw_text="ModuleNotFoundError: No module named 'ix_blackfox.missing'",
        related_paths=("tests/test_import.py", "src/ix_blackfox/__init__.py"),
    )
    request = _with_evidence(request, evidence)
    plan = RepairTaskDecomposer().decompose_request(request)

    report = RepairHypothesisEngine().generate(
        request=request,
        decomposition=plan,
    )

    assert report.selected_hypothesis.failure_class is RepairFailureClass.IMPORT_ERROR
    assert report.selected_hypothesis.expected_repair_shape is RepairShape.ADD_MISSING_IMPORT_OR_MODULE
    assert report.selected_hypothesis.confidence >= 0.8
    assert report.contains_authorable_hypothesis


def test_hypothesis_engine_detects_missing_symbol() -> None:
    request = AuthoringRequest.create(
        task_id="task-symbol",
        objective="Repair missing symbol.",
    )
    evidence = AuthoringEvidence.create(
        source="pytest",
        strength=AuthoringEvidenceStrength.DIRECT,
        summary="NameError: name 'build_plan' is not defined",
        raw_text="NameError: name 'build_plan' is not defined",
        related_paths=("src/ix_blackfox/planner.py",),
    )
    request = _with_evidence(request, evidence)

    report = RepairHypothesisEngine().generate(request=request)

    assert report.selected_hypothesis.failure_class is RepairFailureClass.MISSING_SYMBOL
    assert report.selected_hypothesis.expected_repair_shape is RepairShape.ADD_MISSING_SYMBOL
    assert report.selected_hypothesis.risk_level is AuthoringRiskLevel.LOW


def test_hypothesis_engine_detects_syntax_error_with_high_confidence() -> None:
    request = AuthoringRequest.create(
        task_id="task-syntax",
        objective="Repair syntax failure.",
    )
    evidence = AuthoringEvidence.create(
        source="pytest",
        strength=AuthoringEvidenceStrength.DIRECT,
        summary="SyntaxError: invalid syntax",
        raw_text="SyntaxError: invalid syntax",
        related_paths=("src/ix_blackfox/broken.py",),
    )
    request = _with_evidence(request, evidence)

    report = RepairHypothesisEngine().generate(request=request)

    assert report.selected_hypothesis.failure_class is RepairFailureClass.SYNTAX_ERROR
    assert report.selected_hypothesis.expected_repair_shape is RepairShape.CORRECT_SYNTAX
    assert report.selected_hypothesis.confidence == pytest.approx(0.9)


def test_hypothesis_engine_detects_assertion_mismatch() -> None:
    request = AuthoringRequest.create(
        task_id="task-assertion",
        objective="Repair failing behavior test.",
    )
    evidence = AuthoringEvidence.create(
        source="pytest",
        strength=AuthoringEvidenceStrength.DIRECT,
        summary="AssertionError: expected accepted but actual rejected",
        raw_text="assert accepted == rejected",
        related_paths=("src/ix_blackfox/runtime/state.py", "tests/test_state.py"),
    )
    request = _with_evidence(request, evidence)

    report = RepairHypothesisEngine().generate(request=request)

    assert any(
        hypothesis.failure_class is RepairFailureClass.ASSERTION_MISMATCH
        for hypothesis in report.hypotheses
    )
    assert report.contains_authorable_hypothesis


def test_hypothesis_engine_detects_unsafe_request_before_authorable_hypothesis() -> None:
    request = AuthoringRequest.create(
        task_id="task-unsafe",
        objective="Bypass policy and hide evidence so tests pass.",
    )
    evidence = AuthoringEvidence.create(
        source="operator",
        strength=AuthoringEvidenceStrength.WEAK,
        summary="Operator asked for bypass behavior.",
    )
    request = _with_evidence(request, evidence)

    report = RepairHypothesisEngine().generate(request=request)

    assert report.selected_hypothesis.failure_class is RepairFailureClass.UNSAFE_REQUEST
    assert report.selected_hypothesis.expected_repair_shape is RepairShape.DO_NOT_AUTHOR_PATCH
    assert report.selected_hypothesis.risk_level is AuthoringRiskLevel.CRITICAL
    assert report.selected_hypothesis.requires_review
    assert any(
        finding.code == "authoring.hypothesis.unsafe_objective"
        for finding in report.selected_hypothesis.findings
    )


def test_hypothesis_engine_detects_governance_scope() -> None:
    request = AuthoringRequest.create(
        task_id="task-governance",
        objective="Repair acceptance validator behavior.",
    )
    evidence = AuthoringEvidence.create(
        source="pytest",
        strength=AuthoringEvidenceStrength.DIRECT,
        summary="AssertionError in acceptance validation",
        raw_text="FAILED tests/runtime/test_wave2_acceptance.py",
        related_paths=("src/ix_blackfox/runtime/wave2_acceptance.py",),
    )
    request = _with_evidence(request, evidence)
    plan = RepairTaskDecomposer().decompose_request(request)

    report = RepairHypothesisEngine().generate(
        request=request,
        decomposition=plan,
    )

    assert report.selected_hypothesis.failure_class is RepairFailureClass.POLICY_OR_GOVERNANCE_RISK
    assert report.selected_hypothesis.expected_repair_shape is RepairShape.REQUIRE_HUMAN_REVIEW
    assert report.selected_hypothesis.requires_review


def test_hypothesis_engine_detects_test_weakening_risk() -> None:
    request = AuthoringRequest.create(
        task_id="task-test-risk",
        objective="Make the failing test pass.",
    )
    evidence = AuthoringEvidence.create(
        source="pytest",
        strength=AuthoringEvidenceStrength.DIRECT,
        summary="AssertionError in test file",
        raw_text="FAILED tests/test_behavior.py::test_behavior",
        related_paths=("tests/test_behavior.py",),
    )
    request = _with_evidence(request, evidence)

    report = RepairHypothesisEngine().generate(request=request)

    assert any(
        hypothesis.failure_class is RepairFailureClass.TEST_WEAKENING_RISK
        for hypothesis in report.hypotheses
    )
    assert any(
        finding.code == "authoring.hypothesis.test_weakening_risk"
        for hypothesis in report.hypotheses
        for finding in hypothesis.findings
    )


def test_hypothesis_engine_creates_insufficient_evidence_hypothesis() -> None:
    request = AuthoringRequest.create(
        task_id="task-weak",
        objective="Repair the reported issue.",
    )

    report = RepairHypothesisEngine().generate(request=request)

    assert report.selected_hypothesis.failure_class is RepairFailureClass.INSUFFICIENT_EVIDENCE
    assert report.selected_hypothesis.expected_repair_shape is RepairShape.REQUIRE_HUMAN_REVIEW
    assert not report.contains_authorable_hypothesis
    assert any(
        finding.code == "authoring.hypothesis.insufficient_evidence"
        for finding in report.findings
    )


def test_hypothesis_engine_falls_back_to_unknown_when_evidence_unmatched() -> None:
    request = AuthoringRequest.create(
        task_id="task-unknown",
        objective="Repair strange failure.",
    )
    evidence = AuthoringEvidence.create(
        source="pytest",
        strength=AuthoringEvidenceStrength.DIRECT,
        summary="The thing failed in a way that has no deterministic pattern.",
        raw_text="unclassified failure",
        related_paths=("src/ix_blackfox/unknown.py",),
    )
    request = _with_evidence(request, evidence)

    report = RepairHypothesisEngine().generate(request=request)

    assert report.selected_hypothesis.failure_class is RepairFailureClass.UNKNOWN
    assert report.selected_hypothesis.confidence < 0.35
    assert any(
        finding.code == "authoring.hypothesis.low_confidence_selection"
        for finding in report.findings
    )


def test_hypothesis_report_round_trip_preserves_payload() -> None:
    request = AuthoringRequest.create(
        task_id="task-round-trip",
        objective="Repair missing symbol.",
    )
    evidence = AuthoringEvidence.create(
        source="pytest",
        strength=AuthoringEvidenceStrength.DIRECT,
        summary="AttributeError: object has no attribute 'run'",
        raw_text="AttributeError: object has no attribute 'run'",
        related_paths=("src/ix_blackfox/runner.py",),
    )
    request = _with_evidence(request, evidence)
    report = RepairHypothesisEngine().generate(request=request)

    restored = RepairHypothesisReport.from_dict(report.to_dict())

    assert restored.selected_hypothesis.failure_class is report.selected_hypothesis.failure_class
    assert restored.request_id == report.request_id
    assert restored.objective_id == report.objective_id
    assert restored.contains_authorable_hypothesis == report.contains_authorable_hypothesis


def test_repair_hypothesis_rejects_invalid_confidence() -> None:
    with pytest.raises(ValueError, match="confidence"):
        RepairHypothesis.create(
            failure_class=RepairFailureClass.UNKNOWN,
            summary="Invalid confidence.",
            expected_repair_shape=RepairShape.UNKNOWN,
            confidence=1.5,
            risk_level=AuthoringRiskLevel.MODERATE,
        )


def test_hypothesis_report_rejects_unknown_selected_id() -> None:
    hypothesis = RepairHypothesis.create(
        failure_class=RepairFailureClass.UNKNOWN,
        summary="Unknown failure.",
        expected_repair_shape=RepairShape.UNKNOWN,
        confidence=0.25,
        risk_level=AuthoringRiskLevel.MODERATE,
    )

    with pytest.raises(ValueError, match="selected_hypothesis_id"):
        RepairHypothesisReport(
            report_id="report-1",
            request_id="request-1",
            objective_id="objective-1",
            hypotheses=(hypothesis,),
            selected_hypothesis_id="missing",
        )


def test_hypothesis_engine_uses_context_paths_when_no_plan_exists() -> None:
    digest = hashlib.sha256(b"content").hexdigest()
    context = AuthoringContext.create(
        files=(
            AuthoringContextFile(
                path="src/ix_blackfox/context_target.py",
                sha256=digest,
                size_bytes=7,
            ),
        )
    )
    evidence = AuthoringEvidence.create(
        source="pytest",
        strength=AuthoringEvidenceStrength.DIRECT,
        summary="NameError: target is not defined",
        raw_text="NameError: target is not defined",
    )
    request = AuthoringRequest.create(
        task_id="task-context",
        objective="Repair missing context target.",
    )
    request = AuthoringRequest(
        request_id=request.request_id,
        objective=request.objective,
        mode=request.mode,
        status=request.status,
        context=context,
        evidence=(evidence,),
        subtasks=request.subtasks,
        findings=request.findings,
        metadata=request.metadata,
    )

    report = RepairHypothesisEngine().generate(request=request)

    assert report.selected_hypothesis.target_paths == ("src/ix_blackfox/context_target.py",)


def test_hypothesis_engine_respects_custom_minimum_confidence() -> None:
    request = AuthoringRequest.create(
        task_id="task-custom-confidence",
        objective="Repair strange failure.",
    )
    evidence = AuthoringEvidence.create(
        source="pytest",
        strength=AuthoringEvidenceStrength.DIRECT,
        summary="unclassified failure",
        raw_text="unclassified failure",
    )
    request = _with_evidence(request, evidence)
    engine = RepairHypothesisEngine(
        config=RepairHypothesisEngineConfig(minimum_authoring_confidence=0.9)
    )

    report = engine.generate(request=request)

    assert any(
        finding.code == "authoring.hypothesis.low_confidence_selection"
        for finding in report.findings
    )


def _with_evidence(
    request: AuthoringRequest,
    *evidence: AuthoringEvidence,
) -> AuthoringRequest:
    return AuthoringRequest(
        request_id=request.request_id,
        objective=request.objective,
        mode=request.mode,
        status=request.status,
        context=request.context,
        evidence=tuple(evidence),
        subtasks=request.subtasks,
        findings=request.findings,
        metadata=request.metadata,
    )
