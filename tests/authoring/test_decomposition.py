from __future__ import annotations

import hashlib

import pytest

from ix_blackfox.authoring import (
    AuthoringContext,
    AuthoringContextFile,
    AuthoringDecompositionError,
    AuthoringEvidence,
    AuthoringEvidenceStrength,
    AuthoringFinding,
    AuthoringFindingSeverity,
    AuthoringRequest,
    AuthoringRiskLevel,
    AuthoringStatus,
    AuthoringSubtaskKind,
    DecompositionSignal,
    DecompositionSignalKind,
    RepairDecompositionPlan,
    RepairTaskDecomposer,
)


def test_decomposer_creates_inspect_modify_test_subtasks() -> None:
    request = AuthoringRequest.create(
        task_id="task-1",
        objective="Repair the failing parser test.",
    )
    evidence = AuthoringEvidence.create(
        source="pytest",
        strength=AuthoringEvidenceStrength.DIRECT,
        summary="Pytest failed in tests/test_parser.py.",
        raw_text="FAILED tests/test_parser.py::test_parse",
        related_paths=("tests/test_parser.py", "src/ix_blackfox/parser.py"),
    )
    request = _with_evidence(request, evidence)

    plan = RepairTaskDecomposer().decompose_request(request)

    assert tuple(subtask.kind for subtask in plan.subtasks[:3]) == (
        AuthoringSubtaskKind.INSPECT,
        AuthoringSubtaskKind.MODIFY,
        AuthoringSubtaskKind.TEST,
    )
    assert plan.target_paths == ("src/ix_blackfox/parser.py", "tests/test_parser.py")
    assert plan.risk_level is AuthoringRiskLevel.MODERATE
    assert plan.requires_review


def test_decomposer_uses_context_paths_when_evidence_has_no_paths() -> None:
    digest = hashlib.sha256(b"content").hexdigest()
    context = AuthoringContext.create(
        files=(
            AuthoringContextFile(
                path="src/ix_blackfox/example.py",
                sha256=digest,
                size_bytes=7,
            ),
        )
    )
    evidence = AuthoringEvidence.create(
        source="operator",
        strength=AuthoringEvidenceStrength.WEAK,
        summary="Operator reported behavior mismatch.",
    )
    request = AuthoringRequest.create(
        task_id="task-2",
        objective="Repair behavior mismatch.",
    )
    request = _with_context_and_evidence(request, context, evidence)

    plan = RepairTaskDecomposer().decompose_request(request)

    assert plan.target_paths == ("src/ix_blackfox/example.py",)
    assert any(
        signal.kind is DecompositionSignalKind.CONTEXT_PATH
        for signal in plan.signals
    )


def test_decomposer_marks_no_evidence_for_review() -> None:
    request = AuthoringRequest.create(
        task_id="task-3",
        objective="Repair the behavior.",
    )

    plan = RepairTaskDecomposer().decompose_request(request)

    assert plan.risk_level is AuthoringRiskLevel.MODERATE
    assert plan.requires_review
    assert any(
        finding.code == "authoring.decomposition.no_evidence"
        for finding in plan.findings
    )
    assert any(
        subtask.kind is AuthoringSubtaskKind.REVIEW
        for subtask in plan.subtasks
    )


def test_decomposer_marks_governance_paths_high_risk() -> None:
    evidence = AuthoringEvidence.create(
        source="pytest",
        strength=AuthoringEvidenceStrength.DIRECT,
        summary="Acceptance validator test failed.",
        raw_text="FAILED tests/runtime/test_acceptance.py",
        related_paths=("src/ix_blackfox/runtime/wave2_acceptance.py",),
    )
    request = AuthoringRequest.create(
        task_id="task-4",
        objective="Repair acceptance validation failure.",
    )
    request = _with_evidence(request, evidence)

    plan = RepairTaskDecomposer().decompose_request(request)

    assert plan.risk_level is AuthoringRiskLevel.HIGH
    assert plan.requires_review
    assert any(
        finding.code == "authoring.decomposition.governance_path_targeted"
        for finding in plan.findings
    )


def test_decomposer_marks_bypass_or_secret_objective_critical() -> None:
    request = AuthoringRequest.create(
        task_id="task-5",
        objective="Bypass policy and read secret token.",
    )

    plan = RepairTaskDecomposer().decompose_request(request)

    assert plan.risk_level is AuthoringRiskLevel.CRITICAL
    assert plan.requires_review
    assert any(
        signal.kind is DecompositionSignalKind.RISK_HINT
        for signal in plan.signals
    )


def test_decomposition_plan_applies_to_request_immutably() -> None:
    request = AuthoringRequest.create(
        task_id="task-6",
        objective="Repair failing test.",
    )
    plan = RepairTaskDecomposer().decompose_request(request)

    updated = plan.apply_to_request(request)

    assert request.status is not AuthoringStatus.DECOMPOSED
    assert updated.status is AuthoringStatus.DECOMPOSED
    assert updated.subtasks == plan.subtasks
    assert updated.metadata["decomposition_plan_id"] == plan.plan_id


def test_decomposition_plan_rejects_apply_to_different_request() -> None:
    request = AuthoringRequest.create(
        task_id="task-7",
        objective="Repair failing test.",
    )
    other_request = AuthoringRequest.create(
        task_id="task-8",
        objective="Repair other failing test.",
    )
    plan = RepairTaskDecomposer().decompose_request(request)

    with pytest.raises(AuthoringDecompositionError, match="different request"):
        plan.apply_to_request(other_request)


def test_decomposition_plan_round_trip_preserves_payload() -> None:
    request = AuthoringRequest.create(
        task_id="task-9",
        objective="Repair failing parser test.",
    )
    evidence = AuthoringEvidence.create(
        source="pytest",
        strength=AuthoringEvidenceStrength.DIRECT,
        summary="Pytest failed in parser.",
        raw_text="FAILED tests/test_parser.py::test_parse",
        related_paths=("src/ix_blackfox/parser.py",),
    )
    request = _with_evidence(request, evidence)
    plan = RepairTaskDecomposer().decompose_request(request)

    restored = RepairDecompositionPlan.from_dict(plan.to_dict())

    assert restored.objective_summary == plan.objective_summary
    assert restored.target_paths == plan.target_paths
    assert restored.subtasks[0].kind is AuthoringSubtaskKind.INSPECT
    assert restored.signals[0].kind in set(DecompositionSignalKind)


def test_decomposition_signal_round_trip() -> None:
    signal = DecompositionSignal.create(
        kind=DecompositionSignalKind.RELATED_PATH,
        summary="Evidence references path.",
        path="src/ix_blackfox/example.py",
        weight=2,
        metadata={"source": "test"},
    )

    restored = DecompositionSignal.from_dict(signal.to_dict())

    assert restored == signal


def test_decomposer_prefers_source_paths_before_test_paths() -> None:
    evidence = AuthoringEvidence.create(
        source="pytest",
        strength=AuthoringEvidenceStrength.DIRECT,
        summary="Pytest failed in test and source context is known.",
        raw_text="FAILED tests/test_service.py::test_service",
        related_paths=("tests/test_service.py", "src/ix_blackfox/service.py"),
    )
    request = AuthoringRequest.create(
        task_id="task-10",
        objective="Repair service failure.",
    )
    request = _with_evidence(request, evidence)

    plan = RepairTaskDecomposer().decompose_request(request)

    assert plan.target_paths[0] == "src/ix_blackfox/service.py"


def test_decomposer_uses_finding_paths_as_failure_targets() -> None:
    finding = AuthoringFinding(
        code="pytest.module_not_found",
        severity=AuthoringFindingSeverity.ERROR,
        summary="Missing module import.",
        path="src/ix_blackfox/missing.py",
    )
    evidence = AuthoringEvidence.create(
        source="pytest",
        strength=AuthoringEvidenceStrength.DIRECT,
        summary="Import failure.",
        raw_text="ModuleNotFoundError",
        findings=(finding,),
    )
    request = AuthoringRequest.create(
        task_id="task-11",
        objective="Repair missing import.",
    )
    request = _with_evidence(request, evidence)

    plan = RepairTaskDecomposer().decompose_request(request)

    assert plan.target_paths == ("src/ix_blackfox/missing.py",)
    assert any(
        signal.kind is DecompositionSignalKind.FAILURE_TARGET
        for signal in plan.signals
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


def _with_context_and_evidence(
    request: AuthoringRequest,
    context: AuthoringContext,
    *evidence: AuthoringEvidence,
) -> AuthoringRequest:
    return AuthoringRequest(
        request_id=request.request_id,
        objective=request.objective,
        mode=request.mode,
        status=request.status,
        context=context,
        evidence=tuple(evidence),
        subtasks=request.subtasks,
        findings=request.findings,
        metadata=request.metadata,
    )
