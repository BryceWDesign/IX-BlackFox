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
    AuthoringMode,
    AuthoringRequest,
    AuthoringRiskLevel,
    AuthoringSubtask,
    AuthoringSubtaskKind,
)


def test_authoring_request_create_normalizes_core_fields() -> None:
    request = AuthoringRequest.create(
        task_id=" Task A ",
        objective=" Repair failing import test. ",
        mode=AuthoringMode.DETERMINISTIC,
        requested_by=" Runtime Authoring ",
    )

    assert request.task_id == "task-a"
    assert request.objective.summary == "Repair failing import test."
    assert request.objective.requested_by == "runtime-authoring"
    assert request.mode is AuthoringMode.DETERMINISTIC
    assert not request.has_context
    assert not request.has_direct_evidence


def test_context_manifest_computes_digest_and_total_bytes() -> None:
    file_digest = hashlib.sha256(b"content").hexdigest()
    context_file = AuthoringContextFile(
        path="src/ix_blackfox/example.py",
        sha256=file_digest,
        size_bytes=7,
    )

    context = AuthoringContext.create(files=(context_file,))

    assert context.total_bytes == 7
    assert context.paths == ("src/ix_blackfox/example.py",)
    assert context.digest is not None
    assert len(context.digest) == 64


def test_context_manifest_rejects_incorrect_total_bytes() -> None:
    file_digest = hashlib.sha256(b"content").hexdigest()
    context_file = AuthoringContextFile(
        path="src/ix_blackfox/example.py",
        sha256=file_digest,
        size_bytes=7,
    )

    with pytest.raises(ValueError, match="total_bytes"):
        AuthoringContext(
            context_id="context-test",
            files=(context_file,),
            total_bytes=99,
        )


def test_evidence_create_records_raw_digest_and_direct_status() -> None:
    evidence = AuthoringEvidence.create(
        source="pytest",
        strength=AuthoringEvidenceStrength.DIRECT,
        summary="One pytest failure points to the missing symbol.",
        raw_text="NameError: missing_symbol",
        related_paths=("tests/test_example.py",),
    )

    assert evidence.has_direct_evidence
    assert evidence.raw_digest == hashlib.sha256(
        b"NameError: missing_symbol"
    ).hexdigest()
    assert evidence.related_paths == ("tests/test_example.py",)


def test_finding_and_subtask_round_trip_through_dict() -> None:
    finding = AuthoringFinding(
        code=" authoring.missing_context ",
        severity=AuthoringFindingSeverity.WARNING,
        summary=" Context is weak. ",
        path="src/ix_blackfox/example.py",
    )
    subtask = AuthoringSubtask(
        subtask_id=" Inspect Failure ",
        summary="Inspect failing test evidence.",
        kind=AuthoringSubtaskKind.INSPECT,
        risk_level=AuthoringRiskLevel.LOW,
        target_paths=("tests/test_example.py",),
    )

    assert AuthoringFinding.from_dict(finding.to_dict()) == finding
    assert AuthoringSubtask.from_dict(subtask.to_dict()) == subtask
    assert subtask.subtask_id == "inspect-failure"


def test_request_round_trip_preserves_nested_models() -> None:
    evidence = AuthoringEvidence.create(
        source="operator",
        strength=AuthoringEvidenceStrength.WEAK,
        summary="Operator reported a failing test.",
    )
    subtask = AuthoringSubtask(
        subtask_id="inspect",
        summary="Inspect the reported failure.",
        kind=AuthoringSubtaskKind.INSPECT,
    )
    request = AuthoringRequest.create(
        task_id="task-1",
        objective="Repair the reported failure.",
    )
    request = AuthoringRequest(
        request_id=request.request_id,
        objective=request.objective,
        mode=request.mode,
        status=request.status,
        evidence=(evidence,),
        subtasks=(subtask,),
    )

    restored = AuthoringRequest.from_dict(request.to_dict())

    assert restored == request
    assert restored.evidence[0].summary == "Operator reported a failing test."
    assert restored.subtasks[0].kind is AuthoringSubtaskKind.INSPECT


def test_relative_path_validation_rejects_escape_paths() -> None:
    digest = hashlib.sha256(b"content").hexdigest()

    with pytest.raises(ValueError, match="relative"):
        AuthoringContextFile(path="/tmp/example.py", sha256=digest, size_bytes=7)

    with pytest.raises(ValueError, match="traversal"):
        AuthoringContextFile(path="../example.py", sha256=digest, size_bytes=7)
