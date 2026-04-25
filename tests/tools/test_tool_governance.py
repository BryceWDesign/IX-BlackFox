from __future__ import annotations

from pathlib import PurePosixPath

import pytest

from ix_blackfox.tools import (
    ToolApprovalMode,
    ToolCapability,
    ToolFailure,
    ToolFailureKind,
    ToolInvocationReceiptLedger,
    ToolInvocationRequest,
    ToolInvocationResult,
    ToolInvocationStatus,
    ToolManifest,
    ToolManifestRegistry,
    ToolOutputArtifact,
    ToolPathPolicy,
    ToolPolicyDecision,
    ToolPolicyEvaluator,
    ToolPolicyEvaluatorConfig,
    ToolRiskClassifier,
    ToolRiskLevel,
    ToolSideEffect,
)


def test_tool_manifest_registry_registers_and_finds_by_capability() -> None:
    registry = ToolManifestRegistry()
    read_manifest = _make_manifest(
        tool_id="blackfox.workspace.read_file",
        capabilities=(ToolCapability.FILE_READ,),
        side_effects=(ToolSideEffect.READ_WORKSPACE,),
    )
    patch_manifest = _make_manifest(
        tool_id="blackfox.workspace.apply_patch",
        capabilities=(ToolCapability.PATCH_APPLY, ToolCapability.FILE_WRITE),
        side_effects=(ToolSideEffect.WRITE_WORKSPACE,),
        approval_mode=ToolApprovalMode.ALWAYS,
        path_policy=ToolPathPolicy(
            allowed_roots=("src", "tests"),
            blocked_roots=(".git", ".env"),
        ),
    )

    registry.register(patch_manifest)
    registry.register(read_manifest)

    assert registry.contains("blackfox.workspace.read_file") is True
    assert registry.list_tool_ids() == (
        "blackfox.workspace.apply_patch",
        "blackfox.workspace.read_file",
    )
    assert registry.find_by_capability(ToolCapability.PATCH_APPLY) == (patch_manifest,)
    assert registry.get("blackfox.workspace.read_file") is read_manifest

    payload = registry.to_dict()

    assert payload["manifests"][0]["tool_id"] == "blackfox.workspace.apply_patch"
    assert payload["manifests"][0]["path_policy"] == {
        "allowed_roots": ["src", "tests"],
        "blocked_roots": [".git", ".env"],
        "allow_absolute_paths": False,
    }


def test_tool_manifest_rejects_invalid_or_conflicting_declarations() -> None:
    with pytest.raises(ValueError, match="tool_id"):
        _make_manifest(tool_id="Invalid Tool ID!")

    with pytest.raises(ValueError, match="at least one capability"):
        _make_manifest(capabilities=())

    with pytest.raises(ValueError, match="cannot be combined"):
        _make_manifest(
            side_effects=(ToolSideEffect.NONE, ToolSideEffect.WRITE_WORKSPACE),
        )

    with pytest.raises(ValueError, match="positive"):
        _make_manifest(default_timeout_seconds=0)


def test_tool_contracts_round_trip_request_result_failure_and_artifact() -> None:
    request = ToolInvocationRequest.create(
        tool_id="blackfox.workspace.read_file",
        capability=ToolCapability.FILE_READ,
        arguments={"path": "src/ix_blackfox/runtime/orchestrator.py"},
        task_id="task-123",
        run_id="run-456",
        requested_by="runtime",
        labels=("Read", " Workspace ", "read"),
        metadata={"reason": "inspection"},
    )
    artifact = ToolOutputArtifact.create(
        name="inspection.json",
        uri="artifacts/runs/run-456/inspection.json",
        media_type="application/json",
        sha256="a" * 64,
        metadata={"kind": "inspection"},
    )
    result = ToolInvocationResult.succeeded(
        request=request,
        output={"line_count": 100},
        artifacts=(artifact,),
        metadata={"source": "unit-test"},
    )

    restored_request = ToolInvocationRequest.from_dict(request.to_dict())
    restored_result = ToolInvocationResult.from_dict(result.to_dict())

    assert restored_request.tool_id == "blackfox.workspace.read_file"
    assert restored_request.capability is ToolCapability.FILE_READ
    assert restored_request.labels == ("read", "workspace")
    assert restored_request.metadata == {"reason": "inspection"}

    assert restored_result.status is ToolInvocationStatus.SUCCEEDED
    assert restored_result.failure is None
    assert restored_result.output == {"line_count": 100}
    assert restored_result.artifacts[0].sha256 == "a" * 64
    assert restored_result.artifacts[0].media_type == "application/json"

    failure = ToolFailure(
        kind=ToolFailureKind.PATH_VIOLATION,
        message="Path is outside the workspace.",
        retryable=False,
        metadata={"path": "../secrets.env"},
    )
    failed_result = ToolInvocationResult.failed(
        request=request,
        status=ToolInvocationStatus.BLOCKED,
        failure=failure,
    )
    restored_failed_result = ToolInvocationResult.from_dict(failed_result.to_dict())

    assert restored_failed_result.status is ToolInvocationStatus.BLOCKED
    assert restored_failed_result.failure is not None
    assert restored_failed_result.failure.kind is ToolFailureKind.PATH_VIOLATION
    assert restored_failed_result.failure.metadata == {"path": "../secrets.env"}


def test_tool_invocation_result_requires_failure_for_unsuccessful_status() -> None:
    request = ToolInvocationRequest.create(
        tool_id="blackfox.workspace.read_file",
        capability=ToolCapability.FILE_READ,
    )

    with pytest.raises(ValueError, match="must include failure"):
        ToolInvocationResult(
            invocation_id=request.invocation_id,
            tool_id=request.tool_id,
            status=ToolInvocationStatus.BLOCKED,
        )

    with pytest.raises(ValueError, match="must not include failure"):
        ToolInvocationResult(
            invocation_id=request.invocation_id,
            tool_id=request.tool_id,
            status=ToolInvocationStatus.SUCCEEDED,
            failure=ToolFailure(
                kind=ToolFailureKind.EXECUTION_ERROR,
                message="Should not be present.",
            ),
        )


def test_risk_classifier_allows_read_only_workspace_inspection_as_low_risk() -> None:
    manifest = _make_manifest(
        tool_id="blackfox.workspace.read_file",
        capabilities=(ToolCapability.FILE_READ,),
        side_effects=(ToolSideEffect.READ_WORKSPACE,),
    )
    request = ToolInvocationRequest.create(
        tool_id=manifest.tool_id,
        capability=ToolCapability.FILE_READ,
        arguments={"path": "src/ix_blackfox/tools/manifest.py"},
    )

    assessment = ToolRiskClassifier().assess(manifest=manifest, request=request)

    assert assessment.level is ToolRiskLevel.LOW
    assert assessment.score == 10
    assert assessment.approval_recommended is False
    assert assessment.block_recommended is False
    assert assessment.has_signal("workspace-read") is True


def test_policy_evaluator_allows_read_only_workspace_inspection() -> None:
    manifest = _make_manifest(
        tool_id="blackfox.workspace.read_file",
        capabilities=(ToolCapability.FILE_READ,),
        side_effects=(ToolSideEffect.READ_WORKSPACE,),
    )
    request = ToolInvocationRequest.create(
        tool_id=manifest.tool_id,
        capability=ToolCapability.FILE_READ,
        arguments={"path": "src/ix_blackfox/tools/policy.py"},
    )

    evaluation = ToolPolicyEvaluator().evaluate(
        manifest=manifest,
        request=request,
    )

    assert evaluation.decision is ToolPolicyDecision.ALLOW
    assert evaluation.is_allowed is True
    assert evaluation.requires_review is False
    assert evaluation.is_blocked is False
    assert evaluation.reason_codes == ("policy-allow-default",)
    assert evaluation.risk_assessment.level is ToolRiskLevel.LOW


def test_policy_evaluator_requires_review_for_workspace_write_patch_tool() -> None:
    manifest = _make_manifest(
        tool_id="blackfox.workspace.apply_patch",
        capabilities=(ToolCapability.PATCH_APPLY, ToolCapability.FILE_WRITE),
        side_effects=(ToolSideEffect.WRITE_WORKSPACE,),
        approval_mode=ToolApprovalMode.ALWAYS,
        path_policy=ToolPathPolicy(
            allowed_roots=("src", "tests"),
            blocked_roots=(".git", ".env"),
        ),
    )
    request = ToolInvocationRequest.create(
        tool_id=manifest.tool_id,
        capability=ToolCapability.PATCH_APPLY,
        arguments={
            "patch_path": "artifacts/runs/run-001/patch.diff",
            "target_paths": ["src/ix_blackfox/tools/policy.py"],
        },
        run_id="run-001",
    )

    evaluation = ToolPolicyEvaluator().evaluate(
        manifest=manifest,
        request=request,
    )

    assert evaluation.decision is ToolPolicyDecision.REVIEW_REQUIRED
    assert evaluation.requires_review is True
    assert evaluation.is_blocked is False
    assert evaluation.risk_assessment.approval_recommended is True
    assert evaluation.risk_assessment.has_signal("workspace-write") is True
    assert evaluation.risk_assessment.has_signal("patch-apply-capability") is True
    assert evaluation.has_reason("manifest-approval-required") is True
    assert evaluation.has_reason("workspace-write-review-required") is True


def test_policy_evaluator_blocks_unsupported_requested_capability() -> None:
    manifest = _make_manifest(
        tool_id="blackfox.workspace.read_file",
        capabilities=(ToolCapability.FILE_READ,),
        side_effects=(ToolSideEffect.READ_WORKSPACE,),
    )
    request = ToolInvocationRequest.create(
        tool_id=manifest.tool_id,
        capability=ToolCapability.PATCH_APPLY,
        arguments={"path": "src/ix_blackfox/tools/policy.py"},
    )

    evaluation = ToolPolicyEvaluator().evaluate(
        manifest=manifest,
        request=request,
    )

    assert evaluation.decision is ToolPolicyDecision.BLOCK
    assert evaluation.is_blocked is True
    assert evaluation.risk_assessment.block_recommended is True
    assert evaluation.risk_assessment.has_signal("unsupported-capability") is True
    assert evaluation.has_reason("unsupported-capability") is True
    assert evaluation.has_reason("risk-block-recommended") is True


def test_policy_evaluator_blocks_network_access_by_default() -> None:
    manifest = _make_manifest(
        tool_id="blackfox.network.fetch",
        capabilities=(ToolCapability.ARTIFACT_EXPORT,),
        side_effects=(ToolSideEffect.ACCESS_NETWORK,),
    )
    request = ToolInvocationRequest.create(
        tool_id=manifest.tool_id,
        capability=ToolCapability.ARTIFACT_EXPORT,
        arguments={"url": "https://example.invalid/report.json"},
    )

    evaluation = ToolPolicyEvaluator().evaluate(
        manifest=manifest,
        request=request,
    )

    assert evaluation.decision is ToolPolicyDecision.BLOCK
    assert evaluation.is_blocked is True
    assert evaluation.has_reason("network-access-blocked") is True
    assert evaluation.risk_assessment.has_signal("network-access") is True


def test_policy_evaluator_can_be_configured_to_review_network_instead_of_blocking() -> None:
    manifest = _make_manifest(
        tool_id="blackfox.network.fetch",
        capabilities=(ToolCapability.ARTIFACT_EXPORT,),
        side_effects=(ToolSideEffect.ACCESS_NETWORK,),
    )
    request = ToolInvocationRequest.create(
        tool_id=manifest.tool_id,
        capability=ToolCapability.ARTIFACT_EXPORT,
        arguments={"url": "https://example.invalid/report.json"},
    )
    evaluator = ToolPolicyEvaluator(
        config=ToolPolicyEvaluatorConfig(
            allow_network_access=True,
            blocked_side_effects=(),
            review_side_effects=(ToolSideEffect.ACCESS_NETWORK,),
        )
    )

    evaluation = evaluator.evaluate(manifest=manifest, request=request)

    assert evaluation.decision is ToolPolicyDecision.REVIEW_REQUIRED
    assert evaluation.requires_review is True
    assert evaluation.has_reason("network-access-blocked") is False
    assert evaluation.has_reason("side-effect-review-required") is True


def test_policy_evaluator_blocks_path_traversal_references() -> None:
    manifest = _make_manifest(
        tool_id="blackfox.workspace.read_file",
        capabilities=(ToolCapability.FILE_READ,),
        side_effects=(ToolSideEffect.READ_WORKSPACE,),
    )
    request = ToolInvocationRequest.create(
        tool_id=manifest.tool_id,
        capability=ToolCapability.FILE_READ,
        arguments={"path": "../.env"},
    )

    evaluation = ToolPolicyEvaluator().evaluate(
        manifest=manifest,
        request=request,
    )

    assert evaluation.decision is ToolPolicyDecision.BLOCK
    assert evaluation.is_blocked is True
    assert evaluation.risk_assessment.level is ToolRiskLevel.CRITICAL
    assert evaluation.risk_assessment.has_signal("path-traversal-reference") is True
    assert evaluation.has_reason("path-traversal-blocked") is True


def test_policy_evaluator_blocks_absolute_paths_by_default() -> None:
    manifest = _make_manifest(
        tool_id="blackfox.workspace.read_file",
        capabilities=(ToolCapability.FILE_READ,),
        side_effects=(ToolSideEffect.READ_WORKSPACE,),
    )
    request = ToolInvocationRequest.create(
        tool_id=manifest.tool_id,
        capability=ToolCapability.FILE_READ,
        arguments={"path": "/etc/passwd"},
    )

    evaluation = ToolPolicyEvaluator().evaluate(
        manifest=manifest,
        request=request,
    )

    assert evaluation.decision is ToolPolicyDecision.BLOCK
    assert evaluation.has_reason("absolute-path-blocked") is True
    assert evaluation.risk_assessment.has_signal("absolute-path-reference") is True


def test_policy_evaluator_requires_review_for_sensitive_paths_when_not_otherwise_blocked() -> None:
    manifest = _make_manifest(
        tool_id="blackfox.workspace.read_file",
        capabilities=(ToolCapability.FILE_READ,),
        side_effects=(ToolSideEffect.READ_WORKSPACE,),
    )
    request = ToolInvocationRequest.create(
        tool_id=manifest.tool_id,
        capability=ToolCapability.FILE_READ,
        arguments={"path": PurePosixPath("config/local.env").as_posix()},
    )

    evaluation = ToolPolicyEvaluator().evaluate(
        manifest=manifest,
        request=request,
    )

    assert evaluation.decision is ToolPolicyDecision.REVIEW_REQUIRED
    assert evaluation.requires_review is True
    assert evaluation.is_blocked is False
    assert evaluation.risk_assessment.has_signal("sensitive-path-reference") is True
    assert evaluation.has_reason("sensitive-path-review-required") is True


def test_tool_receipt_ledger_records_policy_execution_result_and_artifacts() -> None:
    manifest = _make_manifest(
        tool_id="blackfox.workspace.read_file",
        capabilities=(ToolCapability.FILE_READ,),
        side_effects=(ToolSideEffect.READ_WORKSPACE,),
    )
    request = ToolInvocationRequest.create(
        tool_id=manifest.tool_id,
        capability=ToolCapability.FILE_READ,
        arguments={"path": "src/ix_blackfox/tools/receipts.py"},
        task_id="task-abc",
        run_id="run-abc",
    )
    evaluation = ToolPolicyEvaluator().evaluate(
        manifest=manifest,
        request=request,
    )
    result = ToolInvocationResult.succeeded(
        request=request,
        output={"bytes_read": 2048},
        artifacts=(
            ToolOutputArtifact.create(
                name="read-file-result.json",
                uri="artifacts/runs/run-abc/read-file-result.json",
                media_type="application/json",
            ),
        ),
    )

    ledger = ToolInvocationReceiptLedger()
    policy_receipt = ledger.record_policy_evaluation(
        evaluation=evaluation,
        request=request,
    )
    start_receipt = ledger.record_invocation_started(request=request)
    result_receipt = ledger.record_invocation_result(
        result=result,
        request=request,
    )
    artifact_receipt = ledger.record_artifact_emitted(
        result=result,
        artifact_name="read-file-result.json",
        artifact_uri="artifacts/runs/run-abc/read-file-result.json",
    )

    snapshot = ledger.snapshot()

    assert ledger.count() == 4
    assert ledger.verify_invocation_chain(request.invocation_id) is True
    assert snapshot.latest_for_invocation(request.invocation_id) == artifact_receipt

    assert policy_receipt.previous_receipt_id is None
    assert policy_receipt.previous_chain_digest is None
    assert policy_receipt.policy_decision is ToolPolicyDecision.ALLOW
    assert policy_receipt.risk_level is ToolRiskLevel.LOW

    assert start_receipt.previous_receipt_id == policy_receipt.receipt_id
    assert start_receipt.previous_chain_digest == policy_receipt.chain_digest

    assert result_receipt.previous_receipt_id == start_receipt.receipt_id
    assert result_receipt.invocation_status is ToolInvocationStatus.SUCCEEDED
    assert result_receipt.artifact_count == 1
    assert result_receipt.metadata["output_keys"] == ["bytes_read"]

    assert artifact_receipt.previous_receipt_id == result_receipt.receipt_id
    assert artifact_receipt.artifact_count == 1
    assert artifact_receipt.metadata["artifact_name"] == "read-file-result.json"

    assert len(snapshot.filter_by_invocation(request.invocation_id)) == 4
    assert len(snapshot.filter_by_tool(manifest.tool_id)) == 4
    assert len(snapshot.filter_by_task("task-abc")) == 3
    assert len(snapshot.filter_by_run("run-abc")) == 3


def test_tool_receipt_ledger_records_blocked_policy_decision_without_execution() -> None:
    manifest = _make_manifest(
        tool_id="blackfox.network.fetch",
        capabilities=(ToolCapability.ARTIFACT_EXPORT,),
        side_effects=(ToolSideEffect.ACCESS_NETWORK,),
    )
    request = ToolInvocationRequest.create(
        tool_id=manifest.tool_id,
        capability=ToolCapability.ARTIFACT_EXPORT,
        arguments={"url": "https://example.invalid/bundle.json"},
        run_id="run-blocked",
    )
    evaluation = ToolPolicyEvaluator().evaluate(
        manifest=manifest,
        request=request,
    )

    ledger = ToolInvocationReceiptLedger()
    receipt = ledger.record_policy_evaluation(
        evaluation=evaluation,
        request=request,
    )

    assert evaluation.decision is ToolPolicyDecision.BLOCK
    assert receipt.policy_decision is ToolPolicyDecision.BLOCK
    assert receipt.event_type.value == "invocation_blocked"
    assert ledger.verify_invocation_chain(request.invocation_id) is True
    assert ledger.snapshot().latest_for_invocation(request.invocation_id) == receipt


def _make_manifest(
    *,
    tool_id: str = "blackfox.workspace.read_file",
    name: str = "Workspace Read File",
    version: str = "0.1.0",
    summary: str = "Read one file from a governed workspace.",
    capabilities: tuple[ToolCapability, ...] = (ToolCapability.FILE_READ,),
    side_effects: tuple[ToolSideEffect, ...] = (ToolSideEffect.READ_WORKSPACE,),
    approval_mode: ToolApprovalMode = ToolApprovalMode.POLICY,
    default_timeout_seconds: float | None = 10.0,
    path_policy: ToolPathPolicy | None = None,
) -> ToolManifest:
    return ToolManifest(
        tool_id=tool_id,
        name=name,
        version=version,
        summary=summary,
        capabilities=capabilities,
        side_effects=side_effects,
        approval_mode=approval_mode,
        input_schema={"type": "object"},
        output_schema={"type": "object"},
        default_timeout_seconds=default_timeout_seconds,
        path_policy=path_policy,
        tags=("governed", "tool"),
        metadata={"owner": "blackfox"},
    )
