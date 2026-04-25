from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

from ix_blackfox.tools import (
    GovernedToolGateway,
    ToolApprovalMode,
    ToolArtifactStore,
    ToolCapability,
    ToolFailureKind,
    ToolGatewayError,
    ToolInvocationReceiptLedger,
    ToolInvocationRequest,
    ToolInvocationResult,
    ToolInvocationStatus,
    ToolManifest,
    ToolOutputArtifact,
    ToolPathPolicy,
    ToolPolicyDecision,
    ToolPolicyDocument,
    ToolSideEffect,
    WorkspaceFileReadTool,
)


def test_governed_tool_gateway_allows_read_only_tool_and_records_receipts(
    tmp_path: Path,
) -> None:
    workspace = _make_workspace(tmp_path)
    receipt_ledger = ToolInvocationReceiptLedger()
    tool = WorkspaceFileReadTool(
        workspace_root=workspace,
        path_policy=ToolPathPolicy(
            allowed_roots=("src",),
            blocked_roots=(".git", "secrets"),
        ),
    )
    gateway = GovernedToolGateway.from_policy_document(
        policy_document=ToolPolicyDocument.from_toml_text(
            """
[execution]
allow_file_read = true
allow_file_write = true
allow_process_execution = true
allow_network = false

[approval]
require_for_workspace_write = true
require_for_process_execution = true
require_for_secret_access = true

[paths]
allowed_roots = ["src"]
blocked_roots = [".git", "secrets"]
"""
        ),
        invokers=(tool,),
        receipt_ledger=receipt_ledger,
    )
    request = ToolInvocationRequest.create(
        tool_id="blackfox.workspace.read_file",
        capability=ToolCapability.FILE_READ,
        arguments={"path": "src/example.py"},
        task_id="task-gateway",
        run_id="run-gateway",
    )

    report = gateway.invoke(request)

    assert report.allowed_by_policy is True
    assert report.succeeded is True
    assert report.policy_evaluation.decision is ToolPolicyDecision.ALLOW
    assert report.result.status is ToolInvocationStatus.SUCCEEDED
    assert report.result.output["path"] == "src/example.py"
    assert report.result.output["text"] == "VALUE = 7\n"
    assert report.receipt_chain_verified is True
    assert report.metadata["gateway_decision"] == "executed"

    snapshot = receipt_ledger.snapshot()
    receipts = snapshot.filter_by_invocation(request.invocation_id)

    assert len(receipts) == 4
    assert receipts[0].event_type.value == "policy_evaluated"
    assert receipts[1].event_type.value == "invocation_started"
    assert receipts[2].event_type.value == "invocation_succeeded"
    assert receipts[3].event_type.value == "artifact_emitted"
    assert receipt_ledger.verify_invocation_chain(request.invocation_id) is True

    payload = report.to_dict()

    assert payload["allowed_by_policy"] is True
    assert payload["result"]["status"] == "succeeded"
    assert payload["receipt_chain_verified"] is True


def test_governed_tool_gateway_returns_review_required_without_executing_write_tool() -> None:
    tool = _CountingInvoker(
        manifest=ToolManifest(
            tool_id="blackfox.workspace.apply_patch",
            name="Apply Patch",
            version="0.1.0",
            summary="Apply a patch.",
            capabilities=(ToolCapability.PATCH_APPLY, ToolCapability.FILE_WRITE),
            side_effects=(ToolSideEffect.WRITE_WORKSPACE,),
            approval_mode=ToolApprovalMode.POLICY,
        )
    )
    gateway = GovernedToolGateway.from_policy_document(
        policy_document=ToolPolicyDocument.from_toml_text(
            """
[execution]
allow_file_write = true

[approval]
require_for_workspace_write = true
review_high_risk = true
block_critical_risk = true
"""
        ),
        invokers=(tool,),
    )
    request = ToolInvocationRequest.create(
        tool_id="blackfox.workspace.apply_patch",
        capability=ToolCapability.PATCH_APPLY,
        arguments={"patch": {"patch_id": "patch-demo"}},
    )

    report = gateway.invoke(request)

    assert report.review_required_by_policy is True
    assert report.allowed_by_policy is False
    assert report.result.status is ToolInvocationStatus.REVIEW_REQUIRED
    assert report.result.failure is not None
    assert report.result.failure.kind is ToolFailureKind.APPROVAL_REQUIRED
    assert report.result.output["policy_decision"] == "review_required"
    assert tool.invoke_count == 0
    assert report.receipt_chain_verified is True


def test_governed_tool_gateway_returns_blocked_without_executing_disabled_write_tool() -> None:
    tool = _CountingInvoker(
        manifest=ToolManifest(
            tool_id="blackfox.workspace.apply_patch",
            name="Apply Patch",
            version="0.1.0",
            summary="Apply a patch.",
            capabilities=(ToolCapability.PATCH_APPLY, ToolCapability.FILE_WRITE),
            side_effects=(ToolSideEffect.WRITE_WORKSPACE,),
            approval_mode=ToolApprovalMode.POLICY,
        )
    )
    gateway = GovernedToolGateway.from_policy_document(
        policy_document=ToolPolicyDocument.from_toml_text(
            """
[execution]
allow_file_write = false

[approval]
require_for_workspace_write = true
"""
        ),
        invokers=(tool,),
    )
    request = ToolInvocationRequest.create(
        tool_id="blackfox.workspace.apply_patch",
        capability=ToolCapability.PATCH_APPLY,
        arguments={"patch": {"patch_id": "patch-demo"}},
    )

    report = gateway.invoke(request)

    assert report.blocked_by_policy is True
    assert report.result.status is ToolInvocationStatus.BLOCKED
    assert report.result.failure is not None
    assert report.result.failure.kind is ToolFailureKind.POLICY_BLOCKED
    assert report.result.output["policy_decision"] == "block"
    assert "capability-blocked" in report.result.output["reason_codes"]
    assert tool.invoke_count == 0
    assert report.receipt_chain_verified is True


def test_governed_tool_gateway_blocks_absolute_path_before_tool_execution(
    tmp_path: Path,
) -> None:
    workspace = _make_workspace(tmp_path)
    tool = WorkspaceFileReadTool(workspace_root=workspace)
    gateway = GovernedToolGateway.from_policy_document(
        policy_document=ToolPolicyDocument.from_toml_text(
            """
[execution]
allow_file_read = true
allow_absolute_paths = false
"""
        ),
        invokers=(tool,),
    )
    request = ToolInvocationRequest.create(
        tool_id="blackfox.workspace.read_file",
        capability=ToolCapability.FILE_READ,
        arguments={"path": str(workspace / "src/example.py")},
    )

    report = gateway.invoke(request)

    assert report.blocked_by_policy is True
    assert report.result.status is ToolInvocationStatus.BLOCKED
    assert report.result.failure is not None
    assert report.result.failure.kind is ToolFailureKind.POLICY_BLOCKED
    assert report.policy_evaluation.has_reason("absolute-path-blocked") is True


def test_governed_tool_gateway_evaluate_only_does_not_write_receipts(
    tmp_path: Path,
) -> None:
    workspace = _make_workspace(tmp_path)
    receipt_ledger = ToolInvocationReceiptLedger()
    gateway = GovernedToolGateway.from_policy_document(
        policy_document=ToolPolicyDocument.from_toml_text(
            """
[execution]
allow_file_read = true
"""
        ),
        invokers=(WorkspaceFileReadTool(workspace_root=workspace),),
        receipt_ledger=receipt_ledger,
    )
    request = ToolInvocationRequest.create(
        tool_id="blackfox.workspace.read_file",
        capability=ToolCapability.FILE_READ,
        arguments={"path": "src/example.py"},
    )

    evaluation = gateway.evaluate_only(request)

    assert evaluation.decision is ToolPolicyDecision.ALLOW
    assert receipt_ledger.count() == 0


def test_governed_tool_gateway_raises_for_unknown_tool() -> None:
    gateway = GovernedToolGateway.from_policy_document(
        policy_document=ToolPolicyDocument(),
    )
    request = ToolInvocationRequest.create(
        tool_id="blackfox.workspace.missing",
        capability=ToolCapability.FILE_READ,
    )

    with pytest.raises(ToolGatewayError, match="Unknown tool requested"):
        gateway.invoke(request)


def test_governed_tool_gateway_wraps_invoker_exception_as_failed_result() -> None:
    tool = _ExplodingInvoker(
        manifest=ToolManifest(
            tool_id="blackfox.workspace.read_file",
            name="Exploding Read Tool",
            version="0.1.0",
            summary="Raises at invocation time.",
            capabilities=(ToolCapability.FILE_READ,),
            side_effects=(ToolSideEffect.READ_WORKSPACE,),
        )
    )
    gateway = GovernedToolGateway.from_policy_document(
        policy_document=ToolPolicyDocument(),
        invokers=(tool,),
    )
    request = ToolInvocationRequest.create(
        tool_id=tool.manifest.tool_id,
        capability=ToolCapability.FILE_READ,
    )

    report = gateway.invoke(request)

    assert report.allowed_by_policy is True
    assert report.result.status is ToolInvocationStatus.FAILED
    assert report.result.failure is not None
    assert report.result.failure.kind is ToolFailureKind.EXECUTION_ERROR
    assert "boom" in report.result.failure.message
    assert report.receipt_chain_verified is True


def test_governed_tool_gateway_records_artifacts_from_successful_tool(
    tmp_path: Path,
) -> None:
    artifact_store = ToolArtifactStore(tmp_path / "artifacts")
    artifact = artifact_store.write_json(
        relative_path="results/output.json",
        payload={"ok": True},
    )
    tool = _ArtifactInvoker(
        manifest=ToolManifest(
            tool_id="blackfox.report.emit",
            name="Emit Report",
            version="0.1.0",
            summary="Emit an artifact.",
            capabilities=(ToolCapability.REPORT_GENERATION,),
            side_effects=(ToolSideEffect.NONE,),
        ),
        artifact=artifact,
    )
    receipt_ledger = ToolInvocationReceiptLedger()
    gateway = GovernedToolGateway.from_policy_document(
        policy_document=ToolPolicyDocument(),
        invokers=(tool,),
        receipt_ledger=receipt_ledger,
    )
    request = ToolInvocationRequest.create(
        tool_id=tool.manifest.tool_id,
        capability=ToolCapability.REPORT_GENERATION,
    )

    report = gateway.invoke(request)

    assert report.result.status is ToolInvocationStatus.SUCCEEDED
    assert len(report.result.artifacts) == 1

    receipts = receipt_ledger.snapshot().filter_by_invocation(request.invocation_id)

    assert receipts[-1].event_type.value == "artifact_emitted"
    assert receipts[-1].metadata["artifact_uri"] == "results/output.json" or receipts[-1].metadata["artifact_id"] == artifact.artifact_id
    assert receipt_ledger.verify_invocation_chain(request.invocation_id) is True


@dataclass(slots=True)
class _CountingInvoker:
    manifest: ToolManifest
    invoke_count: int = 0

    def invoke(self, request: ToolInvocationRequest) -> ToolInvocationResult:
        self.invoke_count += 1
        return ToolInvocationResult.succeeded(
            request=request,
            output={"invoked": True},
        )


@dataclass(frozen=True, slots=True)
class _ExplodingInvoker:
    manifest: ToolManifest

    def invoke(self, request: ToolInvocationRequest) -> ToolInvocationResult:
        raise RuntimeError("boom")


@dataclass(frozen=True, slots=True)
class _ArtifactInvoker:
    manifest: ToolManifest
    artifact: ToolOutputArtifact

    def invoke(self, request: ToolInvocationRequest) -> ToolInvocationResult:
        return ToolInvocationResult.succeeded(
            request=request,
            output={"artifact": self.artifact.uri},
            artifacts=(self.artifact,),
        )


def _make_workspace(tmp_path: Path) -> Path:
    workspace = tmp_path / "workspace"
    (workspace / "src").mkdir(parents=True)
    (workspace / "secrets").mkdir(parents=True)
    (workspace / ".blackfox-workspace").write_text("reserved\n", encoding="utf-8")
    (workspace / "src/example.py").write_text("VALUE = 7\n", encoding="utf-8")
    (workspace / "secrets/token.txt").write_text("secret\n", encoding="utf-8")
    return workspace
