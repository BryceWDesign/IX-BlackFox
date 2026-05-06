from __future__ import annotations

from pathlib import Path

import pytest

from ix_blackfox.tools import (
    ToolCapability,
    ToolPathPolicy,
    ToolPolicyDecision,
    ToolPolicyDocument,
    ToolPolicyDocumentError,
    ToolPolicyEvaluator,
    ToolSideEffect,
)
from ix_blackfox.tools.contracts import ToolInvocationRequest
from ix_blackfox.tools.manifest import (
    ToolApprovalMode,
    ToolManifest,
)


def test_policy_document_parses_default_governed_policy_text() -> None:
    document = ToolPolicyDocument.from_toml_text(
        """
[execution]
allow_file_read = true
allow_file_write = true
allow_process_execution = true
allow_network = false
allow_system_mutation = false
allow_absolute_paths = false
max_repair_attempts = 3
max_tool_timeout_seconds = 900

[approval]
require_for_delete = true
require_for_network = true
require_for_secret_access = true
require_for_workspace_write = true
require_for_process_execution = true
review_high_risk = true
block_critical_risk = true

[paths]
allowed_roots = ["src", "tests", "docs", "artifacts"]
blocked_roots = [".git", ".env", "secrets", "credentials"]
allow_absolute_paths = false

[metadata]
policy_name = "test policy"
policy_version = "0.1.0"
"""
    )

    assert document.execution.allow_file_read is True
    assert document.execution.allow_file_write is True
    assert document.execution.allow_process_execution is True
    assert document.execution.allow_network is False
    assert document.execution.allow_system_mutation is False
    assert document.execution.allow_absolute_paths is False
    assert document.execution.max_repair_attempts == 3
    assert document.execution.max_tool_timeout_seconds == 900.0

    assert document.approval.require_for_network is True
    assert document.approval.require_for_secret_access is True
    assert document.approval.require_for_workspace_write is True
    assert document.approval.require_for_process_execution is True
    assert document.approval.review_high_risk is True
    assert document.approval.block_critical_risk is True

    assert document.paths.allowed_roots == ("src", "tests", "docs", "artifacts")
    assert document.paths.blocked_roots == (
        ".git",
        ".env",
        "secrets",
        "credentials",
    )
    assert document.paths.allow_absolute_paths is False
    assert document.metadata == {
        "policy_name": "test policy",
        "policy_version": "0.1.0",
    }


def test_policy_document_loads_from_path_and_records_source(tmp_path: Path) -> None:
    policy_path = tmp_path / "blackfox.policy.toml"
    policy_path.write_text(
        """
[execution]
max_repair_attempts = 2

[paths]
allowed_roots = ["src", "tests"]
blocked_roots = [".git", "secrets"]
""",
        encoding="utf-8",
    )

    document = ToolPolicyDocument.from_path(policy_path)

    assert document.source_path == policy_path.resolve()
    assert document.execution.max_repair_attempts == 2
    assert document.paths.allowed_roots == ("src", "tests")
    assert document.paths.blocked_roots == (".git", "secrets")


def test_policy_document_converts_to_tool_evaluator_config() -> None:
    document = ToolPolicyDocument.from_toml_text(
        """
[execution]
allow_file_read = true
allow_file_write = false
allow_process_execution = false
allow_network = false
allow_system_mutation = false
allow_absolute_paths = false
max_repair_attempts = 2
max_tool_timeout_seconds = 120

[approval]
require_for_secret_access = true
require_for_workspace_write = true
require_for_process_execution = true
review_high_risk = true
block_critical_risk = true

[paths]
allowed_roots = ["src", "tests"]
blocked_roots = [".git", "secrets"]
"""
    )

    evaluator_config = document.to_tool_policy_evaluator_config()
    repair_config = document.to_repair_loop_config()
    path_policy = document.to_tool_path_policy()

    assert evaluator_config.allow_network_access is False
    assert evaluator_config.allow_system_mutation is False
    assert evaluator_config.allow_absolute_paths is False
    assert evaluator_config.review_workspace_writes is True
    assert evaluator_config.review_process_execution is True
    assert evaluator_config.review_sensitive_paths is True
    assert evaluator_config.block_on_critical_risk is True
    assert evaluator_config.review_high_risk is True

    assert ToolCapability.FILE_WRITE in evaluator_config.blocked_capabilities
    assert ToolCapability.PATCH_APPLY in evaluator_config.blocked_capabilities
    assert ToolCapability.COMMAND_EXECUTION in evaluator_config.blocked_capabilities
    assert ToolCapability.TEST_EXECUTION in evaluator_config.blocked_capabilities

    assert ToolSideEffect.WRITE_WORKSPACE in evaluator_config.blocked_side_effects
    assert ToolSideEffect.RUN_PROCESS in evaluator_config.blocked_side_effects

    assert repair_config.max_attempts == 2
    assert isinstance(path_policy, ToolPathPolicy)
    assert path_policy.allowed_roots == ("src", "tests")
    assert path_policy.blocked_roots == (".git", "secrets")


def test_policy_document_drives_evaluator_to_block_disabled_file_write() -> None:
    document = ToolPolicyDocument.from_toml_text(
        """
[execution]
allow_file_write = false

[approval]
require_for_workspace_write = true

[paths]
allowed_roots = ["src"]
blocked_roots = [".git"]
"""
    )
    manifest = _patch_manifest()
    request = ToolInvocationRequest.create(
        tool_id=manifest.tool_id,
        capability=ToolCapability.PATCH_APPLY,
        arguments={"patch": {"patch_id": "patch-test"}},
    )

    evaluation = ToolPolicyEvaluator(
        config=document.to_tool_policy_evaluator_config()
    ).evaluate(
        manifest=manifest,
        request=request,
    )

    assert evaluation.decision is ToolPolicyDecision.BLOCK
    assert evaluation.has_reason("capability-blocked") is True
    assert evaluation.has_reason("side-effect-blocked") is True


def test_policy_document_drives_evaluator_to_review_workspace_write_when_allowed() -> None:
    document = ToolPolicyDocument.from_toml_text(
        """
[execution]
allow_file_write = true

[approval]
require_for_workspace_write = true

[paths]
allowed_roots = ["src"]
blocked_roots = [".git"]
"""
    )
    manifest = _patch_manifest()
    request = ToolInvocationRequest.create(
        tool_id=manifest.tool_id,
        capability=ToolCapability.PATCH_APPLY,
        arguments={"patch": {"patch_id": "patch-test"}},
    )

    evaluation = ToolPolicyEvaluator(
        config=document.to_tool_policy_evaluator_config()
    ).evaluate(
        manifest=manifest,
        request=request,
    )

    assert evaluation.decision is ToolPolicyDecision.REVIEW_REQUIRED
    assert evaluation.has_reason("capability-blocked") is False
    assert evaluation.has_reason("side-effect-blocked") is False
    assert evaluation.has_reason("workspace-write-review-required") is True


def test_policy_document_rejects_unknown_sections_and_keys() -> None:
    with pytest.raises(ToolPolicyDocumentError, match="Unknown key"):
        ToolPolicyDocument.from_toml_text(
            """
[execution]
allow_network = false

[unknown]
enabled = true
"""
        )

    with pytest.raises(ToolPolicyDocumentError, match="execution"):
        ToolPolicyDocument.from_toml_text(
            """
[execution]
fake_key = true
"""
        )


def test_policy_document_rejects_unsafe_path_roots() -> None:
    with pytest.raises(ToolPolicyDocumentError, match="relative paths"):
        ToolPolicyDocument.from_toml_text(
            """
[paths]
allowed_roots = ["/etc"]
"""
        )

    with pytest.raises(ToolPolicyDocumentError, match="traversal"):
        ToolPolicyDocument.from_toml_text(
            """
[paths]
blocked_roots = ["../secrets"]
"""
        )


def test_policy_document_rejects_wrong_types_and_bad_limits() -> None:
    with pytest.raises(ToolPolicyDocumentError, match="must be a boolean"):
        ToolPolicyDocument.from_toml_text(
            """
[execution]
allow_network = "false"
"""
        )

    with pytest.raises(ToolPolicyDocumentError, match="must not exceed 10"):
        ToolPolicyDocument.from_toml_text(
            """
[execution]
max_repair_attempts = 99
"""
        )

    with pytest.raises(ToolPolicyDocumentError, match="must not exceed 900"):
        ToolPolicyDocument.from_toml_text(
            """
[execution]
max_tool_timeout_seconds = 901
"""
        )


def test_policy_document_to_dict_is_stable() -> None:
    document = ToolPolicyDocument.from_toml_text(
        """
[execution]
allow_network = false
max_repair_attempts = 4

[approval]
review_high_risk = true

[paths]
allowed_roots = ["src"]
blocked_roots = [".git"]
"""
    )

    payload = document.to_dict()

    assert payload["execution"]["allow_network"] is False
    assert payload["execution"]["max_repair_attempts"] == 4
    assert payload["approval"]["review_high_risk"] is True
    assert payload["paths"]["allowed_roots"] == ["src"]
    assert payload["paths"]["blocked_roots"] == [".git"]
    assert payload["source_path"] is None


def _patch_manifest() -> ToolManifest:
    return ToolManifest(
        tool_id="blackfox.workspace.apply_patch",
        name="Workspace Apply Patch",
        version="0.1.0",
        summary="Apply a governed patch.",
        capabilities=(ToolCapability.PATCH_APPLY, ToolCapability.FILE_WRITE),
        side_effects=(ToolSideEffect.WRITE_WORKSPACE,),
        approval_mode=ToolApprovalMode.ALWAYS,
        input_schema={"type": "object"},
        output_schema={"type": "object"},
        default_timeout_seconds=30.0,
    )
