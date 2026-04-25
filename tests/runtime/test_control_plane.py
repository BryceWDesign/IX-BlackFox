from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from ix_blackfox.runtime import (
    EngineeringControlPlane,
    EngineeringControlPlaneConfig,
    RepairLoopStatus,
    RunBundleArtifactKind,
    VerificationSummaryStatus,
)
from ix_blackfox.tools import PatchDiff, PatchFileChange, ToolPolicyDocument


def test_engineering_control_plane_runs_programming_repair_and_writes_bundle(
    tmp_path: Path,
) -> None:
    workspace = _make_workspace(tmp_path, failing_test=True)
    policy_path = workspace / "blackfox.policy.toml"
    policy_path.write_text(_policy_text(), encoding="utf-8")

    control_plane = EngineeringControlPlane.from_workspace(
        workspace_root=workspace,
        policy_path=policy_path,
        artifact_root=tmp_path,
        test_command=_pytest_command(),
        allowed_test_executables=(Path(sys.executable).name, "python", "python3", "py"),
        metadata={"suite": "unit"},
    )
    patch = PatchDiff.create(
        summary="Repair controlled smoke test.",
        file_changes=(
            PatchFileChange.modify(
                path="tests/test_smoke.py",
                before_text="def test_smoke() -> None:\n    assert False\n",
                after_text="def test_smoke() -> None:\n    assert True\n",
            ),
        ),
        created_by="blackfox-test",
    )

    report = control_plane.run_programming_repair(
        task_id="task-control-plane",
        run_id="run-control-plane",
        objective="Repair the failing smoke test and capture evidence.",
        candidate_patches=(patch,),
        metadata={"requester": "unit-test"},
    )

    assert report.succeeded is True
    assert report.verification_status == VerificationSummaryStatus.VERIFIED.value
    assert report.programming_repair_report.loop_state.status is RepairLoopStatus.SUCCEEDED
    assert report.programming_repair_report.latest_test_run is not None
    assert report.programming_repair_report.latest_test_run.passed == 1
    assert report.tool_receipt_count >= 6
    assert report.repair_receipt_count == 5
    assert report.run_bundle_manifest.artifact_count == 6
    assert report.run_bundle_manifest_artifact.relative_path == "manifest.json"
    assert report.run_bundle_manifest.metadata["control_plane"] == "engineering"
    assert report.run_bundle_manifest.metadata["suite"] == "unit"
    assert report.run_bundle_manifest.metadata["requester"] == "unit-test"

    bundle_root = tmp_path / "artifacts/runs/run-control-plane"

    assert (bundle_root / "manifest.json").exists() is True
    assert (bundle_root / "reports/programming-repair-report.json").exists() is True
    assert (bundle_root / "reports/operator-summary.md").exists() is True
    assert (bundle_root / "verification/verification-summary.json").exists() is True
    assert (bundle_root / "receipts/tool-receipts.json").exists() is True
    assert (bundle_root / "receipts/repair-receipts.json").exists() is True
    assert (bundle_root / "traces/control-plane-trace.json").exists() is True

    manifest_payload = json.loads((bundle_root / "manifest.json").read_text(encoding="utf-8"))
    verification_payload = json.loads(
        (bundle_root / "verification/verification-summary.json").read_text(
            encoding="utf-8"
        )
    )
    operator_summary = (bundle_root / "reports/operator-summary.md").read_text(
        encoding="utf-8"
    )

    assert manifest_payload["artifact_count"] == 6
    assert verification_payload["status"] == "verified"
    assert "Repair loop reached a test-passing terminal state." in operator_summary

    artifact_kinds = {
        artifact.kind
        for artifact in report.run_bundle_manifest.artifacts
    }

    assert RunBundleArtifactKind.RUN_REPORT in artifact_kinds
    assert RunBundleArtifactKind.OPERATOR_SUMMARY in artifact_kinds
    assert RunBundleArtifactKind.VERIFICATION_SUMMARY in artifact_kinds
    assert RunBundleArtifactKind.TOOL_RECEIPTS in artifact_kinds
    assert RunBundleArtifactKind.REPAIR_RECEIPTS in artifact_kinds
    assert RunBundleArtifactKind.TRACE in artifact_kinds


def test_engineering_control_plane_reports_failed_verification_when_tests_still_fail(
    tmp_path: Path,
) -> None:
    workspace = _make_workspace(tmp_path, failing_test=True)
    patch = PatchDiff.create(
        summary="Patch but keep smoke test failing.",
        file_changes=(
            PatchFileChange.modify(
                path="tests/test_smoke.py",
                before_text="def test_smoke() -> None:\n    assert False\n",
                after_text="def test_smoke() -> None:\n    assert 1 == 2\n",
            ),
        ),
        created_by="blackfox-test",
    )

    control_plane = EngineeringControlPlane(
        config=EngineeringControlPlaneConfig(
            workspace_root=workspace,
            artifact_root=tmp_path,
            policy_document=ToolPolicyDocument.from_toml_text(_policy_text()),
            test_command=_pytest_command(),
            allowed_test_executables=(Path(sys.executable).name, "python", "python3", "py"),
        )
    )

    report = control_plane.run_programming_repair(
        task_id="task-control-plane-failed",
        run_id="run-control-plane-failed",
        objective="Show that failed tests do not verify the objective.",
        candidate_patches=(patch,),
    )

    assert report.succeeded is False
    assert report.verification_status == VerificationSummaryStatus.FAILED.value
    assert report.programming_repair_report.latest_test_run is not None
    assert report.programming_repair_report.latest_test_run.failed == 1
    assert report.verification_summary.error_count >= 2

    bundle_root = tmp_path / "artifacts/runs/run-control-plane-failed"
    verification_payload = json.loads(
        (bundle_root / "verification/verification-summary.json").read_text(
            encoding="utf-8"
        )
    )

    assert verification_payload["status"] == "failed"
    assert "failed or errored" in verification_payload["conclusion"]


def test_engineering_control_plane_requires_reserved_workspace_marker(
    tmp_path: Path,
) -> None:
    workspace = _make_workspace(tmp_path, failing_test=True)
    (workspace / ".blackfox-workspace").unlink()

    control_plane = EngineeringControlPlane(
        config=EngineeringControlPlaneConfig(
            workspace_root=workspace,
            artifact_root=tmp_path,
            policy_document=ToolPolicyDocument.from_toml_text(_policy_text()),
            test_command=_pytest_command(),
            allowed_test_executables=(Path(sys.executable).name, "python", "python3", "py"),
        )
    )

    patch = PatchDiff.create(
        summary="Attempt repair without marker.",
        file_changes=(
            PatchFileChange.modify(
                path="tests/test_smoke.py",
                before_text="def test_smoke() -> None:\n    assert False\n",
                after_text="def test_smoke() -> None:\n    assert True\n",
            ),
        ),
        created_by="blackfox-test",
    )

    with pytest.raises(FileNotFoundError, match="reserved workspace marker"):
        control_plane.run_programming_repair(
            task_id="task-missing-marker",
            run_id="run-missing-marker",
            objective="This should not run without a marker.",
            candidate_patches=(patch,),
        )


def test_engineering_control_plane_report_serializes_to_dict(tmp_path: Path) -> None:
    workspace = _make_workspace(tmp_path, failing_test=True)
    control_plane = EngineeringControlPlane(
        config=EngineeringControlPlaneConfig(
            workspace_root=workspace,
            artifact_root=tmp_path,
            policy_document=ToolPolicyDocument.from_toml_text(_policy_text()),
            test_command=_pytest_command(),
            allowed_test_executables=(Path(sys.executable).name, "python", "python3", "py"),
        )
    )
    patch = PatchDiff.create(
        summary="Repair controlled smoke test.",
        file_changes=(
            PatchFileChange.modify(
                path="tests/test_smoke.py",
                before_text="def test_smoke() -> None:\n    assert False\n",
                after_text="def test_smoke() -> None:\n    assert True\n",
            ),
        ),
        created_by="blackfox-test",
    )

    report = control_plane.run_programming_repair(
        task_id="task-control-plane-dict",
        run_id="run-control-plane-dict",
        objective="Serialize the end-to-end control-plane report.",
        candidate_patches=(patch,),
    )
    payload = report.to_dict()

    assert payload["run_id"] == "run-control-plane-dict"
    assert payload["task_id"] == "task-control-plane-dict"
    assert payload["succeeded"] is True
    assert payload["verification_status"] == "verified"
    assert payload["programming_repair_report"]["succeeded"] is True
    assert payload["operator_summary"]["status"] == "succeeded"
    assert payload["verification_summary"]["status"] == "verified"
    assert payload["run_bundle_manifest"]["artifact_count"] == 6
    assert payload["run_bundle_manifest_artifact"]["relative_path"] == "manifest.json"
    assert payload["tool_receipt_count"] >= 6
    assert payload["repair_receipt_count"] == 5
    assert payload["bundle_root"].endswith("artifacts/runs/run-control-plane-dict")


def _make_workspace(tmp_path: Path, *, failing_test: bool) -> Path:
    workspace = tmp_path / "workspace"
    (workspace / "tests").mkdir(parents=True)
    (workspace / "src").mkdir(parents=True)
    (workspace / ".blackfox-workspace").write_text("reserved\n", encoding="utf-8")
    (workspace / "src/__init__.py").write_text("", encoding="utf-8")

    assertion = "False" if failing_test else "True"
    (workspace / "tests/test_smoke.py").write_text(
        "def test_smoke() -> None:\n"
        f"    assert {assertion}\n",
        encoding="utf-8",
    )

    return workspace


def _pytest_command() -> tuple[str, ...]:
    return (sys.executable, "-m", "pytest", "tests/test_smoke.py", "-q")


def _policy_text() -> str:
    return """
[execution]
allow_file_read = true
allow_file_write = true
allow_process_execution = true
allow_network = false
allow_system_mutation = false
allow_absolute_paths = false
max_repair_attempts = 2
max_tool_timeout_seconds = 120

[approval]
require_for_delete = true
require_for_network = true
require_for_secret_access = true
require_for_workspace_write = true
require_for_process_execution = true
review_high_risk = true
block_critical_risk = true

[paths]
allowed_roots = ["src", "tests", "artifacts"]
blocked_roots = [".git", ".env", ".ssh", "secrets", "credentials", "dist", "build"]
allow_absolute_paths = false
"""
