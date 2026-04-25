from __future__ import annotations

import sys
from pathlib import Path

from ix_blackfox.runtime import (
    EngineeringControlPlane,
    EngineeringControlPlaneConfig,
    Wave2AcceptanceReport,
    Wave2AcceptanceStatus,
    Wave2AcceptanceValidator,
)
from ix_blackfox.tools import PatchDiff, PatchFileChange, ToolPolicyDocument


def test_wave2_acceptance_validator_accepts_verified_control_plane_run(
    tmp_path: Path,
) -> None:
    workspace = _make_workspace(tmp_path, failing_test=True)
    patch = PatchDiff.create(
        summary="Repair smoke test for acceptance.",
        file_changes=(
            PatchFileChange.modify(
                path="tests/test_smoke.py",
                before_text="def test_smoke() -> None:\n    assert False\n",
                after_text="def test_smoke() -> None:\n    assert True\n",
            ),
        ),
        created_by="blackfox-test",
    )
    control_plane = _make_control_plane(
        tmp_path=tmp_path,
        workspace=workspace,
    )

    control_plane_report = control_plane.run_programming_repair(
        task_id="task-acceptance",
        run_id="run-acceptance",
        objective="Repair the smoke test and pass Wave 2 acceptance.",
        candidate_patches=(patch,),
    )
    acceptance = Wave2AcceptanceValidator().validate_control_plane_report(
        control_plane_report,
        check_filesystem=True,
    )

    assert acceptance.status is Wave2AcceptanceStatus.ACCEPTED
    assert acceptance.accepted is True
    assert acceptance.error_count == 0
    assert acceptance.pass_count >= 10
    assert acceptance.has_finding("repair.succeeded") is True
    assert acceptance.has_finding("verification.verified") is True
    assert acceptance.has_finding("tests.latest_passed") is True
    assert acceptance.has_finding("receipts.tool_count_ok") is True
    assert acceptance.has_finding("receipts.repair_count_ok") is True
    assert acceptance.has_finding("bundle.run_report_present") is True
    assert acceptance.has_finding("bundle.operator_summary_present") is True
    assert acceptance.has_finding("bundle.verification_summary_present") is True
    assert acceptance.has_finding("bundle.tool_receipts_present") is True
    assert acceptance.has_finding("bundle.repair_receipts_present") is True
    assert acceptance.has_finding("bundle.trace_present") is True
    assert acceptance.has_finding("bundle.manifest_file_present") is True
    assert acceptance.has_finding("bundle.artifact_file_verified") is True
    assert len(acceptance.digest) == 64

    payload = acceptance.to_dict()

    assert payload["status"] == "accepted"
    assert payload["accepted"] is True
    assert payload["rejected"] is False
    assert payload["error_count"] == 0
    assert payload["metadata"]["verification_status"] == "verified"


def test_wave2_acceptance_validator_rejects_failed_control_plane_run(
    tmp_path: Path,
) -> None:
    workspace = _make_workspace(tmp_path, failing_test=True)
    patch = PatchDiff.create(
        summary="Keep smoke test failing.",
        file_changes=(
            PatchFileChange.modify(
                path="tests/test_smoke.py",
                before_text="def test_smoke() -> None:\n    assert False\n",
                after_text="def test_smoke() -> None:\n    assert 1 == 2\n",
            ),
        ),
        created_by="blackfox-test",
    )
    control_plane = _make_control_plane(
        tmp_path=tmp_path,
        workspace=workspace,
    )

    control_plane_report = control_plane.run_programming_repair(
        task_id="task-acceptance-failed",
        run_id="run-acceptance-failed",
        objective="Show that failing tests reject Wave 2 acceptance.",
        candidate_patches=(patch,),
    )
    acceptance = Wave2AcceptanceValidator().validate_control_plane_report(
        control_plane_report,
        check_filesystem=True,
    )

    assert acceptance.status is Wave2AcceptanceStatus.REJECTED
    assert acceptance.rejected is True
    assert acceptance.error_count >= 3
    assert acceptance.has_finding("repair.not_successful") is True
    assert acceptance.has_finding("verification.not_verified") is True
    assert acceptance.has_finding("tests.latest_not_passing") is True
    assert "rejected the run" in acceptance.conclusion


def test_wave2_acceptance_validator_rejects_manifest_missing_required_artifacts(
    tmp_path: Path,
) -> None:
    workspace = _make_workspace(tmp_path, failing_test=True)
    patch = PatchDiff.create(
        summary="Repair smoke test.",
        file_changes=(
            PatchFileChange.modify(
                path="tests/test_smoke.py",
                before_text="def test_smoke() -> None:\n    assert False\n",
                after_text="def test_smoke() -> None:\n    assert True\n",
            ),
        ),
        created_by="blackfox-test",
    )
    control_plane = _make_control_plane(
        tmp_path=tmp_path,
        workspace=workspace,
    )
    control_plane_report = control_plane.run_programming_repair(
        task_id="task-manifest-only",
        run_id="run-manifest-only",
        objective="Build a bundle to test manifest-only acceptance.",
        candidate_patches=(patch,),
    )

    validator = Wave2AcceptanceValidator(
        required_artifact_kinds=(
            control_plane_report.run_bundle_manifest.artifacts[0].kind,
        )
    )
    manifest_acceptance = validator.validate_manifest(
        run_id=control_plane_report.run_id,
        task_id=control_plane_report.task_id,
        manifest=control_plane_report.run_bundle_manifest,
        check_filesystem=True,
    )

    assert manifest_acceptance.status is Wave2AcceptanceStatus.ACCEPTED
    assert manifest_acceptance.error_count == 0

    strict_acceptance = Wave2AcceptanceValidator(
        required_artifact_kinds=(
            control_plane_report.run_bundle_manifest.artifacts[0].kind,
            control_plane_report.run_bundle_manifest_artifact.kind,
        )
    ).validate_manifest(
        run_id=control_plane_report.run_id,
        task_id=control_plane_report.task_id,
        manifest=control_plane_report.run_bundle_manifest,
        check_filesystem=True,
    )

    assert strict_acceptance.status is Wave2AcceptanceStatus.REJECTED
    assert strict_acceptance.has_finding("bundle.manifest_missing") is True


def test_wave2_acceptance_report_round_trips_serialized_payload(
    tmp_path: Path,
) -> None:
    workspace = _make_workspace(tmp_path, failing_test=True)
    patch = PatchDiff.create(
        summary="Repair smoke test for round trip.",
        file_changes=(
            PatchFileChange.modify(
                path="tests/test_smoke.py",
                before_text="def test_smoke() -> None:\n    assert False\n",
                after_text="def test_smoke() -> None:\n    assert True\n",
            ),
        ),
        created_by="blackfox-test",
    )
    control_plane = _make_control_plane(
        tmp_path=tmp_path,
        workspace=workspace,
    )
    control_plane_report = control_plane.run_programming_repair(
        task_id="task-acceptance-round-trip",
        run_id="run-acceptance-round-trip",
        objective="Round-trip the acceptance report.",
        candidate_patches=(patch,),
    )
    acceptance = Wave2AcceptanceValidator().validate_control_plane_report(
        control_plane_report,
        check_filesystem=True,
    )
    restored = Wave2AcceptanceReport.from_dict(acceptance.to_dict())

    assert restored.report_id == acceptance.report_id
    assert restored.run_id == acceptance.run_id
    assert restored.task_id == acceptance.task_id
    assert restored.status is Wave2AcceptanceStatus.ACCEPTED
    assert restored.conclusion == acceptance.conclusion
    assert restored.finding_count == acceptance.finding_count
    assert restored.error_count == acceptance.error_count
    assert restored.digest == acceptance.digest


def _make_control_plane(
    *,
    tmp_path: Path,
    workspace: Path,
) -> EngineeringControlPlane:
    return EngineeringControlPlane(
        config=EngineeringControlPlaneConfig(
            workspace_root=workspace,
            artifact_root=tmp_path,
            policy_document=ToolPolicyDocument.from_toml_text(_policy_text()),
            test_command=_pytest_command(),
            allowed_test_executables=(
                Path(sys.executable).name,
                "python",
                "python3",
                "py",
            ),
        )
    )


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
