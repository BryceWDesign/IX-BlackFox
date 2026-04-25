from __future__ import annotations

import json
import sys
from pathlib import Path

from ix_blackfox.runtime import (
    ControlPlaneCliResult,
    run_control_plane_cli,
)
from ix_blackfox.tools import PatchDiff, PatchFileChange


def test_control_plane_cli_runs_repair_from_patch_json_and_writes_report(
    tmp_path: Path,
) -> None:
    workspace = _make_workspace(tmp_path, failing_test=True)
    patch_path = tmp_path / "patch.json"
    output_path = tmp_path / "cli-result.json"

    patch = PatchDiff.create(
        summary="Repair smoke test through CLI.",
        file_changes=(
            PatchFileChange.modify(
                path="tests/test_smoke.py",
                before_text="def test_smoke() -> None:\n    assert False\n",
                after_text="def test_smoke() -> None:\n    assert True\n",
            ),
        ),
        created_by="blackfox-test",
    )
    patch_path.write_text(
        json.dumps(patch.to_dict(), indent=2, sort_keys=True),
        encoding="utf-8",
    )

    result = run_control_plane_cli(
        (
            "--workspace-root",
            str(workspace),
            "--artifact-root",
            str(tmp_path),
            "--policy",
            str(workspace / "blackfox.policy.toml"),
            "--task-id",
            "task-cli",
            "--run-id",
            "run-cli",
            "--objective",
            "Repair the CLI smoke test.",
            "--patch",
            str(patch_path),
            "--test-command",
            sys.executable,
            "-m",
            "pytest",
            "tests/test_smoke.py",
            "-q",
            "--allowed-executable",
            Path(sys.executable).name,
            "--output-json",
            str(output_path),
        )
    )

    assert isinstance(result, ControlPlaneCliResult)
    assert result.succeeded is True
    assert result.verification_status == "verified"
    assert result.report.run_id == "run-cli"
    assert result.report.task_id == "task-cli"
    assert result.report_output_path == output_path.resolve()
    assert output_path.exists() is True

    payload = json.loads(output_path.read_text(encoding="utf-8"))

    assert payload["succeeded"] is True
    assert payload["verification_status"] == "verified"
    assert payload["report"]["run_id"] == "run-cli"
    assert payload["report"]["run_bundle_manifest"]["artifact_count"] == 6

    bundle_root = tmp_path / "artifacts/runs/run-cli"

    assert (bundle_root / "manifest.json").exists() is True
    assert (bundle_root / "reports/operator-summary.md").exists() is True
    assert (bundle_root / "verification/verification-summary.json").exists() is True


def test_control_plane_cli_exports_run_bundle_zip(tmp_path: Path) -> None:
    workspace = _make_workspace(tmp_path, failing_test=True)
    patch_path = tmp_path / "patch.json"

    patch = PatchDiff.create(
        summary="Repair smoke test and export bundle.",
        file_changes=(
            PatchFileChange.modify(
                path="tests/test_smoke.py",
                before_text="def test_smoke() -> None:\n    assert False\n",
                after_text="def test_smoke() -> None:\n    assert True\n",
            ),
        ),
        created_by="blackfox-test",
    )
    patch_path.write_text(
        json.dumps(patch.to_dict(), indent=2, sort_keys=True),
        encoding="utf-8",
    )

    result = run_control_plane_cli(
        (
            "--workspace-root",
            str(workspace),
            "--artifact-root",
            str(tmp_path),
            "--policy",
            str(workspace / "blackfox.policy.toml"),
            "--task-id",
            "task-cli-export",
            "--run-id",
            "run-cli-export",
            "--objective",
            "Repair and export the CLI smoke test.",
            "--patch",
            str(patch_path),
            "--test-command",
            sys.executable,
            "-m",
            "pytest",
            "tests/test_smoke.py",
            "-q",
            "--allowed-executable",
            Path(sys.executable).name,
            "--export",
            "--export-dir",
            str(tmp_path / "exports"),
            "--export-name",
            "operator-review-pack",
        )
    )

    assert result.succeeded is True
    assert result.export_result is not None
    assert result.export_result.export_path == tmp_path / "exports/operator-review-pack.zip"
    assert result.export_result.export_path.exists() is True
    assert result.export_result.file_count == 7
    assert result.export_result.manifest_digest == result.report.run_bundle_manifest.digest


def test_control_plane_cli_reports_failed_verification_for_bad_patch(
    tmp_path: Path,
) -> None:
    workspace = _make_workspace(tmp_path, failing_test=True)
    patch_path = tmp_path / "bad-patch.json"

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
    patch_path.write_text(
        json.dumps(patch.to_dict(), indent=2, sort_keys=True),
        encoding="utf-8",
    )

    result = run_control_plane_cli(
        (
            "--workspace-root",
            str(workspace),
            "--artifact-root",
            str(tmp_path),
            "--policy",
            str(workspace / "blackfox.policy.toml"),
            "--task-id",
            "task-cli-failed",
            "--run-id",
            "run-cli-failed",
            "--objective",
            "Show failed tests remain unverified.",
            "--patch",
            str(patch_path),
            "--test-command",
            sys.executable,
            "-m",
            "pytest",
            "tests/test_smoke.py",
            "-q",
            "--allowed-executable",
            Path(sys.executable).name,
        )
    )

    assert result.succeeded is False
    assert result.verification_status == "failed"
    assert result.report.programming_repair_report.latest_test_run is not None
    assert result.report.programming_repair_report.latest_test_run.failed == 1


def _make_workspace(tmp_path: Path, *, failing_test: bool) -> Path:
    workspace = tmp_path / "workspace"
    (workspace / "tests").mkdir(parents=True)
    (workspace / "src").mkdir(parents=True)
    (workspace / ".blackfox-workspace").write_text("reserved\n", encoding="utf-8")
    (workspace / "blackfox.policy.toml").write_text(_policy_text(), encoding="utf-8")
    (workspace / "src/__init__.py").write_text("", encoding="utf-8")

    assertion = "False" if failing_test else "True"
    (workspace / "tests/test_smoke.py").write_text(
        "def test_smoke() -> None:\n"
        f"    assert {assertion}\n",
        encoding="utf-8",
    )

    return workspace


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
