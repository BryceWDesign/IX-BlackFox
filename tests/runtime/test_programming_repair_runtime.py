from __future__ import annotations

import sys
from pathlib import Path

from ix_blackfox.runtime import (
    ProgrammingRepairRuntime,
    RepairLoopConfig,
    RepairLoopStatus,
    RepairLoopTerminalReason,
)
from ix_blackfox.tools import (
    PatchApplyTool,
    PatchDiff,
    PatchFileChange,
    TestRunnerTool,
    ToolArtifactStore,
    ToolInvocationReceiptLedger,
    ToolPathPolicy,
)


def test_programming_repair_runtime_applies_patch_and_stops_when_tests_pass(
    tmp_path: Path,
) -> None:
    workspace = _make_workspace(tmp_path, failing_test=True)
    artifact_store = ToolArtifactStore(tmp_path / "artifacts")
    receipt_ledger = ToolInvocationReceiptLedger()

    runtime = ProgrammingRepairRuntime(
        patch_tool=PatchApplyTool(
            workspace_root=workspace,
            artifact_store=artifact_store,
            receipt_ledger=receipt_ledger,
        ),
        test_runner=TestRunnerTool(
            workspace_root=workspace,
            path_policy=_open_workspace_policy(),
            default_command=_pytest_command(),
            allowed_executables=(Path(sys.executable).name, "python", "python3", "py"),
            timeout_seconds=30.0,
            artifact_store=artifact_store,
            receipt_ledger=receipt_ledger,
        ),
        config=RepairLoopConfig(max_attempts=2),
    )

    patch = PatchDiff.create(
        summary="Repair failing smoke test.",
        file_changes=(
            PatchFileChange.modify(
                path="tests/test_smoke.py",
                before_text="def test_smoke() -> None:\n    assert False\n",
                after_text="def test_smoke() -> None:\n    assert True\n",
            ),
        ),
        created_by="blackfox-test",
    )

    report = runtime.run(
        task_id="task-programming-repair",
        run_id="run-programming-repair",
        objective="Make the governed smoke test pass.",
        candidate_patches=(patch,),
        test_command=_pytest_command(),
    )

    assert report.succeeded is True
    assert report.loop_state.status is RepairLoopStatus.SUCCEEDED
    assert report.loop_state.terminal_reason is RepairLoopTerminalReason.TESTS_PASSED
    assert report.attempts_used == 1
    assert report.latest_test_run is not None
    assert report.latest_test_run.passed == 1
    assert len(report.patch_results) == 1
    assert len(report.test_results) == 1
    assert len(report.parsed_test_runs) == 1

    assert (workspace / "tests/test_smoke.py").read_text(encoding="utf-8") == (
        "def test_smoke() -> None:\n"
        "    assert True\n"
    )

    assert receipt_ledger.count() >= 6
    assert (tmp_path / "artifacts/patches").exists() is True
    assert (tmp_path / "artifacts/test-runs").exists() is True


def test_programming_repair_runtime_uses_second_candidate_after_failed_tests(
    tmp_path: Path,
) -> None:
    workspace = _make_workspace(tmp_path, failing_test=True)
    artifact_store = ToolArtifactStore(tmp_path / "artifacts")
    receipt_ledger = ToolInvocationReceiptLedger()

    runtime = ProgrammingRepairRuntime(
        patch_tool=PatchApplyTool(
            workspace_root=workspace,
            artifact_store=artifact_store,
            receipt_ledger=receipt_ledger,
        ),
        test_runner=TestRunnerTool(
            workspace_root=workspace,
            path_policy=_open_workspace_policy(),
            default_command=_pytest_command(),
            allowed_executables=(Path(sys.executable).name, "python", "python3", "py"),
            timeout_seconds=30.0,
            artifact_store=artifact_store,
            receipt_ledger=receipt_ledger,
        ),
        config=RepairLoopConfig(max_attempts=2),
    )

    first_patch = PatchDiff.create(
        summary="Change failure but keep assertion failing.",
        file_changes=(
            PatchFileChange.modify(
                path="tests/test_smoke.py",
                before_text="def test_smoke() -> None:\n    assert False\n",
                after_text="def test_smoke() -> None:\n    assert 1 == 2\n",
            ),
        ),
        created_by="blackfox-test",
    )
    second_patch = PatchDiff.create(
        summary="Repair assertion correctly.",
        file_changes=(
            PatchFileChange.modify(
                path="tests/test_smoke.py",
                before_text="def test_smoke() -> None:\n    assert 1 == 2\n",
                after_text="def test_smoke() -> None:\n    assert 1 == 1\n",
            ),
        ),
        created_by="blackfox-test",
    )

    report = runtime.run(
        task_id="task-programming-repair",
        run_id="run-programming-repair",
        objective="Use bounded repair attempts until tests pass.",
        candidate_patches=(first_patch, second_patch),
        test_command=_pytest_command(),
    )

    assert report.succeeded is True
    assert report.loop_state.status is RepairLoopStatus.SUCCEEDED
    assert report.loop_state.terminal_reason is RepairLoopTerminalReason.TESTS_PASSED
    assert report.attempts_used == 2
    assert len(report.patch_results) == 2
    assert len(report.test_results) == 2
    assert len(report.parsed_test_runs) == 2
    assert report.parsed_test_runs[0].failed == 1
    assert report.parsed_test_runs[1].passed == 1

    assert (workspace / "tests/test_smoke.py").read_text(encoding="utf-8") == (
        "def test_smoke() -> None:\n"
        "    assert 1 == 1\n"
    )


def test_programming_repair_runtime_reports_patch_block_as_terminal(
    tmp_path: Path,
) -> None:
    workspace = _make_workspace(tmp_path, failing_test=True)
    receipt_ledger = ToolInvocationReceiptLedger()

    runtime = ProgrammingRepairRuntime(
        patch_tool=PatchApplyTool(
            workspace_root=workspace,
            receipt_ledger=receipt_ledger,
        ),
        test_runner=TestRunnerTool(
            workspace_root=workspace,
            path_policy=_open_workspace_policy(),
            default_command=_pytest_command(),
            allowed_executables=(Path(sys.executable).name, "python", "python3", "py"),
            timeout_seconds=30.0,
            receipt_ledger=receipt_ledger,
        ),
        config=RepairLoopConfig(max_attempts=2),
    )

    blocked_patch = PatchDiff.create(
        summary="Attempt to patch a blocked path.",
        file_changes=(
            PatchFileChange.modify(
                path="secrets/token.txt",
                before_text="secret\n",
                after_text="changed\n",
            ),
        ),
        created_by="blackfox-test",
    )

    report = runtime.run(
        task_id="task-programming-repair",
        run_id="run-programming-repair",
        objective="Prove blocked patches terminate safely.",
        candidate_patches=(blocked_patch,),
        test_command=_pytest_command(),
    )

    assert report.succeeded is False
    assert report.loop_state.status is RepairLoopStatus.BLOCKED
    assert report.loop_state.terminal_reason is RepairLoopTerminalReason.PATCH_BLOCKED
    assert report.attempts_used == 1
    assert len(report.patch_results) == 1
    assert len(report.test_results) == 0
    assert report.patch_results[0].status.value == "blocked"


def test_programming_repair_runtime_serializes_operator_report(
    tmp_path: Path,
) -> None:
    workspace = _make_workspace(tmp_path, failing_test=False)

    runtime = ProgrammingRepairRuntime(
        patch_tool=PatchApplyTool(workspace_root=workspace),
        test_runner=TestRunnerTool(
            workspace_root=workspace,
            path_policy=_open_workspace_policy(),
            default_command=_pytest_command(),
            allowed_executables=(Path(sys.executable).name, "python", "python3", "py"),
            timeout_seconds=30.0,
        ),
        config=RepairLoopConfig(max_attempts=1),
    )

    patch = PatchDiff.create(
        summary="Add helper file.",
        file_changes=(
            PatchFileChange.add(
                path="src/helper.py",
                after_text="def helper() -> str:\n    return 'ok'\n",
            ),
        ),
        created_by="blackfox-test",
    )

    report = runtime.run(
        task_id="task-programming-repair",
        run_id="run-programming-repair",
        objective="Verify report serialization.",
        candidate_patches=(patch,),
        test_command=_pytest_command(),
        metadata={"suite": "unit"},
    )
    payload = report.to_dict()

    assert payload["succeeded"] is True
    assert payload["terminal_reason"] == "tests_passed"
    assert payload["attempts_used"] == 1
    assert payload["metadata"]["runtime"] == "programming_repair"
    assert payload["metadata"]["suite"] == "unit"
    assert payload["loop_state"]["status"] == "succeeded"
    assert payload["parsed_test_runs"][0]["passed"] == 1


def _make_workspace(tmp_path: Path, *, failing_test: bool) -> Path:
    workspace = tmp_path / "workspace"
    (workspace / "src").mkdir(parents=True)
    (workspace / "tests").mkdir(parents=True)
    (workspace / "secrets").mkdir(parents=True)
    (workspace / ".blackfox-workspace").write_text("reserved\n", encoding="utf-8")
    (workspace / "secrets/token.txt").write_text("secret\n", encoding="utf-8")

    assertion = "False" if failing_test else "True"
    (workspace / "tests/test_smoke.py").write_text(
        "def test_smoke() -> None:\n"
        f"    assert {assertion}\n",
        encoding="utf-8",
    )

    return workspace


def _pytest_command() -> tuple[str, ...]:
    return (sys.executable, "-m", "pytest", "tests/test_smoke.py", "-q")


def _open_workspace_policy() -> ToolPathPolicy:
    return ToolPathPolicy(
        allowed_roots=(),
        blocked_roots=(
            ".git",
            ".env",
            ".ssh",
            "secrets",
            "credentials",
            "dist",
            "build",
        ),
        allow_absolute_paths=False,
    )
