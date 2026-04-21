from __future__ import annotations

import json
from pathlib import Path

from ix_blackfox.kernel import TaskKind
from ix_blackfox.runtime import BlackFoxRuntime, RuntimeRunStatus


def test_runtime_executes_programming_prompt_end_to_end(tmp_path: Path) -> None:
    runtime = BlackFoxRuntime.create_default(root_dir=tmp_path)

    report = runtime.run_prompt(
        prompt="Fix the failing tests, prepare a patch, and run regression checks.",
        kind=TaskKind.PROGRAMMING,
        labels=("code", "tests", "patching"),
    )

    assert report.status == RuntimeRunStatus.PASSED
    assert report.pack_name == "programming"
    assert report.route is not None
    assert report.route.capability_name == "programming"
    assert "programming-plan.json" in report.produced_artifacts
    assert report.report_path is not None

    plan_path = Path(report.artifact_paths["programming-plan.json"])
    payload = json.loads(plan_path.read_text(encoding="utf-8"))
    assert payload["pack_name"] == "programming"
    assert payload["task_id"] == report.task_id

    report_payload = json.loads(Path(report.report_path).read_text(encoding="utf-8"))
    assert report_payload["task_id"] == report.task_id
    assert report_payload["status"] == "passed"


def test_runtime_marks_duplicate_unknown_prompt_for_review(tmp_path: Path) -> None:
    runtime = BlackFoxRuntime.create_default(root_dir=tmp_path)

    first = runtime.run_prompt(
        prompt="Fix the failing tests and patch the repository.",
        labels=("code", "testing"),
    )
    second = runtime.run_prompt(
        prompt="Fix the failing tests and patch the repository.",
        labels=("code", "testing"),
    )

    assert first.task_kind == TaskKind.PROGRAMMING
    assert second.task_kind == TaskKind.PROGRAMMING
    assert second.replay_observation.duplicate_detected is True
    assert second.status == RuntimeRunStatus.NEEDS_REVIEW
    assert second.evaluation_result.status.value == "needs_review"
