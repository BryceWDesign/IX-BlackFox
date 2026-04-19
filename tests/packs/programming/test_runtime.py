from __future__ import annotations

from pathlib import Path

from ix_blackfox.bus import EventTopic, InMemoryEventBus
from ix_blackfox.config import load_runtime_config
from ix_blackfox.kernel import SharedStateStore, TaskKind, TaskRecord, TaskRequest
from ix_blackfox.packs import PackContext
from ix_blackfox.packs.programming import ProgrammingPack, build_programming_manifest


def test_programming_manifest_is_wired_for_pack_loading() -> None:
    manifest = build_programming_manifest()

    assert manifest.pack_name == "programming"
    assert manifest.supported_kinds == (TaskKind.PROGRAMMING,)
    assert manifest.entrypoint == "ix_blackfox.packs.programming.runtime:ProgrammingPack"
    assert manifest.is_default is True
    assert manifest.declares_capability("patch planning") is True


def test_programming_pack_executes_and_records_state(tmp_path: Path) -> None:
    config = load_runtime_config(root_dir=tmp_path, env={})
    bus = InMemoryEventBus()
    shared_state = SharedStateStore()
    context = PackContext(
        config=config,
        bus=bus,
        shared_state=shared_state,
    )
    task = TaskRecord(
        request=TaskRequest.create(
            prompt="Fix the failing tests and profile the slow path.",
            kind=TaskKind.PROGRAMMING,
            labels=("code", "tests"),
        )
    ).mark_running()

    result = ProgrammingPack().execute(task=task, context=context)

    assert result.summary.startswith("Programming pack prepared")
    assert result.artifacts == ("programming-plan.json",)
    assert result.metrics["step_count"] == 4
    assert result.metrics["has_test_step"] is True
    assert result.metrics["has_patch_step"] is True
    assert result.data["pack"] == "programming"

    last_pack = shared_state.get("packs", "last_executed")
    last_task = shared_state.get("programming", "last_task_id")
    last_step_count = shared_state.get("programming", "last_plan_step_count")

    assert last_pack is not None
    assert last_pack.value == "programming"
    assert last_task is not None
    assert last_task.value == task.request.task_id
    assert last_step_count is not None
    assert last_step_count.value == 4

    history = bus.history()
    assert len(history) == 1
    assert history[0].topic == EventTopic.PACK
    assert history[0].source == "programming"
    assert history[0].correlation_id == task.request.task_id
    assert history[0].payload["actions"] == (
        "inspect-repository",
        "prepare-patch",
        "run-tests",
        "profile-execution",
    )


def test_programming_pack_adds_analysis_step_when_prompt_is_generic(
    tmp_path: Path,
) -> None:
    config = load_runtime_config(root_dir=tmp_path, env={})
    context = PackContext(
        config=config,
        bus=InMemoryEventBus(),
        shared_state=SharedStateStore(),
    )
    task = TaskRecord(
        request=TaskRequest.create(
            prompt="Look at this repository.",
            kind=TaskKind.PROGRAMMING,
        )
    ).mark_running()

    result = ProgrammingPack().execute(task=task, context=context)

    assert result.metrics["step_count"] == 2
    assert result.data["steps"][1]["action"] == "analyze-code"
