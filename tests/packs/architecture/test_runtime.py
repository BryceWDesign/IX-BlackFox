from __future__ import annotations

from pathlib import Path

from ix_blackfox.bus import EventTopic, InMemoryEventBus
from ix_blackfox.config import load_runtime_config
from ix_blackfox.kernel import SharedStateStore, TaskKind, TaskRecord, TaskRequest
from ix_blackfox.packs import PackContext
from ix_blackfox.packs.architecture import (
    ArchitecturePack,
    build_architecture_manifest,
)


def test_architecture_manifest_is_wired_for_pack_loading() -> None:
    manifest = build_architecture_manifest()

    assert manifest.pack_name == "architecture"
    assert manifest.supported_kinds == (TaskKind.ARCHITECTURE, TaskKind.ANALYSIS)
    assert (
        manifest.entrypoint
        == "ix_blackfox.packs.architecture.runtime:ArchitecturePack"
    )
    assert manifest.is_default is False
    assert manifest.declares_capability("boundary planning") is True


def test_architecture_pack_executes_and_records_state(tmp_path: Path) -> None:
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
            prompt=(
                "Design the API, state, security, and performance architecture "
                "for this runtime."
            ),
            kind=TaskKind.ARCHITECTURE,
            labels=("design", "architecture"),
        )
    ).mark_running()

    result = ArchitecturePack().execute(task=task, context=context)

    assert result.summary.startswith("Architecture pack prepared")
    assert result.artifacts == ("architecture-plan.json",)
    assert result.metrics["decision_count"] == 5
    assert result.metrics["has_boundary_decision"] is True
    assert result.metrics["has_interface_decision"] is True
    assert result.data["pack"] == "architecture"

    last_pack = shared_state.get("packs", "last_executed")
    last_task = shared_state.get("architecture", "last_task_id")
    last_decision_count = shared_state.get("architecture", "last_decision_count")

    assert last_pack is not None
    assert last_pack.value == "architecture"
    assert last_task is not None
    assert last_task.value == task.request.task_id
    assert last_decision_count is not None
    assert last_decision_count.value == 5

    history = bus.history()
    assert len(history) == 1
    assert history[0].topic == EventTopic.PACK
    assert history[0].source == "architecture"
    assert history[0].correlation_id == task.request.task_id
    assert history[0].payload["concerns"] == (
        "system-boundary",
        "interface-surface",
        "state-model",
        "trust-boundary",
        "performance-path",
    )


def test_architecture_pack_adds_module_separation_when_prompt_is_generic(
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
            prompt="Design the runtime.",
            kind=TaskKind.ARCHITECTURE,
        )
    ).mark_running()

    result = ArchitecturePack().execute(task=task, context=context)

    assert result.metrics["decision_count"] == 2
    assert result.data["decisions"][1]["concern"] == "module-separation"
