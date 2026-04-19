from __future__ import annotations

from pathlib import Path

import pytest

from ix_blackfox.bus import InMemoryEventBus
from ix_blackfox.config import load_runtime_config
from ix_blackfox.kernel import SharedStateStore, TaskRecord, TaskRequest
from ix_blackfox.packs import BasePack, PackContext, PackExecutionResult


class DemoPack(BasePack):
    @property
    def pack_name(self) -> str:
        return "demo"

    def execute(
        self,
        *,
        task: TaskRecord,
        context: PackContext,
    ) -> PackExecutionResult:
        context.shared_state.put(
            "packs",
            "last_executed",
            self.pack_name,
            source=self.pack_name,
        )
        return PackExecutionResult(
            summary=f"Handled {task.request.task_id}",
            artifacts=(" report.json ", "report.json", ""),
            metrics={"steps": 1, "success": True},
            data={"pack": self.pack_name},
        )


def test_pack_execution_result_normalizes_summary_and_artifacts() -> None:
    result = PackExecutionResult(
        summary="  Completed task.  ",
        artifacts=(" output.txt ", "output.txt", "", "trace.log"),
    )

    assert result.summary == "Completed task."
    assert result.artifacts == ("output.txt", "trace.log")


def test_pack_execution_result_rejects_empty_summary() -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        PackExecutionResult(summary="   ")


def test_base_pack_execution_uses_context(tmp_path: Path) -> None:
    config = load_runtime_config(root_dir=tmp_path, env={})
    context = PackContext(
        config=config,
        bus=InMemoryEventBus(),
        shared_state=SharedStateStore(),
    )
    task = TaskRecord(request=TaskRequest.create(prompt="Inspect repo.")).mark_running()

    pack = DemoPack()
    result = pack.execute(task=task, context=context)

    assert pack.pack_name == "demo"
    assert result.summary.startswith("Handled task-")
    assert result.artifacts == ("report.json",)
    assert result.metrics == {"steps": 1, "success": True}
    assert result.data == {"pack": "demo"}

    entry = context.shared_state.get("packs", "last_executed")
    assert entry is not None
    assert entry.value == "demo"
    assert entry.source == "demo"
