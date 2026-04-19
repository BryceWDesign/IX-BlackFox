from __future__ import annotations

from pathlib import Path

import pytest

from ix_blackfox.config import load_runtime_config
from ix_blackfox.forge import (
    ForgeCodeAnalyzer,
    ForgeFileGraphScanner,
    ForgePatchPlanner,
    ForgeWorkspaceManager,
    PatchOperation,
    PatchOperationType,
    PatchPriority,
)


def test_patch_operation_normalizes_fields() -> None:
    operation = PatchOperation(
        operation_type=PatchOperationType.UPDATE,
        relative_path=" src\\app.py ",
        priority=PatchPriority.HIGH,
        summary="  Repair broken module.  ",
        rationale="  Syntax error at line 1.  ",
    )

    assert operation.relative_path == "src/app.py"
    assert operation.summary == "Repair broken module."
    assert operation.rationale == "Syntax error at line 1."


def test_patch_planner_build_plan_deduplicates_operations() -> None:
    planner = ForgePatchPlanner()
    operation = PatchOperation(
        operation_type=PatchOperationType.CREATE,
        relative_path="input/tests/test_app.py",
        priority=PatchPriority.NORMAL,
        summary="Create matching test module.",
        rationale="Missing test stub.",
    )

    plan = planner.build_plan(
        summary="  Initial plan.  ",
        operations=(operation, operation),
    )

    assert plan.plan_id.startswith("plan-")
    assert plan.summary == "Initial plan."
    assert plan.operation_count() == 1
    assert plan.filter_by_priority(PatchPriority.NORMAL) == (operation,)


def test_patch_planner_suggests_repairs_docstrings_and_tests(
    tmp_path: Path,
) -> None:
    config = load_runtime_config(root_dir=tmp_path, env={})
    manager = ForgeWorkspaceManager(config)
    workspace = manager.reserve(prefix="plan")

    manager.materialize_file(
        workspace=workspace,
        relative_path="input/src/tool.py",
        content="""def run() -> str:
    return "ok"
""",
    )
    manager.materialize_file(
        workspace=workspace,
        relative_path="input/src/broken.py",
        content="def broken(:\n    pass\n",
    )
    manager.materialize_file(
        workspace=workspace,
        relative_path="input/src/already_tested.py",
        content='''"""Tested module."""

def ping() -> str:
    return "ok"
''',
    )
    manager.materialize_file(
        workspace=workspace,
        relative_path="input/tests/test_already_tested.py",
        content="def test_ping() -> None:\n    assert True\n",
    )

    graph = ForgeFileGraphScanner().scan(workspace)
    analysis = ForgeCodeAnalyzer().analyze_graph(graph)
    plan = ForgePatchPlanner().suggest_from_analysis(analysis=analysis, graph=graph)

    assert plan.summary == "Initial forge patch plan generated from static analysis."
    assert plan.operation_count() == 3

    broken_ops = plan.filter_by_path("input/src/broken.py")
    tool_ops = plan.filter_by_path("input/src/tool.py")
    tool_test_ops = plan.filter_by_path("input/tests/test_tool.py")
    existing_test_ops = plan.filter_by_path("input/tests/test_already_tested.py")

    assert len(broken_ops) == 1
    assert broken_ops[0].operation_type == PatchOperationType.UPDATE
    assert broken_ops[0].priority == PatchPriority.CRITICAL

    assert len(tool_ops) == 1
    assert tool_ops[0].summary == "Add module docstring."
    assert tool_ops[0].priority == PatchPriority.LOW

    assert len(tool_test_ops) == 1
    assert tool_test_ops[0].operation_type == PatchOperationType.CREATE
    assert tool_test_ops[0].priority == PatchPriority.NORMAL

    assert existing_test_ops == ()


@pytest.mark.parametrize(
    ("relative_path", "message"),
    [
        ("", "Forge patch relative path must not be empty"),
        ("   ", "Forge patch relative path must not be empty"),
    ],
)
def test_patch_operation_rejects_empty_relative_path(
    relative_path: str,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        PatchOperation(
            operation_type=PatchOperationType.UPDATE,
            relative_path=relative_path,
            priority=PatchPriority.HIGH,
            summary="Repair module.",
            rationale="Syntax error.",
        )
