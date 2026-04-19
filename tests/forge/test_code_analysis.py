from __future__ import annotations

from pathlib import Path

import pytest

from ix_blackfox.config import load_runtime_config
from ix_blackfox.forge import (
    ForgeCodeAnalyzer,
    ForgeFileGraphScanner,
    ForgeWorkspaceManager,
)


def test_code_analyzer_extracts_python_symbols(tmp_path: Path) -> None:
    config = load_runtime_config(root_dir=tmp_path, env={})
    manager = ForgeWorkspaceManager(config)
    workspace = manager.reserve(prefix="analyze")

    manager.materialize_file(
        workspace=workspace,
        relative_path="input/app/main.py",
        content='''"""Main module docstring."""

import json
from pathlib import Path as P


def build() -> str:
    return "ok"


async def abuild() -> str:
    return "ok"


class Runner:
    def start(self) -> None:
        return None
''',
    )

    graph = ForgeFileGraphScanner().scan(workspace)
    snapshot = ForgeCodeAnalyzer().analyze_graph(graph)
    module = snapshot.get_module("input/app/main.py")

    assert snapshot.module_count() == 1
    assert snapshot.valid_module_count() == 1
    assert module is not None
    assert module.module_name == "input.app.main"
    assert module.docstring == "Main module docstring."
    assert module.import_count == 2
    assert module.function_count == 2
    assert module.class_count == 1
    assert tuple(symbol.name for symbol in module.functions) == ("build", "abuild")
    assert module.functions[1].is_async is True
    assert module.classes[0].name == "Runner"
    assert module.classes[0].method_names == ("start",)
    assert module.imports[0].name == "json"
    assert module.imports[1].module == "pathlib"
    assert module.imports[1].alias == "P"


def test_code_analyzer_captures_syntax_errors_without_crashing(tmp_path: Path) -> None:
    config = load_runtime_config(root_dir=tmp_path, env={})
    manager = ForgeWorkspaceManager(config)
    workspace = manager.reserve(prefix="syntax")

    manager.materialize_file(
        workspace=workspace,
        relative_path="input/broken.py",
        content="def broken(:\n    pass\n",
    )

    graph = ForgeFileGraphScanner().scan(workspace)
    snapshot = ForgeCodeAnalyzer().analyze_graph(graph)
    module = snapshot.get_module("input/broken.py")

    assert snapshot.module_count() == 1
    assert snapshot.valid_module_count() == 0
    assert module is not None
    assert module.is_valid_python is False
    assert module.syntax_error is not None
    assert "line 1" in module.syntax_error
    assert module.import_count == 0
    assert module.function_count == 0
    assert module.class_count == 0


def test_code_analyzer_skips_non_python_files(tmp_path: Path) -> None:
    config = load_runtime_config(root_dir=tmp_path, env={})
    manager = ForgeWorkspaceManager(config)
    workspace = manager.reserve(prefix="mixed")

    manager.materialize_file(
        workspace=workspace,
        relative_path="input/readme.txt",
        content="hello\n",
    )
    manager.materialize_file(
        workspace=workspace,
        relative_path="input/tool.py",
        content="VALUE = 1\n",
    )

    graph = ForgeFileGraphScanner().scan(workspace)
    snapshot = ForgeCodeAnalyzer().analyze_graph(graph)

    assert snapshot.module_count() == 1
    assert snapshot.get_module("input/tool.py") is not None
    assert snapshot.get_module("input/readme.txt") is None


def test_code_analyzer_rejects_non_python_file_nodes(tmp_path: Path) -> None:
    config = load_runtime_config(root_dir=tmp_path, env={})
    manager = ForgeWorkspaceManager(config)
    workspace = manager.reserve(prefix="reject")

    manager.materialize_file(
        workspace=workspace,
        relative_path="input/data.json",
        content='{"ok": true}\n',
    )

    graph = ForgeFileGraphScanner().scan(workspace)
    node = graph.get_file("input/data.json")
    assert node is not None

    with pytest.raises(ValueError, match="only supports Python files"):
        ForgeCodeAnalyzer().analyze_python_file(node)
