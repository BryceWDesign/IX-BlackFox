from __future__ import annotations

from pathlib import Path

import pytest

from ix_blackfox.repository import (
    PythonCodeGraphBuilder,
    RepositoryDependencyScope,
    RepositoryEdgeKind,
    RepositoryInventoryScanner,
    RepositoryNodeKind,
    build_python_code_graph,
    is_internal_module,
    module_name_from_path,
    resolve_from_import_module,
)


def test_python_graph_extracts_modules_symbols_constants_and_import_edges(
    tmp_path: Path,
) -> None:
    repo = _build_python_repo(tmp_path)
    snapshot = RepositoryInventoryScanner().scan(repo)

    graph = PythonCodeGraphBuilder().build(repo, snapshot)

    symbols = {symbol.qualified_name: symbol for symbol in graph.symbols}
    assert symbols["ix_blackfox.runtime.brain_repair"].kind is RepositoryNodeKind.MODULE
    assert symbols["ix_blackfox.runtime.brain_repair.BrainRepair"].kind is RepositoryNodeKind.CLASS
    assert (
        symbols["ix_blackfox.runtime.brain_repair.BrainRepair.select"].kind
        is RepositoryNodeKind.METHOD
    )
    assert (
        symbols["ix_blackfox.runtime.brain_repair.run_repair"].kind
        is RepositoryNodeKind.FUNCTION
    )
    assert symbols["ix_blackfox.runtime.brain_repair.MAX_ATTEMPTS"].kind is RepositoryNodeKind.CONSTANT
    assert (
        symbols["tests.runtime.test_brain_repair.test_select"].kind
        is RepositoryNodeKind.FUNCTION
    )

    internal_edge = _find_edge(
        graph.edges,
        source="ix_blackfox.runtime.brain_repair",
        target="ix_blackfox.repository",
    )
    assert internal_edge.kind is RepositoryEdgeKind.IMPORTS
    assert internal_edge.scope is RepositoryDependencyScope.INTERNAL
    assert internal_edge.metadata["resolved_path"] == "src/ix_blackfox/repository/__init__.py"

    relative_edge = _find_edge(
        graph.edges,
        source="ix_blackfox.runtime.brain_repair",
        target="ix_blackfox.runtime.evidence",
    )
    assert relative_edge.scope is RepositoryDependencyScope.INTERNAL
    assert relative_edge.metadata["level"] == 1

    external_edge = _find_edge(
        graph.edges,
        source="ix_blackfox.runtime.brain_repair",
        target="json",
    )
    assert external_edge.scope is RepositoryDependencyScope.UNKNOWN
    assert external_edge.metadata["alias"] == "json_lib"

    assert graph.syntax_error_paths == ()
    assert graph.metadata["builder"] == "python-ast"
    assert graph.metadata["graphable_file_count"] == 5
    assert graph.digest == graph.to_dict()["digest"]


def test_python_graph_records_syntax_errors_without_executing_repo_code(
    tmp_path: Path,
) -> None:
    repo = _build_python_repo(tmp_path)
    _write_text(
        repo / "src" / "ix_blackfox" / "runtime" / "broken.py",
        "def broken(:\n",
    )
    snapshot = RepositoryInventoryScanner().scan(repo)

    graph = build_python_code_graph(repo, snapshot)

    assert graph.syntax_error_paths == ("src/ix_blackfox/runtime/broken.py",)
    assert not any(
        symbol.path == "src/ix_blackfox/runtime/broken.py"
        for symbol in graph.symbols
    )


def test_python_graph_can_exclude_tests_and_scripts(tmp_path: Path) -> None:
    repo = _build_python_repo(tmp_path)
    snapshot = RepositoryInventoryScanner().scan(repo)

    graph = PythonCodeGraphBuilder(include_tests=False, include_scripts=False).build(
        repo,
        snapshot,
    )

    assert graph.metadata["graphable_file_count"] == 3
    assert not any(symbol.path.startswith("tests/") for symbol in graph.symbols)
    assert not any(symbol.path.startswith("scripts/") for symbol in graph.symbols)


def test_python_graph_rejects_missing_root(tmp_path: Path) -> None:
    snapshot = RepositoryInventoryScanner().scan(_build_python_repo(tmp_path))

    with pytest.raises(ValueError, match="Repository root does not exist"):
        PythonCodeGraphBuilder().build(tmp_path / "missing", snapshot)


def test_module_name_and_relative_import_helpers_are_deterministic() -> None:
    assert (
        module_name_from_path("src/ix_blackfox/repository/__init__.py")
        == "ix_blackfox.repository"
    )
    assert (
        module_name_from_path("tests/repository/test_python_graph.py")
        == "tests.repository.test_python_graph"
    )
    assert module_name_from_path("scripts/run_wave8.py") == "scripts.run_wave8"

    assert (
        resolve_from_import_module(
            source_module="ix_blackfox.runtime.brain_repair",
            raw_module="evidence",
            level=1,
        )
        == "ix_blackfox.runtime.evidence"
    )
    assert (
        resolve_from_import_module(
            source_module="ix_blackfox.runtime.brain_repair",
            raw_module="repository",
            level=2,
        )
        == "ix_blackfox.repository"
    )

    assert is_internal_module("ix_blackfox.runtime") is True
    assert is_internal_module("tests.runtime.test_brain_repair") is True
    assert is_internal_module("json") is False


def _find_edge(edges: object, *, source: str, target: str) -> object:
    for edge in edges:
        if edge.source == source and edge.target == target:
            return edge
    raise AssertionError(f"Missing edge: {source} -> {target}")


def _build_python_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "IX-BlackFox-main"

    _write_text(
        repo / "src" / "ix_blackfox" / "repository" / "__init__.py",
        "class RepositorySnapshot:\n    pass\n",
    )
    _write_text(
        repo / "src" / "ix_blackfox" / "runtime" / "evidence.py",
        "class EvidenceReceipt:\n    pass\n",
    )
    _write_text(
        repo / "src" / "ix_blackfox" / "runtime" / "brain_repair.py",
        "\n".join(
            [
                "from __future__ import annotations",
                "",
                "import json as json_lib",
                "from ix_blackfox.repository import RepositorySnapshot",
                "from .evidence import EvidenceReceipt",
                "",
                "MAX_ATTEMPTS = 3",
                "",
                "class BrainRepair:",
                "    @classmethod",
                "    def select(cls, receipt: EvidenceReceipt) -> str:",
                "        return json_lib.dumps({'receipt': receipt.__class__.__name__})",
                "",
                "async def run_repair(snapshot: RepositorySnapshot) -> str:",
                "    return snapshot.__class__.__name__",
                "",
            ]
        ),
    )
    _write_text(
        repo / "tests" / "runtime" / "test_brain_repair.py",
        "\n".join(
            [
                "from ix_blackfox.runtime.brain_repair import BrainRepair",
                "",
                "def test_select() -> None:",
                "    assert BrainRepair is not None",
                "",
            ]
        ),
    )
    _write_text(
        repo / "scripts" / "run_wave8.py",
        "from ix_blackfox.runtime.brain_repair import BrainRepair\n",
    )

    return repo


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
