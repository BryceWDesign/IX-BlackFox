from __future__ import annotations

from pathlib import Path

import pytest

from ix_blackfox.repository import (
    RepositoryDependencyMapper,
    RepositoryDependencyScope,
    RepositoryInventoryScanner,
    build_dependency_map,
    dependencies_from_pyproject,
    dependencies_from_workflows,
    dependency_name_from_requirement,
    external_import_dependencies,
    internal_import_edges,
)
from ix_blackfox.repository.python_graph import PythonCodeGraphBuilder


def test_dependency_mapper_extracts_pyproject_workflow_and_import_edges(
    tmp_path: Path,
) -> None:
    repo = _build_dependency_repo(tmp_path)
    snapshot = RepositoryInventoryScanner().scan(repo)
    graph = PythonCodeGraphBuilder().build(repo, snapshot)

    dependency_map = RepositoryDependencyMapper().build(repo, snapshot, graph)

    dependencies = {
        (dependency.name, dependency.scope, dependency.source)
        for dependency in dependency_map.dependencies
    }

    assert (
        "setuptools",
        RepositoryDependencyScope.BUILD,
        "pyproject.toml:build-system.requires",
    ) in dependencies
    assert (
        "click",
        RepositoryDependencyScope.RUNTIME,
        "pyproject.toml:project.dependencies",
    ) in dependencies
    assert (
        "pytest",
        RepositoryDependencyScope.DEVELOPMENT,
        "pyproject.toml:project.optional-dependencies.dev",
    ) in dependencies
    assert any(
        dependency.name == "actions/setup-python"
        and dependency.scope is RepositoryDependencyScope.WORKFLOW
        and dependency.specifier == "v5"
        for dependency in dependency_map.dependencies
    )
    assert any(
        dependency.name == "requests"
        and dependency.scope is RepositoryDependencyScope.UNKNOWN
        and dependency.source.startswith("python-import:")
        for dependency in dependency_map.dependencies
    )

    assert len(dependency_map.internal_edges) >= 2
    assert "pyproject.toml" in dependency_map.sensitive_paths
    assert ".github/workflows/wave8.yml" in dependency_map.sensitive_paths
    assert "scripts/run_wave8.py" in dependency_map.sensitive_paths
    assert dependency_map.metadata["internal_edge_count"] == len(
        dependency_map.internal_edges
    )
    assert dependency_map.to_dict()["digest"] == dependency_map.digest


def test_build_dependency_map_convenience_wrapper(tmp_path: Path) -> None:
    repo = _build_dependency_repo(tmp_path)
    snapshot = RepositoryInventoryScanner().scan(repo)
    graph = PythonCodeGraphBuilder().build(repo, snapshot)

    dependency_map = build_dependency_map(repo, snapshot, graph)

    assert dependency_map.map_id == "wave-8-repository-dependency-map"
    assert dependency_map.metadata["dependency_count"] >= 5


def test_dependency_mapper_rejects_missing_root(tmp_path: Path) -> None:
    repo = _build_dependency_repo(tmp_path)
    snapshot = RepositoryInventoryScanner().scan(repo)
    graph = PythonCodeGraphBuilder().build(repo, snapshot)

    with pytest.raises(ValueError, match="Repository root does not exist"):
        RepositoryDependencyMapper().build(tmp_path / "missing", snapshot, graph)


def test_dependencies_from_pyproject_handles_missing_file(tmp_path: Path) -> None:
    assert dependencies_from_pyproject(tmp_path / "pyproject.toml") == ()


def test_dependencies_from_pyproject_parses_all_supported_scopes(
    tmp_path: Path,
) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        "\n".join(
            [
                "[build-system]",
                'requires = ["setuptools>=69", "wheel"]',
                "",
                "[project]",
                'dependencies = ["click>=8.0", "requests[socks]>=2.31"]',
                "",
                "[project.optional-dependencies]",
                'dev = ["pytest>=8", "ruff>=0.5"]',
                'docs = ["mkdocs>=1.5"]',
                "",
            ]
        ),
        encoding="utf-8",
    )

    dependencies = dependencies_from_pyproject(pyproject)

    assert {dependency.name for dependency in dependencies} == {
        "click",
        "mkdocs",
        "pytest",
        "requests",
        "ruff",
        "setuptools",
        "wheel",
    }
    assert any(
        dependency.name == "requests"
        and dependency.specifier == "requests[socks]>=2.31"
        for dependency in dependencies
    )
    assert any(
        dependency.name == "mkdocs"
        and dependency.scope is RepositoryDependencyScope.DEVELOPMENT
        and dependency.metadata == {"optional_group": "docs"}
        for dependency in dependencies
    )


def test_dependencies_from_workflows_extracts_action_uses(tmp_path: Path) -> None:
    repo = _build_dependency_repo(tmp_path)
    snapshot = RepositoryInventoryScanner().scan(repo)

    dependencies = dependencies_from_workflows(repo, snapshot)

    assert any(
        dependency.name == "actions/checkout"
        and dependency.specifier == "v4"
        and dependency.scope is RepositoryDependencyScope.WORKFLOW
        for dependency in dependencies
    )
    assert any(
        dependency.name == "actions/setup-python"
        and dependency.specifier == "v5"
        and dependency.scope is RepositoryDependencyScope.WORKFLOW
        for dependency in dependencies
    )


def test_internal_and_external_import_helpers(tmp_path: Path) -> None:
    repo = _build_dependency_repo(tmp_path)
    snapshot = RepositoryInventoryScanner().scan(repo)
    graph = PythonCodeGraphBuilder().build(repo, snapshot)

    internal_edges = internal_import_edges(graph)
    external_dependencies = external_import_dependencies(graph)

    assert any(edge.target == "ix_blackfox.repository" for edge in internal_edges)
    assert any(edge.target == "ix_blackfox.runtime.evidence" for edge in internal_edges)
    assert any(dependency.name == "requests" for dependency in external_dependencies)
    assert not any(dependency.name == "json" for dependency in external_dependencies)
    assert not any(dependency.name == "__future__" for dependency in external_dependencies)


def test_dependency_name_parser_handles_extras_specifiers_and_empty_values() -> None:
    assert dependency_name_from_requirement("requests[socks]>=2.31") == "requests"
    assert dependency_name_from_requirement("pytest-cov>=5,<6") == "pytest-cov"
    assert dependency_name_from_requirement("my_pkg==1.0") == "my-pkg"
    assert dependency_name_from_requirement("   ") is None


def _build_dependency_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "IX-BlackFox-main"

    _write_text(
        repo / "pyproject.toml",
        "\n".join(
            [
                "[build-system]",
                'requires = ["setuptools>=69.0", "wheel"]',
                'build-backend = "setuptools.build_meta"',
                "",
                "[project]",
                'name = "ix-blackfox"',
                'dependencies = ["click>=8.0"]',
                "",
                "[project.optional-dependencies]",
                'dev = ["pytest>=8.2", "ruff>=0.5"]',
                'docs = ["mkdocs>=1.5"]',
                "",
            ]
        ),
    )
    _write_text(
        repo / ".github" / "workflows" / "wave8.yml",
        "\n".join(
            [
                "name: Wave 8",
                "on: [push]",
                "jobs:",
                "  test:",
                "    runs-on: ubuntu-latest",
                "    steps:",
                "      - uses: actions/checkout@v4",
                "      - uses: actions/setup-python@v5",
                "        with:",
                '          python-version: "3.11"',
                "",
            ]
        ),
    )
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
                "import json",
                "import requests",
                "from ix_blackfox.repository import RepositorySnapshot",
                "from .evidence import EvidenceReceipt",
                "",
                "def repair(snapshot: RepositorySnapshot) -> EvidenceReceipt:",
                "    return EvidenceReceipt()",
                "",
            ]
        ),
    )
    _write_text(
        repo / "tests" / "runtime" / "test_brain_repair.py",
        "\n".join(
            [
                "from ix_blackfox.runtime.brain_repair import repair",
                "",
                "def test_repair() -> None:",
                "    assert repair is not None",
                "",
            ]
        ),
    )
    _write_text(
        repo / "scripts" / "run_wave8.py",
        "from ix_blackfox.runtime.brain_repair import repair\n",
    )
    _write_text(repo / "README.md", "# IX-BlackFox\n")
    _write_text(repo / "LICENSE", "source-available evaluation license\n")

    return repo


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"{content.rstrip()}\n", encoding="utf-8")
