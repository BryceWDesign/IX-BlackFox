from __future__ import annotations

from pathlib import Path

from ix_blackfox.repository import (
    RepositoryCoverageMapper,
    RepositoryFileRole,
    RepositoryInventoryScanner,
    RepositorySensitivity,
    build_coverage_map,
    infer_subsystem_id,
    module_path_lookup,
    owned_paths_for_subsystem,
    source_module_test_candidates,
)
from ix_blackfox.repository.python_graph import PythonCodeGraphBuilder


def test_coverage_map_links_sources_to_tests_by_path_and_graph(tmp_path: Path) -> None:
    repo = _build_coverage_repo(tmp_path)
    snapshot = RepositoryInventoryScanner().scan(repo)
    graph = PythonCodeGraphBuilder().build(repo, snapshot)

    coverage = RepositoryCoverageMapper().build(snapshot, graph)

    assert coverage.tests_for_source("src/ix_blackfox/runtime/brain_repair.py") == (
        "tests/runtime/test_brain_repair.py",
    )
    assert coverage.tests_for_source("src/ix_blackfox/authoring/context.py") == (
        "tests/authoring/test_context_behavior.py",
    )
    assert coverage.metadata["graph_used"] is True
    assert coverage.link_count >= 2
    assert coverage.to_dict()["digest"] == coverage.digest


def test_coverage_map_tracks_subsystems_and_sensitive_paths(tmp_path: Path) -> None:
    repo = _build_coverage_repo(tmp_path)
    snapshot = RepositoryInventoryScanner().scan(repo)

    coverage = build_coverage_map(snapshot)
    subsystems = {subsystem.subsystem: subsystem for subsystem in coverage.subsystems}

    assert "runtime" in subsystems
    assert "authoring" in subsystems
    assert "ci-workflows" in subsystems
    assert "repo-governance" in subsystems
    assert subsystems["runtime"].owns_path("src/ix_blackfox/runtime/brain_repair.py")
    assert "src/ix_blackfox/runtime/brain_repair.py" in subsystems["runtime"].source_paths
    assert "tests/runtime/test_brain_repair.py" in subsystems["runtime"].test_paths
    assert ".github/workflows/ci.yml" in subsystems["ci-workflows"].sensitive_paths
    assert "pyproject.toml" in subsystems["repo-governance"].sensitive_paths


def test_coverage_map_reports_orphan_sources_and_tests(tmp_path: Path) -> None:
    repo = _build_coverage_repo(tmp_path)
    _write_text(repo / "src" / "ix_blackfox" / "vault" / "uncovered.py", "VALUE = 1\n")
    _write_text(repo / "tests" / "vault" / "test_lonely.py", "def test_lonely() -> None:\n    assert True\n")
    snapshot = RepositoryInventoryScanner().scan(repo)

    coverage = build_coverage_map(snapshot)

    assert "src/ix_blackfox/vault/uncovered.py" in coverage.orphan_source_paths
    assert "tests/vault/test_lonely.py" in coverage.orphan_test_paths
    assert "src/ix_blackfox/vault/__init__.py" not in coverage.orphan_source_paths


def test_source_module_test_candidates_are_deterministic() -> None:
    assert source_module_test_candidates("src/ix_blackfox/runtime/brain_repair.py") == (
        "tests/runtime/test_brain_repair.py",
    )
    assert source_module_test_candidates("src/ix_blackfox/brains/providers/openai.py") == (
        "tests/brains/providers/test_openai.py",
        "tests/brains/test_openai.py",
    )
    assert source_module_test_candidates("src/ix_blackfox/runtime/__init__.py") == ()


def test_subsystem_helpers_cover_review_surfaces() -> None:
    assert infer_subsystem_id("src/ix_blackfox/runtime/brain_repair.py") == "runtime"
    assert infer_subsystem_id("tests/runtime/test_brain_repair.py") == "runtime"
    assert infer_subsystem_id(".github/workflows/ci.yml") == "ci-workflows"
    assert infer_subsystem_id("scripts/run_wave8.py") == "scripts"
    assert infer_subsystem_id("docs/system-architecture.md") == "docs"
    assert infer_subsystem_id("pyproject.toml") == "repo-governance"
    assert infer_subsystem_id("IX-BlackFox-Logo.png") is None

    assert owned_paths_for_subsystem("runtime") == (
        "src/ix_blackfox/runtime",
        "tests/runtime",
    )
    assert ".github/workflows" in owned_paths_for_subsystem("ci-workflows")


def test_module_path_lookup_uses_inventory_paths(tmp_path: Path) -> None:
    repo = _build_coverage_repo(tmp_path)
    snapshot = RepositoryInventoryScanner().scan(repo)

    lookup = module_path_lookup(snapshot)

    assert lookup["ix_blackfox.runtime.brain_repair"] == "src/ix_blackfox/runtime/brain_repair.py"
    assert lookup["tests.runtime.test_brain_repair"] == "tests/runtime/test_brain_repair.py"


def test_coverage_map_preserves_existing_stronger_graph_link(tmp_path: Path) -> None:
    repo = _build_coverage_repo(tmp_path)
    snapshot = RepositoryInventoryScanner().scan(repo)
    graph = PythonCodeGraphBuilder().build(repo, snapshot)

    coverage = build_coverage_map(snapshot, graph)
    links = {
        (link.source_path, link.test_path): link
        for link in coverage.links
    }

    link = links[("src/ix_blackfox/runtime/brain_repair.py", "tests/runtime/test_brain_repair.py")]
    assert link.confidence == 95
    assert "importing" in link.reason


def test_inventory_roles_remain_the_source_of_coverage_truth(tmp_path: Path) -> None:
    repo = _build_coverage_repo(tmp_path)
    snapshot = RepositoryInventoryScanner().scan(repo)
    roles = {record.path: record.role for record in snapshot.files}
    sensitivities = {record.path: record.sensitivity for record in snapshot.files}

    assert roles["src/ix_blackfox/runtime/brain_repair.py"] is RepositoryFileRole.SOURCE
    assert roles["tests/runtime/test_brain_repair.py"] is RepositoryFileRole.TEST
    assert sensitivities["src/ix_blackfox/runtime/brain_repair.py"] is RepositorySensitivity.SECURITY_RELEVANT


def _build_coverage_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "IX-BlackFox-main"

    _write_text(repo / "src" / "ix_blackfox" / "runtime" / "__init__.py", "")
    _write_text(
        repo / "src" / "ix_blackfox" / "runtime" / "brain_repair.py",
        "def repair() -> str:\n    return 'ok'\n",
    )
    _write_text(repo / "src" / "ix_blackfox" / "authoring" / "__init__.py", "")
    _write_text(
        repo / "src" / "ix_blackfox" / "authoring" / "context.py",
        "class AuthoringContext:\n    pass\n",
    )
    _write_text(
        repo / "tests" / "runtime" / "test_brain_repair.py",
        "from ix_blackfox.runtime.brain_repair import repair\n\n"
        "def test_repair() -> None:\n    assert repair() == 'ok'\n",
    )
    _write_text(
        repo / "tests" / "authoring" / "test_context_behavior.py",
        "from ix_blackfox.authoring.context import AuthoringContext\n\n"
        "def test_context() -> None:\n    assert AuthoringContext is not None\n",
    )
    _write_text(repo / ".github" / "workflows" / "ci.yml", "name: CI\n")
    _write_text(repo / "scripts" / "run_wave8.py", "print('wave8')\n")
    _write_text(repo / "docs" / "system-architecture.md", "# Architecture\n")
    _write_text(repo / "pyproject.toml", "[project]\nname = 'ix-blackfox'\n")
    _write_text(repo / "README.md", "# IX-BlackFox\n")
    _write_text(repo / "LICENSE", "source-available evaluation license\n")

    return repo


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
