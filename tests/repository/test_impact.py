from __future__ import annotations

from pathlib import Path

from ix_blackfox.repository import (
    RepositoryImpactAnalyzer,
    RepositoryImpactSeverity,
    RepositoryInventoryScanner,
    analyze_repository_impact,
    build_architecture_memory,
    build_coverage_map,
    build_dependency_map,
)
from ix_blackfox.repository.python_graph import PythonCodeGraphBuilder


def test_impact_analyzer_maps_source_change_to_tests_and_runtime_subsystem(
    tmp_path: Path,
) -> None:
    repo = _build_impact_repo(tmp_path)
    snapshot, dependency_map, coverage_map, memory = _build_analysis_inputs(repo)

    report = RepositoryImpactAnalyzer().analyze(
        snapshot=snapshot,
        dependency_map=dependency_map,
        coverage_map=coverage_map,
        architecture_memory=memory,
        changed_paths=("src/ix_blackfox/runtime/brain_repair.py",),
    )

    assert report.changed_paths == ("src/ix_blackfox/runtime/brain_repair.py",)
    assert "src/ix_blackfox/runtime/brain_repair.py" in report.impacted_paths
    assert "tests/runtime/test_brain_repair.py" in report.impacted_tests
    assert "runtime" in report.impacted_subsystems
    assert report.requires_human_review is True
    assert report.max_severity is RepositoryImpactSeverity.HIGH
    assert any(
        finding.code == "repository.sensitivity.security_relevant"
        for finding in report.findings
    )
    assert any(
        "tests/runtime/test_brain_repair.py" in command
        for command in report.recommended_commands
    )
    assert "python -m pytest -q" in report.recommended_commands


def test_impact_analyzer_uses_dependency_edges_to_find_importers(
    tmp_path: Path,
) -> None:
    repo = _build_impact_repo(tmp_path)
    snapshot, dependency_map, coverage_map, memory = _build_analysis_inputs(repo)

    report = analyze_repository_impact(
        snapshot=snapshot,
        dependency_map=dependency_map,
        coverage_map=coverage_map,
        architecture_memory=memory,
        changed_paths=("src/ix_blackfox/repository/__init__.py",),
    )

    assert "src/ix_blackfox/runtime/brain_repair.py" in report.impacted_paths
    assert "tests/runtime/test_brain_repair.py" in report.impacted_tests
    assert {"repository", "runtime"}.issubset(set(report.impacted_subsystems))
    assert any(
        finding.code == "repository.impact.cross_subsystem"
        for finding in report.findings
    )


def test_impact_analyzer_escalates_workflow_and_release_surface_changes(
    tmp_path: Path,
) -> None:
    repo = _build_impact_repo(tmp_path)
    snapshot, dependency_map, coverage_map, memory = _build_analysis_inputs(repo)

    report = analyze_repository_impact(
        snapshot=snapshot,
        dependency_map=dependency_map,
        coverage_map=coverage_map,
        architecture_memory=memory,
        changed_paths=(".github/workflows/wave8.yml",),
    )

    assert report.requires_human_review is True
    assert report.max_severity is RepositoryImpactSeverity.HIGH
    assert "ci-workflows" in report.impacted_subsystems
    assert any(
        finding.code == "repository.role.workflow"
        for finding in report.findings
    )
    assert "python -m pytest tests/ci -q" in report.recommended_commands


def test_impact_analyzer_marks_license_changes_as_critical(
    tmp_path: Path,
) -> None:
    repo = _build_impact_repo(tmp_path)
    snapshot, dependency_map, coverage_map, memory = _build_analysis_inputs(repo)

    report = analyze_repository_impact(
        snapshot=snapshot,
        dependency_map=dependency_map,
        coverage_map=coverage_map,
        architecture_memory=memory,
        changed_paths=("LICENSE",),
    )

    assert report.max_severity is RepositoryImpactSeverity.CRITICAL
    assert report.requires_human_review is True
    assert any(finding.code == "repository.role.license" for finding in report.findings)


def test_impact_analyzer_reports_unknown_changed_paths(tmp_path: Path) -> None:
    repo = _build_impact_repo(tmp_path)
    snapshot, dependency_map, coverage_map, memory = _build_analysis_inputs(repo)

    report = analyze_repository_impact(
        snapshot=snapshot,
        dependency_map=dependency_map,
        coverage_map=coverage_map,
        architecture_memory=memory,
        changed_paths=("src/ix_blackfox/runtime/new_file.py",),
    )

    assert report.max_severity is RepositoryImpactSeverity.MEDIUM
    assert report.requires_human_review is True
    assert any(
        finding.code == "repository.change.unknown_path"
        for finding in report.findings
    )


def test_impact_analyzer_reports_unmapped_source_tests(tmp_path: Path) -> None:
    repo = _build_impact_repo(tmp_path)
    _write_text(
        repo / "src" / "ix_blackfox" / "vault" / "uncovered.py",
        "def protect() -> bool:\n    return True\n",
    )
    snapshot, dependency_map, coverage_map, memory = _build_analysis_inputs(repo)

    report = analyze_repository_impact(
        snapshot=snapshot,
        dependency_map=dependency_map,
        coverage_map=coverage_map,
        architecture_memory=memory,
        changed_paths=("src/ix_blackfox/vault/uncovered.py",),
    )

    assert any(
        finding.code == "repository.coverage.unmapped_source"
        for finding in report.findings
    )
    assert "vault" in report.impacted_subsystems


def test_impact_analyzer_deduplicates_changed_paths_and_commands(
    tmp_path: Path,
) -> None:
    repo = _build_impact_repo(tmp_path)
    snapshot, dependency_map, coverage_map, memory = _build_analysis_inputs(repo)

    report = analyze_repository_impact(
        snapshot=snapshot,
        dependency_map=dependency_map,
        coverage_map=coverage_map,
        architecture_memory=memory,
        changed_paths=(
            "src/ix_blackfox/runtime/brain_repair.py",
            "src/ix_blackfox/runtime/brain_repair.py",
        ),
    )

    assert report.changed_paths == ("src/ix_blackfox/runtime/brain_repair.py",)
    assert len(report.recommended_commands) == len(set(report.recommended_commands))


def _build_analysis_inputs(repo: Path) -> tuple[object, object, object, object]:
    snapshot = RepositoryInventoryScanner().scan(repo)
    graph = PythonCodeGraphBuilder().build(repo, snapshot)
    dependency_map = build_dependency_map(repo, snapshot, graph)
    coverage_map = build_coverage_map(snapshot, graph)
    memory = build_architecture_memory(snapshot, coverage_map)
    return snapshot, dependency_map, coverage_map, memory


def _build_impact_repo(tmp_path: Path) -> Path:
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
        repo / "src" / "ix_blackfox" / "sandbox" / "workspace.py",
        "class Workspace:\n    pass\n",
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
        repo / "tests" / "repository" / "test_models.py",
        "def test_models() -> None:\n    assert True\n",
    )
    _write_text(
        repo / "tests" / "ci" / "test_wave8.py",
        "def test_wave8_ci() -> None:\n    assert True\n",
    )
    _write_text(repo / ".github" / "workflows" / "wave8.yml", "name: Wave 8\n")
    _write_text(repo / "scripts" / "run_wave8.py", "print('wave8')\n")
    _write_text(repo / "pyproject.toml", "[project]\nname = 'ix-blackfox'\n")
    _write_text(repo / "README.md", "# IX-BlackFox\n")
    _write_text(repo / "LICENSE", "source-available evaluation license\n")

    return repo


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"{content.rstrip()}\n", encoding="utf-8")
