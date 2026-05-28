from __future__ import annotations

from pathlib import Path

import pytest

from ix_blackfox.repository import (
    ArchitectureMemorySnapshot,
    RepositoryArchitectureRecord,
    RepositoryCoverageMapper,
    RepositoryInventoryScanner,
    architecture_memory_summary,
    architecture_records_by_subsystem,
    architecture_records_for_path,
    build_architecture_memory,
    default_architecture_records,
    validate_architecture_memory,
)


def test_default_architecture_records_cover_wave8_required_boundaries() -> None:
    records = default_architecture_records()
    by_subsystem = architecture_records_by_subsystem(records)

    required = {
        "authoring",
        "brains",
        "ci-workflows",
        "docs",
        "forge",
        "governance",
        "interface",
        "memory",
        "reliability",
        "repo-governance",
        "repository",
        "runtime",
        "sandbox",
        "scripts",
        "sentinel",
        "vault",
        "workflow",
    }

    assert required.issubset(by_subsystem)
    assert by_subsystem["repository"].wave == 8
    assert "src/ix_blackfox/repository" in by_subsystem["repository"].owned_paths
    assert by_subsystem["runtime"].owns_path("src/ix_blackfox/runtime/brain_repair.py")
    assert by_subsystem["repo-governance"].owns_path("pyproject.toml")
    assert by_subsystem["ci-workflows"].owns_path(".github/workflows/wave8.yml")


def test_architecture_memory_snapshot_is_stable_and_digestable() -> None:
    first = ArchitectureMemorySnapshot(
        memory_id=" Wave 8 Memory ",
        records=default_architecture_records(),
    )
    second = ArchitectureMemorySnapshot(
        memory_id="wave-8-memory",
        records=tuple(reversed(default_architecture_records())),
    )

    assert first.memory_id == "wave-8-memory"
    assert first.record_count == second.record_count
    assert first.subsystem_ids == second.subsystem_ids
    assert first.digest == second.digest
    assert first.to_dict()["digest"] == first.digest


def test_architecture_memory_snapshot_rejects_duplicate_record_ids() -> None:
    first = RepositoryArchitectureRecord(
        record_id="runtime-boundary",
        subsystem="runtime-a",
        owned_paths=("src/ix_blackfox/runtime",),
        responsibilities=("Preserve runtime behavior.",),
        constraints=("Runtime must stay governed.",),
        evidence_expectations=("Runtime changes need evidence.",),
    )
    second = RepositoryArchitectureRecord(
        record_id="runtime-boundary",
        subsystem="runtime-b",
        owned_paths=("tests/runtime",),
        responsibilities=("Preserve runtime tests.",),
        constraints=("Runtime tests must stay active.",),
        evidence_expectations=("Runtime test changes need evidence.",),
    )

    with pytest.raises(ValueError, match="record_id values must be unique"):
        ArchitectureMemorySnapshot(memory_id="memory", records=(first, second))


def test_architecture_memory_snapshot_rejects_duplicate_subsystems() -> None:
    first = RepositoryArchitectureRecord(
        record_id="runtime-source-boundary",
        subsystem="runtime",
        owned_paths=("src/ix_blackfox/runtime",),
        responsibilities=("Preserve runtime behavior.",),
        constraints=("Runtime must stay governed.",),
        evidence_expectations=("Runtime changes need evidence.",),
    )
    second = RepositoryArchitectureRecord(
        record_id="runtime-test-boundary",
        subsystem="runtime",
        owned_paths=("tests/runtime",),
        responsibilities=("Preserve runtime tests.",),
        constraints=("Runtime tests must stay active.",),
        evidence_expectations=("Runtime test changes need evidence.",),
    )

    with pytest.raises(ValueError, match="subsystem values must be unique"):
        ArchitectureMemorySnapshot(memory_id="memory", records=(first, second))


def test_build_architecture_memory_binds_to_inventory_and_coverage(tmp_path: Path) -> None:
    repo = _build_architecture_repo(tmp_path)
    snapshot = RepositoryInventoryScanner().scan(repo)
    coverage = RepositoryCoverageMapper().build(snapshot)

    memory = build_architecture_memory(snapshot, coverage)

    assert memory.memory_id == "wave-8-architecture-memory"
    assert memory.metadata["snapshot_digest"] == snapshot.digest
    assert memory.metadata["coverage_map_digest"] == coverage.digest
    assert memory.metadata["source_path_count"] == 4
    assert memory.metadata["owned_source_path_count"] == 4
    assert memory.metadata["unowned_source_paths"] == []
    assert "pyproject.toml" not in memory.metadata["unowned_sensitive_paths"]

    repository_records = memory.records_for_path("src/ix_blackfox/repository/models.py")
    assert len(repository_records) == 1
    assert repository_records[0].subsystem == "repository"

    governance_records = architecture_records_for_path(
        memory.records,
        "blackfox.policy.toml",
    )
    assert governance_records[0].subsystem == "repo-governance"


def test_build_architecture_memory_adds_discovered_coverage_subsystems(
    tmp_path: Path,
) -> None:
    repo = _build_architecture_repo(tmp_path)
    _write_text(
        repo / "src" / "ix_blackfox" / "newcapability" / "engine.py",
        "def run() -> str:\n    return 'new'\n",
    )
    _write_text(
        repo / "tests" / "newcapability" / "test_engine.py",
        "def test_engine() -> None:\n    assert True\n",
    )
    snapshot = RepositoryInventoryScanner().scan(repo)
    coverage = RepositoryCoverageMapper().build(snapshot)

    memory = build_architecture_memory(snapshot, coverage)
    discovered = memory.record_for_subsystem("newcapability")

    assert discovered is not None
    assert discovered.metadata == {"discovered_from_coverage_map": True}
    assert discovered.owns_path("src/ix_blackfox/newcapability/engine.py")


def test_architecture_memory_summary_and_validation_are_reviewable(
    tmp_path: Path,
) -> None:
    repo = _build_architecture_repo(tmp_path)
    snapshot = RepositoryInventoryScanner().scan(repo)
    coverage = RepositoryCoverageMapper().build(snapshot)
    memory = build_architecture_memory(snapshot, coverage)

    summary = architecture_memory_summary(memory)
    validation = validate_architecture_memory(memory)

    assert summary["memory_id"] == "wave-8-architecture-memory"
    assert summary["record_count"] == memory.record_count
    assert summary["digest"] == memory.digest
    assert validation["valid"] is True
    assert validation["warnings"] == []
    assert validation["digest"] == memory.digest


def _build_architecture_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "IX-BlackFox-main"

    _write_text(
        repo / "src" / "ix_blackfox" / "repository" / "models.py",
        "class RepositorySnapshot:\n    pass\n",
    )
    _write_text(
        repo / "src" / "ix_blackfox" / "runtime" / "brain_repair.py",
        "def repair() -> str:\n    return 'ok'\n",
    )
    _write_text(
        repo / "src" / "ix_blackfox" / "sandbox" / "workspace.py",
        "class Workspace:\n    pass\n",
    )
    _write_text(
        repo / "src" / "ix_blackfox" / "governance" / "policy.py",
        "def allow() -> bool:\n    return False\n",
    )
    _write_text(
        repo / "tests" / "repository" / "test_models.py",
        "def test_models() -> None:\n    assert True\n",
    )
    _write_text(
        repo / "tests" / "runtime" / "test_brain_repair.py",
        "def test_runtime() -> None:\n    assert True\n",
    )
    _write_text(repo / ".github" / "workflows" / "ci.yml", "name: CI\n")
    _write_text(repo / "scripts" / "run_wave8.py", "print('wave8')\n")
    _write_text(repo / "docs" / "wave8.md", "# Wave 8\n")
    _write_text(repo / "blackfox.policy.toml", "[policy]\n")
    _write_text(repo / "pyproject.toml", "[project]\nname = 'ix-blackfox'\n")
    _write_text(repo / "README.md", "# IX-BlackFox\n")
    _write_text(repo / "LICENSE", "source-available evaluation license\n")
    _write_text(repo / "NOTICE.md", "IX-BlackFox notice\n")

    return repo


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
