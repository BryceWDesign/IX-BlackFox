from __future__ import annotations

import hashlib

import pytest

from ix_blackfox.repository import (
    RepositoryArchitectureRecord,
    RepositoryCodeGraph,
    RepositoryCoverageLink,
    RepositoryDependencyMap,
    RepositoryDependencyRecord,
    RepositoryDependencyScope,
    RepositoryEdgeKind,
    RepositoryFileRecord,
    RepositoryFileRole,
    RepositoryGraphEdge,
    RepositoryImpactFinding,
    RepositoryImpactReport,
    RepositoryImpactSeverity,
    RepositoryNodeKind,
    RepositorySensitivity,
    RepositorySnapshot,
    RepositorySymbolRecord,
)


def test_file_record_normalizes_path_and_digest() -> None:
    digest = hashlib.sha256(b"module").hexdigest().upper()

    record = RepositoryFileRecord(
        path=" src\\ix_blackfox\\runtime.py ",
        role=RepositoryFileRole.SOURCE,
        sha256=digest,
        size_bytes=6,
        sensitivity=RepositorySensitivity.SECURITY_RELEVANT,
        metadata={"owner": "runtime"},
    )

    assert record.path == "src/ix_blackfox/runtime.py"
    assert record.sha256 == digest.lower()
    assert record.to_dict()["sensitivity"] == "security_relevant"
    assert record.to_dict()["metadata"] == {"owner": "runtime"}


def test_file_record_rejects_absolute_and_escape_paths() -> None:
    digest = hashlib.sha256(b"module").hexdigest()

    with pytest.raises(ValueError, match="repository-relative"):
        RepositoryFileRecord(
            path="/tmp/example.py",
            role=RepositoryFileRole.SOURCE,
            sha256=digest,
            size_bytes=1,
        )

    with pytest.raises(ValueError, match="traversal"):
        RepositoryFileRecord(
            path="../example.py",
            role=RepositoryFileRole.SOURCE,
            sha256=digest,
            size_bytes=1,
        )


def test_snapshot_sorts_files_and_computes_stable_digest() -> None:
    source = _file("src/ix_blackfox/runtime.py", RepositoryFileRole.SOURCE, b"source")
    test = _file("tests/test_runtime.py", RepositoryFileRole.TEST, b"test")

    snapshot = RepositorySnapshot(
        snapshot_id=" Wave 8 Snapshot ",
        root_label=" IX-BlackFox ",
        files=(test, source),
    )
    same_snapshot = RepositorySnapshot(
        snapshot_id="wave-8-snapshot",
        root_label="IX-BlackFox",
        files=(source, test),
    )

    assert snapshot.snapshot_id == "wave-8-snapshot"
    assert snapshot.file_count == 2
    assert snapshot.total_bytes == source.size_bytes + test.size_bytes
    assert snapshot.paths_by_role(RepositoryFileRole.SOURCE) == (
        "src/ix_blackfox/runtime.py",
    )
    assert snapshot.digest == same_snapshot.digest
    assert snapshot.to_dict()["digest"] == snapshot.digest


def test_snapshot_rejects_duplicate_paths() -> None:
    first = _file("src/ix_blackfox/runtime.py", RepositoryFileRole.SOURCE, b"one")
    second = _file("src/ix_blackfox/runtime.py", RepositoryFileRole.SOURCE, b"two")

    with pytest.raises(ValueError, match="unique"):
        RepositorySnapshot(
            snapshot_id="snapshot",
            root_label="repo",
            files=(first, second),
        )


def test_code_graph_sorts_symbols_edges_and_digests_payload() -> None:
    symbol = RepositorySymbolRecord(
        path="src/ix_blackfox/runtime.py",
        qualified_name="ix_blackfox.runtime.Engine",
        kind=RepositoryNodeKind.CLASS,
        line=10,
    )
    edge = RepositoryGraphEdge(
        source="ix_blackfox.runtime",
        target="ix_blackfox.governance",
        kind=RepositoryEdgeKind.IMPORTS,
        reason="runtime imports governance checks",
    )

    graph = RepositoryCodeGraph(
        graph_id=" Python Graph ",
        symbols=(symbol,),
        edges=(edge,),
        syntax_error_paths=("tests/broken.py",),
    )

    assert graph.graph_id == "python-graph"
    assert graph.symbol_count == 1
    assert graph.edge_count == 1
    assert graph.syntax_error_paths == ("tests/broken.py",)
    assert graph.to_dict()["digest"] == graph.digest


def test_dependency_map_normalizes_dependencies_and_sensitive_paths() -> None:
    dependency = RepositoryDependencyRecord(
        name=" PyTest ",
        scope=RepositoryDependencyScope.DEVELOPMENT,
        source=" pyproject.toml ",
        specifier=">=8,<9",
    )
    edge = RepositoryGraphEdge(
        source="ix_blackfox.runtime",
        target="ix_blackfox.workflow",
        kind=RepositoryEdgeKind.IMPORTS,
    )

    dependency_map = RepositoryDependencyMap(
        map_id=" Dependency Map ",
        dependencies=(dependency,),
        internal_edges=(edge,),
        sensitive_paths=(".github/workflows/wave7.yml", "pyproject.toml"),
    )

    assert dependency_map.map_id == "dependency-map"
    assert dependency_map.dependencies[0].name == "pytest"
    assert dependency_map.sensitive_paths == (
        ".github/workflows/wave7.yml",
        "pyproject.toml",
    )
    assert dependency_map.to_dict()["digest"] == dependency_map.digest


def test_coverage_link_validates_confidence_range() -> None:
    link = RepositoryCoverageLink(
        source_path="src/ix_blackfox/runtime.py",
        test_path="tests/runtime/test_runtime.py",
        confidence=90,
        reason="module name match",
    )

    assert link.to_dict()["confidence"] == 90

    with pytest.raises(ValueError, match="between 0 and 100"):
        RepositoryCoverageLink(
            source_path="src/ix_blackfox/runtime.py",
            test_path="tests/runtime/test_runtime.py",
            confidence=101,
            reason="invalid confidence",
        )


def test_architecture_record_owns_paths_and_has_stable_digest() -> None:
    record = RepositoryArchitectureRecord(
        record_id=" Runtime Boundary ",
        subsystem=" Runtime ",
        owned_paths=("src/ix_blackfox/runtime",),
        responsibilities=("Coordinate governed execution.",),
        constraints=("Do not bypass human approval.",),
        evidence_expectations=("Emit reviewable receipts.",),
    )

    assert record.record_id == "runtime-boundary"
    assert record.subsystem == "runtime"
    assert record.owns_path("src/ix_blackfox/runtime/brain_repair.py")
    assert not record.owns_path("src/ix_blackfox/sandbox/workspace.py")
    assert record.to_dict()["digest"] == record.digest


def test_impact_report_exposes_review_and_max_severity() -> None:
    finding = RepositoryImpactFinding(
        code="repository.sensitive_path",
        severity=RepositoryImpactSeverity.HIGH,
        summary="Workflow change requires human review.",
        paths=(".github/workflows/wave8.yml",),
        review_required=True,
    )

    report = RepositoryImpactReport(
        report_id=" Impact Report ",
        changed_paths=(".github/workflows/wave8.yml",),
        impacted_paths=("pyproject.toml", ".github/workflows/wave8.yml"),
        impacted_tests=("tests/ci/test_wave8.py",),
        impacted_subsystems=(" CI ", "repository"),
        findings=(finding,),
        recommended_commands=("python -m pytest tests/ci/test_wave8.py",),
    )

    assert report.report_id == "impact-report"
    assert report.requires_human_review is True
    assert report.max_severity is RepositoryImpactSeverity.HIGH
    assert report.impacted_paths == (
        ".github/workflows/wave8.yml",
        "pyproject.toml",
    )
    assert report.impacted_subsystems == ("ci", "repository")
    assert report.to_dict()["digest"] == report.digest


def test_impact_report_requires_changed_paths() -> None:
    with pytest.raises(ValueError, match="changed_paths"):
        RepositoryImpactReport(report_id="empty", changed_paths=())


def _file(path: str, role: RepositoryFileRole, content: bytes) -> RepositoryFileRecord:
    return RepositoryFileRecord(
        path=path,
        role=role,
        sha256=hashlib.sha256(content).hexdigest(),
        size_bytes=len(content),
    )
