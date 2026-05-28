from __future__ import annotations

import re
import sys
import tomllib
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Final

from ix_blackfox.repository.models import (
    RepositoryCodeGraph,
    RepositoryDependencyMap,
    RepositoryDependencyRecord,
    RepositoryDependencyScope,
    RepositoryEdgeKind,
    RepositoryGraphEdge,
    RepositorySensitivity,
    RepositorySnapshot,
)

_REQUIREMENT_NAME_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^\s*([A-Za-z0-9_.-]+)"
)
_WORKFLOW_USES_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^\s*(?:-\s+)?uses:\s*([A-Za-z0-9_.\-/]+)(?:@([A-Za-z0-9_.\-/]+))?\s*$"
)

DEPENDENCY_FILE_NAMES: Final[frozenset[str]] = frozenset(
    {
        "constraints.txt",
        "pdm.lock",
        "poetry.lock",
        "pyproject.toml",
        "requirements-dev.txt",
        "requirements.txt",
        "uv.lock",
    }
)

_STANDARD_LIBRARY_MODULES: Final[frozenset[str]] = frozenset(
    getattr(sys, "stdlib_module_names", frozenset())
)


class RepositoryDependencyMapper:
    """Build dependency evidence from project metadata and repository graph edges."""

    def build(
        self,
        root: str | Path,
        snapshot: RepositorySnapshot,
        graph: RepositoryCodeGraph,
        *,
        map_id: str = "wave-8-repository-dependency-map",
    ) -> RepositoryDependencyMap:
        repo_root = Path(root).resolve()
        if not repo_root.is_dir():
            raise ValueError(f"Repository root does not exist: {repo_root}")

        dependencies: list[RepositoryDependencyRecord] = []
        dependencies.extend(dependencies_from_pyproject(repo_root / "pyproject.toml"))
        dependencies.extend(dependencies_from_workflows(repo_root, snapshot))
        dependencies.extend(external_import_dependencies(graph))

        internal_edges = internal_import_edges(graph)
        sensitive_paths = sensitive_dependency_paths(snapshot)

        return RepositoryDependencyMap(
            map_id=map_id,
            dependencies=tuple(deduplicate_dependencies(dependencies)),
            internal_edges=internal_edges,
            sensitive_paths=sensitive_paths,
            metadata=build_dependency_metadata(
                dependencies=dependencies,
                internal_edges=internal_edges,
                sensitive_paths=sensitive_paths,
            ),
        )


def build_dependency_map(
    root: str | Path,
    snapshot: RepositorySnapshot,
    graph: RepositoryCodeGraph,
    *,
    map_id: str = "wave-8-repository-dependency-map",
) -> RepositoryDependencyMap:
    """Convenience wrapper for the default Wave 8 dependency map."""
    return RepositoryDependencyMapper().build(
        root,
        snapshot,
        graph,
        map_id=map_id,
    )


def dependencies_from_pyproject(path: Path) -> tuple[RepositoryDependencyRecord, ...]:
    if not path.exists():
        return ()

    payload = tomllib.loads(path.read_text(encoding="utf-8"))
    records: list[RepositoryDependencyRecord] = []

    build_system = payload.get("build-system", {})
    if isinstance(build_system, dict):
        records.extend(
            dependency_records_from_requirement_list(
                build_system.get("requires", []),
                scope=RepositoryDependencyScope.BUILD,
                source="pyproject.toml:build-system.requires",
            )
        )

    project = payload.get("project", {})
    if isinstance(project, dict):
        records.extend(
            dependency_records_from_requirement_list(
                project.get("dependencies", []),
                scope=RepositoryDependencyScope.RUNTIME,
                source="pyproject.toml:project.dependencies",
            )
        )

        optional_dependencies = project.get("optional-dependencies", {})
        if isinstance(optional_dependencies, dict):
            for group, requirements in sorted(optional_dependencies.items()):
                if not isinstance(group, str):
                    continue
                records.extend(
                    dependency_records_from_requirement_list(
                        requirements,
                        scope=RepositoryDependencyScope.DEVELOPMENT,
                        source=f"pyproject.toml:project.optional-dependencies.{group}",
                        metadata={"optional_group": group},
                    )
                )

    return tuple(records)


def dependencies_from_workflows(
    root: Path,
    snapshot: RepositorySnapshot,
) -> tuple[RepositoryDependencyRecord, ...]:
    records: list[RepositoryDependencyRecord] = []
    workflow_paths = tuple(
        file_record.path
        for file_record in snapshot.files
        if file_record.path.startswith(".github/workflows/")
        and file_record.path.endswith((".yml", ".yaml"))
    )

    for workflow_path in workflow_paths:
        full_path = root / workflow_path
        try:
            lines = full_path.read_text(encoding="utf-8").splitlines()
        except OSError:
            continue

        for line_number, line in enumerate(lines, start=1):
            match = _WORKFLOW_USES_PATTERN.match(line)
            if match is None:
                continue
            action_name = match.group(1).lower()
            action_ref = match.group(2) or ""
            records.append(
                RepositoryDependencyRecord(
                    name=action_name,
                    scope=RepositoryDependencyScope.WORKFLOW,
                    source=f"{workflow_path}:uses:{line_number}",
                    specifier=action_ref,
                    metadata={"workflow_path": workflow_path, "line": line_number},
                )
            )

    return tuple(records)


def dependency_records_from_requirement_list(
    requirements: object,
    *,
    scope: RepositoryDependencyScope,
    source: str,
    metadata: dict[str, object] | None = None,
) -> tuple[RepositoryDependencyRecord, ...]:
    if not isinstance(requirements, list):
        return ()

    records: list[RepositoryDependencyRecord] = []
    for requirement in requirements:
        if not isinstance(requirement, str):
            continue
        dependency_name = dependency_name_from_requirement(requirement)
        if dependency_name is None:
            continue
        records.append(
            RepositoryDependencyRecord(
                name=dependency_name,
                scope=scope,
                source=source,
                specifier=requirement.strip(),
                metadata=metadata or {},
            )
        )
    return tuple(records)


def dependency_name_from_requirement(requirement: str) -> str | None:
    match = _REQUIREMENT_NAME_PATTERN.match(requirement)
    if match is None:
        return None
    return match.group(1).lower().replace("_", "-")


def internal_import_edges(graph: RepositoryCodeGraph) -> tuple[RepositoryGraphEdge, ...]:
    return tuple(
        edge
        for edge in graph.edges
        if edge.kind is RepositoryEdgeKind.IMPORTS
        and edge.scope is RepositoryDependencyScope.INTERNAL
    )


def external_import_dependencies(
    graph: RepositoryCodeGraph,
) -> tuple[RepositoryDependencyRecord, ...]:
    observed: dict[str, tuple[str, str]] = {}

    for edge in graph.edges:
        if edge.kind is not RepositoryEdgeKind.IMPORTS:
            continue
        if edge.scope is RepositoryDependencyScope.INTERNAL:
            continue

        top_level_name = edge.target.split(".", maxsplit=1)[0]
        if not top_level_name or top_level_name in {"__future__", "unknown"}:
            continue
        if top_level_name in _STANDARD_LIBRARY_MODULES:
            continue

        source_path = str(edge.metadata.get("source_path") or edge.source)
        observed.setdefault(top_level_name, (edge.target, source_path))

    return tuple(
        RepositoryDependencyRecord(
            name=name,
            scope=RepositoryDependencyScope.UNKNOWN,
            source=f"python-import:{source_path}",
            metadata={"observed_module": observed_module},
        )
        for name, (observed_module, source_path) in sorted(observed.items())
    )


def sensitive_dependency_paths(snapshot: RepositorySnapshot) -> tuple[str, ...]:
    paths: list[str] = []

    for file_record in snapshot.files:
        name = PurePosixPath(file_record.path).name
        is_dependency_file = name in DEPENDENCY_FILE_NAMES
        is_sensitive = file_record.sensitivity is not RepositorySensitivity.NORMAL
        if is_dependency_file or is_sensitive:
            paths.append(file_record.path)

    return tuple(sorted(set(paths)))


def deduplicate_dependencies(
    dependencies: list[RepositoryDependencyRecord],
) -> tuple[RepositoryDependencyRecord, ...]:
    deduped: list[RepositoryDependencyRecord] = []
    seen: set[tuple[str, str, str, str]] = set()

    for dependency in dependencies:
        key = (
            dependency.name,
            dependency.scope.value,
            dependency.source,
            dependency.specifier,
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(dependency)

    return tuple(deduped)


def build_dependency_metadata(
    *,
    dependencies: list[RepositoryDependencyRecord],
    internal_edges: tuple[RepositoryGraphEdge, ...],
    sensitive_paths: tuple[str, ...],
) -> dict[str, object]:
    scope_counts = Counter(dependency.scope for dependency in dependencies)
    return {
        "dependency_count": len(deduplicate_dependencies(dependencies)),
        "internal_edge_count": len(internal_edges),
        "sensitive_path_count": len(sensitive_paths),
        "scope_counts": {
            scope.value: scope_counts.get(scope, 0)
            for scope in RepositoryDependencyScope
        },
    }
