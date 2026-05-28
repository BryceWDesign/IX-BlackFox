from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any

from ix_blackfox.repository.models import (
    RepositoryCodeGraph,
    RepositoryCoverageLink,
    RepositoryFileRole,
    RepositorySensitivity,
    RepositorySnapshot,
    digest_payload,
    normalize_identifier,
    normalize_path_tuple,
    normalize_relative_path,
    normalize_text,
)
from ix_blackfox.repository.python_graph import module_name_from_path


@dataclass(frozen=True, slots=True)
class RepositorySubsystemRecord:
    subsystem: str
    owned_paths: tuple[str, ...]
    source_paths: tuple[str, ...] = ()
    test_paths: tuple[str, ...] = ()
    documentation_paths: tuple[str, ...] = ()
    configuration_paths: tuple[str, ...] = ()
    sensitive_paths: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "subsystem",
            normalize_identifier(self.subsystem, label="subsystem"),
        )
        object.__setattr__(
            self,
            "owned_paths",
            normalize_path_tuple(self.owned_paths, label="owned_paths"),
        )
        if not self.owned_paths:
            raise ValueError("owned_paths must not be empty.")
        object.__setattr__(
            self,
            "source_paths",
            normalize_path_tuple(self.source_paths, label="source_paths"),
        )
        object.__setattr__(
            self,
            "test_paths",
            normalize_path_tuple(self.test_paths, label="test_paths"),
        )
        object.__setattr__(
            self,
            "documentation_paths",
            normalize_path_tuple(
                self.documentation_paths,
                label="documentation_paths",
            ),
        )
        object.__setattr__(
            self,
            "configuration_paths",
            normalize_path_tuple(
                self.configuration_paths,
                label="configuration_paths",
            ),
        )
        object.__setattr__(
            self,
            "sensitive_paths",
            normalize_path_tuple(self.sensitive_paths, label="sensitive_paths"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def file_count(self) -> int:
        return len(
            set(
                self.source_paths
                + self.test_paths
                + self.documentation_paths
                + self.configuration_paths
            )
        )

    @property
    def digest(self) -> str:
        return digest_payload(self.to_dict(include_digest=False))

    def owns_path(self, path: str) -> bool:
        normalized = normalize_relative_path(path)
        return any(
            normalized == owned_path or normalized.startswith(f"{owned_path.rstrip('/')}/")
            for owned_path in self.owned_paths
        )

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "subsystem": self.subsystem,
            "owned_paths": list(self.owned_paths),
            "source_paths": list(self.source_paths),
            "test_paths": list(self.test_paths),
            "documentation_paths": list(self.documentation_paths),
            "configuration_paths": list(self.configuration_paths),
            "sensitive_paths": list(self.sensitive_paths),
            "file_count": self.file_count,
            "metadata": dict(self.metadata),
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload


@dataclass(frozen=True, slots=True)
class RepositoryCoverageMap:
    map_id: str
    links: tuple[RepositoryCoverageLink, ...] = ()
    subsystems: tuple[RepositorySubsystemRecord, ...] = ()
    orphan_source_paths: tuple[str, ...] = ()
    orphan_test_paths: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "map_id",
            normalize_identifier(self.map_id, label="map_id"),
        )
        object.__setattr__(
            self,
            "links",
            tuple(
                sorted(
                    self.links,
                    key=lambda item: (item.source_path, item.test_path, item.confidence),
                )
            ),
        )
        object.__setattr__(
            self,
            "subsystems",
            tuple(sorted(self.subsystems, key=lambda item: item.subsystem)),
        )
        object.__setattr__(
            self,
            "orphan_source_paths",
            normalize_path_tuple(
                self.orphan_source_paths,
                label="orphan_source_paths",
            ),
        )
        object.__setattr__(
            self,
            "orphan_test_paths",
            normalize_path_tuple(
                self.orphan_test_paths,
                label="orphan_test_paths",
            ),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def link_count(self) -> int:
        return len(self.links)

    @property
    def subsystem_count(self) -> int:
        return len(self.subsystems)

    @property
    def digest(self) -> str:
        return digest_payload(self.to_dict(include_digest=False))

    def tests_for_source(self, source_path: str) -> tuple[str, ...]:
        normalized = normalize_relative_path(source_path)
        return tuple(
            link.test_path for link in self.links if link.source_path == normalized
        )

    def subsystems_for_path(self, path: str) -> tuple[str, ...]:
        normalized = normalize_relative_path(path)
        return tuple(
            subsystem.subsystem
            for subsystem in self.subsystems
            if subsystem.owns_path(normalized)
        )

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "map_id": self.map_id,
            "link_count": self.link_count,
            "subsystem_count": self.subsystem_count,
            "links": [link.to_dict() for link in self.links],
            "subsystems": [subsystem.to_dict() for subsystem in self.subsystems],
            "orphan_source_paths": list(self.orphan_source_paths),
            "orphan_test_paths": list(self.orphan_test_paths),
            "metadata": dict(self.metadata),
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload


@dataclass(frozen=True, slots=True)
class RepositoryCoverageMapper:
    """Infer conservative source-test and subsystem relationships."""

    minimum_stem_confidence: int = 70

    def build(
        self,
        snapshot: RepositorySnapshot,
        graph: RepositoryCodeGraph | None = None,
        *,
        map_id: str = "wave-8-repository-coverage-map",
    ) -> RepositoryCoverageMap:
        source_paths = tuple(
            file_record.path
            for file_record in snapshot.files
            if file_record.role is RepositoryFileRole.SOURCE
            and file_record.path.endswith(".py")
        )
        test_paths = tuple(
            file_record.path
            for file_record in snapshot.files
            if file_record.role is RepositoryFileRole.TEST
            and file_record.path.endswith(".py")
        )

        links = infer_source_test_links(
            source_paths=source_paths,
            test_paths=test_paths,
            graph=graph,
            minimum_stem_confidence=self.minimum_stem_confidence,
        )
        linked_sources = {link.source_path for link in links}
        linked_tests = {link.test_path for link in links}

        subsystems = infer_subsystem_records(snapshot)

        return RepositoryCoverageMap(
            map_id=map_id,
            links=links,
            subsystems=subsystems,
            orphan_source_paths=tuple(
                path
                for path in source_paths
                if path not in linked_sources and not path.endswith("/__init__.py")
            ),
            orphan_test_paths=tuple(path for path in test_paths if path not in linked_tests),
            metadata={
                "source_path_count": len(source_paths),
                "test_path_count": len(test_paths),
                "graph_used": graph is not None,
                "heuristics": [
                    "direct source/test path mirror",
                    "test import edge resolved by Python graph",
                    "same-subsystem test filename stem match",
                ],
            },
        )


def build_coverage_map(
    snapshot: RepositorySnapshot,
    graph: RepositoryCodeGraph | None = None,
    *,
    map_id: str = "wave-8-repository-coverage-map",
) -> RepositoryCoverageMap:
    """Convenience wrapper for the default Wave 8 coverage map."""
    return RepositoryCoverageMapper().build(snapshot, graph, map_id=map_id)


def infer_source_test_links(
    *,
    source_paths: Sequence[str],
    test_paths: Sequence[str],
    graph: RepositoryCodeGraph | None = None,
    minimum_stem_confidence: int = 70,
) -> tuple[RepositoryCoverageLink, ...]:
    normalized_sources = tuple(normalize_relative_path(path) for path in source_paths)
    normalized_tests = tuple(normalize_relative_path(path) for path in test_paths)
    source_set = set(normalized_sources)
    test_set = set(normalized_tests)

    links: dict[tuple[str, str], RepositoryCoverageLink] = {}

    for source_path in normalized_sources:
        for test_path, confidence, reason in direct_test_candidates(source_path, test_set):
            links[(source_path, test_path)] = RepositoryCoverageLink(
                source_path=source_path,
                test_path=test_path,
                confidence=confidence,
                reason=reason,
            )

    if graph is not None:
        for source_path, test_path in graph_based_links(graph, source_set, test_set):
            links[(source_path, test_path)] = choose_stronger_link(
                links.get((source_path, test_path)),
                RepositoryCoverageLink(
                    source_path=source_path,
                    test_path=test_path,
                    confidence=95,
                    reason="Python graph shows the test module importing this source module.",
                ),
            )

    for source_path in normalized_sources:
        for test_path, confidence, reason in stem_match_candidates(
            source_path,
            normalized_tests,
            minimum_confidence=minimum_stem_confidence,
        ):
            key = (source_path, test_path)
            links[key] = choose_stronger_link(
                links.get(key),
                RepositoryCoverageLink(
                    source_path=source_path,
                    test_path=test_path,
                    confidence=confidence,
                    reason=reason,
                ),
            )

    return tuple(sorted(links.values(), key=lambda item: (item.source_path, item.test_path)))


def direct_test_candidates(
    source_path: str,
    test_paths: set[str],
) -> tuple[tuple[str, int, str], ...]:
    if not source_path.startswith("src/ix_blackfox/") or not source_path.endswith(".py"):
        return ()

    relative = source_path.removeprefix("src/ix_blackfox/")
    pure_path = PurePosixPath(relative)
    module_stem = pure_path.stem
    if module_stem == "__init__":
        return ()

    package_parts = pure_path.parent.parts
    candidates: list[str] = []
    candidates.append(
        PurePosixPath("tests", *package_parts, f"test_{module_stem}.py").as_posix()
    )
    if package_parts:
        candidates.append(
            PurePosixPath("tests", package_parts[0], f"test_{module_stem}.py").as_posix()
        )

    matched: list[tuple[str, int, str]] = []
    for candidate in dict.fromkeys(candidates):
        if candidate in test_paths:
            matched.append(
                (
                    candidate,
                    90,
                    "Path mirror maps the source module to this test module.",
                )
            )
    return tuple(matched)


def graph_based_links(
    graph: RepositoryCodeGraph,
    source_paths: set[str],
    test_paths: set[str],
) -> tuple[tuple[str, str], ...]:
    pairs: list[tuple[str, str]] = []
    for edge in graph.edges:
        source_path = str(edge.metadata.get("source_path") or "")
        target_path = str(edge.metadata.get("resolved_path") or "")
        if source_path in test_paths and target_path in source_paths:
            pairs.append((target_path, source_path))
    return tuple(sorted(set(pairs)))


def stem_match_candidates(
    source_path: str,
    test_paths: Sequence[str],
    *,
    minimum_confidence: int,
) -> tuple[tuple[str, int, str], ...]:
    if not source_path.startswith("src/ix_blackfox/") or not source_path.endswith(".py"):
        return ()

    module_stem = PurePosixPath(source_path).stem
    if module_stem == "__init__":
        return ()

    source_subsystem = infer_subsystem_id(source_path)
    matches: list[tuple[str, int, str]] = []
    for test_path in test_paths:
        test_name = PurePosixPath(test_path).stem
        test_subsystem = infer_subsystem_id(test_path)
        if source_subsystem != test_subsystem:
            continue
        if module_stem not in test_name:
            continue
        matches.append(
            (
                test_path,
                minimum_confidence,
                "Same-subsystem test filename contains the source module stem.",
            )
        )
    return tuple(matches)


def choose_stronger_link(
    existing: RepositoryCoverageLink | None,
    candidate: RepositoryCoverageLink,
) -> RepositoryCoverageLink:
    if existing is None:
        return candidate
    if candidate.confidence > existing.confidence:
        return candidate
    return existing


def infer_subsystem_records(
    snapshot: RepositorySnapshot,
) -> tuple[RepositorySubsystemRecord, ...]:
    grouped: dict[str, dict[str, list[str]]] = defaultdict(
        lambda: {
            "source_paths": [],
            "test_paths": [],
            "documentation_paths": [],
            "configuration_paths": [],
            "sensitive_paths": [],
        }
    )

    for file_record in snapshot.files:
        subsystem = infer_subsystem_id(file_record.path)
        if subsystem is None:
            continue
        bucket = grouped[subsystem]
        if file_record.role is RepositoryFileRole.SOURCE:
            bucket["source_paths"].append(file_record.path)
        elif file_record.role is RepositoryFileRole.TEST:
            bucket["test_paths"].append(file_record.path)
        elif file_record.role is RepositoryFileRole.DOCUMENTATION:
            bucket["documentation_paths"].append(file_record.path)
        elif file_record.role in {
            RepositoryFileRole.CONFIGURATION,
            RepositoryFileRole.WORKFLOW,
            RepositoryFileRole.SCRIPT,
            RepositoryFileRole.LICENSE,
        }:
            bucket["configuration_paths"].append(file_record.path)
        if file_record.sensitivity is not RepositorySensitivity.NORMAL:
            bucket["sensitive_paths"].append(file_record.path)

    records: list[RepositorySubsystemRecord] = []
    for subsystem, paths in sorted(grouped.items()):
        records.append(
            RepositorySubsystemRecord(
                subsystem=subsystem,
                owned_paths=owned_paths_for_subsystem(subsystem),
                source_paths=tuple(paths["source_paths"]),
                test_paths=tuple(paths["test_paths"]),
                documentation_paths=tuple(paths["documentation_paths"]),
                configuration_paths=tuple(paths["configuration_paths"]),
                sensitive_paths=tuple(paths["sensitive_paths"]),
                metadata={"inferred": True},
            )
        )
    return tuple(records)


def infer_subsystem_id(path: str) -> str | None:
    normalized = normalize_relative_path(path)
    parts = PurePosixPath(normalized).parts

    if len(parts) >= 3 and parts[0] == "src" and parts[1] == "ix_blackfox":
        return "package-root" if parts[2] == "__init__.py" else parts[2]
    if len(parts) >= 2 and parts[0] == "tests":
        return "tests-root" if parts[1] == "__init__.py" else parts[1]
    if normalized.startswith(".github/workflows/"):
        return "ci-workflows"
    if normalized.startswith("scripts/"):
        return "scripts"
    if normalized.startswith("docs/"):
        return "docs"
    if normalized in {
        ".blackfox-workspace",
        ".editorconfig",
        ".gitattributes",
        ".gitignore",
        "COMMERCIAL.md",
        "LICENSE",
        "NOTICE.md",
        "README.md",
        "blackfox.policy.toml",
        "pyproject.toml",
    }:
        return "repo-governance"
    return None


def owned_paths_for_subsystem(subsystem: str) -> tuple[str, ...]:
    normalized = normalize_identifier(subsystem, label="subsystem")
    if normalized == "package-root":
        return ("src/ix_blackfox/__init__.py",)
    if normalized == "tests-root":
        return ("tests/__init__.py",)
    if normalized == "ci-workflows":
        return (".github/workflows",)
    if normalized == "scripts":
        return ("scripts",)
    if normalized == "docs":
        return ("docs",)
    if normalized == "repo-governance":
        return (
            ".blackfox-workspace",
            ".editorconfig",
            ".gitattributes",
            ".gitignore",
            "COMMERCIAL.md",
            "LICENSE",
            "NOTICE.md",
            "README.md",
            "blackfox.policy.toml",
            "pyproject.toml",
        )
    return (f"src/ix_blackfox/{normalized}", f"tests/{normalized}")


def source_module_test_candidates(source_path: str) -> tuple[str, ...]:
    normalized = normalize_relative_path(source_path)
    if not normalized.startswith("src/ix_blackfox/") or not normalized.endswith(".py"):
        return ()
    relative = normalized.removeprefix("src/ix_blackfox/")
    pure_path = PurePosixPath(relative)
    if pure_path.stem == "__init__":
        return ()
    package_parts = pure_path.parent.parts
    candidates = [
        PurePosixPath("tests", *package_parts, f"test_{pure_path.stem}.py").as_posix()
    ]
    if package_parts:
        candidates.append(
            PurePosixPath("tests", package_parts[0], f"test_{pure_path.stem}.py").as_posix()
        )
    return tuple(dict.fromkeys(candidates))


def module_path_lookup(snapshot: RepositorySnapshot) -> dict[str, str]:
    return {
        module_name_from_path(file_record.path): file_record.path
        for file_record in snapshot.files
        if file_record.path.endswith(".py")
        and file_record.role in {RepositoryFileRole.SOURCE, RepositoryFileRole.TEST}
    }
