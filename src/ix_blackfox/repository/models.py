from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum, auto
from pathlib import PurePosixPath
from typing import Any

_SHA256_LENGTH = 64


class RepositoryFileRole(StrEnum):
    SOURCE = auto()
    TEST = auto()
    DOCUMENTATION = auto()
    CONFIGURATION = auto()
    WORKFLOW = auto()
    SCRIPT = auto()
    LICENSE = auto()
    ARTIFACT = auto()
    UNKNOWN = auto()


class RepositorySensitivity(StrEnum):
    NORMAL = auto()
    POLICY_RELEVANT = auto()
    SECURITY_RELEVANT = auto()
    RELEASE_RELEVANT = auto()
    GENERATED_OR_ARTIFACT = auto()


class RepositoryNodeKind(StrEnum):
    MODULE = auto()
    CLASS = auto()
    FUNCTION = auto()
    METHOD = auto()
    IMPORT = auto()
    CONSTANT = auto()


class RepositoryEdgeKind(StrEnum):
    IMPORTS = auto()
    DEFINES = auto()
    TESTS = auto()
    OWNS = auto()
    IMPACTS = auto()
    REFERENCES = auto()


class RepositoryDependencyScope(StrEnum):
    INTERNAL = auto()
    RUNTIME = auto()
    DEVELOPMENT = auto()
    BUILD = auto()
    WORKFLOW = auto()
    UNKNOWN = auto()


class RepositoryImpactSeverity(StrEnum):
    NONE = auto()
    LOW = auto()
    MEDIUM = auto()
    HIGH = auto()
    CRITICAL = auto()


@dataclass(frozen=True, slots=True)
class RepositoryFileRecord:
    path: str
    role: RepositoryFileRole
    sha256: str
    size_bytes: int
    sensitivity: RepositorySensitivity = RepositorySensitivity.NORMAL
    executable: bool = False
    generated: bool = False
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", normalize_relative_path(self.path))
        object.__setattr__(self, "sha256", normalize_sha256(self.sha256))
        if self.size_bytes < 0:
            raise ValueError("size_bytes must be zero or greater.")
        object.__setattr__(self, "metadata", dict(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "role": self.role.value,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "sensitivity": self.sensitivity.value,
            "executable": self.executable,
            "generated": self.generated,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class RepositorySnapshot:
    snapshot_id: str
    root_label: str
    files: tuple[RepositoryFileRecord, ...]
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "snapshot_id",
            normalize_identifier(self.snapshot_id, label="snapshot_id"),
        )
        object.__setattr__(
            self,
            "root_label",
            normalize_text(self.root_label, label="root_label"),
        )
        files = tuple(sorted(self.files, key=lambda item: item.path))
        paths = [file_record.path for file_record in files]
        if len(paths) != len(set(paths)):
            raise ValueError("RepositorySnapshot file paths must be unique.")
        object.__setattr__(self, "files", files)
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def file_count(self) -> int:
        return len(self.files)

    @property
    def total_bytes(self) -> int:
        return sum(file_record.size_bytes for file_record in self.files)

    @property
    def digest(self) -> str:
        return digest_payload(self.to_dict(include_digest=False))

    def paths_by_role(self, role: RepositoryFileRole) -> tuple[str, ...]:
        return tuple(file_record.path for file_record in self.files if file_record.role is role)

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "snapshot_id": self.snapshot_id,
            "root_label": self.root_label,
            "file_count": self.file_count,
            "total_bytes": self.total_bytes,
            "files": [file_record.to_dict() for file_record in self.files],
            "metadata": dict(self.metadata),
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload


@dataclass(frozen=True, slots=True)
class RepositorySymbolRecord:
    path: str
    qualified_name: str
    kind: RepositoryNodeKind
    line: int
    column: int = 0
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", normalize_relative_path(self.path))
        object.__setattr__(
            self,
            "qualified_name",
            normalize_dotted_name(self.qualified_name, label="qualified_name"),
        )
        if self.line <= 0:
            raise ValueError("line must be greater than zero.")
        if self.column < 0:
            raise ValueError("column must be zero or greater.")
        object.__setattr__(self, "metadata", dict(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "qualified_name": self.qualified_name,
            "kind": self.kind.value,
            "line": self.line,
            "column": self.column,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class RepositoryGraphEdge:
    source: str
    target: str
    kind: RepositoryEdgeKind
    scope: RepositoryDependencyScope = RepositoryDependencyScope.INTERNAL
    reason: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "source", normalize_graph_ref(self.source, label="source"))
        object.__setattr__(self, "target", normalize_graph_ref(self.target, label="target"))
        object.__setattr__(self, "reason", self.reason.strip())
        object.__setattr__(self, "metadata", dict(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "kind": self.kind.value,
            "scope": self.scope.value,
            "reason": self.reason,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class RepositoryCodeGraph:
    graph_id: str
    symbols: tuple[RepositorySymbolRecord, ...] = ()
    edges: tuple[RepositoryGraphEdge, ...] = ()
    syntax_error_paths: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "graph_id",
            normalize_identifier(self.graph_id, label="graph_id"),
        )
        object.__setattr__(
            self,
            "symbols",
            tuple(sorted(self.symbols, key=lambda item: (item.path, item.qualified_name))),
        )
        object.__setattr__(
            self,
            "edges",
            tuple(sorted(self.edges, key=lambda item: (item.source, item.target, item.kind.value))),
        )
        syntax_error_paths = normalize_path_tuple(
            self.syntax_error_paths,
            label="syntax_error_paths",
        )
        object.__setattr__(self, "syntax_error_paths", syntax_error_paths)
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def symbol_count(self) -> int:
        return len(self.symbols)

    @property
    def edge_count(self) -> int:
        return len(self.edges)

    @property
    def digest(self) -> str:
        return digest_payload(self.to_dict(include_digest=False))

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "graph_id": self.graph_id,
            "symbol_count": self.symbol_count,
            "edge_count": self.edge_count,
            "symbols": [symbol.to_dict() for symbol in self.symbols],
            "edges": [edge.to_dict() for edge in self.edges],
            "syntax_error_paths": list(self.syntax_error_paths),
            "metadata": dict(self.metadata),
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload


@dataclass(frozen=True, slots=True)
class RepositoryDependencyRecord:
    name: str
    scope: RepositoryDependencyScope
    source: str
    specifier: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", normalize_dependency_name(self.name))
        object.__setattr__(self, "source", normalize_text(self.source, label="source"))
        object.__setattr__(self, "specifier", self.specifier.strip())
        object.__setattr__(self, "metadata", dict(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "scope": self.scope.value,
            "source": self.source,
            "specifier": self.specifier,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class RepositoryDependencyMap:
    map_id: str
    dependencies: tuple[RepositoryDependencyRecord, ...] = ()
    internal_edges: tuple[RepositoryGraphEdge, ...] = ()
    sensitive_paths: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "map_id",
            normalize_identifier(self.map_id, label="map_id"),
        )
        object.__setattr__(
            self,
            "dependencies",
            tuple(sorted(self.dependencies, key=lambda item: (item.scope.value, item.name))),
        )
        object.__setattr__(
            self,
            "internal_edges",
            tuple(sorted(self.internal_edges, key=lambda item: (item.source, item.target))),
        )
        object.__setattr__(
            self,
            "sensitive_paths",
            normalize_path_tuple(self.sensitive_paths, label="sensitive_paths"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def digest(self) -> str:
        return digest_payload(self.to_dict(include_digest=False))

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "map_id": self.map_id,
            "dependencies": [dependency.to_dict() for dependency in self.dependencies],
            "internal_edges": [edge.to_dict() for edge in self.internal_edges],
            "sensitive_paths": list(self.sensitive_paths),
            "metadata": dict(self.metadata),
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload


@dataclass(frozen=True, slots=True)
class RepositoryCoverageLink:
    source_path: str
    test_path: str
    confidence: int
    reason: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "source_path", normalize_relative_path(self.source_path))
        object.__setattr__(self, "test_path", normalize_relative_path(self.test_path))
        if not 0 <= self.confidence <= 100:
            raise ValueError("confidence must be between 0 and 100.")
        object.__setattr__(self, "reason", normalize_text(self.reason, label="reason"))

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_path": self.source_path,
            "test_path": self.test_path,
            "confidence": self.confidence,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class RepositoryArchitectureRecord:
    record_id: str
    subsystem: str
    owned_paths: tuple[str, ...]
    responsibilities: tuple[str, ...]
    constraints: tuple[str, ...] = ()
    evidence_expectations: tuple[str, ...] = ()
    wave: int = 8
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "record_id",
            normalize_identifier(self.record_id, label="record_id"),
        )
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
        object.__setattr__(
            self,
            "responsibilities",
            normalize_text_tuple(self.responsibilities, label="responsibilities"),
        )
        if not self.responsibilities:
            raise ValueError("responsibilities must not be empty.")
        object.__setattr__(
            self,
            "constraints",
            normalize_text_tuple(self.constraints, label="constraints"),
        )
        object.__setattr__(
            self,
            "evidence_expectations",
            normalize_text_tuple(
                self.evidence_expectations,
                label="evidence_expectations",
            ),
        )
        if self.wave <= 0:
            raise ValueError("wave must be greater than zero.")
        object.__setattr__(self, "metadata", dict(self.metadata))

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
            "record_id": self.record_id,
            "subsystem": self.subsystem,
            "owned_paths": list(self.owned_paths),
            "responsibilities": list(self.responsibilities),
            "constraints": list(self.constraints),
            "evidence_expectations": list(self.evidence_expectations),
            "wave": self.wave,
            "metadata": dict(self.metadata),
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload


@dataclass(frozen=True, slots=True)
class RepositoryImpactFinding:
    code: str
    severity: RepositoryImpactSeverity
    summary: str
    paths: tuple[str, ...] = ()
    review_required: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "code", normalize_dotted_name(self.code, label="code"))
        object.__setattr__(self, "summary", normalize_text(self.summary, label="summary"))
        object.__setattr__(self, "paths", normalize_path_tuple(self.paths, label="paths"))

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "severity": self.severity.value,
            "summary": self.summary,
            "paths": list(self.paths),
            "review_required": self.review_required,
        }


@dataclass(frozen=True, slots=True)
class RepositoryImpactReport:
    report_id: str
    changed_paths: tuple[str, ...]
    impacted_paths: tuple[str, ...] = ()
    impacted_tests: tuple[str, ...] = ()
    impacted_subsystems: tuple[str, ...] = ()
    findings: tuple[RepositoryImpactFinding, ...] = ()
    recommended_commands: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "report_id",
            normalize_identifier(self.report_id, label="report_id"),
        )
        object.__setattr__(
            self,
            "changed_paths",
            normalize_path_tuple(self.changed_paths, label="changed_paths"),
        )
        if not self.changed_paths:
            raise ValueError("changed_paths must not be empty.")
        object.__setattr__(
            self,
            "impacted_paths",
            normalize_path_tuple(self.impacted_paths, label="impacted_paths"),
        )
        object.__setattr__(
            self,
            "impacted_tests",
            normalize_path_tuple(self.impacted_tests, label="impacted_tests"),
        )
        object.__setattr__(
            self,
            "impacted_subsystems",
            normalize_identifier_tuple(
                self.impacted_subsystems,
                label="impacted_subsystems",
            ),
        )
        object.__setattr__(
            self,
            "findings",
            tuple(sorted(self.findings, key=lambda item: (item.severity.value, item.code))),
        )
        object.__setattr__(
            self,
            "recommended_commands",
            normalize_text_tuple(self.recommended_commands, label="recommended_commands"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def requires_human_review(self) -> bool:
        return any(finding.review_required for finding in self.findings)

    @property
    def max_severity(self) -> RepositoryImpactSeverity:
        order = {
            RepositoryImpactSeverity.NONE: 0,
            RepositoryImpactSeverity.LOW: 1,
            RepositoryImpactSeverity.MEDIUM: 2,
            RepositoryImpactSeverity.HIGH: 3,
            RepositoryImpactSeverity.CRITICAL: 4,
        }
        if not self.findings:
            return RepositoryImpactSeverity.NONE
        return max((finding.severity for finding in self.findings), key=order.__getitem__)

    @property
    def digest(self) -> str:
        return digest_payload(self.to_dict(include_digest=False))

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "report_id": self.report_id,
            "changed_paths": list(self.changed_paths),
            "impacted_paths": list(self.impacted_paths),
            "impacted_tests": list(self.impacted_tests),
            "impacted_subsystems": list(self.impacted_subsystems),
            "findings": [finding.to_dict() for finding in self.findings],
            "recommended_commands": list(self.recommended_commands),
            "requires_human_review": self.requires_human_review,
            "max_severity": self.max_severity.value,
            "metadata": dict(self.metadata),
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload


def digest_payload(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    return hashlib.sha256(encoded).hexdigest()


def normalize_identifier(value: str, *, label: str) -> str:
    cleaned = value.strip().lower().replace("_", "-").replace(" ", "-")
    while "--" in cleaned:
        cleaned = cleaned.replace("--", "-")
    cleaned = cleaned.strip("-")
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def normalize_dotted_name(value: str, *, label: str) -> str:
    cleaned = value.strip().replace("/", ".")
    cleaned = ".".join(part.strip() for part in cleaned.split(".") if part.strip())
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def normalize_dependency_name(value: str) -> str:
    cleaned = value.strip().lower().replace("_", "-")
    if not cleaned:
        raise ValueError("dependency name must not be empty.")
    return cleaned


def normalize_graph_ref(value: str, *, label: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def normalize_text(value: str, *, label: str) -> str:
    cleaned = " ".join(value.strip().split())
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def normalize_sha256(value: str) -> str:
    cleaned = value.strip().lower()
    if len(cleaned) != _SHA256_LENGTH or any(char not in "0123456789abcdef" for char in cleaned):
        raise ValueError("sha256 must be a 64-character lowercase hexadecimal digest.")
    return cleaned


def normalize_relative_path(value: str) -> str:
    cleaned = value.strip().replace("\\", "/")
    if not cleaned:
        raise ValueError("path must not be empty.")
    path = PurePosixPath(cleaned)
    if path.is_absolute():
        raise ValueError("path must be repository-relative.")
    if any(part == ".." for part in path.parts):
        raise ValueError("path traversal is not allowed.")
    return path.as_posix()


def normalize_identifier_tuple(values: Sequence[str], *, label: str) -> tuple[str, ...]:
    normalized: list[str] = []
    seen: set[str] = set()
    for value in values:
        item = normalize_identifier(value, label=label)
        if item not in seen:
            normalized.append(item)
            seen.add(item)
    return tuple(normalized)


def normalize_path_tuple(values: Sequence[str], *, label: str) -> tuple[str, ...]:
    normalized: list[str] = []
    seen: set[str] = set()
    for value in values:
        item = normalize_relative_path(value)
        if item not in seen:
            normalized.append(item)
            seen.add(item)
    return tuple(sorted(normalized))


def normalize_text_tuple(values: Sequence[str], *, label: str) -> tuple[str, ...]:
    normalized: list[str] = []
    seen: set[str] = set()
    for value in values:
        item = normalize_text(value, label=label)
        if item not in seen:
            normalized.append(item)
            seen.add(item)
    return tuple(normalized)
