from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum, auto
from typing import Any

from ix_blackfox.operating.models import (
    OperatingArtifactKind,
    OperatingArtifactRef,
    OperatingDomain,
    OperatingEnvelope,
    OperatingFinding,
    OperatingSeverity,
    normalize_identifier,
    normalize_optional_text,
    normalize_relative_path,
    normalize_text,
    unique_sorted_enum_tuple,
)


class RepositoryRole(StrEnum):
    """Role a repository plays inside a Wave 10 operating registry."""

    CONTROL_PLANE = auto()
    GOVERNED_REPOSITORY = auto()
    POLICY_PACK = auto()
    EVIDENCE_PRODUCER = auto()
    TEST_HARNESS = auto()
    DOCUMENTATION = auto()
    EXTERNAL_REFERENCE = auto()


class RepositoryDependencyKind(StrEnum):
    """Typed dependency relationship between governed repositories."""

    BUILDS_ON = auto()
    PRODUCES_EVIDENCE_FOR = auto()
    CONSUMES_POLICY_FROM = auto()
    TESTS = auto()
    DOCUMENTS = auto()
    REFERENCES = auto()


class RepositoryRiskLevel(StrEnum):
    """Normalized repository risk level for Wave 10 multi-repo governance."""

    LOW = auto()
    MEDIUM = auto()
    HIGH = auto()
    CRITICAL = auto()


@dataclass(frozen=True, slots=True)
class RepositoryPolicyBinding:
    """Policy pack assignment required for a managed repository."""

    policy_id: str
    policy_pack: str
    version: str
    path: str
    required_controls: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "policy_id",
            normalize_identifier(self.policy_id, label="policy_id"),
        )
        object.__setattr__(
            self,
            "policy_pack",
            normalize_text(self.policy_pack, label="policy_pack"),
        )
        object.__setattr__(self, "version", normalize_text(self.version, label="version"))
        object.__setattr__(self, "path", normalize_relative_path(self.path))
        object.__setattr__(
            self,
            "required_controls",
            normalize_required_controls(self.required_controls),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "policy_pack": self.policy_pack,
            "version": self.version,
            "path": self.path,
            "required_controls": list(self.required_controls),
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class RepositoryEvidenceState:
    """Evidence inventory currently known for a managed repository."""

    repository_id: str
    artifacts: tuple[OperatingArtifactRef, ...] = ()
    missing_artifact_kinds: tuple[OperatingArtifactKind, ...] = ()
    stale_artifact_ids: tuple[str, ...] = ()
    verified: bool = False
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "repository_id",
            normalize_identifier(self.repository_id, label="repository_id"),
        )
        artifacts = tuple(sorted(self.artifacts, key=lambda artifact: artifact.artifact_id))
        artifact_ids = [artifact.artifact_id for artifact in artifacts]
        if len(artifact_ids) != len(set(artifact_ids)):
            raise ValueError("RepositoryEvidenceState artifact_id values must be unique.")
        object.__setattr__(self, "artifacts", artifacts)
        object.__setattr__(
            self,
            "missing_artifact_kinds",
            unique_sorted_enum_tuple(self.missing_artifact_kinds),
        )
        object.__setattr__(
            self,
            "stale_artifact_ids",
            normalize_identifier_tuple(self.stale_artifact_ids, label="stale_artifact_ids"),
        )
        unknown_stale_ids = set(self.stale_artifact_ids) - set(artifact_ids)
        if unknown_stale_ids:
            unknown = ", ".join(sorted(unknown_stale_ids))
            raise ValueError(f"stale artifact ids are not registered: {unknown}")
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def artifact_count(self) -> int:
        return len(self.artifacts)

    @property
    def has_blocking_gap(self) -> bool:
        return bool(self.missing_artifact_kinds or self.stale_artifact_ids or not self.verified)

    def to_dict(self) -> dict[str, Any]:
        return {
            "repository_id": self.repository_id,
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
            "missing_artifact_kinds": [kind.value for kind in self.missing_artifact_kinds],
            "stale_artifact_ids": list(self.stale_artifact_ids),
            "verified": self.verified,
            "artifact_count": self.artifact_count,
            "has_blocking_gap": self.has_blocking_gap,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class RepositoryRiskSurface:
    """Repository risk facts used by the Wave 10 operating scorecard."""

    repository_id: str
    handles_secrets: bool = False
    internet_exposed: bool = False
    production_touching: bool = False
    safety_critical: bool = False
    regulated_data: bool = False
    third_party_dependencies: bool = False
    ai_agent_writes_code: bool = True
    notes: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "repository_id",
            normalize_identifier(self.repository_id, label="repository_id"),
        )
        object.__setattr__(self, "notes", normalize_text_tuple(self.notes, label="notes"))
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def risk_score(self) -> int:
        score = 0
        if self.handles_secrets:
            score += 2
        if self.internet_exposed:
            score += 2
        if self.production_touching:
            score += 2
        if self.safety_critical:
            score += 3
        if self.regulated_data:
            score += 2
        if self.third_party_dependencies:
            score += 1
        if self.ai_agent_writes_code:
            score += 2
        return score

    @property
    def risk_level(self) -> RepositoryRiskLevel:
        if self.risk_score >= 8:
            return RepositoryRiskLevel.CRITICAL
        if self.risk_score >= 5:
            return RepositoryRiskLevel.HIGH
        if self.risk_score >= 2:
            return RepositoryRiskLevel.MEDIUM
        return RepositoryRiskLevel.LOW

    def to_dict(self) -> dict[str, Any]:
        return {
            "repository_id": self.repository_id,
            "handles_secrets": self.handles_secrets,
            "internet_exposed": self.internet_exposed,
            "production_touching": self.production_touching,
            "safety_critical": self.safety_critical,
            "regulated_data": self.regulated_data,
            "third_party_dependencies": self.third_party_dependencies,
            "ai_agent_writes_code": self.ai_agent_writes_code,
            "notes": list(self.notes),
            "risk_score": self.risk_score,
            "risk_level": self.risk_level.value,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class ManagedRepository:
    """A repository governed by the Wave 10 operating registry."""

    repository_id: str
    name: str
    root_path: str
    owner_team_id: str
    roles: tuple[RepositoryRole, ...]
    default_branch: str = "main"
    policy_bindings: tuple[RepositoryPolicyBinding, ...] = ()
    evidence_state: RepositoryEvidenceState | None = None
    risk_surface: RepositoryRiskSurface | None = None
    description: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        repository_id = normalize_identifier(self.repository_id, label="repository_id")
        object.__setattr__(self, "repository_id", repository_id)
        object.__setattr__(self, "name", normalize_text(self.name, label="name"))
        object.__setattr__(self, "root_path", normalize_relative_path(self.root_path))
        object.__setattr__(
            self,
            "owner_team_id",
            normalize_identifier(self.owner_team_id, label="owner_team_id"),
        )
        if not self.roles:
            raise ValueError("ManagedRepository roles must not be empty.")
        object.__setattr__(self, "roles", unique_sorted_enum_tuple(self.roles))
        object.__setattr__(
            self,
            "default_branch",
            normalize_identifier(self.default_branch, label="default_branch"),
        )
        bindings = tuple(sorted(self.policy_bindings, key=lambda item: item.policy_id))
        policy_ids = [binding.policy_id for binding in bindings]
        if len(policy_ids) != len(set(policy_ids)):
            raise ValueError("ManagedRepository policy_id values must be unique.")
        object.__setattr__(self, "policy_bindings", bindings)
        if self.evidence_state is not None and self.evidence_state.repository_id != repository_id:
            raise ValueError("evidence_state repository_id must match ManagedRepository.")
        if self.risk_surface is not None and self.risk_surface.repository_id != repository_id:
            raise ValueError("risk_surface repository_id must match ManagedRepository.")
        object.__setattr__(
            self,
            "description",
            normalize_optional_text(self.description, label="description"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def has_policy_coverage(self) -> bool:
        return bool(self.policy_bindings)

    @property
    def has_verified_evidence(self) -> bool:
        return self.evidence_state is not None and self.evidence_state.verified

    @property
    def risk_level(self) -> RepositoryRiskLevel:
        if self.risk_surface is None:
            return RepositoryRiskLevel.MEDIUM
        return self.risk_surface.risk_level

    def to_dict(self) -> dict[str, Any]:
        return {
            "repository_id": self.repository_id,
            "name": self.name,
            "root_path": self.root_path,
            "owner_team_id": self.owner_team_id,
            "roles": [role.value for role in self.roles],
            "default_branch": self.default_branch,
            "policy_bindings": [binding.to_dict() for binding in self.policy_bindings],
            "evidence_state": (
                self.evidence_state.to_dict() if self.evidence_state is not None else None
            ),
            "risk_surface": self.risk_surface.to_dict() if self.risk_surface is not None else None,
            "risk_level": self.risk_level.value,
            "has_policy_coverage": self.has_policy_coverage,
            "has_verified_evidence": self.has_verified_evidence,
            "description": self.description,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class RepositoryDependency:
    """Directed cross-repository dependency tracked by the operating registry."""

    dependency_id: str
    source_repository_id: str
    target_repository_id: str
    kind: RepositoryDependencyKind
    rationale: str
    required: bool = True
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "dependency_id",
            normalize_identifier(self.dependency_id, label="dependency_id"),
        )
        object.__setattr__(
            self,
            "source_repository_id",
            normalize_identifier(self.source_repository_id, label="source_repository_id"),
        )
        object.__setattr__(
            self,
            "target_repository_id",
            normalize_identifier(self.target_repository_id, label="target_repository_id"),
        )
        if self.source_repository_id == self.target_repository_id:
            raise ValueError("RepositoryDependency cannot target the source repository.")
        object.__setattr__(self, "rationale", normalize_text(self.rationale, label="rationale"))
        object.__setattr__(self, "metadata", dict(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return {
            "dependency_id": self.dependency_id,
            "source_repository_id": self.source_repository_id,
            "target_repository_id": self.target_repository_id,
            "kind": self.kind.value,
            "rationale": self.rationale,
            "required": self.required,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class OperatingRegistry:
    """Deterministic Wave 10 registry for governed multi-repo operations."""

    registry_id: str
    repositories: tuple[ManagedRepository, ...]
    dependencies: tuple[RepositoryDependency, ...] = ()
    generated_by: str = "IX-BlackFox Wave 10 operating registry"
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "registry_id",
            normalize_identifier(self.registry_id, label="registry_id"),
        )
        if not self.repositories:
            raise ValueError("OperatingRegistry repositories must not be empty.")
        repositories = tuple(sorted(self.repositories, key=lambda item: item.repository_id))
        repository_ids = [repository.repository_id for repository in repositories]
        if len(repository_ids) != len(set(repository_ids)):
            raise ValueError("OperatingRegistry repository_id values must be unique.")
        object.__setattr__(self, "repositories", repositories)
        dependencies = tuple(sorted(self.dependencies, key=lambda item: item.dependency_id))
        dependency_ids = [dependency.dependency_id for dependency in dependencies]
        if len(dependency_ids) != len(set(dependency_ids)):
            raise ValueError("OperatingRegistry dependency_id values must be unique.")
        registered_ids = set(repository_ids)
        for dependency in dependencies:
            missing = {
                dependency.source_repository_id,
                dependency.target_repository_id,
            } - registered_ids
            if missing:
                missing_text = ", ".join(sorted(missing))
                raise ValueError(f"dependency references unregistered repository: {missing_text}")
        object.__setattr__(self, "dependencies", dependencies)
        object.__setattr__(
            self,
            "generated_by",
            normalize_text(self.generated_by, label="generated_by"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def repository_ids(self) -> tuple[str, ...]:
        return tuple(repository.repository_id for repository in self.repositories)

    @property
    def root_paths(self) -> tuple[str, ...]:
        return tuple(repository.root_path for repository in self.repositories)

    @property
    def critical_repository_ids(self) -> tuple[str, ...]:
        return tuple(
            repository.repository_id
            for repository in self.repositories
            if repository.risk_level is RepositoryRiskLevel.CRITICAL
        )

    @property
    def findings(self) -> tuple[OperatingFinding, ...]:
        findings: list[OperatingFinding] = []
        for repository in self.repositories:
            if not repository.has_policy_coverage:
                findings.append(
                    OperatingFinding(
                        code="operating.registry.missing-policy-coverage",
                        severity=OperatingSeverity.CRITICAL,
                        summary=(
                            f"Repository {repository.repository_id} has no assigned "
                            "operating policy binding."
                        ),
                        domains=(
                            OperatingDomain.MULTI_REPO,
                            OperatingDomain.POLICY_GOVERNED,
                        ),
                        paths=(repository.root_path,),
                        blocking=True,
                        metadata={"repository_id": repository.repository_id},
                    )
                )
            if not repository.has_verified_evidence:
                findings.append(
                    OperatingFinding(
                        code="operating.registry.missing-verified-evidence",
                        severity=OperatingSeverity.HIGH,
                        summary=(
                            f"Repository {repository.repository_id} does not have "
                            "verified operating evidence."
                        ),
                        domains=(OperatingDomain.MULTI_REPO, OperatingDomain.MEASURABLE),
                        paths=(repository.root_path,),
                        blocking=True,
                        metadata={"repository_id": repository.repository_id},
                    )
                )
            if repository.evidence_state is not None and repository.evidence_state.has_blocking_gap:
                findings.append(
                    OperatingFinding(
                        code="operating.registry.evidence-gap",
                        severity=OperatingSeverity.HIGH,
                        summary=(
                            f"Repository {repository.repository_id} has missing, stale, "
                            "or unverified evidence."
                        ),
                        domains=(OperatingDomain.MULTI_REPO, OperatingDomain.MEASURABLE),
                        paths=(repository.root_path,),
                        blocking=True,
                        metadata={"repository_id": repository.repository_id},
                    )
                )
        return tuple(sorted(findings, key=lambda finding: (finding.code, finding.summary)))

    @property
    def disposition(self) -> str:
        envelope = self.to_envelope()
        return envelope.disposition.value

    def repositories_by_role(self, role: RepositoryRole) -> tuple[ManagedRepository, ...]:
        return tuple(repository for repository in self.repositories if role in repository.roles)

    def dependency_edges(self) -> tuple[tuple[str, str, str], ...]:
        return tuple(
            (
                dependency.source_repository_id,
                dependency.target_repository_id,
                dependency.kind.value,
            )
            for dependency in self.dependencies
        )

    def to_envelope(self) -> OperatingEnvelope:
        return OperatingEnvelope(
            envelope_id=f"{self.registry_id}-registry-envelope",
            artifact_kind=OperatingArtifactKind.REPOSITORY_REGISTRY,
            subject=f"Wave 10 operating registry {self.registry_id}",
            domains=(
                OperatingDomain.MULTI_REPO,
                OperatingDomain.POLICY_GOVERNED,
                OperatingDomain.MEASURABLE,
            ),
            findings=self.findings,
            metadata={
                "registry_id": self.registry_id,
                "repository_ids": list(self.repository_ids),
                "dependency_edges": [list(edge) for edge in self.dependency_edges()],
                "critical_repository_ids": list(self.critical_repository_ids),
            },
        )

    def to_dict(self) -> dict[str, Any]:
        envelope = self.to_envelope()
        return {
            "registry_id": self.registry_id,
            "generated_by": self.generated_by,
            "repositories": [repository.to_dict() for repository in self.repositories],
            "dependencies": [dependency.to_dict() for dependency in self.dependencies],
            "repository_count": len(self.repositories),
            "dependency_count": len(self.dependencies),
            "critical_repository_ids": list(self.critical_repository_ids),
            "findings": [finding.to_dict() for finding in self.findings],
            "disposition": envelope.disposition.value,
            "digest": envelope.digest,
            "metadata": dict(self.metadata),
        }


def normalize_identifier_tuple(values: Sequence[str], *, label: str) -> tuple[str, ...]:
    normalized: list[str] = []
    seen: set[str] = set()
    for value in values:
        item = normalize_identifier(value, label=label)
        if item not in seen:
            normalized.append(item)
            seen.add(item)
    return tuple(sorted(normalized))


def normalize_required_controls(values: Sequence[str]) -> tuple[str, ...]:
    normalized: list[str] = []
    seen: set[str] = set()
    for value in values:
        item = normalize_text(value, label="required_control")
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
    return tuple(sorted(normalized))
