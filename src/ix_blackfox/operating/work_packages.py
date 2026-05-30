from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum, auto
from typing import Any

from ix_blackfox.operating.models import (
    OperatingArtifactKind,
    OperatingDomain,
    OperatingEnvelope,
    OperatingFinding,
    OperatingSeverity,
    OperatingSourceWave,
    normalize_identifier,
    normalize_optional_text,
    normalize_relative_path,
    normalize_text,
    unique_sorted_enum_tuple,
)
from ix_blackfox.operating.registry import normalize_identifier_tuple, normalize_text_tuple


class WorkPackageStatus(StrEnum):
    """Lifecycle state for a bounded Wave 10 operating work package."""

    PROPOSED = auto()
    READY_FOR_REVIEW = auto()
    APPROVED = auto()
    IN_PROGRESS = auto()
    COMPLETED = auto()
    BLOCKED = auto()
    REJECTED = auto()


class WorkPackageDependencyKind(StrEnum):
    """Relationship between operating work packages."""

    REQUIRES = auto()
    BLOCKS = auto()
    PRODUCES_EVIDENCE_FOR = auto()
    VALIDATES = auto()
    ROLLBACK_DEPENDS_ON = auto()


class ValidationKind(StrEnum):
    """Validation categories that can be required before a work package is ready."""

    UNIT_TEST = auto()
    INTEGRATION_TEST = auto()
    POLICY_EVALUATION = auto()
    SCHEMA_VALIDATION = auto()
    STATIC_ANALYSIS = auto()
    TYPE_CHECK = auto()
    SECURITY_SCAN = auto()
    SUPPLY_CHAIN_CHECK = auto()
    REPLAY_CHECK = auto()
    HUMAN_REVIEW = auto()


@dataclass(frozen=True, slots=True)
class EvidenceRequirement:
    """Required evidence that must bind a work package to reviewable artifacts."""

    requirement_id: str
    artifact_kind: OperatingArtifactKind
    source_wave: OperatingSourceWave
    description: str
    mandatory: bool = True
    satisfied_by_artifact_ids: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "requirement_id",
            normalize_identifier(self.requirement_id, label="requirement_id"),
        )
        object.__setattr__(self, "description", normalize_text(self.description, label="description"))
        object.__setattr__(
            self,
            "satisfied_by_artifact_ids",
            normalize_identifier_tuple(
                self.satisfied_by_artifact_ids,
                label="satisfied_by_artifact_ids",
            ),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def satisfied(self) -> bool:
        return bool(self.satisfied_by_artifact_ids)

    @property
    def blocking_gap(self) -> bool:
        return self.mandatory and not self.satisfied

    def to_dict(self) -> dict[str, Any]:
        return {
            "requirement_id": self.requirement_id,
            "artifact_kind": self.artifact_kind.value,
            "source_wave": self.source_wave.value,
            "description": self.description,
            "mandatory": self.mandatory,
            "satisfied": self.satisfied,
            "satisfied_by_artifact_ids": list(self.satisfied_by_artifact_ids),
            "blocking_gap": self.blocking_gap,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class RequiredValidation:
    """Validation command or review action required by a work package."""

    validation_id: str
    kind: ValidationKind
    description: str
    command: tuple[str, ...] = ()
    expected_artifact_ids: tuple[str, ...] = ()
    passed: bool = False
    required: bool = True
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "validation_id",
            normalize_identifier(self.validation_id, label="validation_id"),
        )
        object.__setattr__(self, "description", normalize_text(self.description, label="description"))
        object.__setattr__(self, "command", normalize_command_tuple(self.command))
        object.__setattr__(
            self,
            "expected_artifact_ids",
            normalize_identifier_tuple(self.expected_artifact_ids, label="expected_artifact_ids"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def evidence_bound(self) -> bool:
        return bool(self.expected_artifact_ids)

    @property
    def blocking_gap(self) -> bool:
        return self.required and (not self.passed or not self.evidence_bound)

    def to_dict(self) -> dict[str, Any]:
        return {
            "validation_id": self.validation_id,
            "kind": self.kind.value,
            "description": self.description,
            "command": list(self.command),
            "expected_artifact_ids": list(self.expected_artifact_ids),
            "passed": self.passed,
            "required": self.required,
            "evidence_bound": self.evidence_bound,
            "blocking_gap": self.blocking_gap,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class RollbackRequirement:
    """Rollback condition that must be defined before risky AI-assisted changes proceed."""

    rollback_id: str
    trigger: str
    action: str
    owner_team_id: str
    evidence_artifact_ids: tuple[str, ...] = ()
    tested: bool = False
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "rollback_id", normalize_identifier(self.rollback_id, label="rollback_id"))
        object.__setattr__(self, "trigger", normalize_text(self.trigger, label="trigger"))
        object.__setattr__(self, "action", normalize_text(self.action, label="action"))
        object.__setattr__(
            self,
            "owner_team_id",
            normalize_identifier(self.owner_team_id, label="owner_team_id"),
        )
        object.__setattr__(
            self,
            "evidence_artifact_ids",
            normalize_identifier_tuple(self.evidence_artifact_ids, label="evidence_artifact_ids"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def evidence_bound(self) -> bool:
        return bool(self.evidence_artifact_ids)

    @property
    def blocking_gap(self) -> bool:
        return not self.tested or not self.evidence_bound

    def to_dict(self) -> dict[str, Any]:
        return {
            "rollback_id": self.rollback_id,
            "trigger": self.trigger,
            "action": self.action,
            "owner_team_id": self.owner_team_id,
            "evidence_artifact_ids": list(self.evidence_artifact_ids),
            "tested": self.tested,
            "evidence_bound": self.evidence_bound,
            "blocking_gap": self.blocking_gap,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class ForbiddenAction:
    """Action a work package explicitly forbids inside its operating envelope."""

    action_id: str
    description: str
    rationale: str
    enforcement_refs: tuple[str, ...] = ()
    detected: bool = False
    evidence_artifact_ids: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "action_id", normalize_identifier(self.action_id, label="action_id"))
        object.__setattr__(self, "description", normalize_text(self.description, label="description"))
        object.__setattr__(self, "rationale", normalize_text(self.rationale, label="rationale"))
        object.__setattr__(
            self,
            "enforcement_refs",
            normalize_text_tuple(self.enforcement_refs, label="enforcement_refs"),
        )
        object.__setattr__(
            self,
            "evidence_artifact_ids",
            normalize_identifier_tuple(self.evidence_artifact_ids, label="evidence_artifact_ids"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def violation(self) -> bool:
        return self.detected

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "description": self.description,
            "rationale": self.rationale,
            "enforcement_refs": list(self.enforcement_refs),
            "detected": self.detected,
            "violation": self.violation,
            "evidence_artifact_ids": list(self.evidence_artifact_ids),
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class WorkPackageDependency:
    """Directed dependency between two bounded operating work packages."""

    dependency_id: str
    source_work_package_id: str
    target_work_package_id: str
    kind: WorkPackageDependencyKind
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
            "source_work_package_id",
            normalize_identifier(self.source_work_package_id, label="source_work_package_id"),
        )
        object.__setattr__(
            self,
            "target_work_package_id",
            normalize_identifier(self.target_work_package_id, label="target_work_package_id"),
        )
        if self.source_work_package_id == self.target_work_package_id:
            raise ValueError("WorkPackageDependency cannot target the source work package.")
        object.__setattr__(self, "rationale", normalize_text(self.rationale, label="rationale"))
        object.__setattr__(self, "metadata", dict(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return {
            "dependency_id": self.dependency_id,
            "source_work_package_id": self.source_work_package_id,
            "target_work_package_id": self.target_work_package_id,
            "kind": self.kind.value,
            "rationale": self.rationale,
            "required": self.required,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class OperatingWorkPackage:
    """Bounded unit of AI-assisted engineering work governed by Wave 10."""

    work_package_id: str
    title: str
    objective: str
    repository_ids: tuple[str, ...]
    owner_team_id: str
    author_id: str
    domains: tuple[OperatingDomain, ...]
    status: WorkPackageStatus = WorkPackageStatus.PROPOSED
    changed_paths: tuple[str, ...] = ()
    evidence_requirements: tuple[EvidenceRequirement, ...] = ()
    required_validations: tuple[RequiredValidation, ...] = ()
    rollback_requirements: tuple[RollbackRequirement, ...] = ()
    forbidden_actions: tuple[ForbiddenAction, ...] = ()
    dependency_ids: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "work_package_id",
            normalize_identifier(self.work_package_id, label="work_package_id"),
        )
        object.__setattr__(self, "title", normalize_text(self.title, label="title"))
        object.__setattr__(self, "objective", normalize_text(self.objective, label="objective"))
        if not self.repository_ids:
            raise ValueError("OperatingWorkPackage repository_ids must not be empty.")
        if not self.domains:
            raise ValueError("OperatingWorkPackage domains must not be empty.")
        object.__setattr__(
            self,
            "repository_ids",
            normalize_identifier_tuple(self.repository_ids, label="repository_ids"),
        )
        object.__setattr__(
            self,
            "owner_team_id",
            normalize_identifier(self.owner_team_id, label="owner_team_id"),
        )
        object.__setattr__(self, "author_id", normalize_identifier(self.author_id, label="author_id"))
        object.__setattr__(self, "domains", unique_sorted_enum_tuple(self.domains))
        object.__setattr__(self, "changed_paths", normalize_changed_paths(self.changed_paths))
        object.__setattr__(
            self,
            "evidence_requirements",
            sort_unique_by_id(
                self.evidence_requirements,
                attribute="requirement_id",
                label="evidence requirement_id",
            ),
        )
        object.__setattr__(
            self,
            "required_validations",
            sort_unique_by_id(
                self.required_validations,
                attribute="validation_id",
                label="validation_id",
            ),
        )
        object.__setattr__(
            self,
            "rollback_requirements",
            sort_unique_by_id(
                self.rollback_requirements,
                attribute="rollback_id",
                label="rollback_id",
            ),
        )
        object.__setattr__(
            self,
            "forbidden_actions",
            sort_unique_by_id(
                self.forbidden_actions,
                attribute="action_id",
                label="forbidden action_id",
            ),
        )
        object.__setattr__(
            self,
            "dependency_ids",
            normalize_identifier_tuple(self.dependency_ids, label="dependency_ids"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def missing_evidence_requirement_ids(self) -> tuple[str, ...]:
        return tuple(
            requirement.requirement_id
            for requirement in self.evidence_requirements
            if requirement.blocking_gap
        )

    @property
    def failing_validation_ids(self) -> tuple[str, ...]:
        return tuple(
            validation.validation_id
            for validation in self.required_validations
            if validation.blocking_gap
        )

    @property
    def untested_rollback_ids(self) -> tuple[str, ...]:
        return tuple(
            rollback.rollback_id
            for rollback in self.rollback_requirements
            if rollback.blocking_gap
        )

    @property
    def detected_forbidden_action_ids(self) -> tuple[str, ...]:
        return tuple(action.action_id for action in self.forbidden_actions if action.violation)

    @property
    def findings(self) -> tuple[OperatingFinding, ...]:
        findings: list[OperatingFinding] = []
        if self.status in {WorkPackageStatus.BLOCKED, WorkPackageStatus.REJECTED}:
            findings.append(
                self._finding(
                    code="operating.work_package.blocked-status",
                    severity=OperatingSeverity.CRITICAL,
                    summary=f"Work package {self.work_package_id} is {self.status.value}.",
                    metadata={"status": self.status.value},
                )
            )
        if not self.changed_paths:
            findings.append(
                self._finding(
                    code="operating.work_package.no-changed-paths",
                    severity=OperatingSeverity.MEDIUM,
                    summary=(
                        f"Work package {self.work_package_id} has no declared changed paths."
                    ),
                    blocking=False,
                )
            )
        for requirement_id in self.missing_evidence_requirement_ids:
            findings.append(
                self._finding(
                    code="operating.work_package.missing-evidence",
                    severity=OperatingSeverity.CRITICAL,
                    summary=(
                        f"Work package {self.work_package_id} is missing mandatory "
                        f"evidence requirement {requirement_id}."
                    ),
                    metadata={"requirement_id": requirement_id},
                )
            )
        for validation_id in self.failing_validation_ids:
            findings.append(
                self._finding(
                    code="operating.work_package.validation-gap",
                    severity=OperatingSeverity.CRITICAL,
                    summary=(
                        f"Work package {self.work_package_id} has an unsatisfied "
                        f"required validation {validation_id}."
                    ),
                    metadata={"validation_id": validation_id},
                )
            )
        for rollback_id in self.untested_rollback_ids:
            findings.append(
                self._finding(
                    code="operating.work_package.rollback-gap",
                    severity=OperatingSeverity.HIGH,
                    summary=(
                        f"Work package {self.work_package_id} has an untested or "
                        f"unbound rollback requirement {rollback_id}."
                    ),
                    metadata={"rollback_id": rollback_id},
                )
            )
        for action_id in self.detected_forbidden_action_ids:
            findings.append(
                self._finding(
                    code="operating.work_package.forbidden-action-detected",
                    severity=OperatingSeverity.CRITICAL,
                    summary=(
                        f"Work package {self.work_package_id} detected forbidden action {action_id}."
                    ),
                    metadata={"action_id": action_id},
                )
            )
        return tuple(sorted(findings, key=lambda finding: (finding.code, finding.summary)))

    def to_envelope(self) -> OperatingEnvelope:
        return OperatingEnvelope(
            envelope_id=f"{self.work_package_id}-work-package-envelope",
            artifact_kind=OperatingArtifactKind.WORK_PACKAGE,
            subject=f"Wave 10 work package {self.work_package_id}: {self.title}",
            domains=self.domains,
            findings=self.findings,
            metadata={
                "work_package_id": self.work_package_id,
                "repository_ids": list(self.repository_ids),
                "owner_team_id": self.owner_team_id,
                "author_id": self.author_id,
                "status": self.status.value,
                "changed_paths": list(self.changed_paths),
                "dependency_ids": list(self.dependency_ids),
            },
        )

    def to_dict(self) -> dict[str, Any]:
        envelope = self.to_envelope()
        return {
            "work_package_id": self.work_package_id,
            "title": self.title,
            "objective": self.objective,
            "repository_ids": list(self.repository_ids),
            "owner_team_id": self.owner_team_id,
            "author_id": self.author_id,
            "domains": [domain.value for domain in self.domains],
            "status": self.status.value,
            "changed_paths": list(self.changed_paths),
            "evidence_requirements": [
                requirement.to_dict() for requirement in self.evidence_requirements
            ],
            "required_validations": [validation.to_dict() for validation in self.required_validations],
            "rollback_requirements": [rollback.to_dict() for rollback in self.rollback_requirements],
            "forbidden_actions": [action.to_dict() for action in self.forbidden_actions],
            "dependency_ids": list(self.dependency_ids),
            "missing_evidence_requirement_ids": list(self.missing_evidence_requirement_ids),
            "failing_validation_ids": list(self.failing_validation_ids),
            "untested_rollback_ids": list(self.untested_rollback_ids),
            "detected_forbidden_action_ids": list(self.detected_forbidden_action_ids),
            "findings": [finding.to_dict() for finding in self.findings],
            "disposition": envelope.disposition.value,
            "digest": envelope.digest,
            "metadata": dict(self.metadata),
        }

    def _finding(
        self,
        *,
        code: str,
        severity: OperatingSeverity,
        summary: str,
        blocking: bool = True,
        metadata: Mapping[str, Any] | None = None,
    ) -> OperatingFinding:
        return OperatingFinding(
            code=code,
            severity=severity,
            summary=summary,
            domains=self.domains,
            paths=self.changed_paths,
            blocking=blocking,
            metadata={
                "work_package_id": self.work_package_id,
                **dict(metadata or {}),
            },
        )


def normalize_command_tuple(values: Sequence[str]) -> tuple[str, ...]:
    normalized: list[str] = []
    for value in values:
        item = normalize_text(value, label="command")
        normalized.append(item)
    return tuple(normalized)


def normalize_changed_paths(values: Sequence[str]) -> tuple[str, ...]:
    normalized: list[str] = []
    seen: set[str] = set()
    for value in values:
        item = normalize_relative_path(value)
        if item not in seen:
            normalized.append(item)
            seen.add(item)
    return tuple(sorted(normalized))


def sort_unique_by_id(
    values: Sequence[Any],
    *,
    attribute: str,
    label: str,
) -> tuple[Any, ...]:
    normalized = tuple(sorted(values, key=lambda value: getattr(value, attribute)))
    identifiers = [getattr(value, attribute) for value in normalized]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError(f"OperatingWorkPackage {label} values must be unique.")
    return normalized
