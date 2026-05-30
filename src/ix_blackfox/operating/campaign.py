from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum, auto
from typing import Any

from ix_blackfox.operating.models import (
    OperatingArtifactKind,
    OperatingDisposition,
    OperatingDomain,
    OperatingEnvelope,
    OperatingFinding,
    OperatingSeverity,
    normalize_identifier,
    normalize_text,
    unique_sorted_enum_tuple,
)
from ix_blackfox.operating.registry import normalize_identifier_tuple
from ix_blackfox.operating.work_packages import (
    OperatingWorkPackage,
    WorkPackageDependency,
    WorkPackageStatus,
)


class CampaignPhaseStatus(StrEnum):
    """Lifecycle state for a Wave 10 operating campaign phase."""

    PLANNED = auto()
    READY_FOR_REVIEW = auto()
    APPROVED = auto()
    IN_PROGRESS = auto()
    COMPLETED = auto()
    BLOCKED = auto()


@dataclass(frozen=True, slots=True)
class CampaignPhase:
    """Ordered phase that groups bounded work packages into a reviewable campaign."""

    phase_id: str
    title: str
    objective: str
    work_package_ids: tuple[str, ...]
    status: CampaignPhaseStatus = CampaignPhaseStatus.PLANNED
    required_prior_phase_ids: tuple[str, ...] = ()
    exit_criteria: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "phase_id", normalize_identifier(self.phase_id, label="phase_id"))
        object.__setattr__(self, "title", normalize_text(self.title, label="title"))
        object.__setattr__(self, "objective", normalize_text(self.objective, label="objective"))
        if not self.work_package_ids:
            raise ValueError("CampaignPhase work_package_ids must not be empty.")
        object.__setattr__(
            self,
            "work_package_ids",
            normalize_identifier_tuple(self.work_package_ids, label="work_package_ids"),
        )
        object.__setattr__(
            self,
            "required_prior_phase_ids",
            normalize_identifier_tuple(
                self.required_prior_phase_ids,
                label="required_prior_phase_ids",
            ),
        )
        if self.phase_id in self.required_prior_phase_ids:
            raise ValueError("CampaignPhase cannot require itself as a prior phase.")
        object.__setattr__(self, "exit_criteria", normalize_text_tuple(self.exit_criteria))
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def complete(self) -> bool:
        return self.status is CampaignPhaseStatus.COMPLETED

    @property
    def blocked(self) -> bool:
        return self.status is CampaignPhaseStatus.BLOCKED

    def to_dict(self) -> dict[str, Any]:
        return {
            "phase_id": self.phase_id,
            "title": self.title,
            "objective": self.objective,
            "work_package_ids": list(self.work_package_ids),
            "status": self.status.value,
            "required_prior_phase_ids": list(self.required_prior_phase_ids),
            "exit_criteria": list(self.exit_criteria),
            "complete": self.complete,
            "blocked": self.blocked,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class CampaignDependencyGraph:
    """Deterministic dependency graph for work packages in one operating campaign."""

    work_package_ids: tuple[str, ...]
    dependencies: tuple[WorkPackageDependency, ...] = ()

    def __post_init__(self) -> None:
        if not self.work_package_ids:
            raise ValueError("CampaignDependencyGraph work_package_ids must not be empty.")
        work_package_ids = normalize_identifier_tuple(
            self.work_package_ids,
            label="work_package_ids",
        )
        object.__setattr__(self, "work_package_ids", work_package_ids)
        dependencies = tuple(sorted(self.dependencies, key=lambda item: item.dependency_id))
        dependency_ids = [dependency.dependency_id for dependency in dependencies]
        if len(dependency_ids) != len(set(dependency_ids)):
            raise ValueError("CampaignDependencyGraph dependency_id values must be unique.")
        registered_ids = set(work_package_ids)
        for dependency in dependencies:
            missing = {
                dependency.source_work_package_id,
                dependency.target_work_package_id,
            } - registered_ids
            if missing:
                missing_text = ", ".join(sorted(missing))
                raise ValueError(f"dependency references unknown work package: {missing_text}")
        object.__setattr__(self, "dependencies", dependencies)

    @property
    def required_edges(self) -> tuple[tuple[str, str], ...]:
        return tuple(
            (dependency.source_work_package_id, dependency.target_work_package_id)
            for dependency in self.dependencies
            if dependency.required
        )

    @property
    def has_cycle(self) -> bool:
        return bool(self.cycle_path())

    def dependency_edges(self) -> tuple[tuple[str, str, str], ...]:
        return tuple(
            (
                dependency.source_work_package_id,
                dependency.target_work_package_id,
                dependency.kind.value,
            )
            for dependency in self.dependencies
        )

    def prerequisites_for(self, work_package_id: str) -> tuple[str, ...]:
        normalized = normalize_identifier(work_package_id, label="work_package_id")
        prerequisites = {
            dependency.target_work_package_id
            for dependency in self.dependencies
            if dependency.source_work_package_id == normalized and dependency.required
        }
        return tuple(sorted(prerequisites))

    def dependents_of(self, work_package_id: str) -> tuple[str, ...]:
        normalized = normalize_identifier(work_package_id, label="work_package_id")
        dependents = {
            dependency.source_work_package_id
            for dependency in self.dependencies
            if dependency.target_work_package_id == normalized and dependency.required
        }
        return tuple(sorted(dependents))

    def ready_work_package_ids(self, completed_work_package_ids: Sequence[str]) -> tuple[str, ...]:
        completed = set(
            normalize_identifier_tuple(
                completed_work_package_ids,
                label="completed_work_package_ids",
            )
        )
        ready: list[str] = []
        for work_package_id in self.work_package_ids:
            if work_package_id in completed:
                continue
            prerequisites = set(self.prerequisites_for(work_package_id))
            if prerequisites <= completed:
                ready.append(work_package_id)
        return tuple(sorted(ready))

    def topological_order(self) -> tuple[str, ...]:
        remaining = set(self.work_package_ids)
        completed: set[str] = set()
        ordered: list[str] = []
        while remaining:
            ready = [
                work_package_id
                for work_package_id in sorted(remaining)
                if set(self.prerequisites_for(work_package_id)) <= completed
            ]
            if not ready:
                return ()
            for work_package_id in ready:
                ordered.append(work_package_id)
                completed.add(work_package_id)
                remaining.remove(work_package_id)
        return tuple(ordered)

    def cycle_path(self) -> tuple[str, ...]:
        visiting: set[str] = set()
        visited: set[str] = set()
        stack: list[str] = []

        def visit(node: str) -> tuple[str, ...]:
            if node in visiting:
                start = stack.index(node)
                return tuple([*stack[start:], node])
            if node in visited:
                return ()
            visiting.add(node)
            stack.append(node)
            for prerequisite in self.prerequisites_for(node):
                cycle = visit(prerequisite)
                if cycle:
                    return cycle
            stack.pop()
            visiting.remove(node)
            visited.add(node)
            return ()

        for work_package_id in self.work_package_ids:
            cycle = visit(work_package_id)
            if cycle:
                return cycle
        return ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "work_package_ids": list(self.work_package_ids),
            "dependencies": [dependency.to_dict() for dependency in self.dependencies],
            "dependency_edges": [list(edge) for edge in self.dependency_edges()],
            "required_edges": [list(edge) for edge in self.required_edges],
            "has_cycle": self.has_cycle,
            "cycle_path": list(self.cycle_path()),
            "topological_order": list(self.topological_order()),
        }


@dataclass(frozen=True, slots=True)
class CampaignValidationReport:
    """Derived validation report for a Wave 10 campaign graph and package set."""

    campaign_id: str
    package_count: int
    phase_count: int
    dependency_count: int
    completed_work_package_ids: tuple[str, ...]
    ready_work_package_ids: tuple[str, ...]
    blocked_work_package_ids: tuple[str, ...]
    warning_work_package_ids: tuple[str, ...]
    cycle_path: tuple[str, ...] = ()
    phase_gap_ids: tuple[str, ...] = ()
    orphan_work_package_ids: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "campaign_id", normalize_identifier(self.campaign_id, label="campaign_id"))
        if self.package_count <= 0:
            raise ValueError("package_count must be greater than zero.")
        if self.phase_count <= 0:
            raise ValueError("phase_count must be greater than zero.")
        if self.dependency_count < 0:
            raise ValueError("dependency_count must not be negative.")
        object.__setattr__(
            self,
            "completed_work_package_ids",
            normalize_identifier_tuple(
                self.completed_work_package_ids,
                label="completed_work_package_ids",
            ),
        )
        object.__setattr__(
            self,
            "ready_work_package_ids",
            normalize_identifier_tuple(self.ready_work_package_ids, label="ready_work_package_ids"),
        )
        object.__setattr__(
            self,
            "blocked_work_package_ids",
            normalize_identifier_tuple(
                self.blocked_work_package_ids,
                label="blocked_work_package_ids",
            ),
        )
        object.__setattr__(
            self,
            "warning_work_package_ids",
            normalize_identifier_tuple(
                self.warning_work_package_ids,
                label="warning_work_package_ids",
            ),
        )
        object.__setattr__(
            self,
            "cycle_path",
            normalize_identifier_sequence(self.cycle_path, label="cycle_path"),
        )
        object.__setattr__(
            self,
            "phase_gap_ids",
            normalize_identifier_tuple(self.phase_gap_ids, label="phase_gap_ids"),
        )
        object.__setattr__(
            self,
            "orphan_work_package_ids",
            normalize_identifier_tuple(
                self.orphan_work_package_ids,
                label="orphan_work_package_ids",
            ),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def passed(self) -> bool:
        return not (
            self.blocked_work_package_ids
            or self.cycle_path
            or self.phase_gap_ids
            or self.orphan_work_package_ids
        )

    @property
    def disposition(self) -> OperatingDisposition:
        if not self.passed:
            return OperatingDisposition.BLOCKED
        if self.warning_work_package_ids:
            return OperatingDisposition.WARNING
        return OperatingDisposition.READY

    def to_dict(self) -> dict[str, Any]:
        return {
            "campaign_id": self.campaign_id,
            "package_count": self.package_count,
            "phase_count": self.phase_count,
            "dependency_count": self.dependency_count,
            "completed_work_package_ids": list(self.completed_work_package_ids),
            "ready_work_package_ids": list(self.ready_work_package_ids),
            "blocked_work_package_ids": list(self.blocked_work_package_ids),
            "warning_work_package_ids": list(self.warning_work_package_ids),
            "cycle_path": list(self.cycle_path),
            "phase_gap_ids": list(self.phase_gap_ids),
            "orphan_work_package_ids": list(self.orphan_work_package_ids),
            "passed": self.passed,
            "disposition": self.disposition.value,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class OperatingCampaign:
    """Multi-step, multi-repo Wave 10 campaign composed of bounded work packages."""

    campaign_id: str
    title: str
    objective: str
    registry_id: str
    work_packages: tuple[OperatingWorkPackage, ...]
    phases: tuple[CampaignPhase, ...]
    dependencies: tuple[WorkPackageDependency, ...] = ()
    board_id: str = ""
    required_domains: tuple[OperatingDomain, ...] = ()
    generated_by: str = "IX-BlackFox Wave 10 operating campaign"
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "campaign_id",
            normalize_identifier(self.campaign_id, label="campaign_id"),
        )
        object.__setattr__(self, "title", normalize_text(self.title, label="title"))
        object.__setattr__(self, "objective", normalize_text(self.objective, label="objective"))
        object.__setattr__(self, "registry_id", normalize_identifier(self.registry_id, label="registry_id"))
        object.__setattr__(self, "board_id", normalize_optional_identifier(self.board_id, label="board_id"))
        if not self.work_packages:
            raise ValueError("OperatingCampaign work_packages must not be empty.")
        work_packages = tuple(sorted(self.work_packages, key=lambda package: package.work_package_id))
        work_package_ids = [package.work_package_id for package in work_packages]
        if len(work_package_ids) != len(set(work_package_ids)):
            raise ValueError("OperatingCampaign work_package_id values must be unique.")
        object.__setattr__(self, "work_packages", work_packages)
        if not self.phases:
            raise ValueError("OperatingCampaign phases must not be empty.")
        phases = tuple(sorted(self.phases, key=lambda phase: phase.phase_id))
        phase_ids = [phase.phase_id for phase in phases]
        if len(phase_ids) != len(set(phase_ids)):
            raise ValueError("OperatingCampaign phase_id values must be unique.")
        registered_package_ids = set(work_package_ids)
        for phase in phases:
            missing_packages = set(phase.work_package_ids) - registered_package_ids
            if missing_packages:
                missing = ", ".join(sorted(missing_packages))
                raise ValueError(f"phase references unknown work package: {missing}")
            missing_phases = set(phase.required_prior_phase_ids) - set(phase_ids)
            if missing_phases:
                missing = ", ".join(sorted(missing_phases))
                raise ValueError(f"phase references unknown prior phase: {missing}")
        object.__setattr__(self, "phases", phases)
        graph = CampaignDependencyGraph(tuple(work_package_ids), self.dependencies)
        object.__setattr__(self, "dependencies", graph.dependencies)
        if self.required_domains:
            domains = unique_sorted_enum_tuple(self.required_domains)
        else:
            domains = unique_sorted_enum_tuple(
                tuple(domain for package in work_packages for domain in package.domains)
            )
        object.__setattr__(self, "required_domains", domains)
        object.__setattr__(
            self,
            "generated_by",
            normalize_text(self.generated_by, label="generated_by"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def graph(self) -> CampaignDependencyGraph:
        return CampaignDependencyGraph(
            tuple(package.work_package_id for package in self.work_packages),
            self.dependencies,
        )

    @property
    def repository_ids(self) -> tuple[str, ...]:
        return normalize_identifier_tuple(
            tuple(
                repository_id
                for package in self.work_packages
                for repository_id in package.repository_ids
            ),
            label="repository_ids",
        )

    @property
    def owner_team_ids(self) -> tuple[str, ...]:
        return normalize_identifier_tuple(
            tuple(package.owner_team_id for package in self.work_packages),
            label="owner_team_ids",
        )

    @property
    def validation_report(self) -> CampaignValidationReport:
        package_by_id = {package.work_package_id: package for package in self.work_packages}
        completed = tuple(
            package.work_package_id
            for package in self.work_packages
            if package.status is WorkPackageStatus.COMPLETED
        )
        blocked = tuple(
            package.work_package_id
            for package in self.work_packages
            if package.to_envelope().disposition is OperatingDisposition.BLOCKED
        )
        warning = tuple(
            package.work_package_id
            for package in self.work_packages
            if package.to_envelope().disposition is OperatingDisposition.WARNING
        )
        phase_package_ids = {
            work_package_id for phase in self.phases for work_package_id in phase.work_package_ids
        }
        orphan_package_ids = set(package_by_id) - phase_package_ids
        phase_gap_ids = {
            phase.phase_id
            for phase in self.phases
            if phase.blocked
            or any(package_by_id[work_package_id].to_envelope().disposition is OperatingDisposition.BLOCKED
                   for work_package_id in phase.work_package_ids)
        }
        return CampaignValidationReport(
            campaign_id=self.campaign_id,
            package_count=len(self.work_packages),
            phase_count=len(self.phases),
            dependency_count=len(self.dependencies),
            completed_work_package_ids=completed,
            ready_work_package_ids=self.graph.ready_work_package_ids(completed),
            blocked_work_package_ids=blocked,
            warning_work_package_ids=warning,
            cycle_path=self.graph.cycle_path(),
            phase_gap_ids=tuple(sorted(phase_gap_ids)),
            orphan_work_package_ids=tuple(sorted(orphan_package_ids)),
            metadata={
                "registry_id": self.registry_id,
                "board_id": self.board_id,
                "repository_ids": list(self.repository_ids),
                "owner_team_ids": list(self.owner_team_ids),
            },
        )

    @property
    def findings(self) -> tuple[OperatingFinding, ...]:
        findings: list[OperatingFinding] = []
        report = self.validation_report
        if report.cycle_path:
            findings.append(
                self._finding(
                    code="operating.campaign.dependency-cycle",
                    severity=OperatingSeverity.CRITICAL,
                    summary=(
                        "Campaign dependency graph contains a cycle: "
                        f"{' -> '.join(report.cycle_path)}."
                    ),
                    metadata={"cycle_path": list(report.cycle_path)},
                )
            )
        for work_package_id in report.blocked_work_package_ids:
            findings.append(
                self._finding(
                    code="operating.campaign.blocked-work-package",
                    severity=OperatingSeverity.CRITICAL,
                    summary=f"Campaign contains blocked work package {work_package_id}.",
                    metadata={"work_package_id": work_package_id},
                )
            )
        for phase_id in report.phase_gap_ids:
            findings.append(
                self._finding(
                    code="operating.campaign.phase-gap",
                    severity=OperatingSeverity.HIGH,
                    summary=f"Campaign phase {phase_id} is blocked or contains blocked work.",
                    metadata={"phase_id": phase_id},
                )
            )
        for work_package_id in report.orphan_work_package_ids:
            findings.append(
                self._finding(
                    code="operating.campaign.orphan-work-package",
                    severity=OperatingSeverity.HIGH,
                    summary=f"Work package {work_package_id} is not assigned to any campaign phase.",
                    metadata={"work_package_id": work_package_id},
                )
            )
        for work_package_id in report.warning_work_package_ids:
            findings.append(
                self._finding(
                    code="operating.campaign.warning-work-package",
                    severity=OperatingSeverity.MEDIUM,
                    summary=f"Campaign contains warning-level work package {work_package_id}.",
                    blocking=False,
                    metadata={"work_package_id": work_package_id},
                )
            )
        return tuple(sorted(findings, key=lambda finding: (finding.code, finding.summary)))

    def to_envelope(self) -> OperatingEnvelope:
        report = self.validation_report
        return OperatingEnvelope(
            envelope_id=f"{self.campaign_id}-campaign-envelope",
            artifact_kind=OperatingArtifactKind.CAMPAIGN_GRAPH,
            subject=f"Wave 10 operating campaign {self.campaign_id}: {self.title}",
            domains=self.required_domains,
            findings=self.findings,
            metadata={
                "campaign_id": self.campaign_id,
                "registry_id": self.registry_id,
                "board_id": self.board_id,
                "repository_ids": list(self.repository_ids),
                "owner_team_ids": list(self.owner_team_ids),
                "work_package_ids": [package.work_package_id for package in self.work_packages],
                "phase_ids": [phase.phase_id for phase in self.phases],
                "validation_report": report.to_dict(),
            },
        )

    def to_dict(self) -> dict[str, Any]:
        envelope = self.to_envelope()
        return {
            "campaign_id": self.campaign_id,
            "title": self.title,
            "objective": self.objective,
            "registry_id": self.registry_id,
            "board_id": self.board_id,
            "generated_by": self.generated_by,
            "repository_ids": list(self.repository_ids),
            "owner_team_ids": list(self.owner_team_ids),
            "required_domains": [domain.value for domain in self.required_domains],
            "work_packages": [package.to_dict() for package in self.work_packages],
            "phases": [phase.to_dict() for phase in self.phases],
            "dependencies": [dependency.to_dict() for dependency in self.dependencies],
            "dependency_graph": self.graph.to_dict(),
            "validation_report": self.validation_report.to_dict(),
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
            domains=self.required_domains,
            blocking=blocking,
            metadata={"campaign_id": self.campaign_id, **dict(metadata or {})},
        )


def normalize_optional_identifier(value: str, *, label: str) -> str:
    if not value.strip():
        return ""
    return normalize_identifier(value, label=label)


def normalize_identifier_sequence(values: Sequence[str], *, label: str) -> tuple[str, ...]:
    return tuple(normalize_identifier(value, label=label) for value in values)


def normalize_text_tuple(values: Sequence[str]) -> tuple[str, ...]:
    normalized: list[str] = []
    seen: set[str] = set()
    for value in values:
        item = normalize_text(value, label="text")
        if item not in seen:
            normalized.append(item)
            seen.add(item)
    return tuple(sorted(normalized))
