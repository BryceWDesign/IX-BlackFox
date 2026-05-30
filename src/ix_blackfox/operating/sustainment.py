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
    normalize_optional_text,
    normalize_text,
)


class BlockerSeverity(StrEnum):
    """Severity for sustainment blockers carried into Wave 10 readiness gates."""

    INFO = auto()
    LOW = auto()
    MEDIUM = auto()
    HIGH = auto()
    CRITICAL = auto()


class BlockerStatus(StrEnum):
    """Lifecycle state for an operating blocker."""

    OPEN = auto()
    ACKNOWLEDGED = auto()
    IN_REVIEW = auto()
    MITIGATED = auto()
    ACCEPTED_RISK = auto()
    CLOSED = auto()


class ReadinessState(StrEnum):
    """Readiness state for a Wave 10 operating scope."""

    UNKNOWN = auto()
    READY = auto()
    WARNING = auto()
    DEGRADED = auto()
    BLOCKED = auto()


@dataclass(frozen=True, slots=True)
class OperatingBlocker:
    """Sustainment-style blocker that can prevent operating readiness."""

    blocker_id: str
    title: str
    summary: str
    severity: BlockerSeverity
    status: BlockerStatus
    owner_team_id: str
    repository_ids: tuple[str, ...]
    opened_by: str
    work_package_ids: tuple[str, ...] = ()
    artifact_ids: tuple[str, ...] = ()
    resolution: str = ""
    accepted_by_human_review_id: str = ""
    blocks_readiness: bool = True
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "blocker_id",
            normalize_identifier(self.blocker_id, label="blocker_id"),
        )
        object.__setattr__(self, "title", normalize_text(self.title, label="title"))
        object.__setattr__(self, "summary", normalize_text(self.summary, label="summary"))
        object.__setattr__(
            self,
            "owner_team_id",
            normalize_identifier(self.owner_team_id, label="owner_team_id"),
        )
        if not self.repository_ids:
            raise ValueError("OperatingBlocker repository_ids must not be empty.")
        object.__setattr__(
            self,
            "repository_ids",
            normalize_identifier_tuple(self.repository_ids, label="repository_ids"),
        )
        object.__setattr__(
            self,
            "opened_by",
            normalize_identifier(self.opened_by, label="opened_by"),
        )
        object.__setattr__(
            self,
            "work_package_ids",
            normalize_identifier_tuple(self.work_package_ids, label="work_package_ids"),
        )
        object.__setattr__(
            self,
            "artifact_ids",
            normalize_identifier_tuple(self.artifact_ids, label="artifact_ids"),
        )
        object.__setattr__(
            self,
            "resolution",
            normalize_optional_text(self.resolution, label="resolution"),
        )
        object.__setattr__(
            self,
            "accepted_by_human_review_id",
            normalize_optional_identifier(
                self.accepted_by_human_review_id,
                label="accepted_by_human_review_id",
            ),
        )
        if self.status in {BlockerStatus.MITIGATED, BlockerStatus.CLOSED} and not self.resolution:
            raise ValueError("mitigated or closed blockers must include a resolution.")
        if self.status is BlockerStatus.ACCEPTED_RISK and not self.accepted_by_human_review_id:
            raise ValueError("accepted-risk blockers must include human review acceptance.")
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def terminal(self) -> bool:
        return self.status in {
            BlockerStatus.MITIGATED,
            BlockerStatus.ACCEPTED_RISK,
            BlockerStatus.CLOSED,
        }

    @property
    def unresolved(self) -> bool:
        return not self.terminal

    @property
    def operating_severity(self) -> OperatingSeverity:
        return operating_severity_from_blocker(self.severity)

    @property
    def blocks_gate(self) -> bool:
        return (
            self.blocks_readiness
            and self.unresolved
            and self.severity in {BlockerSeverity.HIGH, BlockerSeverity.CRITICAL}
        )

    @property
    def warns_gate(self) -> bool:
        return self.unresolved and not self.blocks_gate

    def to_dict(self) -> dict[str, Any]:
        return {
            "blocker_id": self.blocker_id,
            "title": self.title,
            "summary": self.summary,
            "severity": self.severity.value,
            "status": self.status.value,
            "owner_team_id": self.owner_team_id,
            "repository_ids": list(self.repository_ids),
            "opened_by": self.opened_by,
            "work_package_ids": list(self.work_package_ids),
            "artifact_ids": list(self.artifact_ids),
            "resolution": self.resolution,
            "accepted_by_human_review_id": self.accepted_by_human_review_id,
            "blocks_readiness": self.blocks_readiness,
            "terminal": self.terminal,
            "unresolved": self.unresolved,
            "blocks_gate": self.blocks_gate,
            "warns_gate": self.warns_gate,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class ReadinessTransition:
    """Evidence-bound transition between Wave 10 readiness states."""

    transition_id: str
    from_state: ReadinessState
    to_state: ReadinessState
    reason: str
    authorized_by: str
    blocker_ids: tuple[str, ...] = ()
    evidence_artifact_ids: tuple[str, ...] = ()
    human_review_ids: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "transition_id",
            normalize_identifier(self.transition_id, label="transition_id"),
        )
        if self.from_state is self.to_state:
            raise ValueError("ReadinessTransition must change readiness state.")
        object.__setattr__(self, "reason", normalize_text(self.reason, label="reason"))
        object.__setattr__(
            self,
            "authorized_by",
            normalize_identifier(self.authorized_by, label="authorized_by"),
        )
        object.__setattr__(
            self,
            "blocker_ids",
            normalize_identifier_tuple(self.blocker_ids, label="blocker_ids"),
        )
        object.__setattr__(
            self,
            "evidence_artifact_ids",
            normalize_identifier_tuple(
                self.evidence_artifact_ids,
                label="evidence_artifact_ids",
            ),
        )
        object.__setattr__(
            self,
            "human_review_ids",
            normalize_identifier_tuple(self.human_review_ids, label="human_review_ids"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def evidence_bound(self) -> bool:
        return bool(self.evidence_artifact_ids)

    @property
    def human_review_bound(self) -> bool:
        return bool(self.human_review_ids)

    @property
    def ready_transition_gap(self) -> bool:
        return self.to_state is ReadinessState.READY and (
            not self.evidence_bound or not self.human_review_bound
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "transition_id": self.transition_id,
            "from_state": self.from_state.value,
            "to_state": self.to_state.value,
            "reason": self.reason,
            "authorized_by": self.authorized_by,
            "blocker_ids": list(self.blocker_ids),
            "evidence_artifact_ids": list(self.evidence_artifact_ids),
            "human_review_ids": list(self.human_review_ids),
            "evidence_bound": self.evidence_bound,
            "human_review_bound": self.human_review_bound,
            "ready_transition_gap": self.ready_transition_gap,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class ReadinessGate:
    """Fail-closed readiness gate for Wave 10 sustainment and release posture."""

    gate_id: str
    target_id: str
    declared_state: ReadinessState
    repository_ids: tuple[str, ...]
    owner_team_id: str
    blockers: tuple[OperatingBlocker, ...] = ()
    transitions: tuple[ReadinessTransition, ...] = ()
    required_artifact_ids: tuple[str, ...] = ()
    observed_artifact_ids: tuple[str, ...] = ()
    required_human_review_ids: tuple[str, ...] = ()
    observed_human_review_ids: tuple[str, ...] = ()
    generated_by: str = "IX-BlackFox Wave 10 readiness gate"
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "gate_id", normalize_identifier(self.gate_id, label="gate_id"))
        object.__setattr__(
            self,
            "target_id",
            normalize_identifier(self.target_id, label="target_id"),
        )
        if not self.repository_ids:
            raise ValueError("ReadinessGate repository_ids must not be empty.")
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
        blockers = tuple(sorted(self.blockers, key=lambda blocker: blocker.blocker_id))
        blocker_ids = [blocker.blocker_id for blocker in blockers]
        if len(blocker_ids) != len(set(blocker_ids)):
            raise ValueError("ReadinessGate blocker_id values must be unique.")
        for blocker in blockers:
            if not set(blocker.repository_ids) & set(self.repository_ids):
                raise ValueError(
                    f"blocker {blocker.blocker_id} does not apply to gate repositories."
                )
        object.__setattr__(self, "blockers", blockers)
        transitions = tuple(sorted(self.transitions, key=lambda item: item.transition_id))
        transition_ids = [transition.transition_id for transition in transitions]
        if len(transition_ids) != len(set(transition_ids)):
            raise ValueError("ReadinessGate transition_id values must be unique.")
        known_blockers = set(blocker_ids)
        for transition in transitions:
            unknown_blockers = set(transition.blocker_ids) - known_blockers
            if unknown_blockers:
                unknown = ", ".join(sorted(unknown_blockers))
                raise ValueError(f"transition references unknown blocker: {unknown}")
        object.__setattr__(self, "transitions", transitions)
        object.__setattr__(
            self,
            "required_artifact_ids",
            normalize_identifier_tuple(
                self.required_artifact_ids,
                label="required_artifact_ids",
            ),
        )
        object.__setattr__(
            self,
            "observed_artifact_ids",
            normalize_identifier_tuple(
                self.observed_artifact_ids,
                label="observed_artifact_ids",
            ),
        )
        object.__setattr__(
            self,
            "required_human_review_ids",
            normalize_identifier_tuple(
                self.required_human_review_ids,
                label="required_human_review_ids",
            ),
        )
        object.__setattr__(
            self,
            "observed_human_review_ids",
            normalize_identifier_tuple(
                self.observed_human_review_ids,
                label="observed_human_review_ids",
            ),
        )
        object.__setattr__(
            self,
            "generated_by",
            normalize_text(self.generated_by, label="generated_by"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def blocker_ids(self) -> tuple[str, ...]:
        return tuple(blocker.blocker_id for blocker in self.blockers)

    @property
    def unresolved_blocker_ids(self) -> tuple[str, ...]:
        return tuple(blocker.blocker_id for blocker in self.blockers if blocker.unresolved)

    @property
    def blocking_blocker_ids(self) -> tuple[str, ...]:
        return tuple(blocker.blocker_id for blocker in self.blockers if blocker.blocks_gate)

    @property
    def warning_blocker_ids(self) -> tuple[str, ...]:
        return tuple(blocker.blocker_id for blocker in self.blockers if blocker.warns_gate)

    @property
    def missing_artifact_ids(self) -> tuple[str, ...]:
        return tuple(sorted(set(self.required_artifact_ids) - set(self.observed_artifact_ids)))

    @property
    def missing_human_review_ids(self) -> tuple[str, ...]:
        return tuple(
            sorted(set(self.required_human_review_ids) - set(self.observed_human_review_ids))
        )

    @property
    def ready_transition_gap_ids(self) -> tuple[str, ...]:
        return tuple(
            transition.transition_id
            for transition in self.transitions
            if transition.ready_transition_gap
        )

    @property
    def effective_state(self) -> ReadinessState:
        if any(finding.blocking for finding in self.findings):
            return ReadinessState.BLOCKED
        if self.findings or self.declared_state in {ReadinessState.WARNING, ReadinessState.DEGRADED}:
            return self.declared_state if self.declared_state is ReadinessState.DEGRADED else ReadinessState.WARNING
        return ReadinessState.READY

    @property
    def findings(self) -> tuple[OperatingFinding, ...]:
        findings: list[OperatingFinding] = []
        if self.declared_state is ReadinessState.UNKNOWN:
            findings.append(
                self._finding(
                    code="operating.readiness.unknown-state",
                    severity=OperatingSeverity.CRITICAL,
                    summary=f"Readiness gate {self.gate_id} has unknown declared state.",
                    blocking=True,
                )
            )
        for artifact_id in self.missing_artifact_ids:
            findings.append(
                self._finding(
                    code="operating.readiness.missing-required-artifact",
                    severity=OperatingSeverity.CRITICAL,
                    summary=f"Readiness gate {self.gate_id} is missing required artifact {artifact_id}.",
                    blocking=True,
                    metadata={"artifact_id": artifact_id},
                )
            )
        for review_id in self.missing_human_review_ids:
            findings.append(
                self._finding(
                    code="operating.readiness.missing-human-review",
                    severity=OperatingSeverity.CRITICAL,
                    summary=f"Readiness gate {self.gate_id} is missing human review {review_id}.",
                    blocking=True,
                    metadata={"human_review_id": review_id},
                )
            )
        for blocker in self.blockers:
            if blocker.blocks_gate:
                findings.append(
                    self._finding(
                        code="operating.readiness.unresolved-blocking-blocker",
                        severity=blocker.operating_severity,
                        summary=f"Readiness gate {self.gate_id} is blocked by {blocker.blocker_id}.",
                        blocking=True,
                        metadata={"blocker_id": blocker.blocker_id},
                    )
                )
            elif blocker.warns_gate:
                findings.append(
                    self._finding(
                        code="operating.readiness.unresolved-warning-blocker",
                        severity=blocker.operating_severity,
                        summary=f"Readiness gate {self.gate_id} has unresolved warning blocker {blocker.blocker_id}.",
                        blocking=False,
                        metadata={"blocker_id": blocker.blocker_id},
                    )
                )
        for transition_id in self.ready_transition_gap_ids:
            findings.append(
                self._finding(
                    code="operating.readiness.ready-transition-not-review-bound",
                    severity=OperatingSeverity.CRITICAL,
                    summary=(
                        f"Readiness transition {transition_id} moves to ready without "
                        "both evidence and human review binding."
                    ),
                    blocking=True,
                    metadata={"transition_id": transition_id},
                )
            )
        return tuple(sorted(findings, key=lambda finding: (finding.code, finding.summary)))

    @property
    def disposition(self) -> OperatingDisposition:
        if any(finding.blocking for finding in self.findings):
            return OperatingDisposition.BLOCKED
        if self.findings or self.declared_state in {ReadinessState.WARNING, ReadinessState.DEGRADED}:
            return OperatingDisposition.WARNING
        return OperatingDisposition.READY

    def to_envelope(self) -> OperatingEnvelope:
        return OperatingEnvelope(
            envelope_id=f"{self.gate_id}-readiness-gate-envelope",
            artifact_kind=OperatingArtifactKind.POLICY_EVALUATION,
            subject=f"Wave 10 readiness gate {self.gate_id}",
            domains=(OperatingDomain.POLICY_GOVERNED, OperatingDomain.MEASURABLE),
            findings=self.findings,
            metadata={
                "gate_id": self.gate_id,
                "target_id": self.target_id,
                "repository_ids": list(self.repository_ids),
                "owner_team_id": self.owner_team_id,
                "declared_state": self.declared_state.value,
                "effective_state": self.effective_state.value,
                "blocker_ids": list(self.blocker_ids),
                "unresolved_blocker_ids": list(self.unresolved_blocker_ids),
                "blocking_blocker_ids": list(self.blocking_blocker_ids),
                "warning_blocker_ids": list(self.warning_blocker_ids),
                "missing_artifact_ids": list(self.missing_artifact_ids),
                "missing_human_review_ids": list(self.missing_human_review_ids),
                "ready_transition_gap_ids": list(self.ready_transition_gap_ids),
                "disposition": self.disposition.value,
            },
        )

    def to_dict(self) -> dict[str, Any]:
        envelope = self.to_envelope()
        return {
            "gate_id": self.gate_id,
            "target_id": self.target_id,
            "declared_state": self.declared_state.value,
            "effective_state": self.effective_state.value,
            "repository_ids": list(self.repository_ids),
            "owner_team_id": self.owner_team_id,
            "blockers": [blocker.to_dict() for blocker in self.blockers],
            "transitions": [transition.to_dict() for transition in self.transitions],
            "required_artifact_ids": list(self.required_artifact_ids),
            "observed_artifact_ids": list(self.observed_artifact_ids),
            "required_human_review_ids": list(self.required_human_review_ids),
            "observed_human_review_ids": list(self.observed_human_review_ids),
            "blocker_ids": list(self.blocker_ids),
            "unresolved_blocker_ids": list(self.unresolved_blocker_ids),
            "blocking_blocker_ids": list(self.blocking_blocker_ids),
            "warning_blocker_ids": list(self.warning_blocker_ids),
            "missing_artifact_ids": list(self.missing_artifact_ids),
            "missing_human_review_ids": list(self.missing_human_review_ids),
            "ready_transition_gap_ids": list(self.ready_transition_gap_ids),
            "findings": [finding.to_dict() for finding in self.findings],
            "disposition": self.disposition.value,
            "digest": envelope.digest,
            "generated_by": self.generated_by,
            "metadata": dict(self.metadata),
        }

    def _finding(
        self,
        *,
        code: str,
        severity: OperatingSeverity,
        summary: str,
        blocking: bool,
        metadata: Mapping[str, Any] | None = None,
    ) -> OperatingFinding:
        return OperatingFinding(
            code=code,
            severity=severity,
            summary=summary,
            domains=(OperatingDomain.POLICY_GOVERNED, OperatingDomain.MEASURABLE),
            blocking=blocking,
            metadata={"gate_id": self.gate_id, **dict(metadata or {})},
        )


def operating_severity_from_blocker(severity: BlockerSeverity) -> OperatingSeverity:
    mapping: dict[BlockerSeverity, OperatingSeverity] = {
        BlockerSeverity.INFO: OperatingSeverity.INFO,
        BlockerSeverity.LOW: OperatingSeverity.LOW,
        BlockerSeverity.MEDIUM: OperatingSeverity.MEDIUM,
        BlockerSeverity.HIGH: OperatingSeverity.HIGH,
        BlockerSeverity.CRITICAL: OperatingSeverity.CRITICAL,
    }
    return mapping[severity]


def normalize_identifier_tuple(values: Sequence[str], *, label: str) -> tuple[str, ...]:
    normalized: list[str] = []
    seen: set[str] = set()
    for value in values:
        item = normalize_identifier(value, label=label)
        if item not in seen:
            normalized.append(item)
            seen.add(item)
    return tuple(sorted(normalized))


def normalize_optional_identifier(value: str, *, label: str) -> str:
    if not value.strip():
        return ""
    return normalize_identifier(value, label=label)
