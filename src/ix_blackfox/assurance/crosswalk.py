from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum, auto
from typing import Any

from ix_blackfox.assurance.models import (
    AssuranceControl,
    AssuranceEvidenceArtifact,
    AssuranceEvidenceKind,
    AssuranceProfile,
    AssuranceSubject,
    digest_payload,
)
from ix_blackfox.operating.models import normalize_identifier

WAVE12_CROSSWALK_SCHEMA_VERSION = "wave12.assurance_crosswalk.v1"


class ControlEvaluationStatus(StrEnum):
    """Evidence coverage state for one assurance-profile control."""

    SATISFIED = auto()
    PARTIAL = auto()
    MISSING = auto()
    NOT_APPLICABLE = auto()


@dataclass(frozen=True, slots=True)
class AssuranceControlEvaluation:
    """Deterministic evidence match for one assurance control."""

    control: AssuranceControl
    matched_artifact_ids: tuple[str, ...]
    matched_kinds: tuple[AssuranceEvidenceKind, ...]
    missing_kinds: tuple[AssuranceEvidenceKind, ...]
    insufficient_verification_artifact_ids: tuple[str, ...]
    status: ControlEvaluationStatus
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "matched_artifact_ids",
            tuple(sorted(set(self.matched_artifact_ids))),
        )
        object.__setattr__(
            self,
            "matched_kinds",
            _sorted_kinds(self.matched_kinds),
        )
        object.__setattr__(
            self,
            "missing_kinds",
            _sorted_kinds(self.missing_kinds),
        )
        object.__setattr__(
            self,
            "insufficient_verification_artifact_ids",
            tuple(sorted(set(self.insufficient_verification_artifact_ids))),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def blocking(self) -> bool:
        return self.control.mandatory and self.status is not ControlEvaluationStatus.SATISFIED

    def to_dict(self) -> dict[str, Any]:
        return {
            "control_id": self.control.control_id,
            "framework": self.control.framework,
            "reference_id": self.control.reference_id,
            "title": self.control.title,
            "statement": self.control.statement,
            "reference_uri": self.control.reference_uri,
            "required_evidence_kinds": [
                kind.value for kind in self.control.evidence_kinds
            ],
            "minimum_verification": self.control.minimum_verification.value,
            "requires_human_review": self.control.requires_human_review,
            "mandatory": self.control.mandatory,
            "matched_artifact_ids": list(self.matched_artifact_ids),
            "matched_kinds": [kind.value for kind in self.matched_kinds],
            "missing_kinds": [kind.value for kind in self.missing_kinds],
            "insufficient_verification_artifact_ids": list(
                self.insufficient_verification_artifact_ids
            ),
            "status": self.status.value,
            "blocking": self.blocking,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class AssuranceCrosswalkReport:
    """Profile-to-evidence mapping report for a Wave 12 manifest subject."""

    report_id: str
    subject_digest: str
    profile_digest: str
    evaluations: tuple[AssuranceControlEvaluation, ...]
    generated_at: str
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "report_id",
            normalize_identifier(self.report_id, label="report_id"),
        )
        evaluations = tuple(
            sorted(self.evaluations, key=lambda item: item.control.control_id)
        )
        if not evaluations:
            raise ValueError("AssuranceCrosswalkReport evaluations must not be empty.")
        control_ids = [evaluation.control.control_id for evaluation in evaluations]
        if len(control_ids) != len(set(control_ids)):
            raise ValueError("Crosswalk evaluation control ids must be unique.")
        object.__setattr__(self, "evaluations", evaluations)
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def blocking_evaluations(self) -> tuple[AssuranceControlEvaluation, ...]:
        return tuple(evaluation for evaluation in self.evaluations if evaluation.blocking)

    @property
    def warning_evaluations(self) -> tuple[AssuranceControlEvaluation, ...]:
        return tuple(
            evaluation
            for evaluation in self.evaluations
            if not evaluation.blocking
            and evaluation.status
            in {ControlEvaluationStatus.PARTIAL, ControlEvaluationStatus.MISSING}
        )

    @property
    def satisfied_control_count(self) -> int:
        return sum(
            evaluation.status is ControlEvaluationStatus.SATISFIED
            for evaluation in self.evaluations
        )

    @property
    def mandatory_evidence_complete(self) -> bool:
        return not self.blocking_evaluations

    @property
    def digest(self) -> str:
        return digest_payload(self.to_dict(include_digest=False))

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": WAVE12_CROSSWALK_SCHEMA_VERSION,
            "report_id": self.report_id,
            "subject_digest": self.subject_digest,
            "profile_digest": self.profile_digest,
            "generated_at": self.generated_at,
            "evaluation_count": len(self.evaluations),
            "satisfied_control_count": self.satisfied_control_count,
            "blocking_control_count": len(self.blocking_evaluations),
            "warning_control_count": len(self.warning_evaluations),
            "mandatory_evidence_complete": self.mandatory_evidence_complete,
            "evaluations": [evaluation.to_dict() for evaluation in self.evaluations],
            "metadata": dict(self.metadata),
            "scope_note": (
                "This crosswalk records evidence alignment only. It does not certify, "
                "authorize, accredit, or declare formal compliance."
            ),
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload


def evaluate_control(
    control: AssuranceControl,
    artifacts: Sequence[AssuranceEvidenceArtifact],
) -> AssuranceControlEvaluation:
    """Match one control against evidence kinds and verification strength."""

    artifacts_by_kind: dict[
        AssuranceEvidenceKind, list[AssuranceEvidenceArtifact]
    ] = {}
    for artifact in artifacts:
        artifacts_by_kind.setdefault(artifact.evidence_kind, []).append(artifact)

    matched_ids: list[str] = []
    matched_kinds: list[AssuranceEvidenceKind] = []
    missing_kinds: list[AssuranceEvidenceKind] = []
    insufficient_ids: list[str] = []

    for kind in control.evidence_kinds:
        candidates = artifacts_by_kind.get(kind, [])
        if not candidates:
            missing_kinds.append(kind)
            continue
        verified_candidates = [
            artifact
            for artifact in candidates
            if artifact.verification_state.satisfies(control.minimum_verification)
        ]
        if verified_candidates:
            matched_kinds.append(kind)
            matched_ids.extend(
                artifact.artifact_id for artifact in verified_candidates
            )
        else:
            insufficient_ids.extend(artifact.artifact_id for artifact in candidates)

    status = _derive_status(
        control=control,
        matched_kinds=tuple(matched_kinds),
        missing_kinds=tuple(missing_kinds),
        insufficient_ids=tuple(insufficient_ids),
    )
    return AssuranceControlEvaluation(
        control=control,
        matched_artifact_ids=tuple(matched_ids),
        matched_kinds=tuple(matched_kinds),
        missing_kinds=tuple(missing_kinds),
        insufficient_verification_artifact_ids=tuple(insufficient_ids),
        status=status,
    )


def build_assurance_crosswalk(
    *,
    subject: AssuranceSubject,
    profile: AssuranceProfile,
    artifacts: Sequence[AssuranceEvidenceArtifact],
    report_id: str = "wave12-assurance-crosswalk",
    metadata: Mapping[str, Any] | None = None,
) -> AssuranceCrosswalkReport:
    """Evaluate every profile control against packaged evidence."""

    return AssuranceCrosswalkReport(
        report_id=report_id,
        subject_digest=subject.digest,
        profile_digest=profile.digest,
        evaluations=tuple(
            evaluate_control(control, artifacts) for control in profile.controls
        ),
        generated_at=subject.generated_at,
        metadata={} if metadata is None else dict(metadata),
    )


def _derive_status(
    *,
    control: AssuranceControl,
    matched_kinds: tuple[AssuranceEvidenceKind, ...],
    missing_kinds: tuple[AssuranceEvidenceKind, ...],
    insufficient_ids: tuple[str, ...],
) -> ControlEvaluationStatus:
    if (
        not matched_kinds
        and missing_kinds
        and not insufficient_ids
        and not control.mandatory
    ):
        return ControlEvaluationStatus.NOT_APPLICABLE
    if missing_kinds or insufficient_ids:
        if matched_kinds or insufficient_ids:
            return ControlEvaluationStatus.PARTIAL
        return ControlEvaluationStatus.MISSING
    return ControlEvaluationStatus.SATISFIED


def _sorted_kinds(
    values: Sequence[AssuranceEvidenceKind],
) -> tuple[AssuranceEvidenceKind, ...]:
    by_value = {value.value: value for value in values}
    return tuple(by_value[key] for key in sorted(by_value))
