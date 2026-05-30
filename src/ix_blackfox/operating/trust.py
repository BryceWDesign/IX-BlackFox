from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum, auto
from typing import Any

from ix_blackfox.operating.models import (
    OperatingArtifactKind,
    OperatingArtifactRef,
    OperatingDisposition,
    OperatingDomain,
    OperatingEnvelope,
    OperatingFinding,
    OperatingSeverity,
    normalize_identifier,
    normalize_text,
)
from ix_blackfox.operating.registry import normalize_identifier_tuple


class EvidenceFreshnessState(StrEnum):
    """Freshness state for evidence used by Wave 10 operating gates."""

    CURRENT = auto()
    AGING = auto()
    STALE = auto()
    EXPIRED = auto()
    UNKNOWN = auto()


class EvidenceIntegrityState(StrEnum):
    """Integrity state for digest-bound operating evidence."""

    VERIFIED = auto()
    UNVERIFIED = auto()
    MISSING_DIGEST = auto()
    DIGEST_MISMATCH = auto()
    MISSING_ARTIFACT = auto()


class EvidenceTrustLevel(StrEnum):
    """Normalized trust level assigned to one evidence artifact."""

    TRUSTED = auto()
    WATCH = auto()
    DEGRADED = auto()
    UNTRUSTED = auto()


@dataclass(frozen=True, slots=True)
class EvidenceTrustTransition:
    """Evidence-bound transition between trust levels."""

    transition_id: str
    artifact_id: str
    from_level: EvidenceTrustLevel
    to_level: EvidenceTrustLevel
    rationale: str
    authorized_by: str
    evidence_artifact_ids: tuple[str, ...] = ()
    human_review_ids: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "transition_id",
            normalize_identifier(self.transition_id, label="transition_id"),
        )
        object.__setattr__(
            self,
            "artifact_id",
            normalize_identifier(self.artifact_id, label="artifact_id"),
        )
        if self.from_level is self.to_level:
            raise ValueError("EvidenceTrustTransition must change trust level.")
        object.__setattr__(self, "rationale", normalize_text(self.rationale, label="rationale"))
        object.__setattr__(
            self,
            "authorized_by",
            normalize_identifier(self.authorized_by, label="authorized_by"),
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
    def trusted_transition_gap(self) -> bool:
        return self.to_level is EvidenceTrustLevel.TRUSTED and (
            not self.evidence_bound or not self.human_review_bound
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "transition_id": self.transition_id,
            "artifact_id": self.artifact_id,
            "from_level": self.from_level.value,
            "to_level": self.to_level.value,
            "rationale": self.rationale,
            "authorized_by": self.authorized_by,
            "evidence_artifact_ids": list(self.evidence_artifact_ids),
            "human_review_ids": list(self.human_review_ids),
            "evidence_bound": self.evidence_bound,
            "human_review_bound": self.human_review_bound,
            "trusted_transition_gap": self.trusted_transition_gap,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class EvidenceTrustRecord:
    """Trust assessment for one Wave 10 evidence artifact."""

    artifact: OperatingArtifactRef
    freshness_state: EvidenceFreshnessState
    integrity_state: EvidenceIntegrityState
    schema_valid: bool
    producer_trusted: bool
    human_review_bound: bool
    required: bool = True
    notes: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "notes", normalize_text_tuple(self.notes, label="notes"))
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def artifact_id(self) -> str:
        return self.artifact.artifact_id

    @property
    def trust_score(self) -> int:
        score = 100

        freshness_penalties = {
            EvidenceFreshnessState.CURRENT: 0,
            EvidenceFreshnessState.AGING: 15,
            EvidenceFreshnessState.STALE: 40,
            EvidenceFreshnessState.EXPIRED: 70,
            EvidenceFreshnessState.UNKNOWN: 35,
        }
        integrity_penalties = {
            EvidenceIntegrityState.VERIFIED: 0,
            EvidenceIntegrityState.UNVERIFIED: 35,
            EvidenceIntegrityState.MISSING_DIGEST: 60,
            EvidenceIntegrityState.DIGEST_MISMATCH: 100,
            EvidenceIntegrityState.MISSING_ARTIFACT: 100,
        }

        score -= freshness_penalties[self.freshness_state]
        score -= integrity_penalties[self.integrity_state]

        if not self.schema_valid:
            score -= 40
        if not self.producer_trusted:
            score -= 30
        if not self.human_review_bound:
            score -= 25

        return max(score, 0)

    @property
    def trust_level(self) -> EvidenceTrustLevel:
        if self.blocking_gap:
            return EvidenceTrustLevel.UNTRUSTED
        if self.trust_score > 85:
            return EvidenceTrustLevel.TRUSTED
        if self.trust_score >= 65:
            return EvidenceTrustLevel.WATCH
        if self.trust_score >= 40:
            return EvidenceTrustLevel.DEGRADED
        return EvidenceTrustLevel.UNTRUSTED

    @property
    def blocking_gap(self) -> bool:
        if not self.required:
            return False
        return (
            self.freshness_state in {
                EvidenceFreshnessState.STALE,
                EvidenceFreshnessState.EXPIRED,
                EvidenceFreshnessState.UNKNOWN,
            }
            or self.integrity_state
            in {
                EvidenceIntegrityState.MISSING_DIGEST,
                EvidenceIntegrityState.DIGEST_MISMATCH,
                EvidenceIntegrityState.MISSING_ARTIFACT,
            }
            or not self.schema_valid
            or not self.producer_trusted
            or not self.human_review_bound
        )

    @property
    def warning_gap(self) -> bool:
        return not self.blocking_gap and (
            self.freshness_state is EvidenceFreshnessState.AGING
            or self.integrity_state is EvidenceIntegrityState.UNVERIFIED
            or self.trust_level in {EvidenceTrustLevel.WATCH, EvidenceTrustLevel.DEGRADED}
        )

    @property
    def findings(self) -> tuple[OperatingFinding, ...]:
        findings: list[OperatingFinding] = []

        if self.freshness_state in {
            EvidenceFreshnessState.STALE,
            EvidenceFreshnessState.EXPIRED,
            EvidenceFreshnessState.UNKNOWN,
        }:
            findings.append(
                self._finding(
                    code="operating.trust.freshness-blocking-gap",
                    severity=OperatingSeverity.CRITICAL,
                    summary=(
                        f"Evidence artifact {self.artifact_id} freshness is "
                        f"{self.freshness_state.value}."
                    ),
                    blocking=self.required,
                )
            )
        elif self.freshness_state is EvidenceFreshnessState.AGING:
            findings.append(
                self._finding(
                    code="operating.trust.freshness-warning",
                    severity=OperatingSeverity.MEDIUM,
                    summary=f"Evidence artifact {self.artifact_id} is aging.",
                    blocking=False,
                )
            )

        if self.integrity_state in {
            EvidenceIntegrityState.MISSING_DIGEST,
            EvidenceIntegrityState.DIGEST_MISMATCH,
            EvidenceIntegrityState.MISSING_ARTIFACT,
        }:
            findings.append(
                self._finding(
                    code="operating.trust.integrity-blocking-gap",
                    severity=OperatingSeverity.CRITICAL,
                    summary=(
                        f"Evidence artifact {self.artifact_id} integrity is "
                        f"{self.integrity_state.value}."
                    ),
                    blocking=self.required,
                )
            )
        elif self.integrity_state is EvidenceIntegrityState.UNVERIFIED:
            findings.append(
                self._finding(
                    code="operating.trust.integrity-warning",
                    severity=OperatingSeverity.HIGH,
                    summary=f"Evidence artifact {self.artifact_id} digest is unverified.",
                    blocking=False,
                )
            )

        if not self.schema_valid:
            findings.append(
                self._finding(
                    code="operating.trust.invalid-schema",
                    severity=OperatingSeverity.CRITICAL,
                    summary=f"Evidence artifact {self.artifact_id} failed schema validation.",
                    blocking=self.required,
                )
            )

        if not self.producer_trusted:
            findings.append(
                self._finding(
                    code="operating.trust.untrusted-producer",
                    severity=OperatingSeverity.HIGH,
                    summary=f"Evidence artifact {self.artifact_id} came from an untrusted producer.",
                    blocking=self.required,
                )
            )

        if not self.human_review_bound:
            findings.append(
                self._finding(
                    code="operating.trust.missing-human-review-binding",
                    severity=OperatingSeverity.HIGH,
                    summary=f"Evidence artifact {self.artifact_id} is not bound to human review.",
                    blocking=self.required,
                )
            )

        return tuple(sorted(findings, key=lambda finding: (finding.code, finding.summary)))

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact": self.artifact.to_dict(),
            "artifact_id": self.artifact_id,
            "freshness_state": self.freshness_state.value,
            "integrity_state": self.integrity_state.value,
            "schema_valid": self.schema_valid,
            "producer_trusted": self.producer_trusted,
            "human_review_bound": self.human_review_bound,
            "required": self.required,
            "notes": list(self.notes),
            "trust_score": self.trust_score,
            "trust_level": self.trust_level.value,
            "blocking_gap": self.blocking_gap,
            "warning_gap": self.warning_gap,
            "findings": [finding.to_dict() for finding in self.findings],
            "metadata": dict(self.metadata),
        }

    def _finding(
        self,
        *,
        code: str,
        severity: OperatingSeverity,
        summary: str,
        blocking: bool,
    ) -> OperatingFinding:
        return OperatingFinding(
            code=code,
            severity=severity,
            summary=summary,
            domains=(OperatingDomain.MEASURABLE, OperatingDomain.REVIEWABLE),
            paths=(self.artifact.path,),
            blocking=blocking,
            metadata={
                "artifact_id": self.artifact_id,
                "trust_score": self.trust_score,
                "trust_level": self.trust_level.value,
                "required": self.required,
            },
        )


@dataclass(frozen=True, slots=True)
class EvidenceTrustEvaluator:
    """Fail-closed trust evaluator for Wave 10 evidence inventories."""

    evaluator_id: str
    records: tuple[EvidenceTrustRecord, ...]
    required_artifact_ids: tuple[str, ...]
    transitions: tuple[EvidenceTrustTransition, ...] = ()
    generated_by: str = "IX-BlackFox Wave 10 evidence trust evaluator"
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "evaluator_id",
            normalize_identifier(self.evaluator_id, label="evaluator_id"),
        )
        if not self.records:
            raise ValueError("EvidenceTrustEvaluator records must not be empty.")
        records = tuple(sorted(self.records, key=lambda record: record.artifact_id))
        artifact_ids = [record.artifact_id for record in records]
        if len(artifact_ids) != len(set(artifact_ids)):
            raise ValueError("EvidenceTrustEvaluator artifact_id values must be unique.")
        object.__setattr__(self, "records", records)
        if not self.required_artifact_ids:
            raise ValueError("EvidenceTrustEvaluator required_artifact_ids must not be empty.")
        object.__setattr__(
            self,
            "required_artifact_ids",
            normalize_identifier_tuple(
                self.required_artifact_ids,
                label="required_artifact_ids",
            ),
        )
        transitions = tuple(sorted(self.transitions, key=lambda item: item.transition_id))
        transition_ids = [transition.transition_id for transition in transitions]
        if len(transition_ids) != len(set(transition_ids)):
            raise ValueError("EvidenceTrustEvaluator transition_id values must be unique.")
        known_artifacts = set(artifact_ids)
        for transition in transitions:
            if transition.artifact_id not in known_artifacts:
                raise ValueError(
                    f"trust transition references unknown artifact: {transition.artifact_id}"
                )
        object.__setattr__(self, "transitions", transitions)
        object.__setattr__(
            self,
            "generated_by",
            normalize_text(self.generated_by, label="generated_by"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def artifact_ids(self) -> tuple[str, ...]:
        return tuple(record.artifact_id for record in self.records)

    @property
    def missing_required_artifact_ids(self) -> tuple[str, ...]:
        return tuple(sorted(set(self.required_artifact_ids) - set(self.artifact_ids)))

    @property
    def trusted_artifact_ids(self) -> tuple[str, ...]:
        return tuple(
            record.artifact_id
            for record in self.records
            if record.trust_level is EvidenceTrustLevel.TRUSTED
        )

    @property
    def degraded_artifact_ids(self) -> tuple[str, ...]:
        return tuple(
            record.artifact_id
            for record in self.records
            if record.trust_level is EvidenceTrustLevel.DEGRADED
        )

    @property
    def untrusted_artifact_ids(self) -> tuple[str, ...]:
        return tuple(
            record.artifact_id
            for record in self.records
            if record.trust_level is EvidenceTrustLevel.UNTRUSTED
        )

    @property
    def warning_artifact_ids(self) -> tuple[str, ...]:
        return tuple(record.artifact_id for record in self.records if record.warning_gap)

    @property
    def blocking_artifact_ids(self) -> tuple[str, ...]:
        return tuple(record.artifact_id for record in self.records if record.blocking_gap)

    @property
    def trusted_transition_gap_ids(self) -> tuple[str, ...]:
        return tuple(
            transition.transition_id
            for transition in self.transitions
            if transition.trusted_transition_gap
        )

    @property
    def average_trust_score(self) -> float:
        return round(
            sum(record.trust_score for record in self.records) / len(self.records),
            2,
        )

    @property
    def findings(self) -> tuple[OperatingFinding, ...]:
        findings: list[OperatingFinding] = []

        for record in self.records:
            findings.extend(record.findings)

        for artifact_id in self.missing_required_artifact_ids:
            findings.append(
                OperatingFinding(
                    code="operating.trust.missing-required-artifact",
                    severity=OperatingSeverity.CRITICAL,
                    summary=f"Evidence trust evaluator is missing required artifact {artifact_id}.",
                    domains=(OperatingDomain.MEASURABLE, OperatingDomain.REVIEWABLE),
                    blocking=True,
                    metadata={
                        "evaluator_id": self.evaluator_id,
                        "artifact_id": artifact_id,
                    },
                )
            )

        for transition_id in self.trusted_transition_gap_ids:
            findings.append(
                OperatingFinding(
                    code="operating.trust.trusted-transition-not-review-bound",
                    severity=OperatingSeverity.CRITICAL,
                    summary=(
                        f"Trust transition {transition_id} promotes evidence to trusted "
                        "without both evidence and human review binding."
                    ),
                    domains=(OperatingDomain.MEASURABLE, OperatingDomain.REVIEWABLE),
                    blocking=True,
                    metadata={
                        "evaluator_id": self.evaluator_id,
                        "transition_id": transition_id,
                    },
                )
            )

        return tuple(sorted(findings, key=lambda finding: (finding.code, finding.summary)))

    @property
    def disposition(self) -> OperatingDisposition:
        if any(finding.blocking for finding in self.findings):
            return OperatingDisposition.BLOCKED
        if self.findings:
            return OperatingDisposition.WARNING
        return OperatingDisposition.READY

    def to_envelope(self) -> OperatingEnvelope:
        return OperatingEnvelope(
            envelope_id=f"{self.evaluator_id}-trust-evaluator-envelope",
            artifact_kind=OperatingArtifactKind.EVIDENCE_MANIFEST,
            subject=f"Wave 10 evidence trust evaluator {self.evaluator_id}",
            domains=(OperatingDomain.MEASURABLE, OperatingDomain.REVIEWABLE),
            evidence=tuple(record.artifact for record in self.records),
            findings=self.findings,
            metadata={
                "evaluator_id": self.evaluator_id,
                "artifact_ids": list(self.artifact_ids),
                "required_artifact_ids": list(self.required_artifact_ids),
                "trusted_artifact_ids": list(self.trusted_artifact_ids),
                "degraded_artifact_ids": list(self.degraded_artifact_ids),
                "untrusted_artifact_ids": list(self.untrusted_artifact_ids),
                "warning_artifact_ids": list(self.warning_artifact_ids),
                "blocking_artifact_ids": list(self.blocking_artifact_ids),
                "missing_required_artifact_ids": list(self.missing_required_artifact_ids),
                "trusted_transition_gap_ids": list(self.trusted_transition_gap_ids),
                "average_trust_score": self.average_trust_score,
                "disposition": self.disposition.value,
            },
        )

    def to_dict(self) -> dict[str, Any]:
        envelope = self.to_envelope()
        return {
            "evaluator_id": self.evaluator_id,
            "generated_by": self.generated_by,
            "records": [record.to_dict() for record in self.records],
            "transitions": [transition.to_dict() for transition in self.transitions],
            "artifact_ids": list(self.artifact_ids),
            "required_artifact_ids": list(self.required_artifact_ids),
            "trusted_artifact_ids": list(self.trusted_artifact_ids),
            "degraded_artifact_ids": list(self.degraded_artifact_ids),
            "untrusted_artifact_ids": list(self.untrusted_artifact_ids),
            "warning_artifact_ids": list(self.warning_artifact_ids),
            "blocking_artifact_ids": list(self.blocking_artifact_ids),
            "missing_required_artifact_ids": list(self.missing_required_artifact_ids),
            "trusted_transition_gap_ids": list(self.trusted_transition_gap_ids),
            "average_trust_score": self.average_trust_score,
            "findings": [finding.to_dict() for finding in self.findings],
            "disposition": self.disposition.value,
            "digest": envelope.digest,
            "metadata": dict(self.metadata),
        }


def normalize_text_tuple(values: Sequence[str], *, label: str) -> tuple[str, ...]:
    normalized: list[str] = []
    seen: set[str] = set()
    for value in values:
        item = normalize_text(value, label=label)
        if item not in seen:
            normalized.append(item)
            seen.add(item)
    return tuple(sorted(normalized))
