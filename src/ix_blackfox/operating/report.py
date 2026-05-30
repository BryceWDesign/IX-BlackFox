from __future__ import annotations

import json
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
    digest_payload,
    normalize_identifier,
    normalize_text,
)
from ix_blackfox.operating.registry import (
    normalize_identifier_tuple,
    normalize_text_tuple,
)


class OperatingReportSectionKind(StrEnum):
    """Canonical Wave 10 report sections."""

    REGISTRY = auto()
    TEAM_AUTHORITY = auto()
    CAMPAIGN_GRAPH = auto()
    EVIDENCE_INVENTORY = auto()
    REPLAY_MANIFEST = auto()
    REPLAY_VALIDATION = auto()
    REVIEW_BUNDLE = auto()
    TRACEABILITY_MAP = auto()
    POLICY_GATE = auto()
    READINESS_GATE = auto()
    TRUST_EVALUATION = auto()
    FALSIFICATION_GATE = auto()
    SCORECARD = auto()
    STANDARDS_CROSSWALK = auto()
    CLOUD_SECURITY_EXPORT = auto()


@dataclass(frozen=True, slots=True)
class OperatingReportSection:
    """Digest-bound section included in the final Wave 10 operating report."""

    section_id: str
    section_kind: OperatingReportSectionKind
    title: str
    envelope: OperatingEnvelope
    summary: str
    required: bool = True
    reviewer_actions: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "section_id",
            normalize_identifier(self.section_id, label="section_id"),
        )
        object.__setattr__(self, "title", normalize_text(self.title, label="title"))
        object.__setattr__(self, "summary", normalize_text(self.summary, label="summary"))
        object.__setattr__(
            self,
            "reviewer_actions",
            normalize_text_tuple(self.reviewer_actions, label="reviewer_actions"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def disposition(self) -> OperatingDisposition:
        return self.envelope.disposition

    @property
    def envelope_digest(self) -> str:
        return self.envelope.digest

    @property
    def artifact_ids(self) -> tuple[str, ...]:
        return tuple(artifact.artifact_id for artifact in self.envelope.evidence)

    @property
    def finding_codes(self) -> tuple[str, ...]:
        return tuple(finding.code for finding in self.envelope.findings)

    @property
    def blocking_finding_count(self) -> int:
        return len(self.envelope.blocking_findings)

    @property
    def warning_finding_count(self) -> int:
        return len(self.envelope.warning_findings)

    @property
    def blocks_report(self) -> bool:
        return self.required and self.disposition is OperatingDisposition.BLOCKED

    @property
    def warns_report(self) -> bool:
        return self.disposition is OperatingDisposition.WARNING

    def to_dict(self) -> dict[str, Any]:
        return {
            "section_id": self.section_id,
            "section_kind": self.section_kind.value,
            "title": self.title,
            "summary": self.summary,
            "required": self.required,
            "artifact_kind": self.envelope.artifact_kind.value,
            "subject": self.envelope.subject,
            "domains": [domain.value for domain in self.envelope.domains],
            "artifact_ids": list(self.artifact_ids),
            "finding_codes": list(self.finding_codes),
            "blocking_finding_count": self.blocking_finding_count,
            "warning_finding_count": self.warning_finding_count,
            "disposition": self.disposition.value,
            "envelope_digest": self.envelope_digest,
            "blocks_report": self.blocks_report,
            "warns_report": self.warns_report,
            "reviewer_actions": list(self.reviewer_actions),
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class OperatingReportClaim:
    """Bounded claim allowed in the Wave 10 report.

    The claim is intentionally constrained. It can say evidence exists for a
    reviewed campaign scope; it must not claim certification, authorization,
    government approval, AWS approval, or production readiness.
    """

    claim_id: str
    statement: str
    supported_by_section_ids: tuple[str, ...]
    evidence_artifact_ids: tuple[str, ...] = ()
    prohibited_claim_terms: tuple[str, ...] = (
        "certified",
        "certification",
        "authority to operate",
        "ato granted",
        "cato granted",
        "dod approved",
        "government approved",
        "aws approved",
        "security hub integrated",
        "fedramp authorized",
        "production ready",
    )
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "claim_id", normalize_identifier(self.claim_id, label="claim_id"))
        object.__setattr__(self, "statement", normalize_text(self.statement, label="statement"))
        if not self.supported_by_section_ids:
            raise ValueError("OperatingReportClaim supported_by_section_ids must not be empty.")
        object.__setattr__(
            self,
            "supported_by_section_ids",
            normalize_identifier_tuple(
                self.supported_by_section_ids,
                label="supported_by_section_ids",
            ),
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
            "prohibited_claim_terms",
            normalize_text_tuple(self.prohibited_claim_terms, label="prohibited_claim_terms"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def prohibited_claim_hits(self) -> tuple[str, ...]:
        statement = self.statement.lower()
        return tuple(term for term in self.prohibited_claim_terms if term in statement)

    def to_dict(self) -> dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "statement": self.statement,
            "supported_by_section_ids": list(self.supported_by_section_ids),
            "evidence_artifact_ids": list(self.evidence_artifact_ids),
            "prohibited_claim_terms": list(self.prohibited_claim_terms),
            "prohibited_claim_hits": list(self.prohibited_claim_hits),
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class OperatingReport:
    """Final Wave 10 operating report/dossier for human review.

    This report assembles evidence. It does not certify compliance, grant
    authority to operate, claim official approval, or authorize autonomous
    execution.
    """

    report_id: str
    registry_id: str
    campaign_id: str
    repository_ids: tuple[str, ...]
    sections: tuple[OperatingReportSection, ...]
    claims: tuple[OperatingReportClaim, ...]
    required_section_kinds: tuple[OperatingReportSectionKind, ...] = (
        OperatingReportSectionKind.REGISTRY,
        OperatingReportSectionKind.TEAM_AUTHORITY,
        OperatingReportSectionKind.CAMPAIGN_GRAPH,
        OperatingReportSectionKind.EVIDENCE_INVENTORY,
        OperatingReportSectionKind.REPLAY_MANIFEST,
        OperatingReportSectionKind.REPLAY_VALIDATION,
        OperatingReportSectionKind.REVIEW_BUNDLE,
        OperatingReportSectionKind.TRACEABILITY_MAP,
        OperatingReportSectionKind.POLICY_GATE,
        OperatingReportSectionKind.READINESS_GATE,
        OperatingReportSectionKind.TRUST_EVALUATION,
        OperatingReportSectionKind.FALSIFICATION_GATE,
        OperatingReportSectionKind.SCORECARD,
        OperatingReportSectionKind.STANDARDS_CROSSWALK,
        OperatingReportSectionKind.CLOUD_SECURITY_EXPORT,
    )
    generated_by: str = "IX-BlackFox Wave 10 operating report"
    disclaimer: str = (
        "Evidence-bound operating report only. This report does not certify, "
        "authorize, accredit, approve, or declare production readiness for any system."
    )
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "report_id", normalize_identifier(self.report_id, label="report_id"))
        object.__setattr__(self, "registry_id", normalize_identifier(self.registry_id, label="registry_id"))
        object.__setattr__(self, "campaign_id", normalize_identifier(self.campaign_id, label="campaign_id"))
        if not self.repository_ids:
            raise ValueError("OperatingReport repository_ids must not be empty.")
        object.__setattr__(
            self,
            "repository_ids",
            normalize_identifier_tuple(self.repository_ids, label="repository_ids"),
        )
        required_section_kinds = unique_ordered_section_kinds(self.required_section_kinds)
        object.__setattr__(self, "required_section_kinds", required_section_kinds)
        if not self.sections:
            raise ValueError("OperatingReport sections must not be empty.")
        section_kind_order = {
            section_kind: index
            for index, section_kind in enumerate(required_section_kinds)
        }
        sections = tuple(
            sorted(
                self.sections,
                key=lambda section: (
                    section_kind_order.get(section.section_kind, len(section_kind_order)),
                    section.section_id,
                ),
            )
        )
        section_ids = [section.section_id for section in sections]
        if len(section_ids) != len(set(section_ids)):
            raise ValueError("OperatingReport section_id values must be unique.")
        object.__setattr__(self, "sections", sections)
        if not self.claims:
            raise ValueError("OperatingReport claims must not be empty.")
        claims = tuple(sorted(self.claims, key=lambda claim: claim.claim_id))
        claim_ids = [claim.claim_id for claim in claims]
        if len(claim_ids) != len(set(claim_ids)):
            raise ValueError("OperatingReport claim_id values must be unique.")
        object.__setattr__(self, "claims", claims)
        self._validate_claim_references()
        object.__setattr__(
            self,
            "generated_by",
            normalize_text(self.generated_by, label="generated_by"),
        )
        object.__setattr__(self, "disclaimer", normalize_text(self.disclaimer, label="disclaimer"))
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def section_ids(self) -> tuple[str, ...]:
        return tuple(section.section_id for section in self.sections)

    @property
    def section_kinds_present(self) -> tuple[OperatingReportSectionKind, ...]:
        return unique_sorted_section_kinds(tuple(section.section_kind for section in self.sections))

    @property
    def missing_required_section_kinds(self) -> tuple[OperatingReportSectionKind, ...]:
        present = set(self.section_kinds_present)
        return tuple(kind for kind in self.required_section_kinds if kind not in present)

    @property
    def blocked_required_section_ids(self) -> tuple[str, ...]:
        return tuple(section.section_id for section in self.sections if section.blocks_report)

    @property
    def warning_section_ids(self) -> tuple[str, ...]:
        return tuple(section.section_id for section in self.sections if section.warns_report)

    @property
    def artifact_ids(self) -> tuple[str, ...]:
        return normalize_identifier_tuple(
            tuple(artifact_id for section in self.sections for artifact_id in section.artifact_ids),
            label="artifact_ids",
        )

    @property
    def unsupported_claim_ids(self) -> tuple[str, ...]:
        section_ids = set(self.section_ids)
        return tuple(
            claim.claim_id
            for claim in self.claims
            if not set(claim.supported_by_section_ids) <= section_ids
        )

    @property
    def claim_ids_with_missing_artifacts(self) -> tuple[str, ...]:
        artifacts = set(self.artifact_ids)
        return tuple(
            claim.claim_id
            for claim in self.claims
            if claim.evidence_artifact_ids and not set(claim.evidence_artifact_ids) <= artifacts
        )

    @property
    def prohibited_claim_ids(self) -> tuple[str, ...]:
        return tuple(claim.claim_id for claim in self.claims if claim.prohibited_claim_hits)

    @property
    def executive_summary(self) -> dict[str, Any]:
        return {
            "report_id": self.report_id,
            "registry_id": self.registry_id,
            "campaign_id": self.campaign_id,
            "repository_ids": list(self.repository_ids),
            "section_count": len(self.sections),
            "claim_count": len(self.claims),
            "artifact_count": len(self.artifact_ids),
            "missing_required_section_kinds": [
                kind.value for kind in self.missing_required_section_kinds
            ],
            "blocked_required_section_ids": list(self.blocked_required_section_ids),
            "warning_section_ids": list(self.warning_section_ids),
            "unsupported_claim_ids": list(self.unsupported_claim_ids),
            "claim_ids_with_missing_artifacts": list(self.claim_ids_with_missing_artifacts),
            "prohibited_claim_ids": list(self.prohibited_claim_ids),
            "disposition": self.disposition.value,
            "disclaimer": self.disclaimer,
        }

    @property
    def findings(self) -> tuple[OperatingFinding, ...]:
        findings: list[OperatingFinding] = []

        for section_kind in self.missing_required_section_kinds:
            findings.append(
                self._finding(
                    code="operating.report.missing-required-section",
                    severity=OperatingSeverity.CRITICAL,
                    summary=f"Operating report is missing required section {section_kind.value}.",
                    blocking=True,
                    metadata={"section_kind": section_kind.value},
                )
            )

        for section_id in self.blocked_required_section_ids:
            findings.append(
                self._finding(
                    code="operating.report.blocked-required-section",
                    severity=OperatingSeverity.CRITICAL,
                    summary=f"Operating report section {section_id} is blocked.",
                    blocking=True,
                    metadata={"section_id": section_id},
                )
            )

        for section_id in self.warning_section_ids:
            findings.append(
                self._finding(
                    code="operating.report.warning-section",
                    severity=OperatingSeverity.MEDIUM,
                    summary=f"Operating report section {section_id} has warning disposition.",
                    blocking=False,
                    metadata={"section_id": section_id},
                )
            )

        for claim_id in self.unsupported_claim_ids:
            findings.append(
                self._finding(
                    code="operating.report.unsupported-claim",
                    severity=OperatingSeverity.CRITICAL,
                    summary=f"Operating report claim {claim_id} references missing report sections.",
                    blocking=True,
                    metadata={"claim_id": claim_id},
                )
            )

        for claim_id in self.claim_ids_with_missing_artifacts:
            findings.append(
                self._finding(
                    code="operating.report.claim-missing-evidence-artifact",
                    severity=OperatingSeverity.CRITICAL,
                    summary=f"Operating report claim {claim_id} references missing evidence artifacts.",
                    blocking=True,
                    metadata={"claim_id": claim_id},
                )
            )

        for claim in self.claims:
            for term in claim.prohibited_claim_hits:
                findings.append(
                    self._finding(
                        code="operating.report.prohibited-claim-term",
                        severity=OperatingSeverity.CRITICAL,
                        summary=(
                            f"Operating report claim {claim.claim_id} contains "
                            f"prohibited claim term: {term}."
                        ),
                        blocking=True,
                        metadata={"claim_id": claim.claim_id, "prohibited_claim_term": term},
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

    @property
    def digest(self) -> str:
        return digest_payload(self.to_dict(include_digest=False))

    def export_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    def to_envelope(self) -> OperatingEnvelope:
        return OperatingEnvelope(
            envelope_id=f"{self.report_id}-operating-report-envelope",
            artifact_kind=OperatingArtifactKind.OPERATING_REPORT,
            subject=f"Wave 10 operating report {self.report_id}",
            domains=(
                OperatingDomain.MULTI_REPO,
                OperatingDomain.MULTI_TEAM,
                OperatingDomain.POLICY_GOVERNED,
                OperatingDomain.MEASURABLE,
                OperatingDomain.REPLAYABLE,
                OperatingDomain.REVIEWABLE,
            ),
            evidence=tuple(
                artifact
                for section in self.sections
                for artifact in section.envelope.evidence
            ),
            findings=self.findings,
            metadata={
                "report_id": self.report_id,
                "registry_id": self.registry_id,
                "campaign_id": self.campaign_id,
                "repository_ids": list(self.repository_ids),
                "section_ids": list(self.section_ids),
                "section_kinds_present": [kind.value for kind in self.section_kinds_present],
                "required_section_kinds": [kind.value for kind in self.required_section_kinds],
                "claim_ids": [claim.claim_id for claim in self.claims],
                "artifact_ids": list(self.artifact_ids),
                "executive_summary": self.executive_summary,
                "disposition": self.disposition.value,
                "disclaimer": self.disclaimer,
            },
        )

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "report_id": self.report_id,
            "registry_id": self.registry_id,
            "campaign_id": self.campaign_id,
            "repository_ids": list(self.repository_ids),
            "generated_by": self.generated_by,
            "disclaimer": self.disclaimer,
            "sections": [section.to_dict() for section in self.sections],
            "claims": [claim.to_dict() for claim in self.claims],
            "required_section_kinds": [kind.value for kind in self.required_section_kinds],
            "section_ids": list(self.section_ids),
            "section_kinds_present": [kind.value for kind in self.section_kinds_present],
            "missing_required_section_kinds": [
                kind.value for kind in self.missing_required_section_kinds
            ],
            "blocked_required_section_ids": list(self.blocked_required_section_ids),
            "warning_section_ids": list(self.warning_section_ids),
            "artifact_ids": list(self.artifact_ids),
            "unsupported_claim_ids": list(self.unsupported_claim_ids),
            "claim_ids_with_missing_artifacts": list(self.claim_ids_with_missing_artifacts),
            "prohibited_claim_ids": list(self.prohibited_claim_ids),
            "executive_summary": self.executive_summary,
            "findings": [finding.to_dict() for finding in self.findings],
            "disposition": self.disposition.value,
            "metadata": dict(self.metadata),
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload

    def _validate_claim_references(self) -> None:
        section_ids = set(section.section_id for section in self.sections)
        for claim in self.claims:
            for section_id in claim.supported_by_section_ids:
                if section_id not in section_ids:
                    continue

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
            domains=(OperatingDomain.MEASURABLE, OperatingDomain.REVIEWABLE),
            blocking=blocking,
            metadata={"report_id": self.report_id, **dict(metadata or {})},
        )


@dataclass(frozen=True, slots=True)
class OperatingReportValidation:
    """Validation result for a generated Wave 10 operating report."""

    validation_id: str
    report: OperatingReport
    expected_digest: str
    observed_digest: str
    checked_by: str
    observed_section_ids: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "validation_id",
            normalize_identifier(self.validation_id, label="validation_id"),
        )
        object.__setattr__(
            self,
            "expected_digest",
            normalize_text(self.expected_digest, label="expected_digest"),
        )
        object.__setattr__(
            self,
            "observed_digest",
            normalize_text(self.observed_digest, label="observed_digest"),
        )
        object.__setattr__(self, "checked_by", normalize_text(self.checked_by, label="checked_by"))
        object.__setattr__(
            self,
            "observed_section_ids",
            normalize_identifier_tuple_preserving_order(
                self.observed_section_ids,
                label="observed_section_ids",
            ),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def digest_matches(self) -> bool:
        return self.expected_digest == self.observed_digest == self.report.digest

    @property
    def missing_observed_section_ids(self) -> tuple[str, ...]:
        if not self.observed_section_ids:
            return tuple(self.report.section_ids)
        return tuple(sorted(set(self.report.section_ids) - set(self.observed_section_ids)))

    @property
    def findings(self) -> tuple[OperatingFinding, ...]:
        findings: list[OperatingFinding] = [*self.report.findings]

        if not self.digest_matches:
            findings.append(
                OperatingFinding(
                    code="operating.report.digest-mismatch",
                    severity=OperatingSeverity.CRITICAL,
                    summary="Operating report validation digest does not match the generated report.",
                    domains=(OperatingDomain.MEASURABLE, OperatingDomain.REVIEWABLE),
                    blocking=True,
                    metadata={
                        "validation_id": self.validation_id,
                        "report_id": self.report.report_id,
                        "expected_digest": self.expected_digest,
                        "observed_digest": self.observed_digest,
                        "actual_digest": self.report.digest,
                    },
                )
            )

        for section_id in self.missing_observed_section_ids:
            findings.append(
                OperatingFinding(
                    code="operating.report.section-not-observed",
                    severity=OperatingSeverity.CRITICAL,
                    summary=f"Operating report validation did not observe section {section_id}.",
                    domains=(OperatingDomain.MEASURABLE, OperatingDomain.REVIEWABLE),
                    blocking=True,
                    metadata={
                        "validation_id": self.validation_id,
                        "report_id": self.report.report_id,
                        "section_id": section_id,
                    },
                )
            )

        return tuple(sorted(findings, key=lambda finding: (finding.code, finding.summary)))

    @property
    def passed(self) -> bool:
        return not any(finding.blocking for finding in self.findings)

    @property
    def disposition(self) -> OperatingDisposition:
        if any(finding.blocking for finding in self.findings):
            return OperatingDisposition.BLOCKED
        if self.findings:
            return OperatingDisposition.WARNING
        return OperatingDisposition.READY

    def to_envelope(self) -> OperatingEnvelope:
        return OperatingEnvelope(
            envelope_id=f"{self.validation_id}-operating-report-validation-envelope",
            artifact_kind=OperatingArtifactKind.OPERATING_REPORT,
            subject=f"Wave 10 operating report validation {self.validation_id}",
            domains=(OperatingDomain.MEASURABLE, OperatingDomain.REVIEWABLE),
            findings=self.findings,
            metadata={
                "validation_id": self.validation_id,
                "report_id": self.report.report_id,
                "checked_by": self.checked_by,
                "digest_matches": self.digest_matches,
                "missing_observed_section_ids": list(self.missing_observed_section_ids),
                "passed": self.passed,
                "disposition": self.disposition.value,
            },
        )

    def to_dict(self) -> dict[str, Any]:
        envelope = self.to_envelope()
        return {
            "validation_id": self.validation_id,
            "report": self.report.to_dict(),
            "expected_digest": self.expected_digest,
            "observed_digest": self.observed_digest,
            "checked_by": self.checked_by,
            "observed_section_ids": list(self.observed_section_ids),
            "digest_matches": self.digest_matches,
            "missing_observed_section_ids": list(self.missing_observed_section_ids),
            "findings": [finding.to_dict() for finding in self.findings],
            "passed": self.passed,
            "disposition": self.disposition.value,
            "digest": envelope.digest,
            "metadata": dict(self.metadata),
        }


def unique_sorted_section_kinds(
    values: Sequence[OperatingReportSectionKind],
) -> tuple[OperatingReportSectionKind, ...]:
    by_value: dict[str, OperatingReportSectionKind] = {}
    for value in values:
        by_value[value.value] = value
    return tuple(by_value[key] for key in sorted(by_value))


def unique_ordered_section_kinds(
    values: Sequence[OperatingReportSectionKind],
) -> tuple[OperatingReportSectionKind, ...]:
    normalized: list[OperatingReportSectionKind] = []
    seen: set[OperatingReportSectionKind] = set()
    for value in values:
        if value not in seen:
            normalized.append(value)
            seen.add(value)
    return tuple(normalized)


def normalize_identifier_tuple_preserving_order(
    values: Sequence[str],
    *,
    label: str,
) -> tuple[str, ...]:
    normalized: list[str] = []
    seen: set[str] = set()
    for value in values:
        item = normalize_identifier(value, label=label)
        if item not in seen:
            normalized.append(item)
            seen.add(item)
    return tuple(normalized)
