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
)
from ix_blackfox.operating.registry import (
    normalize_identifier_tuple,
    normalize_text_tuple,
)


class StandardsFramework(StrEnum):
    """Standards and evidence ecosystems Wave 10 can map to without claiming certification."""

    NIST_SSDF = auto()
    OSCAL_ASSESSMENT_RESULTS = auto()
    DOD_CATO = auto()
    SLSA_PROVENANCE = auto()
    SBOM = auto()
    GITHUB_ARTIFACT_ATTESTATION = auto()
    OPENSSF_SCORECARD = auto()


class StandardsEvidenceKind(StrEnum):
    """Evidence categories used by standards crosswalk mappings."""

    POLICY = auto()
    HUMAN_REVIEW = auto()
    CI_VALIDATION = auto()
    REPLAY_VALIDATION = auto()
    TRACEABILITY = auto()
    SCORECARD = auto()
    PROVENANCE = auto()
    SBOM = auto()
    ATTESTATION = auto()
    SUPPLY_CHAIN_SCAN = auto()
    VULNERABILITY_SCAN = auto()
    NEGATIVE_CONTROL = auto()


class StandardsMappingStatus(StrEnum):
    """Status of one standards crosswalk mapping."""

    SUPPORTED = auto()
    PARTIAL = auto()
    MISSING = auto()
    NOT_APPLICABLE = auto()


@dataclass(frozen=True, slots=True)
class StandardsEvidenceReference:
    """Evidence reference used to support a standards crosswalk mapping."""

    evidence_id: str
    evidence_kind: StandardsEvidenceKind
    artifact_ids: tuple[str, ...]
    description: str
    verified: bool = False
    metric_ids: tuple[str, ...] = ()
    human_review_ids: tuple[str, ...] = ()
    finding_codes: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "evidence_id",
            normalize_identifier(self.evidence_id, label="evidence_id"),
        )
        if not self.artifact_ids:
            raise ValueError("StandardsEvidenceReference artifact_ids must not be empty.")
        object.__setattr__(
            self,
            "artifact_ids",
            normalize_identifier_tuple(self.artifact_ids, label="artifact_ids"),
        )
        object.__setattr__(self, "description", normalize_text(self.description, label="description"))
        object.__setattr__(
            self,
            "metric_ids",
            normalize_identifier_tuple(self.metric_ids, label="metric_ids"),
        )
        object.__setattr__(
            self,
            "human_review_ids",
            normalize_identifier_tuple(self.human_review_ids, label="human_review_ids"),
        )
        object.__setattr__(
            self,
            "finding_codes",
            normalize_code_tuple(self.finding_codes, label="finding_codes"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def review_bound(self) -> bool:
        return bool(self.human_review_ids)

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "evidence_kind": self.evidence_kind.value,
            "artifact_ids": list(self.artifact_ids),
            "description": self.description,
            "verified": self.verified,
            "metric_ids": list(self.metric_ids),
            "human_review_ids": list(self.human_review_ids),
            "finding_codes": list(self.finding_codes),
            "review_bound": self.review_bound,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class StandardsControlMapping:
    """One bounded mapping from Wave 10 evidence to a standards/control reference."""

    mapping_id: str
    framework: StandardsFramework
    reference_id: str
    title: str
    bounded_statement: str
    evidence_refs: tuple[StandardsEvidenceReference, ...]
    required_artifact_ids: tuple[str, ...] = ()
    required_metric_ids: tuple[str, ...] = ()
    required_human_review_ids: tuple[str, ...] = ()
    status: StandardsMappingStatus = StandardsMappingStatus.SUPPORTED
    mandatory: bool = True
    notes: tuple[str, ...] = ()
    prohibited_claim_terms: tuple[str, ...] = (
        "certified",
        "certification",
        "accredited",
        "authorized",
        "ato granted",
        "cato granted",
        "fedramp authorized",
        "dod approved",
        "government approved",
        "production ready",
    )
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "mapping_id",
            normalize_identifier(self.mapping_id, label="mapping_id"),
        )
        object.__setattr__(
            self,
            "reference_id",
            normalize_reference_id(self.reference_id),
        )
        object.__setattr__(self, "title", normalize_text(self.title, label="title"))
        object.__setattr__(
            self,
            "bounded_statement",
            normalize_text(self.bounded_statement, label="bounded_statement"),
        )
        if not self.evidence_refs:
            raise ValueError("StandardsControlMapping evidence_refs must not be empty.")
        evidence_refs = tuple(sorted(self.evidence_refs, key=lambda item: item.evidence_id))
        evidence_ids = [evidence.evidence_id for evidence in evidence_refs]
        if len(evidence_ids) != len(set(evidence_ids)):
            raise ValueError("StandardsControlMapping evidence_id values must be unique.")
        object.__setattr__(self, "evidence_refs", evidence_refs)
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
            "required_metric_ids",
            normalize_identifier_tuple(self.required_metric_ids, label="required_metric_ids"),
        )
        object.__setattr__(
            self,
            "required_human_review_ids",
            normalize_identifier_tuple(
                self.required_human_review_ids,
                label="required_human_review_ids",
            ),
        )
        object.__setattr__(self, "notes", normalize_text_tuple(self.notes, label="notes"))
        object.__setattr__(
            self,
            "prohibited_claim_terms",
            normalize_text_tuple(self.prohibited_claim_terms, label="prohibited_claim_terms"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def artifact_ids(self) -> tuple[str, ...]:
        return normalize_identifier_tuple(
            tuple(
                artifact_id
                for evidence in self.evidence_refs
                for artifact_id in evidence.artifact_ids
            ),
            label="artifact_ids",
        )

    @property
    def metric_ids(self) -> tuple[str, ...]:
        return normalize_identifier_tuple(
            tuple(metric_id for evidence in self.evidence_refs for metric_id in evidence.metric_ids),
            label="metric_ids",
        )

    @property
    def human_review_ids(self) -> tuple[str, ...]:
        return normalize_identifier_tuple(
            tuple(
                review_id
                for evidence in self.evidence_refs
                for review_id in evidence.human_review_ids
            ),
            label="human_review_ids",
        )

    @property
    def unverified_evidence_ids(self) -> tuple[str, ...]:
        return tuple(evidence.evidence_id for evidence in self.evidence_refs if not evidence.verified)

    @property
    def missing_required_artifact_ids(self) -> tuple[str, ...]:
        return tuple(sorted(set(self.required_artifact_ids) - set(self.artifact_ids)))

    @property
    def missing_required_metric_ids(self) -> tuple[str, ...]:
        return tuple(sorted(set(self.required_metric_ids) - set(self.metric_ids)))

    @property
    def missing_required_human_review_ids(self) -> tuple[str, ...]:
        return tuple(sorted(set(self.required_human_review_ids) - set(self.human_review_ids)))

    @property
    def prohibited_claim_hits(self) -> tuple[str, ...]:
        statement = self.bounded_statement.lower()
        return tuple(term for term in self.prohibited_claim_terms if term in statement)

    @property
    def blocking_gap(self) -> bool:
        if not self.mandatory:
            return False
        return (
            self.status in {StandardsMappingStatus.MISSING, StandardsMappingStatus.NOT_APPLICABLE}
            or bool(self.missing_required_artifact_ids)
            or bool(self.missing_required_metric_ids)
            or bool(self.missing_required_human_review_ids)
            or bool(self.prohibited_claim_hits)
        )

    @property
    def warning_gap(self) -> bool:
        return not self.blocking_gap and (
            self.status is StandardsMappingStatus.PARTIAL
            or bool(self.unverified_evidence_ids)
        )

    @property
    def findings(self) -> tuple[OperatingFinding, ...]:
        findings: list[OperatingFinding] = []

        if self.status in {StandardsMappingStatus.MISSING, StandardsMappingStatus.NOT_APPLICABLE}:
            findings.append(
                self._finding(
                    code="operating.standards.mapping-not-supported",
                    severity=OperatingSeverity.CRITICAL,
                    summary=(
                        f"Standards mapping {self.mapping_id} is {self.status.value} "
                        f"for {self.framework.value}:{self.reference_id}."
                    ),
                    blocking=self.mandatory,
                )
            )

        if self.status is StandardsMappingStatus.PARTIAL:
            findings.append(
                self._finding(
                    code="operating.standards.partial-mapping",
                    severity=OperatingSeverity.MEDIUM,
                    summary=(
                        f"Standards mapping {self.mapping_id} is partial for "
                        f"{self.framework.value}:{self.reference_id}."
                    ),
                    blocking=False,
                )
            )

        for artifact_id in self.missing_required_artifact_ids:
            findings.append(
                self._finding(
                    code="operating.standards.missing-required-artifact",
                    severity=OperatingSeverity.CRITICAL,
                    summary=(
                        f"Standards mapping {self.mapping_id} is missing required "
                        f"artifact {artifact_id}."
                    ),
                    blocking=self.mandatory,
                    metadata={"artifact_id": artifact_id},
                )
            )

        for metric_id in self.missing_required_metric_ids:
            findings.append(
                self._finding(
                    code="operating.standards.missing-required-metric",
                    severity=OperatingSeverity.HIGH,
                    summary=(
                        f"Standards mapping {self.mapping_id} is missing required "
                        f"metric {metric_id}."
                    ),
                    blocking=self.mandatory,
                    metadata={"metric_id": metric_id},
                )
            )

        for review_id in self.missing_required_human_review_ids:
            findings.append(
                self._finding(
                    code="operating.standards.missing-human-review",
                    severity=OperatingSeverity.CRITICAL,
                    summary=(
                        f"Standards mapping {self.mapping_id} is missing required "
                        f"human review {review_id}."
                    ),
                    blocking=self.mandatory,
                    metadata={"human_review_id": review_id},
                )
            )

        for evidence_id in self.unverified_evidence_ids:
            findings.append(
                self._finding(
                    code="operating.standards.unverified-evidence",
                    severity=OperatingSeverity.MEDIUM,
                    summary=(
                        f"Standards mapping {self.mapping_id} includes unverified "
                        f"evidence {evidence_id}."
                    ),
                    blocking=False,
                    metadata={"evidence_id": evidence_id},
                )
            )

        for term in self.prohibited_claim_hits:
            findings.append(
                self._finding(
                    code="operating.standards.prohibited-claim-term",
                    severity=OperatingSeverity.CRITICAL,
                    summary=(
                        f"Standards mapping {self.mapping_id} contains prohibited "
                        f"claim term: {term}."
                    ),
                    blocking=True,
                    metadata={"prohibited_claim_term": term},
                )
            )

        return tuple(sorted(findings, key=lambda finding: (finding.code, finding.summary)))

    def to_dict(self) -> dict[str, Any]:
        return {
            "mapping_id": self.mapping_id,
            "framework": self.framework.value,
            "reference_id": self.reference_id,
            "title": self.title,
            "bounded_statement": self.bounded_statement,
            "evidence_refs": [evidence.to_dict() for evidence in self.evidence_refs],
            "required_artifact_ids": list(self.required_artifact_ids),
            "required_metric_ids": list(self.required_metric_ids),
            "required_human_review_ids": list(self.required_human_review_ids),
            "artifact_ids": list(self.artifact_ids),
            "metric_ids": list(self.metric_ids),
            "human_review_ids": list(self.human_review_ids),
            "unverified_evidence_ids": list(self.unverified_evidence_ids),
            "missing_required_artifact_ids": list(self.missing_required_artifact_ids),
            "missing_required_metric_ids": list(self.missing_required_metric_ids),
            "missing_required_human_review_ids": list(self.missing_required_human_review_ids),
            "prohibited_claim_hits": list(self.prohibited_claim_hits),
            "status": self.status.value,
            "mandatory": self.mandatory,
            "blocking_gap": self.blocking_gap,
            "warning_gap": self.warning_gap,
            "notes": list(self.notes),
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
            metadata={
                "mapping_id": self.mapping_id,
                "framework": self.framework.value,
                "reference_id": self.reference_id,
                **dict(metadata or {}),
            },
        )


@dataclass(frozen=True, slots=True)
class StandardsCrosswalkReport:
    """Deterministic Wave 10 standards crosswalk report.

    This report is intentionally mapping-ready evidence only. It does not claim
    certification, authorization, accreditation, formal compliance, or official
    approval by any standards body, agency, vendor, or government organization.
    """

    report_id: str
    registry_id: str
    campaign_id: str
    mappings: tuple[StandardsControlMapping, ...]
    required_frameworks: tuple[StandardsFramework, ...] = (
        StandardsFramework.NIST_SSDF,
        StandardsFramework.OSCAL_ASSESSMENT_RESULTS,
        StandardsFramework.DOD_CATO,
        StandardsFramework.SLSA_PROVENANCE,
        StandardsFramework.SBOM,
        StandardsFramework.GITHUB_ARTIFACT_ATTESTATION,
        StandardsFramework.OPENSSF_SCORECARD,
    )
    generated_by: str = "IX-BlackFox Wave 10 standards crosswalk"
    disclaimer: str = (
        "Mapping-ready evidence only; this report does not certify, authorize, "
        "accredit, approve, or declare compliance for any system."
    )
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "report_id", normalize_identifier(self.report_id, label="report_id"))
        object.__setattr__(self, "registry_id", normalize_identifier(self.registry_id, label="registry_id"))
        object.__setattr__(self, "campaign_id", normalize_identifier(self.campaign_id, label="campaign_id"))
        if not self.mappings:
            raise ValueError("StandardsCrosswalkReport mappings must not be empty.")
        mappings = tuple(sorted(self.mappings, key=lambda mapping: mapping.mapping_id))
        mapping_ids = [mapping.mapping_id for mapping in mappings]
        if len(mapping_ids) != len(set(mapping_ids)):
            raise ValueError("StandardsCrosswalkReport mapping_id values must be unique.")
        object.__setattr__(self, "mappings", mappings)
        object.__setattr__(
            self,
            "required_frameworks",
            unique_sorted_frameworks(self.required_frameworks),
        )
        object.__setattr__(
            self,
            "generated_by",
            normalize_text(self.generated_by, label="generated_by"),
        )
        object.__setattr__(self, "disclaimer", normalize_text(self.disclaimer, label="disclaimer"))
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def frameworks_present(self) -> tuple[StandardsFramework, ...]:
        return unique_sorted_frameworks(tuple(mapping.framework for mapping in self.mappings))

    @property
    def missing_required_frameworks(self) -> tuple[StandardsFramework, ...]:
        present = set(self.frameworks_present)
        return tuple(framework for framework in self.required_frameworks if framework not in present)

    @property
    def mapping_ids(self) -> tuple[str, ...]:
        return tuple(mapping.mapping_id for mapping in self.mappings)

    @property
    def supported_mapping_ids(self) -> tuple[str, ...]:
        return tuple(
            mapping.mapping_id
            for mapping in self.mappings
            if mapping.status is StandardsMappingStatus.SUPPORTED and not mapping.blocking_gap
        )

    @property
    def partial_mapping_ids(self) -> tuple[str, ...]:
        return tuple(
            mapping.mapping_id
            for mapping in self.mappings
            if mapping.status is StandardsMappingStatus.PARTIAL or mapping.warning_gap
        )

    @property
    def blocking_mapping_ids(self) -> tuple[str, ...]:
        return tuple(mapping.mapping_id for mapping in self.mappings if mapping.blocking_gap)

    @property
    def artifact_ids(self) -> tuple[str, ...]:
        return normalize_identifier_tuple(
            tuple(artifact_id for mapping in self.mappings for artifact_id in mapping.artifact_ids),
            label="artifact_ids",
        )

    @property
    def metric_ids(self) -> tuple[str, ...]:
        return normalize_identifier_tuple(
            tuple(metric_id for mapping in self.mappings for metric_id in mapping.metric_ids),
            label="metric_ids",
        )

    @property
    def human_review_ids(self) -> tuple[str, ...]:
        return normalize_identifier_tuple(
            tuple(review_id for mapping in self.mappings for review_id in mapping.human_review_ids),
            label="human_review_ids",
        )

    @property
    def framework_counts(self) -> dict[str, int]:
        counts = {framework.value: 0 for framework in StandardsFramework}
        for mapping in self.mappings:
            counts[mapping.framework.value] += 1
        return {framework: count for framework, count in counts.items() if count > 0}

    @property
    def findings(self) -> tuple[OperatingFinding, ...]:
        findings: list[OperatingFinding] = []

        for framework in self.missing_required_frameworks:
            findings.append(
                OperatingFinding(
                    code="operating.standards.missing-required-framework",
                    severity=OperatingSeverity.HIGH,
                    summary=(
                        f"Standards crosswalk report {self.report_id} is missing "
                        f"required framework {framework.value}."
                    ),
                    domains=(OperatingDomain.POLICY_GOVERNED, OperatingDomain.MEASURABLE),
                    blocking=True,
                    metadata={"report_id": self.report_id, "framework": framework.value},
                )
            )

        for mapping in self.mappings:
            findings.extend(mapping.findings)

        return tuple(sorted(findings, key=lambda finding: (finding.code, finding.summary)))

    @property
    def disposition(self) -> OperatingDisposition:
        if any(finding.blocking for finding in self.findings):
            return OperatingDisposition.BLOCKED
        if self.findings:
            return OperatingDisposition.WARNING
        return OperatingDisposition.READY

    def mappings_for_framework(
        self,
        framework: StandardsFramework,
    ) -> tuple[StandardsControlMapping, ...]:
        return tuple(mapping for mapping in self.mappings if mapping.framework is framework)

    def to_envelope(self) -> OperatingEnvelope:
        return OperatingEnvelope(
            envelope_id=f"{self.report_id}-standards-crosswalk-envelope",
            artifact_kind=OperatingArtifactKind.STANDARDS_CROSSWALK,
            subject=f"Wave 10 standards crosswalk {self.report_id}",
            domains=(OperatingDomain.POLICY_GOVERNED, OperatingDomain.MEASURABLE),
            findings=self.findings,
            metadata={
                "report_id": self.report_id,
                "registry_id": self.registry_id,
                "campaign_id": self.campaign_id,
                "mapping_ids": list(self.mapping_ids),
                "frameworks_present": [framework.value for framework in self.frameworks_present],
                "missing_required_frameworks": [
                    framework.value for framework in self.missing_required_frameworks
                ],
                "framework_counts": self.framework_counts,
                "supported_mapping_ids": list(self.supported_mapping_ids),
                "partial_mapping_ids": list(self.partial_mapping_ids),
                "blocking_mapping_ids": list(self.blocking_mapping_ids),
                "artifact_ids": list(self.artifact_ids),
                "metric_ids": list(self.metric_ids),
                "human_review_ids": list(self.human_review_ids),
                "disposition": self.disposition.value,
                "disclaimer": self.disclaimer,
            },
        )

    def to_dict(self) -> dict[str, Any]:
        envelope = self.to_envelope()
        return {
            "report_id": self.report_id,
            "registry_id": self.registry_id,
            "campaign_id": self.campaign_id,
            "generated_by": self.generated_by,
            "disclaimer": self.disclaimer,
            "mappings": [mapping.to_dict() for mapping in self.mappings],
            "required_frameworks": [framework.value for framework in self.required_frameworks],
            "frameworks_present": [framework.value for framework in self.frameworks_present],
            "missing_required_frameworks": [
                framework.value for framework in self.missing_required_frameworks
            ],
            "framework_counts": self.framework_counts,
            "mapping_ids": list(self.mapping_ids),
            "supported_mapping_ids": list(self.supported_mapping_ids),
            "partial_mapping_ids": list(self.partial_mapping_ids),
            "blocking_mapping_ids": list(self.blocking_mapping_ids),
            "artifact_ids": list(self.artifact_ids),
            "metric_ids": list(self.metric_ids),
            "human_review_ids": list(self.human_review_ids),
            "findings": [finding.to_dict() for finding in self.findings],
            "disposition": self.disposition.value,
            "digest": envelope.digest,
            "metadata": dict(self.metadata),
        }


def build_default_wave10_standards_crosswalk(
    *,
    report_id: str,
    registry_id: str,
    campaign_id: str,
    artifact_ids: Sequence[str],
    metric_ids: Sequence[str],
    human_review_ids: Sequence[str],
) -> StandardsCrosswalkReport:
    """Build the default Wave 10 mapping-ready crosswalk.

    The generated report uses bounded statements and deliberately avoids claims
    of certification, authorization, accreditation, official approval, or formal
    compliance.
    """

    artifacts = normalize_identifier_tuple(artifact_ids, label="artifact_ids")
    metrics = normalize_identifier_tuple(metric_ids, label="metric_ids")
    reviews = normalize_identifier_tuple(human_review_ids, label="human_review_ids")

    def evidence(
        evidence_id: str,
        evidence_kind: StandardsEvidenceKind,
        description: str,
    ) -> StandardsEvidenceReference:
        return StandardsEvidenceReference(
            evidence_id=evidence_id,
            evidence_kind=evidence_kind,
            artifact_ids=artifacts,
            description=description,
            verified=True,
            metric_ids=metrics,
            human_review_ids=reviews,
        )

    return StandardsCrosswalkReport(
        report_id=report_id,
        registry_id=registry_id,
        campaign_id=campaign_id,
        mappings=(
            StandardsControlMapping(
                mapping_id="nist-ssdf-governed-change-evidence",
                framework=StandardsFramework.NIST_SSDF,
                reference_id="SSDF.PO/PW/RV mapping",
                title="SSDF-style governed change evidence",
                bounded_statement=(
                    "Wave 10 provides mapping-ready evidence for secure software "
                    "development practices, including policy, review, validation, "
                    "and evidence traceability for this campaign scope only."
                ),
                evidence_refs=(
                    evidence(
                        "ssdf-evidence",
                        StandardsEvidenceKind.POLICY,
                        "Policy, validation, review, and traceability evidence for SSDF-style mapping.",
                    ),
                ),
                required_artifact_ids=artifacts,
                required_metric_ids=metrics,
                required_human_review_ids=reviews,
            ),
            StandardsControlMapping(
                mapping_id="oscal-assessment-results-style-evidence",
                framework=StandardsFramework.OSCAL_ASSESSMENT_RESULTS,
                reference_id="OSCAL assessment-results-style export",
                title="OSCAL assessment-results-style evidence",
                bounded_statement=(
                    "Wave 10 can emit structured assessment-result-style facts "
                    "that are suitable for downstream mapping and review."
                ),
                evidence_refs=(
                    evidence(
                        "oscal-style-evidence",
                        StandardsEvidenceKind.TRACEABILITY,
                        "Structured findings, observations, evidence links, and disposition fields.",
                    ),
                ),
                required_artifact_ids=artifacts,
                required_metric_ids=metrics,
                required_human_review_ids=reviews,
            ),
            StandardsControlMapping(
                mapping_id="dod-cato-evidence-category-mapping",
                framework=StandardsFramework.DOD_CATO,
                reference_id="DoD cATO evidence categories",
                title="DoD cATO evidence category mapping",
                bounded_statement=(
                    "Wave 10 provides mapping-ready evidence categories for "
                    "continuous monitoring, software factory, team/process, "
                    "DevSecOps, and supply-chain review without claiming approval."
                ),
                evidence_refs=(
                    evidence(
                        "cato-category-evidence",
                        StandardsEvidenceKind.SCORECARD,
                        "Operating metrics and evidence categories for cATO-style review.",
                    ),
                ),
                required_artifact_ids=artifacts,
                required_metric_ids=metrics,
                required_human_review_ids=reviews,
            ),
            StandardsControlMapping(
                mapping_id="slsa-provenance-reference",
                framework=StandardsFramework.SLSA_PROVENANCE,
                reference_id="SLSA provenance reference",
                title="SLSA/provenance reference mapping",
                bounded_statement=(
                    "Wave 10 records provenance-oriented artifact references, "
                    "builder evidence, digest binding, and replay evidence for "
                    "supply-chain review."
                ),
                evidence_refs=(
                    evidence(
                        "slsa-provenance-evidence",
                        StandardsEvidenceKind.PROVENANCE,
                        "Digest-bound provenance and replay evidence references.",
                    ),
                ),
                required_artifact_ids=artifacts,
                required_metric_ids=metrics,
                required_human_review_ids=reviews,
            ),
            StandardsControlMapping(
                mapping_id="sbom-reference-inventory",
                framework=StandardsFramework.SBOM,
                reference_id="SBOM inventory reference",
                title="SBOM reference mapping",
                bounded_statement=(
                    "Wave 10 tracks SBOM artifact references and evidence status "
                    "so downstream tools can review dependency inventory coverage."
                ),
                evidence_refs=(
                    evidence(
                        "sbom-inventory-evidence",
                        StandardsEvidenceKind.SBOM,
                        "SBOM artifact references and inventory coverage metrics.",
                    ),
                ),
                required_artifact_ids=artifacts,
                required_metric_ids=metrics,
                required_human_review_ids=reviews,
            ),
            StandardsControlMapping(
                mapping_id="github-artifact-attestation-reference",
                framework=StandardsFramework.GITHUB_ARTIFACT_ATTESTATION,
                reference_id="GitHub artifact attestation reference",
                title="GitHub artifact attestation reference mapping",
                bounded_statement=(
                    "Wave 10 tracks artifact attestation references, digest-bound "
                    "artifacts, and review evidence for GitHub Actions provenance review."
                ),
                evidence_refs=(
                    evidence(
                        "github-attestation-evidence",
                        StandardsEvidenceKind.ATTESTATION,
                        "Artifact attestation references and digest-bound review evidence.",
                    ),
                ),
                required_artifact_ids=artifacts,
                required_metric_ids=metrics,
                required_human_review_ids=reviews,
            ),
            StandardsControlMapping(
                mapping_id="openssf-scorecard-signal-reference",
                framework=StandardsFramework.OPENSSF_SCORECARD,
                reference_id="OpenSSF Scorecard signal reference",
                title="OpenSSF Scorecard-style signal mapping",
                bounded_statement=(
                    "Wave 10 tracks scorecard-style repository security signals "
                    "as evidence references for review and continuous improvement."
                ),
                evidence_refs=(
                    evidence(
                        "openssf-scorecard-evidence",
                        StandardsEvidenceKind.SCORECARD,
                        "Repository security signal and scorecard metric references.",
                    ),
                ),
                required_artifact_ids=artifacts,
                required_metric_ids=metrics,
                required_human_review_ids=reviews,
            ),
        ),
    )


def normalize_reference_id(value: str) -> str:
    cleaned = " ".join(value.strip().split())
    if not cleaned:
        raise ValueError("reference_id must not be empty.")
    return cleaned


def normalize_code_tuple(values: Sequence[str], *, label: str) -> tuple[str, ...]:
    normalized: list[str] = []
    seen: set[str] = set()
    for value in values:
        item = normalize_text(value, label=label)
        if item not in seen:
            normalized.append(item)
            seen.add(item)
    return tuple(sorted(normalized))


def unique_sorted_frameworks(values: Sequence[StandardsFramework]) -> tuple[StandardsFramework, ...]:
    by_value: dict[str, StandardsFramework] = {}
    for value in values:
        by_value[value.value] = value
    return tuple(by_value[key] for key in sorted(by_value))
