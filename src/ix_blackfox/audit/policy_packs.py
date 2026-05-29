from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from ix_blackfox.audit.models import (
    WAVE9_POLICY_PACK_SCHEMA_VERSION,
    AuditControlRequirement,
    AuditControlSeverity,
    AuditEvidenceKind,
    AuditNonClaimSet,
    AuditStandardsMapping,
    AuditStandardsMappingKind,
    digest_payload,
    normalize_identifier,
    normalize_optional_text,
    normalize_text,
)

DEFAULT_WAVE9_POLICY_PACK_ID = "ix-blackfox.wave9.default"
DEFAULT_WAVE9_POLICY_PACK_VERSION = "1.0.0"
DEFAULT_WAVE9_POLICY_PACK_TITLE = "IX-BlackFox Wave 9 Compliance Audit Attestation"


@dataclass(frozen=True, slots=True)
class AuditPolicyPack:
    """
    Deterministic Wave 9 policy pack.

    A policy pack is a review contract for IX-BlackFox evidence. It describes
    the controls that must be evaluated before the repo can say an AI-assisted
    code-change workflow is audit-ready. The pack is not a certification,
    production approval, ATO/cATO, procurement approval, or government
    endorsement.
    """

    pack_id: str
    version: str
    title: str
    description: str
    controls: tuple[AuditControlRequirement, ...]
    non_claims: AuditNonClaimSet = field(default_factory=AuditNonClaimSet)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "pack_id", normalize_identifier(self.pack_id, label="pack_id"))
        object.__setattr__(self, "version", normalize_text(self.version, label="version"))
        object.__setattr__(self, "title", normalize_text(self.title, label="title"))
        object.__setattr__(
            self,
            "description",
            normalize_text(self.description, label="description"),
        )
        controls = tuple(sorted(self.controls, key=lambda control: control.control_id))
        control_ids = [control.control_id for control in controls]
        if len(control_ids) != len(set(control_ids)):
            raise ValueError("AuditPolicyPack control_id values must be unique.")
        if not controls:
            raise ValueError("AuditPolicyPack must contain at least one control.")
        object.__setattr__(self, "controls", controls)
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def digest(self) -> str:
        return digest_payload(self.to_dict(include_digest=False))

    @property
    def control_count(self) -> int:
        return len(self.controls)

    @property
    def control_ids(self) -> tuple[str, ...]:
        return tuple(control.control_id for control in self.controls)

    def control_by_id(self, control_id: str) -> AuditControlRequirement:
        normalized = normalize_identifier(control_id, label="control_id")
        for control in self.controls:
            if control.control_id == normalized:
                return control
        raise KeyError(f"Unknown audit policy-pack control: {normalized}")

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": WAVE9_POLICY_PACK_SCHEMA_VERSION,
            "pack_id": self.pack_id,
            "version": self.version,
            "title": self.title,
            "description": self.description,
            "control_count": self.control_count,
            "controls": [control.to_dict() for control in self.controls],
            "non_claims": self.non_claims.to_dict(),
            "metadata": dict(self.metadata),
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload


def default_wave9_policy_pack() -> AuditPolicyPack:
    """Return the default DevSecOps-facing Wave 9 audit policy pack."""

    return AuditPolicyPack(
        pack_id=DEFAULT_WAVE9_POLICY_PACK_ID,
        version=DEFAULT_WAVE9_POLICY_PACK_VERSION,
        title=DEFAULT_WAVE9_POLICY_PACK_TITLE,
        description=(
            "Default IX-BlackFox Wave 9 controls for evidence-standardized, "
            "human-authorized, fail-closed audit attestation across Waves 5-8."
        ),
        controls=_default_wave9_controls(),
        metadata={
            "wave": 9,
            "posture": "source-available evaluation research prototype",
            "audit_scope": "ai-assisted code-change governance evidence",
            "readiness_claim": "audit-readiness only inside the declared IX-BlackFox policy scope",
            "authority_rule": "AI proposes. Humans decide.",
        },
    )


def _default_wave9_controls() -> tuple[AuditControlRequirement, ...]:
    return (
        _control(
            "BF-W9-001",
            "Model output is untrusted input",
            (
                "Require the audit record to preserve that model output is advisory input, "
                "not an engineering control, authorization, verification result, or release decision."
            ),
            AuditControlSeverity.BLOCKING,
            standards_mappings=(
                _mapping(
                    AuditStandardsMappingKind.INTERNAL_IX_BLACKFOX,
                    "IX-BLACKFOX-AI-PROPOSES-HUMANS-DECIDE",
                    "Binds Wave 9 to the IX-BlackFox authority boundary.",
                ),
                _mapping(
                    AuditStandardsMappingKind.DOD_ENTERPRISE_DEVSECOPS,
                    "DOD-DEVSECOPS-GOVERNED-PIPELINE-EVIDENCE",
                    "Aligns with evidence-producing software-factory review posture without claiming DoD approval.",
                ),
            ),
            metadata={
                "control_family": "authority_boundary",
                "required_report_field": "non_claims",
            },
        ),
        _control(
            "BF-W9-002",
            "Policy pack identity and digest are bound to the audit",
            (
                "Require every Wave 9 audit report to identify the policy pack ID, version, "
                "control set, and deterministic policy-pack digest used for evaluation."
            ),
            AuditControlSeverity.BLOCKING,
            standards_mappings=(
                _mapping(
                    AuditStandardsMappingKind.OSCAL_ASSESSMENT_RESULTS,
                    "OSCAL-ASSESSMENT-PLAN-AND-RESULTS-CONTEXT",
                    "Uses explicit assessment context and evaluated control identity as a design pattern only.",
                ),
            ),
            metadata={
                "control_family": "policy_pack_integrity",
                "required_report_field": "policy_pack.digest",
            },
        ),
        _control(
            "BF-W9-003",
            "Evidence manifest uses deterministic artifact metadata",
            (
                "Require evidence artifacts to include stable artifact IDs, evidence kind, source wave, "
                "repository-relative path, SHA-256 digest, positive byte size, producer, and schema metadata when available."
            ),
            AuditControlSeverity.BLOCKING,
            standards_mappings=(
                _mapping(
                    AuditStandardsMappingKind.SLSA_PROVENANCE,
                    "SLSA-PROVENANCE-SUBJECT-DIGEST-PATTERN",
                    "Adopts subject-and-digest provenance discipline without claiming SLSA compliance.",
                ),
                _mapping(
                    AuditStandardsMappingKind.IN_TOTO_STATEMENT,
                    "IN-TOTO-STATEMENT-SUBJECT-PATTERN",
                    "Adopts artifact subject/digest discipline without emitting a formal in-toto statement in this control.",
                ),
            ),
            metadata={
                "control_family": "evidence_standard",
                "required_report_field": "evidence_manifest.digest",
            },
        ),
        _control(
            "BF-W9-004",
            "Wave 5 PR and workflow evidence is present for change-review scope",
            (
                "Require PR evidence-pack or organization-workflow evidence when the audit scope includes "
                "code-change review, merge readiness, or organization-grade workflow claims."
            ),
            AuditControlSeverity.BLOCKING,
            required_evidence_kinds=(
                AuditEvidenceKind.PR_EVIDENCE_PACK,
                AuditEvidenceKind.APPROVAL_RECORD,
            ),
            standards_mappings=(
                _mapping(
                    AuditStandardsMappingKind.INTERNAL_IX_BLACKFOX,
                    "IX-BLACKFOX-WAVE5-PR-EVIDENCE",
                    "Uses existing Wave 5 PR evidence-pack and approval controls as audit inputs.",
                ),
            ),
            metadata={
                "control_family": "wave5_bridge",
                "required_when_scope_contains": ("change", "merge", "pull_request", "pr"),
            },
        ),
        _control(
            "BF-W9-005",
            "CI evidence is bound to the reviewed head SHA",
            (
                "Require CI evidence to identify the reviewed head SHA when the audit report makes a CI-bound "
                "verification claim. CI status without commit binding is not sufficient audit evidence."
            ),
            AuditControlSeverity.BLOCKING,
            required_evidence_kinds=(AuditEvidenceKind.CI_EVIDENCE,),
            standards_mappings=(
                _mapping(
                    AuditStandardsMappingKind.DOD_ENTERPRISE_DEVSECOPS,
                    "DOD-DEVSECOPS-CICD-METADATA-CONTINUOUS-MONITORING",
                    "Aligns with CI/CD metadata collection and pipeline evidence posture without claiming cATO readiness.",
                ),
            ),
            metadata={
                "control_family": "ci_binding",
                "required_when_claim_contains": ("ci", "github_actions", "green"),
            },
        ),
        _control(
            "BF-W9-006",
            "Wave 6 sandbox evidence is present when sandbox claims are made",
            (
                "Require sandbox receipt bundles or adversarial sandbox reports when the audit report claims "
                "isolated execution, sandboxing, egress controls, or hardened workspace behavior."
            ),
            AuditControlSeverity.BLOCKING,
            required_evidence_kinds=(
                AuditEvidenceKind.SANDBOX_RECEIPT_BUNDLE,
                AuditEvidenceKind.SANDBOX_ADVERSARIAL_REPORT,
            ),
            standards_mappings=(
                _mapping(
                    AuditStandardsMappingKind.INTERNAL_IX_BLACKFOX,
                    "IX-BLACKFOX-WAVE6-SANDBOX-EVIDENCE",
                    "Uses Wave 6 sandbox and adversarial evidence as audit inputs.",
                ),
            ),
            metadata={
                "control_family": "wave6_bridge",
                "required_when_claim_contains": ("sandbox", "egress", "isolated", "workspace"),
            },
        ),
        _control(
            "BF-W9-007",
            "Wave 7 model-repair evidence is present when model routing or repair is claimed",
            (
                "Require selected/rejected/blocked candidate evidence, model-routing evidence, or model-repair "
                "receipts when the audit report claims model-agnostic repair intelligence."
            ),
            AuditControlSeverity.BLOCKING,
            required_evidence_kinds=(
                AuditEvidenceKind.MODEL_REPAIR_REPORT,
                AuditEvidenceKind.MODEL_REPAIR_RECEIPT,
            ),
            standards_mappings=(
                _mapping(
                    AuditStandardsMappingKind.INTERNAL_IX_BLACKFOX,
                    "IX-BLACKFOX-WAVE7-MODEL-REPAIR-EVIDENCE",
                    "Uses Wave 7 repair-intelligence evidence as audit inputs.",
                ),
            ),
            metadata={
                "control_family": "wave7_bridge",
                "required_when_claim_contains": ("model", "repair", "routing", "candidate"),
            },
        ),
        _control(
            "BF-W9-008",
            "Wave 8 repository-intelligence evidence is present when repo-impact claims are made",
            (
                "Require repository-intelligence evidence when the audit report claims dependency mapping, code graph, "
                "impact analysis, architecture memory, or repository understanding."
            ),
            AuditControlSeverity.BLOCKING,
            required_evidence_kinds=(
                AuditEvidenceKind.REPOSITORY_INTELLIGENCE_REPORT,
                AuditEvidenceKind.REPOSITORY_EVIDENCE_SNAPSHOT,
            ),
            standards_mappings=(
                _mapping(
                    AuditStandardsMappingKind.INTERNAL_IX_BLACKFOX,
                    "IX-BLACKFOX-WAVE8-REPOSITORY-INTELLIGENCE-EVIDENCE",
                    "Uses Wave 8 repository-intelligence outputs as audit inputs.",
                ),
            ),
            metadata={
                "control_family": "wave8_bridge",
                "required_when_claim_contains": ("dependency", "impact", "code_graph", "architecture_memory"),
            },
        ),
        _control(
            "BF-W9-009",
            "Malformed, missing, zero-byte, or mismatched evidence blocks audit readiness",
            (
                "Require the audit evaluator to fail closed on evidence that is missing, malformed, empty, undigested, "
                "head-SHA mismatched, or impossible to inspect deterministically."
            ),
            AuditControlSeverity.BLOCKING,
            standards_mappings=(
                _mapping(
                    AuditStandardsMappingKind.INTERNAL_IX_BLACKFOX,
                    "IX-AGENT-NOTARY-STRICT-VERIFICATION-DISCIPLINE",
                    "Borrows strict verification posture from notary-style receipt validation without importing implementation code.",
                ),
            ),
            metadata={
                "control_family": "fail_closed_evidence_validation",
                "required_engine_behavior": "reject_unverifiable_evidence",
            },
        ),
        _control(
            "BF-W9-010",
            "Unverified provenance or attestation claims are not accepted as verified evidence",
            (
                "Require the audit report to distinguish recorded attestation metadata from verified provenance. "
                "A provenance claim is not treated as verified unless the verification result is actually present."
            ),
            AuditControlSeverity.BLOCKING,
            required_evidence_kinds=(AuditEvidenceKind.ATTESTATION,),
            standards_mappings=(
                _mapping(
                    AuditStandardsMappingKind.GITHUB_ARTIFACT_ATTESTATION,
                    "GITHUB-ARTIFACT-ATTESTATION-VERIFY-BEFORE-TRUST",
                    "Aligns with verify-before-trust attestation practice without pretending local Sigstore verification occurred.",
                ),
                _mapping(
                    AuditStandardsMappingKind.SLSA_PROVENANCE,
                    "SLSA-PROVENANCE-VERIFICATION-BOUNDARY",
                    "Separates provenance recording from provenance verification.",
                ),
            ),
            metadata={
                "control_family": "provenance_boundary",
                "required_when_claim_contains": ("attestation", "provenance", "slsa", "sigstore"),
            },
        ),
        _control(
            "BF-W9-011",
            "Human signoff is required for audit-ready disposition",
            (
                "Require at least one authoritative human approval bound to the attestation subject digest and policy-pack "
                "digest before the final disposition can become audit_ready."
            ),
            AuditControlSeverity.BLOCKING,
            required_evidence_kinds=(
                AuditEvidenceKind.HUMAN_REVIEW,
                AuditEvidenceKind.APPROVAL_RECORD,
            ),
            standards_mappings=(
                _mapping(
                    AuditStandardsMappingKind.INTERNAL_IX_BLACKFOX,
                    "IX-BLACKFOX-HUMAN-AUTHORITY-GATE",
                    "Preserves the human-authorization boundary for AI-assisted code changes.",
                ),
            ),
            metadata={
                "control_family": "human_authority",
                "required_report_field": "reviewer_signoffs",
            },
        ),
        _control(
            "BF-W9-012",
            "Model or system self-approval cannot satisfy authority",
            (
                "Require model and system signoffs to remain advisory. They may explain evaluation state, but they cannot "
                "satisfy human approval, independent review, release authority, or audit-ready disposition."
            ),
            AuditControlSeverity.BLOCKING,
            standards_mappings=(
                _mapping(
                    AuditStandardsMappingKind.INTERNAL_IX_BLACKFOX,
                    "IX-BLACKFOX-COGNITION-AUTHORITY-FIREWALL",
                    "Uses Cognition-style model-role separation and self-review prevention as an audit control boundary.",
                ),
            ),
            metadata={
                "control_family": "self_review_prevention",
                "forbidden_authority_sources": ("model", "system"),
            },
        ),
        _control(
            "BF-W9-013",
            "Explicit non-claims are preserved in every governance report",
            (
                "Require every Wave 9 governance report to preserve non-claims for production readiness, ATO/cATO, "
                "procurement acceptance, DoD endorsement, official certification, and autonomous authority."
            ),
            AuditControlSeverity.BLOCKING,
            standards_mappings=(
                _mapping(
                    AuditStandardsMappingKind.NIST_SSDF,
                    "NIST-SSDF-SECURE-SOFTWARE-PRACTICE-MAPPING-ONLY",
                    "Uses secure-development vocabulary for buyer/reviewer communication without claiming formal SSDF assessment.",
                ),
            ),
            metadata={
                "control_family": "anti_overclaim",
                "required_report_field": "non_claims",
            },
        ),
        _control(
            "BF-W9-014",
            "Required evidence gaps block audit readiness by default",
            (
                "Require the audit engine to produce blocked disposition, not warning-only disposition, when required "
                "evidence for the declared scope is absent or unverifiable."
            ),
            AuditControlSeverity.BLOCKING,
            standards_mappings=(
                _mapping(
                    AuditStandardsMappingKind.INTERNAL_IX_BLACKFOX,
                    "IX-BLACKFOX-FAIL-CLOSED-AUDIT-GATE",
                    "Preserves fail-closed governance semantics across missing evidence and unknown states.",
                ),
            ),
            metadata={
                "control_family": "fail_closed_disposition",
                "required_engine_behavior": "blocked_on_required_evidence_gap",
            },
        ),
        _control(
            "BF-W9-015",
            "Governance report is deterministic and digest-bound",
            (
                "Require the final governance report to be generated from deterministic policy, evidence, control-result, "
                "and signoff payloads with stable digests that reviewers can independently inspect."
            ),
            AuditControlSeverity.BLOCKING,
            required_evidence_kinds=(AuditEvidenceKind.GOVERNANCE_REPORT,),
            standards_mappings=(
                _mapping(
                    AuditStandardsMappingKind.OSCAL_ASSESSMENT_RESULTS,
                    "OSCAL-ASSESSMENT-RESULTS-REPORT-SHAPE",
                    "Uses structured assessment-result reporting as a shape reference without claiming OSCAL export.",
                ),
            ),
            metadata={
                "control_family": "governance_report_integrity",
                "required_report_field": "report_digest",
            },
        ),
    )


def _control(
    control_id: str,
    title: str,
    objective: str,
    severity: AuditControlSeverity,
    *,
    required_evidence_kinds: Sequence[AuditEvidenceKind] = (),
    standards_mappings: Sequence[AuditStandardsMapping] = (),
    metadata: Mapping[str, Any] | None = None,
) -> AuditControlRequirement:
    return AuditControlRequirement(
        control_id=control_id,
        title=title,
        objective=objective,
        severity=severity,
        required_evidence_kinds=tuple(required_evidence_kinds),
        standards_mappings=tuple(standards_mappings),
        metadata=dict(metadata or {}),
    )


def _mapping(
    kind: AuditStandardsMappingKind,
    reference_id: str,
    summary: str,
    *,
    claim: str = "alignment_reference_only",
    metadata: Mapping[str, Any] | None = None,
) -> AuditStandardsMapping:
    return AuditStandardsMapping(
        kind=kind,
        reference_id=reference_id,
        summary=summary,
        claim=normalize_optional_text(claim, label="claim") or "alignment_reference_only",
        metadata=dict(metadata or {}),
    )
