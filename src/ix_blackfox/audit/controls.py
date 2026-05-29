from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from ix_blackfox.audit.evidence_standard import (
    EvidenceManifestIssueSeverity,
    EvidenceManifestValidationResult,
    validate_evidence_manifest,
)
from ix_blackfox.audit.models import (
    AuditControlFinding,
    AuditControlRequirement,
    AuditControlStatus,
    AuditDisposition,
    AuditEvidenceArtifact,
    AuditEvidenceKind,
    AuditEvidenceManifest,
    AuditReviewDecision,
    AuditReviewerKind,
    AuditReviewerSignoff,
    derive_audit_disposition,
    digest_payload,
    normalize_identifier,
    normalize_text,
)
from ix_blackfox.audit.policy_packs import AuditPolicyPack

_REQUIRED_NON_CLAIM_PHRASES = (
    "production readiness",
    "ato",
    "cato",
    "procurement",
    "dod",
    "autonomous",
    "model confidence",
)
_CONDITIONAL_CONTROL_IDS = frozenset(
    {
        "BF-W9-004",
        "BF-W9-005",
        "BF-W9-006",
        "BF-W9-007",
        "BF-W9-008",
        "BF-W9-010",
    }
)
_REQUIRED_EVIDENCE_CONTROL_IDS = frozenset(
    {
        "BF-W9-004",
        "BF-W9-005",
        "BF-W9-006",
        "BF-W9-007",
        "BF-W9-008",
        "BF-W9-010",
    }
)


@dataclass(frozen=True, slots=True)
class AuditControlEvaluationContext:
    """Inputs used to evaluate a Wave 9 audit policy pack."""

    policy_pack: AuditPolicyPack
    evidence_manifest: AuditEvidenceManifest
    evidence_validation: EvidenceManifestValidationResult
    reviewer_signoffs: tuple[AuditReviewerSignoff, ...] = ()
    claims: tuple[str, ...] = ()
    require_human_signoff: bool = True
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "reviewer_signoffs",
            tuple(sorted(self.reviewer_signoffs, key=lambda signoff: signoff.signoff_id)),
        )
        object.__setattr__(
            self,
            "claims",
            tuple(sorted(normalize_text(claim, label="claim") for claim in self.claims)),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def policy_pack_digest(self) -> str:
        return self.policy_pack.digest

    @property
    def evidence_manifest_digest(self) -> str:
        return self.evidence_manifest.digest

    @property
    def subject_digest(self) -> str:
        return self.evidence_manifest.subject.digest

    @property
    def claims_text(self) -> str:
        return " ".join((self.evidence_manifest.subject.scope, *self.claims)).lower()

    @property
    def artifacts(self) -> tuple[AuditEvidenceArtifact, ...]:
        return self.evidence_manifest.artifacts

    def artifacts_by_kind(self, kind: AuditEvidenceKind) -> tuple[AuditEvidenceArtifact, ...]:
        return tuple(artifact for artifact in self.artifacts if artifact.kind is kind)

    def has_artifact_kind(self, kind: AuditEvidenceKind) -> bool:
        return any(artifact.kind is kind for artifact in self.artifacts)

    def has_any_artifact_kind(self, kinds: Sequence[AuditEvidenceKind]) -> bool:
        return any(self.has_artifact_kind(kind) for kind in kinds)

    def verified_attestations(self) -> tuple[AuditEvidenceArtifact, ...]:
        return tuple(
            artifact
            for artifact in self.artifacts
            if artifact.kind is AuditEvidenceKind.ATTESTATION and artifact.verified
        )

    def unverified_attestations(self) -> tuple[AuditEvidenceArtifact, ...]:
        return tuple(
            artifact
            for artifact in self.artifacts
            if artifact.kind is AuditEvidenceKind.ATTESTATION and not artifact.verified
        )

    def authoritative_human_approvals(self) -> tuple[AuditReviewerSignoff, ...]:
        return tuple(
            signoff
            for signoff in self.reviewer_signoffs
            if signoff.is_authoritative_human_approval
            and signoff.subject_digest == self.subject_digest
            and signoff.policy_pack_digest == self.policy_pack_digest
        )

    def non_authoritative_approval_attempts(self) -> tuple[AuditReviewerSignoff, ...]:
        return tuple(
            signoff
            for signoff in self.reviewer_signoffs
            if signoff.reviewer_kind is not AuditReviewerKind.HUMAN
            and signoff.decision is AuditReviewDecision.APPROVED
        )


@dataclass(frozen=True, slots=True)
class AuditControlEvaluation:
    """Deterministic result of evaluating a Wave 9 policy pack."""

    policy_pack_digest: str
    evidence_manifest_digest: str
    findings: tuple[AuditControlFinding, ...]
    disposition: AuditDisposition
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "policy_pack_digest",
            normalize_identifier(self.policy_pack_digest, label="policy_pack_digest"),
        )
        object.__setattr__(
            self,
            "evidence_manifest_digest",
            normalize_identifier(
                self.evidence_manifest_digest,
                label="evidence_manifest_digest",
            ),
        )
        object.__setattr__(self, "findings", tuple(sorted(self.findings, key=_finding_sort_key)))
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def blocked_count(self) -> int:
        return sum(1 for finding in self.findings if finding.status is AuditControlStatus.BLOCKED)

    @property
    def warning_count(self) -> int:
        return sum(1 for finding in self.findings if finding.status is AuditControlStatus.WARNING)

    @property
    def not_applicable_count(self) -> int:
        return sum(
            1 for finding in self.findings if finding.status is AuditControlStatus.NOT_APPLICABLE
        )

    @property
    def digest(self) -> str:
        return digest_payload(self.to_dict(include_digest=False))

    def finding_by_control_id(self, control_id: str) -> AuditControlFinding:
        normalized = normalize_identifier(control_id, label="control_id")
        for finding in self.findings:
            if finding.control_id == normalized:
                return finding
        raise KeyError(f"Unknown Wave 9 control finding: {normalized}")

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "policy_pack_digest": self.policy_pack_digest,
            "evidence_manifest_digest": self.evidence_manifest_digest,
            "disposition": self.disposition.value,
            "finding_count": self.finding_count,
            "blocked_count": self.blocked_count,
            "warning_count": self.warning_count,
            "not_applicable_count": self.not_applicable_count,
            "findings": [finding.to_dict() for finding in self.findings],
            "metadata": dict(self.metadata),
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload


def evaluate_policy_pack(
    policy_pack: AuditPolicyPack,
    evidence_manifest: AuditEvidenceManifest,
    *,
    evidence_validation: EvidenceManifestValidationResult | None = None,
    reviewer_signoffs: Sequence[AuditReviewerSignoff] = (),
    claims: Sequence[str] = (),
    require_human_signoff: bool = True,
) -> AuditControlEvaluation:
    """
    Evaluate a Wave 9 policy pack against evidence and signoff state.

    The evaluator is intentionally fail-closed. Missing required evidence,
    malformed evidence, unverifiable provenance claims, or missing human approval
    produce blocked findings. A valid blocked evaluation is still useful: it is a
    machine-checkable explanation of why audit readiness has not been reached.
    """

    validation = evidence_validation or validate_evidence_manifest(evidence_manifest)
    context = AuditControlEvaluationContext(
        policy_pack=policy_pack,
        evidence_manifest=evidence_manifest,
        evidence_validation=validation,
        reviewer_signoffs=tuple(reviewer_signoffs),
        claims=tuple(claims),
        require_human_signoff=require_human_signoff,
    )
    findings: list[AuditControlFinding] = []
    for control in policy_pack.controls:
        finding = evaluate_control(control, context, previous_findings=tuple(findings))
        findings.append(finding)

    final_findings = tuple(sorted(findings, key=_finding_sort_key))
    return AuditControlEvaluation(
        policy_pack_digest=policy_pack.digest,
        evidence_manifest_digest=evidence_manifest.digest,
        findings=final_findings,
        disposition=derive_audit_disposition(final_findings),
        metadata={
            "policy_pack_id": policy_pack.pack_id,
            "policy_pack_version": policy_pack.version,
            "manifest_id": evidence_manifest.manifest_id,
            "subject_digest": evidence_manifest.subject.digest,
            "claims": list(context.claims),
            "require_human_signoff": require_human_signoff,
        },
    )


def evaluate_control(
    control: AuditControlRequirement,
    context: AuditControlEvaluationContext,
    *,
    previous_findings: Sequence[AuditControlFinding] = (),
) -> AuditControlFinding:
    """Evaluate one Wave 9 control requirement."""

    if control.control_id in _CONDITIONAL_CONTROL_IDS and not control_is_applicable(
        control,
        context,
    ):
        return _finding(
            control,
            AuditControlStatus.NOT_APPLICABLE,
            "Control is not applicable to the declared audit scope or claims.",
            metadata={"reason": "scope_or_claim_trigger_not_present"},
        )

    if control.control_id == "BF-W9-001":
        return _evaluate_untrusted_model_output(control, context)
    if control.control_id == "BF-W9-002":
        return _evaluate_policy_pack_binding(control, context)
    if control.control_id == "BF-W9-003":
        return _evaluate_evidence_manifest_standard(control, context)
    if control.control_id in {
        "BF-W9-004",
        "BF-W9-005",
        "BF-W9-006",
        "BF-W9-007",
        "BF-W9-008",
    }:
        return _evaluate_required_evidence_kinds(control, context)
    if control.control_id == "BF-W9-009":
        return _evaluate_fail_closed_evidence_validation(control, context)
    if control.control_id == "BF-W9-010":
        return _evaluate_attestation_boundary(control, context)
    if control.control_id == "BF-W9-011":
        return _evaluate_human_signoff(control, context)
    if control.control_id == "BF-W9-012":
        return _evaluate_self_approval_boundary(control, context)
    if control.control_id == "BF-W9-013":
        return _evaluate_non_claims(control, context)
    if control.control_id == "BF-W9-014":
        return _evaluate_required_gap_fail_closed(control, context, previous_findings)
    if control.control_id == "BF-W9-015":
        return _evaluate_deterministic_control_evidence(control, context, previous_findings)
    return _finding(
        control,
        AuditControlStatus.WARNING,
        "No explicit evaluator is registered for this control; it was not treated as passed.",
        remediation="Add an explicit Wave 9 evaluator for this control before relying on it.",
        metadata={"reason": "missing_control_evaluator"},
    )


def control_is_applicable(
    control: AuditControlRequirement,
    context: AuditControlEvaluationContext,
) -> bool:
    """Return whether a conditional control applies to the declared audit context."""

    if not control.metadata:
        return True
    scope_terms = _metadata_terms(control.metadata.get("required_when_scope_contains"))
    claim_terms = _metadata_terms(control.metadata.get("required_when_claim_contains"))
    if context.has_any_artifact_kind(control.required_evidence_kinds):
        return True
    if not scope_terms and not claim_terms:
        return True
    return _contains_trigger(context.claims_text, (*scope_terms, *claim_terms))


def _evaluate_untrusted_model_output(
    control: AuditControlRequirement,
    context: AuditControlEvaluationContext,
) -> AuditControlFinding:
    non_claim_text = " ".join(context.policy_pack.non_claims.items).lower()
    required = ("model confidence", "human approval")
    missing = tuple(phrase for phrase in required if phrase not in non_claim_text)
    if missing:
        return _finding(
            control,
            AuditControlStatus.BLOCKED,
            "Policy pack non-claims do not fully preserve the model-output authority boundary.",
            remediation="Restore non-claims that reject model confidence as evidence and preserve human approval.",
            metadata={"missing_phrases": list(missing)},
        )
    return _finding(
        control,
        AuditControlStatus.PASSED,
        "Policy pack preserves that model output is advisory input, not authority or evidence.",
        metadata={"non_claim_count": len(context.policy_pack.non_claims.items)},
    )


def _evaluate_policy_pack_binding(
    control: AuditControlRequirement,
    context: AuditControlEvaluationContext,
) -> AuditControlFinding:
    control_ids = context.policy_pack.control_ids
    if len(control_ids) != len(set(control_ids)):
        return _finding(
            control,
            AuditControlStatus.BLOCKED,
            "Policy pack contains duplicate control IDs.",
            remediation="Make policy-pack control IDs unique before audit evaluation.",
        )
    return _finding(
        control,
        AuditControlStatus.PASSED,
        "Policy pack ID, version, control set, and digest are available for audit binding.",
        metadata={
            "policy_pack_id": context.policy_pack.pack_id,
            "policy_pack_version": context.policy_pack.version,
            "policy_pack_digest": context.policy_pack_digest,
            "control_count": context.policy_pack.control_count,
        },
    )


def _evaluate_evidence_manifest_standard(
    control: AuditControlRequirement,
    context: AuditControlEvaluationContext,
) -> AuditControlFinding:
    validation = context.evidence_validation
    blocking_issues = [issue.to_dict() for issue in validation.issues if issue.blocks_audit_ready]
    warning_issues = [
        issue.to_dict()
        for issue in validation.issues
        if issue.severity is EvidenceManifestIssueSeverity.WARNING
    ]
    if blocking_issues:
        return _finding(
            control,
            AuditControlStatus.BLOCKED,
            "Evidence manifest validation found blocking evidence-standard issues.",
            remediation="Fix blocking evidence-standard issues before audit-ready disposition can be reached.",
            metadata={"blocking_issues": blocking_issues, "warning_issues": warning_issues},
        )
    if warning_issues:
        return _finding(
            control,
            AuditControlStatus.WARNING,
            "Evidence manifest is structurally valid but contains evidence-standard warnings.",
            remediation="Review warning issues before presenting the report as audit-ready.",
            metadata={"warning_issues": warning_issues},
        )
    return _finding(
        control,
        AuditControlStatus.PASSED,
        "Evidence manifest uses deterministic artifact metadata and has no validation findings.",
        metadata={"manifest_digest": context.evidence_manifest_digest},
    )


def _evaluate_required_evidence_kinds(
    control: AuditControlRequirement,
    context: AuditControlEvaluationContext,
) -> AuditControlFinding:
    acceptable = tuple(control.required_evidence_kinds)
    present = tuple(kind for kind in acceptable if context.has_artifact_kind(kind))
    if not present:
        return _finding(
            control,
            AuditControlStatus.BLOCKED,
            "No acceptable Wave 9 evidence kind is present for the applicable audit scope.",
            remediation="Generate, bridge, or attach at least one acceptable evidence artifact before audit-ready disposition.",
            metadata={
                "acceptable_evidence_kinds": [kind.value for kind in acceptable],
                "present_evidence_kinds": [],
            },
        )
    acceptable_set = set(acceptable)
    evidence_ids = tuple(
        artifact.artifact_id
        for artifact in context.artifacts
        if artifact.kind in acceptable_set
    )
    return _finding(
        control,
        AuditControlStatus.PASSED,
        "At least one acceptable evidence kind is present for the applicable audit scope.",
        evidence_artifact_ids=evidence_ids,
        metadata={
            "acceptable_evidence_kinds": [kind.value for kind in acceptable],
            "present_evidence_kinds": [kind.value for kind in present],
        },
    )


def _evaluate_fail_closed_evidence_validation(
    control: AuditControlRequirement,
    context: AuditControlEvaluationContext,
) -> AuditControlFinding:
    if context.evidence_validation.has_blocking_issues:
        return _finding(
            control,
            AuditControlStatus.BLOCKED,
            "Evidence validation is blocking, so Wave 9 fails closed.",
            remediation="Resolve blocking validation issues instead of downgrading them to warnings.",
            metadata=context.evidence_validation.to_dict(),
        )
    return _finding(
        control,
        AuditControlStatus.PASSED,
        "No blocking evidence-validation issues were downgraded or ignored.",
        metadata={"validation_digest": context.evidence_validation.manifest_digest},
    )


def _evaluate_attestation_boundary(
    control: AuditControlRequirement,
    context: AuditControlEvaluationContext,
) -> AuditControlFinding:
    verified = context.verified_attestations()
    unverified = context.unverified_attestations()
    claims_verified_provenance = _contains_trigger(
        context.claims_text,
        ("verified provenance", "verified attestation", "sigstore", "slsa"),
    )
    if claims_verified_provenance and not verified:
        return _finding(
            control,
            AuditControlStatus.BLOCKED,
            "Audit claims verified provenance but no verified attestation artifact is present.",
            remediation="Add an actual verification result or remove the verified-provenance claim.",
            evidence_artifact_ids=tuple(artifact.artifact_id for artifact in unverified),
            metadata={"unverified_attestation_count": len(unverified)},
        )
    if unverified and not verified:
        return _finding(
            control,
            AuditControlStatus.WARNING,
            "Attestation metadata is recorded, but no attestation is marked verified.",
            remediation="Treat unverified attestations as recorded metadata only.",
            evidence_artifact_ids=tuple(artifact.artifact_id for artifact in unverified),
            metadata={"unverified_attestation_count": len(unverified)},
        )
    return _finding(
        control,
        AuditControlStatus.PASSED,
        "Attestation evidence boundary distinguishes recorded metadata from verified provenance.",
        evidence_artifact_ids=tuple(artifact.artifact_id for artifact in verified),
        metadata={
            "verified_attestation_count": len(verified),
            "unverified_attestation_count": len(unverified),
        },
    )


def _evaluate_human_signoff(
    control: AuditControlRequirement,
    context: AuditControlEvaluationContext,
) -> AuditControlFinding:
    if not context.require_human_signoff:
        return _finding(
            control,
            AuditControlStatus.NOT_APPLICABLE,
            "Human signoff gate was not required for this evaluation mode.",
            metadata={"require_human_signoff": False},
        )
    approvals = context.authoritative_human_approvals()
    if not approvals:
        return _finding(
            control,
            AuditControlStatus.BLOCKED,
            "No authoritative human approval is bound to the subject digest and policy-pack digest.",
            remediation="Add a human approval signoff bound to the current subject digest and policy-pack digest.",
            metadata={
                "subject_digest": context.subject_digest,
                "policy_pack_digest": context.policy_pack_digest,
                "signoff_count": len(context.reviewer_signoffs),
            },
        )
    return _finding(
        control,
        AuditControlStatus.PASSED,
        "Authoritative human approval is bound to the subject digest and policy-pack digest.",
        metadata={
            "authoritative_human_approval_ids": [signoff.signoff_id for signoff in approvals],
        },
    )


def _evaluate_self_approval_boundary(
    control: AuditControlRequirement,
    context: AuditControlEvaluationContext,
) -> AuditControlFinding:
    attempts = context.non_authoritative_approval_attempts()
    if attempts:
        return _finding(
            control,
            AuditControlStatus.WARNING,
            "Model or system approval records are present, but the evaluator treats them as non-authoritative.",
            remediation="Keep model/system approval records advisory and require human authority for audit_ready.",
            metadata={"non_authoritative_approval_ids": [signoff.signoff_id for signoff in attempts]},
        )
    return _finding(
        control,
        AuditControlStatus.PASSED,
        "No model or system self-approval was counted as human authority.",
    )


def _evaluate_non_claims(
    control: AuditControlRequirement,
    context: AuditControlEvaluationContext,
) -> AuditControlFinding:
    non_claim_text = " ".join(context.policy_pack.non_claims.items).lower()
    missing = tuple(phrase for phrase in _REQUIRED_NON_CLAIM_PHRASES if phrase not in non_claim_text)
    if missing:
        return _finding(
            control,
            AuditControlStatus.BLOCKED,
            "Policy pack is missing required anti-overclaim non-claim language.",
            remediation="Restore Wave 9 non-claims before generating a governance report.",
            metadata={"missing_required_phrases": list(missing)},
        )
    return _finding(
        control,
        AuditControlStatus.PASSED,
        "Required Wave 9 non-claims are preserved.",
        metadata={"non_claim_count": len(context.policy_pack.non_claims.items)},
    )


def _evaluate_required_gap_fail_closed(
    control: AuditControlRequirement,
    context: AuditControlEvaluationContext,
    previous_findings: Sequence[AuditControlFinding],
) -> AuditControlFinding:
    gap_findings = tuple(
        finding
        for finding in previous_findings
        if finding.control_id in _REQUIRED_EVIDENCE_CONTROL_IDS
        and finding.status is AuditControlStatus.BLOCKED
    )
    if context.evidence_validation.has_blocking_issues or gap_findings:
        return _finding(
            control,
            AuditControlStatus.BLOCKED,
            "Required evidence gaps or blocking evidence validation issues produced fail-closed disposition.",
            remediation="Provide required evidence and fix blocking validation issues before audit_ready is possible.",
            metadata={
                "blocking_validation_issue_count": context.evidence_validation.blocking_issue_count,
                "blocked_required_evidence_control_ids": [finding.control_id for finding in gap_findings],
            },
        )
    return _finding(
        control,
        AuditControlStatus.PASSED,
        "No required evidence gap was ignored or downgraded from blocked state.",
    )


def _evaluate_deterministic_control_evidence(
    control: AuditControlRequirement,
    context: AuditControlEvaluationContext,
    previous_findings: Sequence[AuditControlFinding],
) -> AuditControlFinding:
    payload_digest = digest_payload(
        {
            "policy_pack_digest": context.policy_pack_digest,
            "evidence_manifest_digest": context.evidence_manifest_digest,
            "subject_digest": context.subject_digest,
            "previous_findings": [finding.to_dict() for finding in previous_findings],
            "signoff_ids": [signoff.signoff_id for signoff in context.reviewer_signoffs],
        }
    )
    return _finding(
        control,
        AuditControlStatus.PASSED,
        "Control evaluation payload is deterministic and digest-bound for governance reporting.",
        metadata={"control_evaluation_payload_digest": payload_digest},
    )


def _finding(
    control: AuditControlRequirement,
    status: AuditControlStatus,
    summary: str,
    *,
    remediation: str = "",
    evidence_artifact_ids: Sequence[str] = (),
    metadata: Mapping[str, Any] | None = None,
) -> AuditControlFinding:
    return AuditControlFinding(
        control_id=control.control_id,
        status=status,
        severity=control.severity,
        summary=summary,
        evidence_artifact_ids=tuple(evidence_artifact_ids),
        remediation=remediation,
        metadata=dict(metadata or {}),
    )


def _metadata_terms(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, Sequence):
        terms: list[str] = []
        for item in value:
            if isinstance(item, str):
                terms.append(item)
        return tuple(terms)
    return ()


def _contains_trigger(text: str, terms: Sequence[str]) -> bool:
    if not terms:
        return False
    normalized_text = text.lower().replace("-", "_")
    tokens = set(re.split(r"[^a-z0-9_]+", normalized_text))
    for term in terms:
        normalized_term = term.lower().strip().replace("-", "_")
        if not normalized_term:
            continue
        if len(normalized_term) <= 3:
            if normalized_term in tokens:
                return True
            continue
        if " " in normalized_term:
            if normalized_term in normalized_text:
                return True
            continue
        if normalized_term in tokens or normalized_term in normalized_text:
            return True
    return False


def _finding_sort_key(finding: AuditControlFinding) -> tuple[str, str]:
    return (finding.control_id, finding.status.value)
