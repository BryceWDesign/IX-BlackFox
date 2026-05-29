from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, cast

from ix_blackfox.audit.controls import (
    AuditControlEvaluation,
    evaluate_policy_pack,
)
from ix_blackfox.audit.evidence_standard import (
    EvidenceManifestValidationResult,
    validate_evidence_manifest,
)
from ix_blackfox.audit.models import (
    WAVE9_GOVERNANCE_REPORT_SCHEMA_VERSION,
    AuditDisposition,
    AuditEvidenceManifest,
    AuditReviewerSignoff,
    AuditSubject,
    digest_payload,
    normalize_identifier,
    normalize_text,
)
from ix_blackfox.audit.policy_packs import (
    AuditPolicyPack,
    default_wave9_policy_pack,
)
from ix_blackfox.audit.signoff import (
    SignoffAuthoritySummary,
    SignoffValidationResult,
    summarize_signoff_authority,
    validate_reviewer_signoffs,
)


@dataclass(frozen=True, slots=True)
class Wave9GovernanceReport:
    """
    Deterministic Wave 9 governance report.

    The report binds a subject, policy pack, evidence manifest, control
    evaluation, and reviewer authority summary into one inspectable audit
    artifact. It records audit readiness inside the declared IX-BlackFox policy
    scope only. It does not certify production readiness, ATO/cATO, procurement
    approval, DoD acceptance, or autonomous authority.
    """

    run_id: str
    subject: AuditSubject
    policy_pack: AuditPolicyPack
    evidence_manifest: AuditEvidenceManifest
    evidence_validation: EvidenceManifestValidationResult
    control_evaluation: AuditControlEvaluation
    signoff_validation: SignoffValidationResult
    signoff_authority: SignoffAuthoritySummary
    generated_at: datetime
    disposition: AuditDisposition
    reviewer_signoffs: tuple[AuditReviewerSignoff, ...] = ()
    claims: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "run_id", normalize_identifier(self.run_id, label="run_id"))
        if self.generated_at.tzinfo is None:
            raise ValueError("generated_at must be timezone-aware.")
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
        _validate_report_links(self)

    @property
    def policy_pack_digest(self) -> str:
        return self.policy_pack.digest

    @property
    def evidence_manifest_digest(self) -> str:
        return self.evidence_manifest.digest

    @property
    def control_evaluation_digest(self) -> str:
        return self.control_evaluation.digest

    @property
    def signoff_validation_digest(self) -> str:
        return digest_payload(self.signoff_validation.to_dict())

    @property
    def attestation_subject_digest(self) -> str:
        return digest_payload(self.attestation_subject_payload())

    @property
    def report_digest(self) -> str:
        return digest_payload(self.to_dict(include_report_digest=False))

    def attestation_subject_payload(self) -> dict[str, Any]:
        """
        Return the payload evaluated before final report digesting.

        This payload deliberately excludes reviewer signoff bodies and the final
        report digest. It gives reviewers and tools a stable description of the
        audit subject: what repo/change was evaluated, under which policy pack,
        against which evidence manifest, and with which control-evaluation
        result.
        """

        return {
            "schema_version": WAVE9_GOVERNANCE_REPORT_SCHEMA_VERSION,
            "run_id": self.run_id,
            "subject_digest": self.subject.digest,
            "subject": self.subject.to_dict(),
            "policy_pack_digest": self.policy_pack_digest,
            "policy_pack": {
                "pack_id": self.policy_pack.pack_id,
                "version": self.policy_pack.version,
                "control_ids": list(self.policy_pack.control_ids),
            },
            "evidence_manifest_digest": self.evidence_manifest_digest,
            "control_evaluation_digest": self.control_evaluation_digest,
            "disposition_before_report_digest": self.disposition.value,
            "claims": list(self.claims),
        }

    def to_dict(self, *, include_report_digest: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": WAVE9_GOVERNANCE_REPORT_SCHEMA_VERSION,
            "wave": 9,
            "run_id": self.run_id,
            "generated_at": self.generated_at.isoformat(),
            "disposition": self.disposition.value,
            "attestation_subject_digest": self.attestation_subject_digest,
            "subject": self.subject.to_dict(),
            "policy_pack": self.policy_pack.to_dict(),
            "evidence_manifest": self.evidence_manifest.to_dict(),
            "evidence_validation": self.evidence_validation.to_dict(),
            "control_evaluation": self.control_evaluation.to_dict(),
            "signoff_validation": self.signoff_validation.to_dict(),
            "signoff_authority": self.signoff_authority.to_dict(),
            "reviewer_signoffs": [signoff.to_dict() for signoff in self.reviewer_signoffs],
            "claims": list(self.claims),
            "non_claims": self.policy_pack.non_claims.to_dict(),
            "standards_alignment": standards_alignment_entries(self.policy_pack),
            "metadata": dict(self.metadata),
        }
        if include_report_digest:
            payload["report_digest"] = self.report_digest
        return payload


def build_governance_report(
    subject: AuditSubject,
    evidence_manifest: AuditEvidenceManifest,
    *,
    generated_at: datetime,
    policy_pack: AuditPolicyPack | None = None,
    reviewer_signoffs: Sequence[AuditReviewerSignoff] = (),
    claims: Sequence[str] = (),
    run_id: str = "",
    require_human_approval: bool = True,
    evidence_validation: EvidenceManifestValidationResult | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> Wave9GovernanceReport:
    """
    Build a Wave 9 governance report from policy, evidence, and signoff state.

    The report can validly be blocked. That is intentional: a blocked report is
    still useful when it explains missing evidence, malformed evidence, missing
    human approval, or overclaim risk without pretending the audit is ready.
    """

    pack = policy_pack or default_wave9_policy_pack()
    validation = evidence_validation or validate_evidence_manifest(evidence_manifest)
    sorted_signoffs = tuple(sorted(reviewer_signoffs, key=lambda signoff: signoff.signoff_id))
    signoff_validation = validate_reviewer_signoffs(
        sorted_signoffs,
        subject=subject,
        policy_pack=pack,
        require_human_approval=require_human_approval,
    )
    signoff_authority = summarize_signoff_authority(
        sorted_signoffs,
        subject=subject,
        policy_pack=pack,
        require_human_approval=require_human_approval,
    )
    control_evaluation = evaluate_policy_pack(
        pack,
        evidence_manifest,
        evidence_validation=validation,
        reviewer_signoffs=sorted_signoffs,
        claims=tuple(claims),
        require_human_signoff=require_human_approval,
    )
    final_disposition = derive_governance_report_disposition(
        control_evaluation,
        signoff_validation,
    )
    report_run_id = run_id or default_governance_report_run_id(
        subject,
        pack,
        evidence_manifest,
        claims=tuple(claims),
    )
    return Wave9GovernanceReport(
        run_id=report_run_id,
        subject=subject,
        policy_pack=pack,
        evidence_manifest=evidence_manifest,
        evidence_validation=validation,
        control_evaluation=control_evaluation,
        signoff_validation=signoff_validation,
        signoff_authority=signoff_authority,
        generated_at=generated_at,
        disposition=final_disposition,
        reviewer_signoffs=sorted_signoffs,
        claims=tuple(claims),
        metadata={
            "report_builder": "ix_blackfox.audit.report.build_governance_report",
            "require_human_approval": require_human_approval,
            **dict(metadata or {}),
        },
    )


def derive_governance_report_disposition(
    control_evaluation: AuditControlEvaluation,
    signoff_validation: SignoffValidationResult,
) -> AuditDisposition:
    """Derive final Wave 9 report disposition from controls and authority."""

    if (
        control_evaluation.disposition is AuditDisposition.BLOCKED
        or signoff_validation.has_blocking_issues
    ):
        return AuditDisposition.BLOCKED
    if (
        control_evaluation.disposition is AuditDisposition.WARNING
        or signoff_validation.warning_issue_count > 0
    ):
        return AuditDisposition.WARNING
    return AuditDisposition.AUDIT_READY


def default_governance_report_run_id(
    subject: AuditSubject,
    policy_pack: AuditPolicyPack,
    evidence_manifest: AuditEvidenceManifest,
    *,
    claims: Sequence[str] = (),
) -> str:
    """Return a stable run ID for the same subject, policy, evidence, and claims."""

    payload = {
        "subject_digest": subject.digest,
        "policy_pack_digest": policy_pack.digest,
        "evidence_manifest_digest": evidence_manifest.digest,
        "claims": sorted(claims),
    }
    return f"wave9:{digest_payload(payload)[:16]}"


def standards_alignment_entries(policy_pack: AuditPolicyPack) -> tuple[dict[str, Any], ...]:
    """
    Return bounded standards-alignment entries from the policy pack.

    These entries are mapping notes, not certification or compliance claims.
    """

    entries: list[dict[str, Any]] = []
    for control in policy_pack.controls:
        for mapping in control.standards_mappings:
            entry = mapping.to_dict()
            entry["control_id"] = control.control_id
            entries.append(entry)
    return tuple(sorted(entries, key=lambda item: (str(item["kind"]), str(item["reference_id"]))))


def write_governance_report(
    report: Wave9GovernanceReport,
    output_path: str | Path,
) -> Path:
    """Write a deterministic Wave 9 governance report JSON artifact."""

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path


def load_governance_report_payload(input_path: str | Path) -> Mapping[str, Any]:
    """Load a Wave 9 governance-report JSON payload from disk."""

    payload = json.loads(Path(input_path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Wave 9 governance report JSON must contain an object.")
    return cast(Mapping[str, Any], payload)


def validate_governance_report_payload_shape(payload: Mapping[str, Any]) -> tuple[str, ...]:
    """
    Validate the minimum shape of an exported Wave 9 governance-report payload.

    Full JSON Schema validation is added separately. This lightweight shape check
    keeps the report exporter honest without introducing a runtime dependency.
    """

    required_keys = (
        "schema_version",
        "wave",
        "run_id",
        "generated_at",
        "disposition",
        "attestation_subject_digest",
        "report_digest",
        "subject",
        "policy_pack",
        "evidence_manifest",
        "evidence_validation",
        "control_evaluation",
        "signoff_validation",
        "signoff_authority",
        "reviewer_signoffs",
        "non_claims",
    )
    missing = tuple(key for key in required_keys if key not in payload)
    issues: list[str] = []
    if missing:
        issues.append(f"missing required keys: {', '.join(missing)}")
    if payload.get("schema_version") != WAVE9_GOVERNANCE_REPORT_SCHEMA_VERSION:
        issues.append("schema_version is not the Wave 9 governance-report schema version")
    if payload.get("wave") != 9:
        issues.append("wave must be 9")
    report_digest = payload.get("report_digest")
    if not isinstance(report_digest, str) or len(report_digest) != 64:
        issues.append("report_digest must be a 64-character SHA-256 digest string")
    return tuple(issues)


def _validate_report_links(report: Wave9GovernanceReport) -> None:
    if report.evidence_manifest.subject.digest != report.subject.digest:
        raise ValueError("evidence_manifest subject digest does not match report subject digest.")
    if report.evidence_validation.manifest_digest != report.evidence_manifest.digest:
        raise ValueError("evidence_validation digest does not match evidence_manifest digest.")
    if report.control_evaluation.policy_pack_digest != report.policy_pack.digest:
        raise ValueError("control_evaluation policy-pack digest does not match policy_pack digest.")
    if report.control_evaluation.evidence_manifest_digest != report.evidence_manifest.digest:
        raise ValueError("control_evaluation manifest digest does not match evidence_manifest digest.")
    if report.signoff_validation.subject_digest != report.subject.digest:
        raise ValueError("signoff_validation subject digest does not match report subject digest.")
    if report.signoff_validation.policy_pack_digest != report.policy_pack.digest:
        raise ValueError("signoff_validation policy-pack digest does not match policy_pack digest.")
    if report.signoff_authority.subject_digest != report.subject.digest:
        raise ValueError("signoff_authority subject digest does not match report subject digest.")
    if report.signoff_authority.policy_pack_digest != report.policy_pack.digest:
        raise ValueError("signoff_authority policy-pack digest does not match policy_pack digest.")
    expected_signoff_validation_digest = digest_payload(report.signoff_validation.to_dict())
    if report.signoff_authority.validation_digest != expected_signoff_validation_digest:
        raise ValueError("signoff_authority validation digest does not match signoff_validation.")
    expected_disposition = derive_governance_report_disposition(
        report.control_evaluation,
        report.signoff_validation,
    )
    if report.disposition is not expected_disposition:
        raise ValueError("report disposition does not match control/signoff validation state.")
