"""Wave 12 certification-ready evidence packaging for IX-BlackFox.

The assurance package collects real prior-wave and quality evidence, evaluates
it against a bounded profile, preserves separate human authority, creates a
deterministic ZIP, and independently verifies every serialized byte and binding.
It does not grant certification, compliance, authorization, or deployment
authority.
"""

from __future__ import annotations

from ix_blackfox.assurance.crosswalk import (
    WAVE12_CROSSWALK_SCHEMA_VERSION,
    AssuranceControlEvaluation,
    AssuranceCrosswalkReport,
    ControlEvaluationStatus,
    build_assurance_crosswalk,
    evaluate_control,
)
from ix_blackfox.assurance.evidence import (
    DEFAULT_MAX_EVIDENCE_BYTES,
    DEFAULT_MAX_TOTAL_EVIDENCE_BYTES,
    CollectedEvidence,
    EvidenceInputSpec,
    collect_evidence,
    load_evidence_specs,
    normalize_evidence_specs,
    resolve_json_pointer,
)
from ix_blackfox.assurance.models import (
    WAVE12_ASSURANCE_SCHEMA_VERSION,
    WAVE12_MANIFEST_SCHEMA_VERSION,
    WAVE12_REVIEW_SCHEMA_VERSION,
    AssuranceClaimSet,
    AssuranceControl,
    AssuranceEvidenceArtifact,
    AssuranceEvidenceKind,
    AssuranceEvidenceSource,
    AssuranceManifest,
    AssuranceProfile,
    AssuranceSubject,
    AuthorityReview,
    AuthorityReviewDecision,
    EvidenceVerificationState,
    ReviewAuthenticationState,
    default_wave12_claims,
)
from ix_blackfox.assurance.package import (
    WAVE12_BUNDLE_INDEX_SCHEMA_VERSION,
    WAVE12_IN_TOTO_PREDICATE_TYPE,
    AssurancePackageBuildResult,
    build_assurance_package,
    build_bundle_index,
    build_in_toto_statement,
    canonical_json_bytes,
)
from ix_blackfox.assurance.profiles import (
    DEFAULT_WAVE12_PROFILE_ID,
    DEFAULT_WAVE12_PROFILE_VERSION,
    default_wave12_assurance_profile,
)
from ix_blackfox.assurance.quality import (
    WAVE12_QUALITY_GATE_SCHEMA_VERSION,
    QualityGateResult,
    QualityGateSpec,
    default_wave12_quality_gates,
    quality_gates_passed,
    run_quality_gate,
    run_wave12_quality_gates,
)
from ix_blackfox.assurance.report import (
    WAVE12_READINESS_SCHEMA_VERSION,
    AssuranceFinding,
    AssuranceFindingCode,
    AssuranceFindingSeverity,
    AssuranceReadinessReport,
    AssuranceReadinessStatus,
    build_assurance_readiness_report,
)
from ix_blackfox.assurance.verify import (
    WAVE12_VERIFICATION_SCHEMA_VERSION,
    AssurancePackageVerification,
    PackageVerificationIssue,
    PackageVerificationIssueCode,
    verify_assurance_package,
    write_package_verification,
)

__all__ = [
    "DEFAULT_MAX_EVIDENCE_BYTES",
    "DEFAULT_MAX_TOTAL_EVIDENCE_BYTES",
    "DEFAULT_WAVE12_PROFILE_ID",
    "DEFAULT_WAVE12_PROFILE_VERSION",
    "WAVE12_ASSURANCE_SCHEMA_VERSION",
    "WAVE12_BUNDLE_INDEX_SCHEMA_VERSION",
    "WAVE12_CROSSWALK_SCHEMA_VERSION",
    "WAVE12_IN_TOTO_PREDICATE_TYPE",
    "WAVE12_MANIFEST_SCHEMA_VERSION",
    "WAVE12_QUALITY_GATE_SCHEMA_VERSION",
    "WAVE12_READINESS_SCHEMA_VERSION",
    "WAVE12_REVIEW_SCHEMA_VERSION",
    "WAVE12_VERIFICATION_SCHEMA_VERSION",
    "AssuranceClaimSet",
    "AssuranceControl",
    "AssuranceControlEvaluation",
    "AssuranceCrosswalkReport",
    "AssuranceEvidenceArtifact",
    "AssuranceEvidenceKind",
    "AssuranceEvidenceSource",
    "AssuranceFinding",
    "AssuranceFindingCode",
    "AssuranceFindingSeverity",
    "AssuranceManifest",
    "AssurancePackageBuildResult",
    "AssurancePackageVerification",
    "AssuranceProfile",
    "AssuranceReadinessReport",
    "AssuranceReadinessStatus",
    "AssuranceSubject",
    "AuthorityReview",
    "AuthorityReviewDecision",
    "CollectedEvidence",
    "ControlEvaluationStatus",
    "EvidenceInputSpec",
    "EvidenceVerificationState",
    "PackageVerificationIssue",
    "PackageVerificationIssueCode",
    "QualityGateResult",
    "QualityGateSpec",
    "ReviewAuthenticationState",
    "build_assurance_crosswalk",
    "build_assurance_package",
    "build_assurance_readiness_report",
    "build_bundle_index",
    "build_in_toto_statement",
    "canonical_json_bytes",
    "collect_evidence",
    "default_wave12_assurance_profile",
    "default_wave12_claims",
    "default_wave12_quality_gates",
    "evaluate_control",
    "load_evidence_specs",
    "normalize_evidence_specs",
    "quality_gates_passed",
    "resolve_json_pointer",
    "run_quality_gate",
    "run_wave12_quality_gates",
    "verify_assurance_package",
    "write_package_verification",
]
