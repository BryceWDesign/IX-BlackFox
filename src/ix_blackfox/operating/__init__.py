"""
Wave 10 AI engineering operating-system primitives.

The operating package is the top-level Wave 10 layer for multi-repo,
multi-team, policy-governed, measurable, replayable, and reviewable AI-assisted
engineering workflows. Commit 3 adds deterministic multi-team review authority,
quorum, and separation-of-duties models so approvals remain human-bound and
cannot be supplied by the model, the system, or the subject author.
"""

from __future__ import annotations

from ix_blackfox.operating.authority import (
    ApprovalQuorum,
    OperatingTeam,
    ReviewBoard,
    ReviewDecision,
    ReviewerAuthority,
    ReviewerKind,
    SeparationOfDutiesRule,
    TeamReviewDecision,
    TeamRole,
)
from ix_blackfox.operating.models import (
    WAVE10_OPERATING_SCHEMA_VERSION,
    OperatingArtifactKind,
    OperatingArtifactRef,
    OperatingDisposition,
    OperatingDomain,
    OperatingEnvelope,
    OperatingFinding,
    OperatingSeverity,
    OperatingSourceWave,
    digest_payload,
    normalize_dotted_name,
    normalize_identifier,
    normalize_optional_text,
    normalize_path_tuple,
    normalize_relative_path,
    normalize_sha256,
    normalize_text,
    unique_sorted_enum_tuple,
)
from ix_blackfox.operating.registry import (
    ManagedRepository,
    OperatingRegistry,
    RepositoryDependency,
    RepositoryDependencyKind,
    RepositoryEvidenceState,
    RepositoryPolicyBinding,
    RepositoryRiskLevel,
    RepositoryRiskSurface,
    RepositoryRole,
    normalize_identifier_tuple,
    normalize_required_controls,
    normalize_text_tuple,
)

__all__ = [
    "WAVE10_OPERATING_SCHEMA_VERSION",
    "ApprovalQuorum",
    "ManagedRepository",
    "OperatingArtifactKind",
    "OperatingArtifactRef",
    "OperatingDisposition",
    "OperatingDomain",
    "OperatingEnvelope",
    "OperatingFinding",
    "OperatingRegistry",
    "OperatingSeverity",
    "OperatingSourceWave",
    "OperatingTeam",
    "ReviewBoard",
    "ReviewDecision",
    "ReviewerAuthority",
    "ReviewerKind",
    "RepositoryDependency",
    "RepositoryDependencyKind",
    "RepositoryEvidenceState",
    "RepositoryPolicyBinding",
    "RepositoryRiskLevel",
    "RepositoryRiskSurface",
    "RepositoryRole",
    "SeparationOfDutiesRule",
    "TeamReviewDecision",
    "TeamRole",
    "digest_payload",
    "normalize_dotted_name",
    "normalize_identifier",
    "normalize_identifier_tuple",
    "normalize_optional_text",
    "normalize_path_tuple",
    "normalize_relative_path",
    "normalize_required_controls",
    "normalize_sha256",
    "normalize_text",
    "normalize_text_tuple",
    "unique_sorted_enum_tuple",
]
