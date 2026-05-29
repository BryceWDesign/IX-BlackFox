from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ix_blackfox.audit.evidence_standard import (
    inspect_evidence_file,
    read_json_evidence_file,
    resolve_evidence_path,
)
from ix_blackfox.audit.models import (
    AuditEvidenceArtifact,
    AuditEvidenceKind,
    AuditEvidenceSourceWave,
    AuditReviewDecision,
    AuditReviewerKind,
    AuditReviewerSignoff,
    normalize_identifier,
    normalize_relative_path,
    normalize_text,
)
from ix_blackfox.workflow.pr_evidence_io import load_pr_evidence_pack
from ix_blackfox.workflow.pr_evidence_pack import (
    ArtifactAttestationKind as Wave5ArtifactAttestationKind,
    EvidenceArtifact as Wave5EvidenceArtifact,
    EvidenceArtifactKind as Wave5EvidenceArtifactKind,
    PullRequestApproval,
    PullRequestEvidencePack,
    ReviewDecision as Wave5ReviewDecision,
    ReviewerKind as Wave5ReviewerKind,
)

WAVE6_CI_REPORT_PATH = ".blackfox-artifacts/wave6/wave6-sandbox-ci-report.json"
WAVE7_CI_REPORT_PATH = ".blackfox-artifacts/wave7/wave7-model-repair-ci-report.json"
WAVE8_CI_REPORT_PATH = ".blackfox-artifacts/wave8/wave8-repository-intelligence-ci-report.json"
WAVE8_EVIDENCE_SNAPSHOT_PATH = ".blackfox-artifacts/wave8/wave8-repository-intelligence-evidence.json"


@dataclass(frozen=True, slots=True)
class KnownWaveEvidencePath:
    """Repository-relative artifact path Wave 9 knows how to bridge."""

    relative_path: str
    kind: AuditEvidenceKind
    source_wave: AuditEvidenceSourceWave
    artifact_id: str
    producer: str
    schema_version: str = ""
    verified: bool = False
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "relative_path", normalize_relative_path(self.relative_path))
        object.__setattr__(
            self,
            "artifact_id",
            normalize_identifier(self.artifact_id, label="artifact_id"),
        )
        object.__setattr__(self, "producer", normalize_text(self.producer, label="producer"))
        object.__setattr__(self, "metadata", dict(self.metadata))


def default_known_wave_evidence_paths() -> tuple[KnownWaveEvidencePath, ...]:
    """Return known generated evidence paths for Waves 6-8.

    These are bridge targets only. They are not assumed to exist until the
    Wave 9 evidence collector inspects the repository checkout or generated CI
    artifact directory.
    """

    return (
        KnownWaveEvidencePath(
            relative_path=WAVE6_CI_REPORT_PATH,
            kind=AuditEvidenceKind.SANDBOX_ADVERSARIAL_REPORT,
            source_wave=AuditEvidenceSourceWave.WAVE6,
            artifact_id="wave6:sandbox-ci-report",
            producer="scripts/run_wave6_sandbox_ci.py",
            schema_version="wave6.sandbox_ci_report.v1",
            metadata={
                "bridge": "known_wave_evidence_path",
                "contains": ("sandbox_adversarial_report", "adversarial_verification"),
            },
        ),
        KnownWaveEvidencePath(
            relative_path=WAVE7_CI_REPORT_PATH,
            kind=AuditEvidenceKind.MODEL_REPAIR_REPORT,
            source_wave=AuditEvidenceSourceWave.WAVE7,
            artifact_id="wave7:model-repair-ci-report",
            producer="scripts/run_wave7_model_repair_ci.py",
            schema_version="wave7.model_repair_ci_report.v1",
            metadata={
                "bridge": "known_wave_evidence_path",
                "contains": ("selection_report", "evidence_export", "ledger_snapshot"),
            },
        ),
        KnownWaveEvidencePath(
            relative_path=WAVE8_CI_REPORT_PATH,
            kind=AuditEvidenceKind.REPOSITORY_INTELLIGENCE_REPORT,
            source_wave=AuditEvidenceSourceWave.WAVE8,
            artifact_id="wave8:repository-intelligence-ci-report",
            producer="scripts/run_wave8_repository_intelligence_ci.py",
            schema_version="wave8.repository_intelligence_ci_report.v1",
            metadata={
                "bridge": "known_wave_evidence_path",
                "contains": ("repository_intelligence_report", "impact_report"),
            },
        ),
        KnownWaveEvidencePath(
            relative_path=WAVE8_EVIDENCE_SNAPSHOT_PATH,
            kind=AuditEvidenceKind.REPOSITORY_EVIDENCE_SNAPSHOT,
            source_wave=AuditEvidenceSourceWave.WAVE8,
            artifact_id="wave8:repository-intelligence-evidence-snapshot",
            producer="scripts/run_wave8_repository_intelligence_ci.py",
            schema_version="wave8.repository_evidence_snapshot.v1",
            metadata={
                "bridge": "known_wave_evidence_path",
                "contains": ("digest_chained_repository_evidence_receipts",),
            },
        ),
    )


def collect_known_wave_evidence(
    repo_root: str | Path,
    *,
    head_sha: str,
    known_paths: Sequence[KnownWaveEvidencePath] | None = None,
    require_existing: bool = False,
) -> tuple[AuditEvidenceArtifact, ...]:
    """Collect inspectable generated evidence artifacts from known Waves 6-8 paths.

    Missing artifacts are skipped by default because CI may generate them later.
    Set ``require_existing=True`` for a strict local audit collection mode.
    """

    artifacts: list[AuditEvidenceArtifact] = []
    root = Path(repo_root)
    for known_path in known_paths or default_known_wave_evidence_paths():
        try:
            resolve_evidence_path(root, known_path.relative_path)
        except FileNotFoundError:
            if require_existing:
                raise
            continue
        metadata = _metadata_from_json_evidence(root, known_path.relative_path)
        artifacts.append(
            inspect_evidence_file(
                root,
                known_path.relative_path,
                kind=known_path.kind,
                source_wave=known_path.source_wave,
                artifact_id=known_path.artifact_id,
                producer=known_path.producer,
                head_sha=_head_sha_from_payload(metadata) or head_sha,
                schema_version=_schema_version_from_payload(metadata) or known_path.schema_version,
                verified=known_path.verified,
                metadata={**dict(known_path.metadata), **metadata},
            )
        )
    return tuple(sorted(artifacts, key=lambda artifact: artifact.artifact_id))


def bridge_pr_evidence_pack_file(
    repo_root: str | Path,
    relative_path: str,
    *,
    artifact_id: str = "wave5:pr-evidence-pack",
    producer: str = "ix_blackfox.workflow.pr_evidence_io",
    verified: bool = False,
) -> AuditEvidenceArtifact:
    """Bridge an existing Wave 5 PR evidence-pack JSON file into Wave 9 evidence."""

    normalized_path = normalize_relative_path(relative_path)
    pack = load_pr_evidence_pack(resolve_evidence_path(repo_root, normalized_path))
    return inspect_evidence_file(
        repo_root,
        normalized_path,
        kind=AuditEvidenceKind.PR_EVIDENCE_PACK,
        source_wave=AuditEvidenceSourceWave.WAVE5,
        artifact_id=artifact_id,
        producer=producer,
        head_sha=pack.pull_request.head_sha,
        schema_version="wave5.pr_evidence_pack.v1",
        verified=verified,
        metadata={
            "bridge": "wave5_pr_evidence_pack_file",
            "pack_id": pack.pack_id,
            "repository": pack.pull_request.repository,
            "pull_request_id": pack.pull_request.pull_request_id,
            "changed_file_count": len(pack.changed_files),
            "requested_check_count": len(pack.requested_checks),
            "embedded_artifact_count": len(pack.artifacts),
            "approval_count": len(pack.approvals),
            "human_approval_count": len(pack.human_approvals()),
        },
    )


def bridge_pr_evidence_pack_artifacts(
    pack: PullRequestEvidencePack,
    *,
    artifact_paths: Mapping[str, str] | None = None,
    producer: str = "ix_blackfox.workflow.pr_evidence_pack",
) -> tuple[AuditEvidenceArtifact, ...]:
    """Bridge inspectable artifact metadata embedded in a Wave 5 PR evidence pack.

    ``artifact_paths`` can bind Wave 5 artifact IDs to concrete repository-relative
    paths when the Wave 5 URI is not a safe repository-relative path. The bridge
    refuses undigested, zero-byte, or pathless artifacts because Wave 9 must not
    create audit evidence from unverifiable claims.
    """

    paths = dict(artifact_paths or {})
    bridged: list[AuditEvidenceArtifact] = []
    for artifact in pack.artifacts:
        bridged.append(
            bridge_wave5_evidence_artifact(
                artifact,
                fallback_path=paths.get(artifact.artifact_id),
                default_head_sha=pack.pull_request.head_sha,
                producer=producer,
            )
        )
    return tuple(sorted(bridged, key=lambda item: item.artifact_id))


def bridge_wave5_evidence_artifact(
    artifact: Wave5EvidenceArtifact,
    *,
    fallback_path: str | None = None,
    default_head_sha: str = "",
    producer: str = "ix_blackfox.workflow.pr_evidence_pack",
) -> AuditEvidenceArtifact:
    """Convert a Wave 5 artifact record into a Wave 9 audit artifact.

    The conversion is intentionally strict: SHA-256, positive byte size, and a
    safe repository-relative path are required. If the Wave 5 URI is not a safe
    local path, provide ``fallback_path``.
    """

    if artifact.sha256 is None:
        raise ValueError(f"Wave 5 artifact '{artifact.artifact_id}' is missing SHA-256.")
    if artifact.size_bytes is None or artifact.size_bytes <= 0:
        raise ValueError(f"Wave 5 artifact '{artifact.artifact_id}' must have positive size_bytes.")
    relative_path = fallback_path or relative_path_from_wave5_uri(artifact.uri)
    return AuditEvidenceArtifact(
        artifact_id=f"wave5:{artifact.artifact_id}",
        kind=map_wave5_artifact_kind(artifact.kind),
        source_wave=AuditEvidenceSourceWave.WAVE5,
        path=relative_path,
        sha256=artifact.sha256,
        size_bytes=artifact.size_bytes,
        producer=producer,
        head_sha=artifact.head_sha or default_head_sha,
        schema_version="wave5.embedded_evidence_artifact.v1",
        verified=artifact_is_verified_by_attestation(artifact),
        metadata={
            "bridge": "wave5_evidence_artifact",
            "wave5_artifact_id": artifact.artifact_id,
            "wave5_artifact_kind": artifact.kind.value,
            "wave5_uri": artifact.uri,
            "attestation_count": len(artifact.attestations),
            "verified_attestation_count": sum(1 for attestation in artifact.attestations if attestation.verified),
            "produced_by": artifact.produced_by,
            **dict(artifact.metadata),
        },
    )


def bridge_wave5_approval_to_signoff(
    approval: PullRequestApproval,
    *,
    subject_digest: str,
    policy_pack_digest: str,
) -> AuditReviewerSignoff:
    """Convert a Wave 5 approval record into a Wave 9 reviewer signoff record."""

    return AuditReviewerSignoff(
        signoff_id=f"wave5:{approval.approval_id}",
        reviewer_id=approval.reviewer_id,
        reviewer_kind=map_wave5_reviewer_kind(approval.reviewer_kind),
        decision=map_wave5_review_decision(approval.decision),
        subject_digest=subject_digest,
        policy_pack_digest=policy_pack_digest,
        signed_at=approval.decided_at,
        role=", ".join(approval.roles) if approval.roles else "wave5-reviewer",
        notes=approval.note,
        metadata={
            "bridge": "wave5_approval_to_signoff",
            "evidence_refs": list(approval.evidence_refs),
            "wave5_approval_id": approval.approval_id,
        },
    )


def bridge_wave5_approvals_to_signoffs(
    approvals: Iterable[PullRequestApproval],
    *,
    subject_digest: str,
    policy_pack_digest: str,
) -> tuple[AuditReviewerSignoff, ...]:
    """Bridge multiple Wave 5 approval records into deterministic Wave 9 signoffs."""

    return tuple(
        sorted(
            (
                bridge_wave5_approval_to_signoff(
                    approval,
                    subject_digest=subject_digest,
                    policy_pack_digest=policy_pack_digest,
                )
                for approval in approvals
            ),
            key=lambda signoff: signoff.signoff_id,
        )
    )


def map_wave5_artifact_kind(kind: Wave5EvidenceArtifactKind) -> AuditEvidenceKind:
    """Map Wave 5 workflow artifact kinds onto Wave 9 evidence kinds."""

    mapping = {
        Wave5EvidenceArtifactKind.RUN_BUNDLE: AuditEvidenceKind.GOVERNANCE_RECEIPT,
        Wave5EvidenceArtifactKind.TEST_REPORT: AuditEvidenceKind.CI_EVIDENCE,
        Wave5EvidenceArtifactKind.GOVERNANCE_RECEIPT: AuditEvidenceKind.GOVERNANCE_RECEIPT,
        Wave5EvidenceArtifactKind.RELIABILITY_REPORT: AuditEvidenceKind.GOVERNANCE_REPORT,
        Wave5EvidenceArtifactKind.POLICY_DECISION: AuditEvidenceKind.POLICY_DECISION,
        Wave5EvidenceArtifactKind.APPROVAL_RECORD: AuditEvidenceKind.APPROVAL_RECORD,
        Wave5EvidenceArtifactKind.CI_SUMMARY: AuditEvidenceKind.CI_EVIDENCE,
        Wave5EvidenceArtifactKind.HUMAN_REVIEW: AuditEvidenceKind.HUMAN_REVIEW,
        Wave5EvidenceArtifactKind.SANDBOX_RECEIPT_BUNDLE: AuditEvidenceKind.SANDBOX_RECEIPT_BUNDLE,
        Wave5EvidenceArtifactKind.SANDBOX_ADVERSARIAL_REPORT: AuditEvidenceKind.SANDBOX_ADVERSARIAL_REPORT,
        Wave5EvidenceArtifactKind.OTHER: AuditEvidenceKind.OTHER,
    }
    return mapping[kind]


def map_wave5_attestation_kind(kind: Wave5ArtifactAttestationKind) -> AuditEvidenceKind:
    """Map Wave 5 attestation kinds to Wave 9 attestation evidence."""

    _ = kind
    return AuditEvidenceKind.ATTESTATION


def map_wave5_reviewer_kind(kind: Wave5ReviewerKind) -> AuditReviewerKind:
    mapping = {
        Wave5ReviewerKind.HUMAN: AuditReviewerKind.HUMAN,
        Wave5ReviewerKind.SYSTEM: AuditReviewerKind.SYSTEM,
        Wave5ReviewerKind.MODEL: AuditReviewerKind.MODEL,
    }
    return mapping[kind]


def map_wave5_review_decision(decision: Wave5ReviewDecision) -> AuditReviewDecision:
    mapping = {
        Wave5ReviewDecision.APPROVED: AuditReviewDecision.APPROVED,
        Wave5ReviewDecision.CHANGES_REQUESTED: AuditReviewDecision.CHANGES_REQUESTED,
        Wave5ReviewDecision.REJECTED: AuditReviewDecision.REJECTED,
        Wave5ReviewDecision.COMMENTED: AuditReviewDecision.COMMENTED,
    }
    return mapping[decision]


def artifact_is_verified_by_attestation(artifact: Wave5EvidenceArtifact) -> bool:
    """Return true only when at least one embedded Wave 5 attestation is verified."""

    return any(attestation.verified for attestation in artifact.attestations)


def relative_path_from_wave5_uri(uri: str) -> str:
    """Extract a safe repository-relative path from a Wave 5 artifact URI."""

    normalized = uri.strip()
    if normalized.startswith("file://"):
        normalized = normalized.removeprefix("file://")
    if normalized.startswith("./"):
        normalized = normalized[2:]
    if "://" in normalized:
        raise ValueError(f"Wave 5 artifact URI is not a repository-relative path: {uri!r}")
    return normalize_relative_path(normalized)


def _metadata_from_json_evidence(repo_root: str | Path, relative_path: str) -> dict[str, Any]:
    try:
        payload = read_json_evidence_file(repo_root, relative_path)
    except (json.JSONDecodeError, OSError, ValueError):
        return {}
    metadata: dict[str, Any] = {"json_object_keys": tuple(sorted(str(key) for key in payload))}
    for key in (
        "wave",
        "passed",
        "run_id",
        "report_digest",
        "evidence_snapshot_digest",
        "head_sha",
        "schema_version",
    ):
        value = payload.get(key)
        if isinstance(value, (str, bool, int, float)):
            metadata[key] = value
    nested_report = payload.get("report")
    if isinstance(nested_report, Mapping):
        nested_schema = nested_report.get("schema_version")
        if isinstance(nested_schema, str):
            metadata["nested_report_schema_version"] = nested_schema
    return metadata


def _head_sha_from_payload(metadata: Mapping[str, Any]) -> str:
    value = metadata.get("head_sha")
    return value if isinstance(value, str) and value.strip() else ""


def _schema_version_from_payload(metadata: Mapping[str, Any]) -> str:
    for key in ("schema_version", "nested_report_schema_version"):
        value = metadata.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return ""
