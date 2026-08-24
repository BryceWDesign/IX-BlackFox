from __future__ import annotations

import json
from dataclasses import dataclass, replace
from pathlib import Path

from ix_blackfox.agents.models import AgentKind
from ix_blackfox.assurance.crosswalk import (
    AssuranceCrosswalkReport,
    build_assurance_crosswalk,
)
from ix_blackfox.assurance.evidence import (
    CollectedEvidence,
    EvidenceInputSpec,
    collect_evidence,
)
from ix_blackfox.assurance.models import (
    AssuranceClaimSet,
    AssuranceEvidenceKind,
    AssuranceEvidenceSource,
    AssuranceManifest,
    AssuranceSubject,
    AuthorityReview,
    AuthorityReviewDecision,
    EvidenceVerificationState,
    ReviewAuthenticationState,
    default_wave12_claims,
)
from ix_blackfox.assurance.profiles import default_wave12_assurance_profile
from ix_blackfox.assurance.report import (
    AssuranceReadinessReport,
    build_assurance_readiness_report,
)

FIXED_TIME = "2026-08-23T12:00:00+00:00"
REVISION = "0123456789abcdef0123456789abcdef01234567"

_REQUIRED_KINDS = (
    AssuranceEvidenceKind.TEST_RESULT,
    AssuranceEvidenceKind.STATIC_ANALYSIS,
    AssuranceEvidenceKind.TYPE_CHECK,
    AssuranceEvidenceKind.POLICY_EVALUATION,
    AssuranceEvidenceKind.SANDBOX_EVIDENCE,
    AssuranceEvidenceKind.REPOSITORY_INTELLIGENCE,
    AssuranceEvidenceKind.AGENT_IDENTITY,
    AssuranceEvidenceKind.PROVENANCE,
)


@dataclass(frozen=True)
class AssuranceStack:
    root: Path
    evidence: tuple[CollectedEvidence, ...]
    manifest: AssuranceManifest
    crosswalk: AssuranceCrosswalkReport
    readiness: AssuranceReadinessReport
    reviews: tuple[AuthorityReview, ...]


def build_stack(
    tmp_path: Path,
    *,
    include_human_review_evidence: bool = False,
    add_authoritative_review: bool = False,
    reviewer_agent_id: str = "release-owner",
    reviewer_kind: AgentKind = AgentKind.HUMAN_OPERATOR,
    decision: AuthorityReviewDecision = (
        AuthorityReviewDecision.APPROVE_FOR_EXTERNAL_ASSESSMENT
    ),
    authentication_state: ReviewAuthenticationState = (
        ReviewAuthenticationState.VERIFIED
    ),
    human_review_externally_verified: bool = False,
    claims: AssuranceClaimSet | None = None,
) -> AssuranceStack:
    root = tmp_path / "repo"
    root.mkdir()
    (root / ".blackfox-workspace").write_text("\n", encoding="utf-8")
    artifacts_dir = root / "artifacts"
    artifacts_dir.mkdir()

    kinds = list(_REQUIRED_KINDS)
    if include_human_review_evidence:
        kinds.append(AssuranceEvidenceKind.HUMAN_REVIEW)
    specs: list[EvidenceInputSpec] = []
    for index, kind in enumerate(kinds):
        artifact_id = f"artifact-{kind.value}"
        filename = f"{index:02d}-{kind.value}.json"
        source_path = f"artifacts/{filename}"
        (root / source_path).write_text(
            json.dumps(
                {
                    "head_sha": REVISION,
                    "kind": kind.value,
                    "passed": True,
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        specs.append(
            EvidenceInputSpec(
                artifact_id=artifact_id,
                source_wave=(
                    AssuranceEvidenceSource.WAVE12
                    if kind
                    in {
                        AssuranceEvidenceKind.TEST_RESULT,
                        AssuranceEvidenceKind.STATIC_ANALYSIS,
                        AssuranceEvidenceKind.TYPE_CHECK,
                        AssuranceEvidenceKind.HUMAN_REVIEW,
                    }
                    else AssuranceEvidenceSource.WAVE11
                ),
                evidence_kind=kind,
                source_path=source_path,
                package_path=f"evidence/{filename}",
                media_type="application/json",
                producer="IX-BlackFox test fixture",
                schema_version=f"test.{kind.value}.v1",
                revision_json_pointer="/head_sha",
            )
        )

    collected = collect_evidence(root, specs, expected_revision=REVISION)
    evidence = tuple(
        replace(
            item,
            artifact=replace(
                item.artifact,
                verification_state=EvidenceVerificationState.EXTERNALLY_VERIFIED,
            ),
        )
        if human_review_externally_verified
        and item.artifact.evidence_kind is AssuranceEvidenceKind.HUMAN_REVIEW
        else item
        for item in collected
    )
    subject = AssuranceSubject(
        repository="IX-BlackFox",
        revision=REVISION,
        scope="Wave 12 test assurance scope",
        producer_agent_id="wave12-package-builder",
        generated_at=FIXED_TIME,
    )
    profile = default_wave12_assurance_profile()
    manifest = AssuranceManifest(
        manifest_id="wave12-test-manifest",
        subject=subject,
        profile=profile,
        evidence=tuple(item.artifact for item in evidence),
        claims=claims or default_wave12_claims(),
    )
    reviews: tuple[AuthorityReview, ...] = ()
    if add_authoritative_review:
        verification_ids = (
            ("artifact-human-review",)
            if include_human_review_evidence
            else ("missing-human-review",)
        )
        reviews = (
            AuthorityReview(
                review_id="wave12-human-review",
                reviewer_agent_id=reviewer_agent_id,
                reviewer_kind=reviewer_kind,
                decision=decision,
                subject_digest=manifest.digest,
                profile_digest=profile.digest,
                reviewed_at=FIXED_TIME,
                authentication_state=authentication_state,
                verification_artifact_ids=verification_ids,
            ),
        )
    crosswalk = build_assurance_crosswalk(
        subject=subject,
        profile=profile,
        artifacts=manifest.evidence,
    )
    readiness = build_assurance_readiness_report(
        manifest=manifest,
        crosswalk=crosswalk,
        reviews=reviews,
    )
    return AssuranceStack(
        root=root,
        evidence=evidence,
        manifest=manifest,
        crosswalk=crosswalk,
        readiness=readiness,
        reviews=reviews,
    )
