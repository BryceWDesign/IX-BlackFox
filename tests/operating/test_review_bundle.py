from __future__ import annotations

import hashlib

import pytest

from ix_blackfox.operating import (
    OperatingArtifactKind,
    OperatingArtifactRef,
    OperatingDisposition,
    OperatingDomain,
    OperatingEnvelope,
    OperatingFinding,
    OperatingReviewBundle,
    OperatingSeverity,
    OperatingSourceWave,
    ReviewBundleArtifact,
    ReviewBundleSection,
    ReviewBundleSectionKind,
    ReviewBundleValidation,
)


def test_review_bundle_is_deterministic_human_review_only_and_ready() -> None:
    bundle = _ready_bundle()
    same_bundle = OperatingReviewBundle(
        bundle_id="wave-10-review-bundle",
        campaign_id="wave-10-campaign",
        repository_ids=("ix-blackfox",),
        created_by="platform security reviewer",
        sections=(
            _section(
                "team-authority",
                ReviewBundleSectionKind.TEAM_AUTHORITY,
                ("team-authority",),
            ),
            _section(
                "registry",
                ReviewBundleSectionKind.REGISTRY,
                ("registry-report",),
            ),
            _section(
                "campaign",
                ReviewBundleSectionKind.CAMPAIGN,
                ("campaign-report",),
            ),
            _section(
                "evidence",
                ReviewBundleSectionKind.EVIDENCE_INVENTORY,
                ("evidence-inventory",),
            ),
            _section(
                "replay",
                ReviewBundleSectionKind.REPLAY_MANIFEST,
                ("replay-manifest",),
            ),
        ),
        artifacts=(
            ReviewBundleArtifact(
                _artifact("replay-manifest"),
                review_note="Confirm replay contract.",
            ),
            ReviewBundleArtifact(
                _artifact("team-authority"),
                review_note="Confirm human authority.",
            ),
            ReviewBundleArtifact(
                _artifact("campaign-report"),
                review_note="Confirm campaign scope.",
            ),
            ReviewBundleArtifact(
                _artifact("evidence-inventory"),
                review_note="Confirm evidence inventory.",
            ),
            ReviewBundleArtifact(
                _artifact("registry-report"),
                review_note="Confirm registry scope.",
            ),
        ),
        reviewer_questions=("Does every section require human authority?",),
    )

    assert bundle.bundle_id == "wave-10-review-bundle"
    assert bundle.requires_human_authority is True
    assert bundle.allowed_for_automatic_execution is False
    assert bundle.artifact_ids == (
        "campaign-report",
        "evidence-inventory",
        "registry-report",
        "replay-manifest",
        "team-authority",
    )
    assert bundle.section_kinds_present == (
        ReviewBundleSectionKind.CAMPAIGN,
        ReviewBundleSectionKind.EVIDENCE_INVENTORY,
        ReviewBundleSectionKind.REGISTRY,
        ReviewBundleSectionKind.REPLAY_MANIFEST,
        ReviewBundleSectionKind.TEAM_AUTHORITY,
    )
    assert bundle.findings == ()
    assert bundle.disposition is OperatingDisposition.READY
    assert bundle.to_envelope().disposition is OperatingDisposition.READY
    assert bundle.to_dict()["digest"] == same_bundle.to_dict()["digest"]
    assert '"allowed_for_automatic_execution":false' in bundle.export_json()


def test_review_bundle_blocks_missing_section_and_artifact() -> None:
    bundle = OperatingReviewBundle(
        bundle_id="missing-section",
        campaign_id="wave-10-campaign",
        repository_ids=("ix-blackfox",),
        created_by="platform security reviewer",
        sections=(
            _section(
                "registry",
                ReviewBundleSectionKind.REGISTRY,
                ("registry-report",),
            ),
        ),
        artifacts=(ReviewBundleArtifact(_artifact("different-artifact")),),
    )

    finding_codes = {finding.code for finding in bundle.findings}
    missing_sections = {
        finding.metadata.get("section_kind") for finding in bundle.findings
    }
    assert finding_codes == {
        "operating.review_bundle.missing-required-section",
        "operating.review_bundle.section-artifact-not-exported",
    }
    assert {
        "team_authority",
        "campaign",
        "evidence_inventory",
        "replay_manifest",
    } <= missing_sections
    assert bundle.missing_section_artifact_ids == ("registry-report",)
    assert bundle.disposition is OperatingDisposition.BLOCKED


def test_review_bundle_blocks_blocked_required_section() -> None:
    blocked_section = _section(
        "campaign",
        ReviewBundleSectionKind.CAMPAIGN,
        ("campaign-report",),
        findings=(
            OperatingFinding(
                code="operating.campaign.blocked-work-package",
                severity=OperatingSeverity.CRITICAL,
                summary="Campaign contains blocked work.",
                domains=(OperatingDomain.REVIEWABLE,),
                blocking=True,
            ),
        ),
    )
    bundle = OperatingReviewBundle(
        bundle_id="blocked-section",
        campaign_id="wave-10-campaign",
        repository_ids=("ix-blackfox",),
        created_by="platform security reviewer",
        sections=(
            _section(
                "registry",
                ReviewBundleSectionKind.REGISTRY,
                ("registry-report",),
            ),
            _section(
                "team-authority",
                ReviewBundleSectionKind.TEAM_AUTHORITY,
                ("team-authority",),
            ),
            blocked_section,
            _section(
                "evidence",
                ReviewBundleSectionKind.EVIDENCE_INVENTORY,
                ("evidence-inventory",),
            ),
            _section(
                "replay",
                ReviewBundleSectionKind.REPLAY_MANIFEST,
                ("replay-manifest",),
            ),
        ),
        artifacts=(
            ReviewBundleArtifact(_artifact("registry-report")),
            ReviewBundleArtifact(_artifact("team-authority")),
            ReviewBundleArtifact(_artifact("campaign-report")),
            ReviewBundleArtifact(_artifact("evidence-inventory")),
            ReviewBundleArtifact(_artifact("replay-manifest")),
        ),
    )

    assert bundle.blocking_section_ids == ("campaign",)
    assert "operating.review_bundle.blocked-section" in {
        finding.code for finding in bundle.findings
    }
    assert bundle.to_envelope().disposition is OperatingDisposition.BLOCKED


def test_review_bundle_refuses_to_become_execution_authority() -> None:
    with pytest.raises(ValueError, match="must require human authority"):
        OperatingReviewBundle(
            bundle_id="bad-human-authority",
            campaign_id="wave-10-campaign",
            repository_ids=("ix-blackfox",),
            created_by="platform security reviewer",
            sections=(
                _section(
                    "registry",
                    ReviewBundleSectionKind.REGISTRY,
                    ("registry-report",),
                ),
            ),
            artifacts=(ReviewBundleArtifact(_artifact("registry-report")),),
            requires_human_authority=False,
        )

    with pytest.raises(ValueError, match="never allow automatic execution"):
        OperatingReviewBundle(
            bundle_id="bad-auto-exec",
            campaign_id="wave-10-campaign",
            repository_ids=("ix-blackfox",),
            created_by="platform security reviewer",
            sections=(
                _section(
                    "registry",
                    ReviewBundleSectionKind.REGISTRY,
                    ("registry-report",),
                ),
            ),
            artifacts=(ReviewBundleArtifact(_artifact("registry-report")),),
            allowed_for_automatic_execution=True,
        )


def test_review_bundle_validation_passes_matching_artifacts() -> None:
    bundle = _ready_bundle()
    validation = ReviewBundleValidation(
        validation_id="review-bundle-validation",
        bundle=bundle,
        observed_artifacts=tuple(artifact.artifact for artifact in bundle.artifacts),
        checked_by="platform security reviewer",
    )

    assert validation.passed is True
    assert validation.missing_required_artifact_ids == ()
    assert validation.mismatched_artifact_ids == ()
    assert validation.unexpected_artifact_ids == ()
    assert validation.to_envelope().disposition is OperatingDisposition.READY


def test_review_bundle_validation_blocks_bad_artifacts() -> None:
    bundle = _ready_bundle()
    validation = ReviewBundleValidation(
        validation_id="blocked-review-bundle-validation",
        bundle=bundle,
        observed_artifacts=(
            _artifact("registry-report", content=b"changed"),
            _artifact("team-authority"),
            _artifact("campaign-report"),
            _artifact("unexpected-artifact"),
        ),
        checked_by="platform security reviewer",
    )

    finding_codes = {finding.code for finding in validation.findings}
    assert "operating.review_bundle.artifact-digest-mismatch" in finding_codes
    assert "operating.review_bundle.missing-required-artifact" in finding_codes
    assert "operating.review_bundle.unexpected-artifact" in finding_codes
    assert validation.mismatched_artifact_ids == ("registry-report",)
    assert validation.missing_required_artifact_ids == (
        "evidence-inventory",
        "replay-manifest",
    )
    assert validation.unexpected_artifact_ids == ("unexpected-artifact",)
    assert validation.passed is False
    assert validation.to_dict()["disposition"] == "blocked"


def _ready_bundle() -> OperatingReviewBundle:
    return OperatingReviewBundle(
        bundle_id=" Wave 10 Review Bundle ",
        campaign_id="Wave 10 Campaign",
        repository_ids=("IX-BlackFox",),
        created_by="platform security reviewer",
        sections=(
            _section(
                "registry",
                ReviewBundleSectionKind.REGISTRY,
                ("registry-report",),
            ),
            _section(
                "team-authority",
                ReviewBundleSectionKind.TEAM_AUTHORITY,
                ("team-authority",),
            ),
            _section(
                "campaign",
                ReviewBundleSectionKind.CAMPAIGN,
                ("campaign-report",),
            ),
            _section(
                "evidence",
                ReviewBundleSectionKind.EVIDENCE_INVENTORY,
                ("evidence-inventory",),
            ),
            _section(
                "replay",
                ReviewBundleSectionKind.REPLAY_MANIFEST,
                ("replay-manifest",),
            ),
        ),
        artifacts=(
            ReviewBundleArtifact(
                _artifact("registry-report"),
                review_note="Confirm registry scope.",
            ),
            ReviewBundleArtifact(
                _artifact("team-authority"),
                review_note="Confirm human authority.",
            ),
            ReviewBundleArtifact(
                _artifact("campaign-report"),
                review_note="Confirm campaign scope.",
            ),
            ReviewBundleArtifact(
                _artifact("evidence-inventory"),
                review_note="Confirm evidence inventory.",
            ),
            ReviewBundleArtifact(
                _artifact("replay-manifest"),
                review_note="Confirm replay contract.",
            ),
        ),
        reviewer_questions=("Does every section require human authority?",),
    )


def _section(
    section_id: str,
    section_kind: ReviewBundleSectionKind,
    artifact_ids: tuple[str, ...],
    *,
    findings: tuple[OperatingFinding, ...] = (),
) -> ReviewBundleSection:
    artifacts = tuple(_artifact(artifact_id) for artifact_id in artifact_ids)
    envelope = OperatingEnvelope(
        envelope_id=f"{section_id}-envelope",
        artifact_kind=OperatingArtifactKind.OPERATING_REPORT,
        subject=f"{section_id} operating evidence",
        domains=(OperatingDomain.REVIEWABLE,),
        evidence=artifacts,
        findings=findings,
    )
    return ReviewBundleSection(
        section_id=section_id,
        section_kind=section_kind,
        title=f"{section_id} review section",
        envelope=envelope,
        reviewer_instructions=("Review the digest-bound evidence before approval.",),
    )


def _artifact(
    artifact_id: str,
    *,
    content: bytes | None = None,
) -> OperatingArtifactRef:
    normalized = artifact_id.strip().lower().replace(" ", "-")
    payload = content if content is not None else normalized.encode("utf-8")
    return OperatingArtifactRef(
        artifact_id=artifact_id,
        kind=OperatingArtifactKind.EVIDENCE_MANIFEST,
        source_wave=OperatingSourceWave.WAVE10,
        path=f".blackfox-artifacts/wave10/{normalized}.json",
        sha256=hashlib.sha256(payload).hexdigest(),
        producer="IX-BlackFox Wave 10 review bundle tests",
    )
