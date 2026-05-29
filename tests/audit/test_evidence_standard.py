from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from ix_blackfox.audit import (
    AuditEvidenceArtifact,
    AuditEvidenceKind,
    AuditEvidenceManifest,
    AuditEvidenceSourceWave,
    AuditSubject,
    EvidenceManifestIssueSeverity,
    build_evidence_manifest,
    default_artifact_id,
    inspect_evidence_file,
    read_json_evidence_file,
    resolve_evidence_path,
    sha256_file,
    validate_evidence_manifest,
)

_HEAD_SHA = "abc123def456"
_SHA256_A = "a" * 64
_SHA256_B = "b" * 64


def _subject(scope: str = "Wave 9 audit scope") -> AuditSubject:
    return AuditSubject(repository="IX-BlackFox", head_sha=_HEAD_SHA, scope=scope)


def test_inspect_evidence_file_computes_digest_size_and_metadata(tmp_path) -> None:
    evidence_path = tmp_path / ".blackfox-artifacts" / "wave8" / "report.json"
    evidence_path.parent.mkdir(parents=True)
    evidence_path.write_text(
        json.dumps(
            {
                "schema_version": "wave8.repository_intelligence_ci_report.v1",
                "head_sha": _HEAD_SHA,
                "passed": True,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    artifact = inspect_evidence_file(
        tmp_path,
        ".blackfox-artifacts/wave8/report.json",
        kind=AuditEvidenceKind.REPOSITORY_INTELLIGENCE_REPORT,
        source_wave=AuditEvidenceSourceWave.WAVE8,
        artifact_id="wave8:repo-report",
        producer="unit-test",
        head_sha=_HEAD_SHA,
        schema_version="wave8.repository_intelligence_ci_report.v1",
        verified=True,
        metadata={"purpose": "unit-test"},
    )

    assert artifact.artifact_id == "wave8:repo-report"
    assert artifact.sha256 == sha256_file(evidence_path)
    assert artifact.size_bytes == evidence_path.stat().st_size
    assert artifact.verified is True
    assert artifact.metadata["purpose"] == "unit-test"


def test_inspect_evidence_file_rejects_missing_empty_and_directory_paths(tmp_path) -> None:
    empty_path = tmp_path / "empty.json"
    empty_path.write_text("", encoding="utf-8")
    directory_path = tmp_path / "evidence-dir"
    directory_path.mkdir()

    with pytest.raises(FileNotFoundError):
        inspect_evidence_file(
            tmp_path,
            "missing.json",
            kind=AuditEvidenceKind.CI_EVIDENCE,
            source_wave=AuditEvidenceSourceWave.WAVE5,
        )

    with pytest.raises(ValueError):
        inspect_evidence_file(
            tmp_path,
            "empty.json",
            kind=AuditEvidenceKind.CI_EVIDENCE,
            source_wave=AuditEvidenceSourceWave.WAVE5,
        )

    with pytest.raises(IsADirectoryError):
        inspect_evidence_file(
            tmp_path,
            "evidence-dir",
            kind=AuditEvidenceKind.CI_EVIDENCE,
            source_wave=AuditEvidenceSourceWave.WAVE5,
        )


def test_resolve_evidence_path_rejects_parent_traversal_and_symlink_escape(tmp_path) -> None:
    outside = tmp_path.parent / "outside-evidence.json"
    outside.write_text("{}", encoding="utf-8")

    with pytest.raises(ValueError):
        resolve_evidence_path(tmp_path, "../outside-evidence.json")

    symlink = tmp_path / "escaped.json"
    try:
        symlink.symlink_to(outside)
    except OSError:
        pytest.skip("symlinks are unavailable in this environment")

    with pytest.raises(ValueError):
        resolve_evidence_path(tmp_path, "escaped.json")


def test_validate_evidence_manifest_passes_for_matching_file_and_head_sha(tmp_path) -> None:
    evidence_path = tmp_path / "evidence" / "ci.json"
    evidence_path.parent.mkdir()
    evidence_path.write_text('{"passed": true}\n', encoding="utf-8")
    artifact = inspect_evidence_file(
        tmp_path,
        "evidence/ci.json",
        kind=AuditEvidenceKind.CI_EVIDENCE,
        source_wave=AuditEvidenceSourceWave.WAVE5,
        artifact_id="wave5:ci",
        producer="unit-test",
        head_sha=_HEAD_SHA,
    )
    manifest = AuditEvidenceManifest(
        manifest_id="wave9:test-manifest",
        subject=_subject("change review ci evidence"),
        artifacts=(artifact,),
        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
    )

    result = validate_evidence_manifest(manifest, repo_root=tmp_path)

    assert result.is_valid is True
    assert result.issue_count == 0
    assert result.manifest_digest == manifest.digest


def test_validate_evidence_manifest_blocks_empty_manifest_when_artifacts_required() -> None:
    manifest = AuditEvidenceManifest(
        manifest_id="wave9:empty-manifest",
        subject=_subject(),
        artifacts=(),
        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
    )

    result = validate_evidence_manifest(manifest)

    assert result.is_valid is False
    assert result.blocking_issue_count == 1
    assert result.issues[0].issue_id == "W9-EVIDENCE-NO-ARTIFACTS"


def test_validate_evidence_manifest_allows_empty_manifest_when_not_required() -> None:
    manifest = AuditEvidenceManifest(
        manifest_id="wave9:empty-diagnostic-manifest",
        subject=_subject(),
        artifacts=(),
        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
    )

    result = validate_evidence_manifest(manifest, require_artifacts=False)

    assert result.is_valid is True
    assert result.issue_count == 0


def test_validate_evidence_manifest_blocks_head_sha_mismatch() -> None:
    artifact = AuditEvidenceArtifact(
        artifact_id="wave8:repo-report",
        kind=AuditEvidenceKind.REPOSITORY_INTELLIGENCE_REPORT,
        source_wave=AuditEvidenceSourceWave.WAVE8,
        path=".blackfox-artifacts/wave8/report.json",
        sha256=_SHA256_A,
        size_bytes=10,
        producer="unit-test",
        head_sha="different-head-sha",
    )
    manifest = AuditEvidenceManifest(
        manifest_id="wave9:head-sha-mismatch",
        subject=_subject(),
        artifacts=(artifact,),
        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
    )

    result = validate_evidence_manifest(manifest)

    assert result.is_valid is False
    assert any(issue.issue_id == "W9-EVIDENCE-HEAD-SHA-MISMATCH" for issue in result.issues)


def test_validate_evidence_manifest_blocks_missing_internal_head_sha() -> None:
    artifact = AuditEvidenceArtifact(
        artifact_id="wave6:sandbox-report",
        kind=AuditEvidenceKind.SANDBOX_ADVERSARIAL_REPORT,
        source_wave=AuditEvidenceSourceWave.WAVE6,
        path=".blackfox-artifacts/wave6/report.json",
        sha256=_SHA256_A,
        size_bytes=10,
        producer="unit-test",
    )
    manifest = AuditEvidenceManifest(
        manifest_id="wave9:missing-head-sha",
        subject=_subject(),
        artifacts=(artifact,),
        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
    )

    result = validate_evidence_manifest(manifest)

    assert result.is_valid is False
    assert any(issue.issue_id == "W9-EVIDENCE-MISSING-HEAD-SHA" for issue in result.issues)


def test_validate_evidence_manifest_warns_on_unverified_attestation() -> None:
    artifact = AuditEvidenceArtifact(
        artifact_id="external:attestation",
        kind=AuditEvidenceKind.ATTESTATION,
        source_wave=AuditEvidenceSourceWave.EXTERNAL,
        path="attestations/provenance.json",
        sha256=_SHA256_A,
        size_bytes=10,
        producer="unit-test",
        verified=False,
    )
    manifest = AuditEvidenceManifest(
        manifest_id="wave9:attestation-warning",
        subject=_subject("attestation metadata review"),
        artifacts=(artifact,),
        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
    )

    result = validate_evidence_manifest(manifest)

    assert result.is_valid is True
    assert result.warning_issue_count == 1
    assert result.issues[0].severity is EvidenceManifestIssueSeverity.WARNING
    assert result.issues[0].issue_id == "W9-EVIDENCE-UNVERIFIED-ATTESTATION"


def test_validate_evidence_manifest_blocks_file_digest_and_size_mismatch(tmp_path) -> None:
    evidence_path = tmp_path / "evidence.json"
    evidence_path.write_text('{"actual": true}\n', encoding="utf-8")
    artifact = AuditEvidenceArtifact(
        artifact_id="wave5:stale-evidence",
        kind=AuditEvidenceKind.CI_EVIDENCE,
        source_wave=AuditEvidenceSourceWave.WAVE5,
        path="evidence.json",
        sha256=_SHA256_B,
        size_bytes=evidence_path.stat().st_size + 1,
        producer="unit-test",
        head_sha=_HEAD_SHA,
    )
    manifest = AuditEvidenceManifest(
        manifest_id="wave9:stale-evidence",
        subject=_subject(),
        artifacts=(artifact,),
        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
    )

    result = validate_evidence_manifest(manifest, repo_root=tmp_path)
    issue_ids = {issue.issue_id for issue in result.issues}

    assert result.is_valid is False
    assert "W9-EVIDENCE-SIZE-MISMATCH" in issue_ids
    assert "W9-EVIDENCE-DIGEST-MISMATCH" in issue_ids


def test_validate_evidence_manifest_blocks_missing_file_when_repo_root_checked(tmp_path) -> None:
    artifact = AuditEvidenceArtifact(
        artifact_id="wave5:missing-file",
        kind=AuditEvidenceKind.CI_EVIDENCE,
        source_wave=AuditEvidenceSourceWave.WAVE5,
        path="missing.json",
        sha256=_SHA256_A,
        size_bytes=1,
        producer="unit-test",
        head_sha=_HEAD_SHA,
    )
    manifest = build_evidence_manifest(
        "wave9:missing-file",
        _subject(),
        (artifact,),
        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
    )

    result = validate_evidence_manifest(manifest, repo_root=tmp_path)

    assert result.is_valid is False
    assert result.issues[0].issue_id == "W9-EVIDENCE-FILE-MISSING"


def test_default_artifact_id_is_stable_and_path_sensitive() -> None:
    first = default_artifact_id(
        AuditEvidenceKind.CI_EVIDENCE,
        AuditEvidenceSourceWave.WAVE5,
        "evidence/ci.json",
    )
    second = default_artifact_id(
        AuditEvidenceKind.CI_EVIDENCE,
        AuditEvidenceSourceWave.WAVE5,
        "evidence/ci.json",
    )
    different = default_artifact_id(
        AuditEvidenceKind.CI_EVIDENCE,
        AuditEvidenceSourceWave.WAVE5,
        "evidence/other-ci.json",
    )

    assert first == second
    assert first != different
    assert first.startswith("artifact:wave5:ci_evidence:")


def test_read_json_evidence_file_requires_json_object(tmp_path) -> None:
    object_path = tmp_path / "object.json"
    list_path = tmp_path / "list.json"
    object_path.write_text('{"passed": true}\n', encoding="utf-8")
    list_path.write_text("[]\n", encoding="utf-8")

    assert read_json_evidence_file(tmp_path, "object.json") == {"passed": True}

    with pytest.raises(ValueError):
        read_json_evidence_file(tmp_path, "list.json")
