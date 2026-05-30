from __future__ import annotations

import hashlib

import pytest

from ix_blackfox.operating import (
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
)


def test_operating_artifact_ref_normalizes_identifier_path_digest_and_text() -> None:
    digest = hashlib.sha256(b"wave-nine-report").hexdigest().upper()

    artifact = OperatingArtifactRef(
        artifact_id=" Wave 9 Governance Report ",
        kind=OperatingArtifactKind.OPERATING_REPORT,
        source_wave=OperatingSourceWave.WAVE9,
        path=" artifacts\\wave9\\governance-report.json ",
        sha256=digest,
        producer="  IX-BlackFox Wave 9 CI  ",
        schema_version="  wave9.compliance_audit_attestation.v1  ",
        metadata={"verified": True},
    )

    assert artifact.artifact_id == "wave-9-governance-report"
    assert artifact.path == "artifacts/wave9/governance-report.json"
    assert artifact.sha256 == digest.lower()
    assert artifact.producer == "IX-BlackFox Wave 9 CI"
    assert artifact.schema_version == "wave9.compliance_audit_attestation.v1"
    assert artifact.to_dict()["source_wave"] == "wave9"
    assert artifact.to_dict()["metadata"] == {"verified": True}


def test_operating_artifact_ref_rejects_unsafe_paths_and_bad_digest() -> None:
    digest = hashlib.sha256(b"artifact").hexdigest()

    with pytest.raises(ValueError, match="repository-relative"):
        OperatingArtifactRef(
            artifact_id="artifact",
            kind=OperatingArtifactKind.EVIDENCE_MANIFEST,
            source_wave=OperatingSourceWave.WAVE8,
            path="/tmp/evidence.json",
            sha256=digest,
            producer="Wave 8",
        )

    with pytest.raises(ValueError, match="path traversal"):
        OperatingArtifactRef(
            artifact_id="artifact",
            kind=OperatingArtifactKind.EVIDENCE_MANIFEST,
            source_wave=OperatingSourceWave.WAVE8,
            path="../evidence.json",
            sha256=digest,
            producer="Wave 8",
        )

    with pytest.raises(ValueError, match="sha256"):
        OperatingArtifactRef(
            artifact_id="artifact",
            kind=OperatingArtifactKind.EVIDENCE_MANIFEST,
            source_wave=OperatingSourceWave.WAVE8,
            path="artifacts/evidence.json",
            sha256="not-a-digest",
            producer="Wave 8",
        )


def test_operating_finding_normalizes_domains_paths_and_metadata() -> None:
    finding = OperatingFinding(
        code=" operating/missing-approval ",
        severity=OperatingSeverity.CRITICAL,
        summary="  Human approval is missing.  ",
        domains=(
            OperatingDomain.REVIEWABLE,
            OperatingDomain.MULTI_TEAM,
            OperatingDomain.REVIEWABLE,
        ),
        paths=("docs\\wave10.md", "src/ix_blackfox/operating/models.py"),
        blocking=True,
        metadata={"required_reviewer": "security-lead"},
    )

    assert finding.code == "operating.missing-approval"
    assert finding.summary == "Human approval is missing."
    assert finding.domains == (
        OperatingDomain.MULTI_TEAM,
        OperatingDomain.REVIEWABLE,
    )
    assert finding.paths == (
        "docs/wave10.md",
        "src/ix_blackfox/operating/models.py",
    )
    assert finding.to_dict()["blocking"] is True
    assert finding.to_dict()["metadata"] == {"required_reviewer": "security-lead"}


def test_operating_envelope_sorts_evidence_computes_digest_and_blocks_on_findings() -> None:
    first = _artifact("wave8-report", OperatingSourceWave.WAVE8, b"wave8")
    second = _artifact("wave9-report", OperatingSourceWave.WAVE9, b"wave9")
    blocking = OperatingFinding(
        code="operating.self-approval",
        severity=OperatingSeverity.CRITICAL,
        summary="Reviewer attempted to approve their own model-authored change.",
        domains=(OperatingDomain.MULTI_TEAM, OperatingDomain.REVIEWABLE),
        blocking=True,
    )

    envelope = OperatingEnvelope(
        envelope_id=" Wave 10 Foundation ",
        artifact_kind=OperatingArtifactKind.OPERATING_REPORT,
        subject="  IX-BlackFox Wave 10 operating foundation  ",
        domains=(
            OperatingDomain.REPLAYABLE,
            OperatingDomain.MULTI_REPO,
            OperatingDomain.REPLAYABLE,
        ),
        evidence=(second, first),
        findings=(blocking,),
    )
    same_envelope = OperatingEnvelope(
        envelope_id="wave-10-foundation",
        artifact_kind=OperatingArtifactKind.OPERATING_REPORT,
        subject="IX-BlackFox Wave 10 operating foundation",
        domains=(OperatingDomain.MULTI_REPO, OperatingDomain.REPLAYABLE),
        evidence=(first, second),
        findings=(blocking,),
    )

    assert envelope.envelope_id == "wave-10-foundation"
    assert envelope.schema_version == WAVE10_OPERATING_SCHEMA_VERSION
    assert envelope.domains == (
        OperatingDomain.MULTI_REPO,
        OperatingDomain.REPLAYABLE,
    )
    assert [artifact.artifact_id for artifact in envelope.evidence] == [
        "wave8-report",
        "wave9-report",
    ]
    assert envelope.disposition is OperatingDisposition.BLOCKED
    assert envelope.blocking_findings == (blocking,)
    assert envelope.digest == same_envelope.digest
    assert envelope.to_dict()["digest"] == envelope.digest


def test_operating_envelope_warns_without_blocking_findings_and_is_ready_without_findings() -> None:
    warning = OperatingFinding(
        code="operating.stale-evidence",
        severity=OperatingSeverity.MEDIUM,
        summary="Evidence is stale and requires refresh before final release.",
        domains=(OperatingDomain.MEASURABLE,),
    )

    warning_envelope = OperatingEnvelope(
        envelope_id="warning-envelope",
        artifact_kind=OperatingArtifactKind.OPERATING_REPORT,
        subject="Warning report",
        findings=(warning,),
    )
    ready_envelope = OperatingEnvelope(
        envelope_id="ready-envelope",
        artifact_kind=OperatingArtifactKind.OPERATING_REPORT,
        subject="Ready report",
    )

    assert warning_envelope.disposition is OperatingDisposition.WARNING
    assert ready_envelope.disposition is OperatingDisposition.READY


def test_operating_envelope_rejects_duplicate_evidence_ids() -> None:
    artifact = _artifact("duplicate", OperatingSourceWave.WAVE8, b"one")
    duplicate = _artifact(" Duplicate ", OperatingSourceWave.WAVE9, b"two")

    with pytest.raises(ValueError, match="unique"):
        OperatingEnvelope(
            envelope_id="duplicate-evidence",
            artifact_kind=OperatingArtifactKind.OPERATING_REPORT,
            subject="Duplicate evidence test",
            evidence=(artifact, duplicate),
        )


def test_digest_payload_is_deterministic_for_key_order() -> None:
    first = digest_payload({"b": 2, "a": [1, 2, 3]})
    second = digest_payload({"a": [1, 2, 3], "b": 2})

    assert first == second
    assert len(first) == 64


def _artifact(
    artifact_id: str,
    source_wave: OperatingSourceWave,
    content: bytes,
) -> OperatingArtifactRef:
    return OperatingArtifactRef(
        artifact_id=artifact_id,
        kind=OperatingArtifactKind.EVIDENCE_MANIFEST,
        source_wave=source_wave,
        path=f"artifacts/{artifact_id.strip().lower().replace(' ', '-')}.json",
        sha256=hashlib.sha256(content).hexdigest(),
        producer="IX-BlackFox test suite",
    )
