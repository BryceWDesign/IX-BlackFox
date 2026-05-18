from __future__ import annotations

from datetime import UTC, datetime

import pytest

from ix_blackfox.sandbox import (
    SandboxArtifactSignatureVerifier,
    SandboxArtifactSigner,
    SandboxSignedArtifactStatement,
)

_HEAD_SHA = "abc1234"
_SUBJECT_DIGEST = "a" * 64
_MANIFEST_DIGEST = "b" * 64
_PROFILE_DIGEST = "c" * 64
_KEY = b"wave6-local-signing-key"


def test_wave6_artifact_signer_creates_verifiable_statement() -> None:
    statement = _statement()

    report = SandboxArtifactSignatureVerifier(
        allowed_signer_ids=("blackfox-ci",)
    ).verify(
        statement,
        keyring={"blackfox-ci": _KEY},
        expected_head_sha=_HEAD_SHA,
        expected_subject_sha256=_SUBJECT_DIGEST,
        expected_artifact_manifest_digest=_MANIFEST_DIGEST,
    )

    assert report.passed is True
    assert report.error_count == 0
    assert report.issue_codes == ()
    assert report.statement_digest == statement.statement_digest
    assert report.body_digest == statement.body_digest
    assert statement.to_dict()["statement_digest"] == statement.statement_digest


def test_wave6_artifact_signature_verifier_rejects_tampered_signature() -> None:
    statement = _statement()
    tampered = SandboxSignedArtifactStatement(
        statement_id=statement.statement_id,
        subject_uri=statement.subject_uri,
        subject_sha256=statement.subject_sha256,
        subject_size_bytes=statement.subject_size_bytes,
        head_sha=statement.head_sha,
        signer_id=statement.signer_id,
        algorithm=statement.algorithm,
        created_at=statement.created_at,
        signature="0" * 64,
        profile_digest=statement.profile_digest,
        artifact_manifest_digest=statement.artifact_manifest_digest,
        metadata=statement.metadata,
    )

    report = SandboxArtifactSignatureVerifier().verify(
        tampered,
        keyring={"blackfox-ci": _KEY},
    )

    assert report.passed is False
    assert "wave6.signature.invalid" in report.issue_codes


def test_wave6_artifact_signature_verifier_rejects_unknown_signer() -> None:
    statement = _statement()

    report = SandboxArtifactSignatureVerifier().verify(
        statement,
        keyring={"other-signer": b"other-key"},
    )

    assert report.passed is False
    assert "wave6.signature.unknown_signer" in report.issue_codes


def test_wave6_artifact_signature_verifier_rejects_disallowed_signer() -> None:
    statement = _statement()

    report = SandboxArtifactSignatureVerifier(
        allowed_signer_ids=("release-bot",)
    ).verify(
        statement,
        keyring={"blackfox-ci": _KEY},
    )

    assert report.passed is False
    assert "wave6.signature.signer_not_allowed" in report.issue_codes


def test_wave6_artifact_signature_verifier_rejects_head_sha_mismatch() -> None:
    statement = _statement()

    report = SandboxArtifactSignatureVerifier().verify(
        statement,
        keyring={"blackfox-ci": _KEY},
        expected_head_sha="def5678",
    )

    assert report.passed is False
    assert "wave6.signature.head_sha_mismatch" in report.issue_codes


def test_wave6_artifact_signature_verifier_rejects_subject_digest_mismatch() -> None:
    statement = _statement()

    report = SandboxArtifactSignatureVerifier().verify(
        statement,
        keyring={"blackfox-ci": _KEY},
        expected_subject_sha256="d" * 64,
    )

    assert report.passed is False
    assert "wave6.signature.subject_digest_mismatch" in report.issue_codes


def test_wave6_artifact_signature_verifier_rejects_manifest_digest_mismatch() -> None:
    statement = _statement()

    report = SandboxArtifactSignatureVerifier().verify(
        statement,
        keyring={"blackfox-ci": _KEY},
        expected_artifact_manifest_digest="e" * 64,
    )

    assert report.passed is False
    assert "wave6.signature.artifact_manifest_digest_mismatch" in report.issue_codes


def test_wave6_artifact_signer_rejects_empty_key() -> None:
    with pytest.raises(ValueError, match="key"):
        SandboxArtifactSigner(signer_id="blackfox-ci", key=b"")


def test_wave6_signed_statement_body_digest_changes_when_subject_changes() -> None:
    first = _statement(subject_sha256=_SUBJECT_DIGEST)
    second = _statement(subject_sha256="f" * 64)

    assert first.body_digest != second.body_digest
    assert first.statement_digest != second.statement_digest


def _statement(*, subject_sha256: str = _SUBJECT_DIGEST) -> SandboxSignedArtifactStatement:
    return SandboxArtifactSigner(
        signer_id="blackfox-ci",
        key=_KEY,
    ).sign(
        statement_id="statement-sandbox-artifact",
        subject_uri="artifacts/wave6/sandbox-adversarial-report.json",
        subject_sha256=subject_sha256,
        subject_size_bytes=2048,
        head_sha=_HEAD_SHA,
        profile_digest=_PROFILE_DIGEST,
        artifact_manifest_digest=_MANIFEST_DIGEST,
        created_at=datetime(2026, 5, 16, 12, 0, tzinfo=UTC),
        metadata={"wave": "6", "scope": "local-signed-artifact"},
    )
