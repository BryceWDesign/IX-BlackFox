from __future__ import annotations

from datetime import UTC, datetime

import pytest

from ix_blackfox.workflow import (
    CiCheckConclusion,
    CiCheckStatus,
    CiEvidenceBundle,
    CiEvidenceNormalizer,
    CiEvidenceRecord,
    CiEvidenceValidator,
    EvidenceArtifactKind,
)


def test_wave5_ci_evidence_passes_when_all_required_checks_succeed() -> None:
    bundle = _bundle(
        records=(
            _record("pytest", CiCheckConclusion.SUCCESS),
            _record("ruff", CiCheckConclusion.SUCCESS),
            _record("mypy", CiCheckConclusion.SUCCESS),
        )
    )

    report = CiEvidenceValidator(required_checks=("pytest", "ruff", "mypy")).validate(bundle)

    assert bundle.passed is True
    assert report.passed is True
    assert report.error_count == 0
    assert report.to_dict()["passed"] is True


def test_wave5_ci_evidence_fails_closed_when_required_check_is_missing() -> None:
    bundle = _bundle(records=(_record("pytest", CiCheckConclusion.SUCCESS),))

    report = CiEvidenceValidator(required_checks=("pytest", "ruff")).validate(bundle)

    assert report.passed is False
    assert "wave5.ci_required_check_missing" in report.issue_codes


def test_wave5_ci_evidence_fails_closed_when_required_check_fails() -> None:
    bundle = _bundle(
        records=(
            _record("pytest", CiCheckConclusion.SUCCESS),
            _record("ruff", CiCheckConclusion.FAILURE),
        )
    )

    report = CiEvidenceValidator(required_checks=("pytest", "ruff")).validate(bundle)

    assert report.passed is False
    assert "wave5.ci_required_check_failed" in report.issue_codes
    assert bundle.failed_required_records[0].check_name == "ruff"


def test_wave5_ci_evidence_fails_closed_when_required_check_is_pending() -> None:
    bundle = _bundle(
        records=(
            _record("pytest", CiCheckConclusion.SUCCESS),
            CiEvidenceRecord(
                check_name="ruff",
                provider="github-actions",
                status=CiCheckStatus.IN_PROGRESS,
                conclusion=CiCheckConclusion.UNKNOWN,
                started_at=_now(),
                required=True,
            ),
        )
    )

    report = CiEvidenceValidator(required_checks=("pytest", "ruff")).validate(bundle)

    assert report.passed is False
    assert "wave5.ci_required_check_not_completed" in report.issue_codes
    assert bundle.pending_required_records[0].check_name == "ruff"


def test_wave5_ci_evidence_normalizer_accepts_iso_payloads() -> None:
    payload = {
        "bundle_id": "ci-bundle-1",
        "provider": "github-actions",
        "repository": "BryceWDesign/IX-BlackFox",
        "head_sha": "abc1234",
        "collected_at": "2026-05-16T12:00:00Z",
        "records": [
            {
                "check_name": "pytest",
                "provider": "github-actions",
                "status": "completed",
                "conclusion": "success",
                "started_at": "2026-05-16T11:58:00Z",
                "completed_at": "2026-05-16T12:00:00Z",
                "url": "https://example.test/actions/1",
                "required": True,
                "metadata": {"runner": "ubuntu-latest"},
            }
        ],
    }

    bundle = CiEvidenceNormalizer().from_mapping(payload)

    assert bundle.bundle_id == "ci-bundle-1"
    assert bundle.records[0].passed is True
    assert bundle.records[0].completed_at == datetime(2026, 5, 16, 12, 0, tzinfo=UTC)


def test_wave5_ci_evidence_accepts_realistic_github_check_names() -> None:
    bundle = _bundle(
        records=(
            _record("tests / python-3.11", CiCheckConclusion.SUCCESS),
            _record("lint-and-typecheck", CiCheckConclusion.SUCCESS),
        )
    )

    report = CiEvidenceValidator(
        required_checks=("tests / python-3.11", "lint-and-typecheck")
    ).validate(bundle)

    assert report.passed is True
    assert report.error_count == 0


def test_wave5_ci_evidence_bundle_creates_ci_summary_artifact() -> None:
    bundle = _bundle(records=(_record("pytest", CiCheckConclusion.SUCCESS),))

    artifact = bundle.to_evidence_artifact(uri="artifacts/ci-summary.json")

    assert artifact.kind is EvidenceArtifactKind.CI_SUMMARY
    assert artifact.artifact_id == "ci-summary-ci-bundle-1"
    assert artifact.sha256 is not None
    assert artifact.size_bytes is not None
    assert artifact.head_sha == "abc1234"
    assert artifact.metadata["passed_required_check_count"] == 1


def test_wave5_ci_evidence_rejects_duplicate_check_names() -> None:
    with pytest.raises(ValueError, match="unique check names"):
        _bundle(
            records=(
                _record("pytest", CiCheckConclusion.SUCCESS),
                _record("pytest", CiCheckConclusion.SUCCESS),
            )
        )


def test_wave5_ci_evidence_rejects_naive_datetimes() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        CiEvidenceRecord(
            check_name="pytest",
            provider="github-actions",
            status=CiCheckStatus.COMPLETED,
            conclusion=CiCheckConclusion.SUCCESS,
            started_at=datetime(2026, 5, 16, 12, 0),
            completed_at=_now(),
        )


def _bundle(*, records: tuple[CiEvidenceRecord, ...]) -> CiEvidenceBundle:
    return CiEvidenceBundle(
        bundle_id="ci-bundle-1",
        provider="github-actions",
        repository="BryceWDesign/IX-BlackFox",
        head_sha="abc1234",
        collected_at=_now(),
        records=records,
    )


def _record(check_name: str, conclusion: CiCheckConclusion) -> CiEvidenceRecord:
    return CiEvidenceRecord(
        check_name=check_name,
        provider="github-actions",
        status=CiCheckStatus.COMPLETED,
        conclusion=conclusion,
        started_at=datetime(2026, 5, 16, 11, 58, tzinfo=UTC),
        completed_at=_now(),
        url=f"https://example.test/actions/{check_name}",
        required=True,
    )


def _now() -> datetime:
    return datetime(2026, 5, 16, 12, 0, tzinfo=UTC)
