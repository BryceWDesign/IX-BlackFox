from __future__ import annotations

from datetime import UTC, datetime

from ix_blackfox.sandbox import (
    SandboxAdversarialHarness,
    SandboxAdversarialOutcome,
    SandboxAdversarialReport,
    SandboxAdversarialScenarioKind,
    SandboxAdversarialScenarioResult,
    SandboxEgressGuard,
    SandboxEgressRequest,
    default_wave6_container_profile,
)
from ix_blackfox.workflow import (
    EvidenceArtifact,
    EvidenceArtifactKind,
    PullRequestApproval,
    PullRequestEvidencePack,
    PullRequestEvidencePackValidator,
    PullRequestIdentity,
    ReviewDecision,
    ReviewerKind,
    SandboxAdversarialEvidenceVerifier,
    sandbox_adversarial_report_to_evidence_artifact,
)

_HEAD_SHA = "abc1234"


def test_wave6_adversarial_report_converts_to_pr_evidence_artifact() -> None:
    pull_request = _identity()
    report = _valid_report()

    artifact = sandbox_adversarial_report_to_evidence_artifact(
        pull_request=pull_request,
        adversarial_report=report,
        uri="artifacts/wave6/sandbox-adversarial-report.json",
    )

    assert artifact.kind is EvidenceArtifactKind.SANDBOX_ADVERSARIAL_REPORT
    assert artifact.sha256 == report.digest
    assert artifact.head_sha == pull_request.head_sha
    assert artifact.size_bytes is not None
    assert artifact.metadata["sandbox_adversarial_report_digest"] == report.digest
    assert artifact.metadata["sandbox_adversarial_scenario_count"] == report.scenario_count
    assert artifact.metadata["sandbox_adversarial_passed"] is True


def test_wave6_pr_evidence_validator_can_require_sandbox_adversarial_report_artifact() -> None:
    pack = _pack(artifacts=(*_required_artifacts(), _adversarial_artifact()))

    report = PullRequestEvidencePackValidator(
        require_sandbox_adversarial_report=True
    ).validate(pack)

    assert report.passed is True
    assert report.error_count == 0


def test_wave6_pr_evidence_validator_fails_without_required_sandbox_adversarial_artifact() -> None:
    pack = _pack(artifacts=_required_artifacts())

    report = PullRequestEvidencePackValidator(
        require_sandbox_adversarial_report=True
    ).validate(pack)

    assert report.passed is False
    assert "wave5.required_artifact_missing" in report.issue_codes


def test_wave6_adversarial_evidence_verifier_accepts_required_scenarios() -> None:
    report = SandboxAdversarialEvidenceVerifier().verify(
        pull_request=_identity(),
        adversarial_report=_valid_report(),
    )

    assert report.passed is True
    assert report.error_count == 0
    assert report.issue_codes == ()


def test_wave6_adversarial_evidence_verifier_rejects_failed_report() -> None:
    adversarial_report = SandboxAdversarialReport(
        report_id="wave6-failed-adversarial-report",
        created_at=_now(),
        results=(
            _scenario(
                "scenario-failed",
                SandboxAdversarialScenarioKind.DENY_ALL_EGRESS,
                passed=False,
            ),
        ),
        metadata={"expected_head_sha": _HEAD_SHA, "wave": "6"},
    )

    report = SandboxAdversarialEvidenceVerifier(
        required_scenario_kinds=(SandboxAdversarialScenarioKind.DENY_ALL_EGRESS,)
    ).verify(
        pull_request=_identity(),
        adversarial_report=adversarial_report,
    )

    assert report.passed is False
    assert "wave6.sandbox_adversarial_report_failed" in report.issue_codes


def test_wave6_adversarial_evidence_verifier_rejects_missing_required_scenario() -> None:
    adversarial_report = SandboxAdversarialReport(
        report_id="wave6-incomplete-adversarial-report",
        created_at=_now(),
        results=(
            _scenario(
                "scenario-deny-all-egress",
                SandboxAdversarialScenarioKind.DENY_ALL_EGRESS,
                passed=True,
            ),
        ),
        metadata={"expected_head_sha": _HEAD_SHA, "wave": "6"},
    )

    report = SandboxAdversarialEvidenceVerifier().verify(
        pull_request=_identity(),
        adversarial_report=adversarial_report,
    )

    assert report.passed is False
    assert "wave6.sandbox_adversarial_required_scenario_missing" in report.issue_codes


def test_wave6_adversarial_evidence_verifier_rejects_head_sha_mismatch() -> None:
    adversarial_report = SandboxAdversarialReport(
        report_id="wave6-stale-adversarial-report",
        created_at=_now(),
        results=(
            _scenario(
                "scenario-deny-all-egress",
                SandboxAdversarialScenarioKind.DENY_ALL_EGRESS,
                passed=True,
            ),
        ),
        metadata={"expected_head_sha": "def5678", "wave": "6"},
    )

    report = SandboxAdversarialEvidenceVerifier(
        required_scenario_kinds=(SandboxAdversarialScenarioKind.DENY_ALL_EGRESS,)
    ).verify(
        pull_request=_identity(),
        adversarial_report=adversarial_report,
    )

    assert report.passed is False
    assert "wave6.sandbox_adversarial_head_sha_mismatch" in report.issue_codes


def test_wave6_adversarial_evidence_verifier_checks_pack_artifact_digest_binding() -> None:
    adversarial_report = _valid_report()
    good_artifact = sandbox_adversarial_report_to_evidence_artifact(
        pull_request=_identity(),
        adversarial_report=adversarial_report,
        uri="artifacts/wave6/sandbox-adversarial-report.json",
    )
    bad_artifact = EvidenceArtifact(
        artifact_id=good_artifact.artifact_id,
        kind=good_artifact.kind,
        uri=good_artifact.uri,
        produced_by=good_artifact.produced_by,
        sha256="f" * 64,
        size_bytes=good_artifact.size_bytes,
        head_sha=good_artifact.head_sha,
        metadata=good_artifact.metadata,
    )
    pack = _pack(artifacts=(*_required_artifacts(), bad_artifact))

    report = SandboxAdversarialEvidenceVerifier().verify_pack_adversarial_artifact(
        pack=pack,
        adversarial_report=adversarial_report,
    )

    assert report.passed is False
    assert "wave6.sandbox_adversarial_artifact_digest_mismatch" in report.issue_codes


def _valid_report() -> SandboxAdversarialReport:
    harness = SandboxAdversarialHarness()
    deny_decision = SandboxEgressGuard().evaluate(
        default_wave6_container_profile(),
        SandboxEgressRequest(
            request_id="egress-denied-proof",
            host="pypi.org",
            port=443,
            protocol="https",
            purpose="deny-all evidence",
        ),
    )
    deny_result = harness.expect_egress_denied(
        deny_decision,
        scenario_id="scenario-deny-all-egress",
    )
    return harness.report(
        report_id="wave6-adversarial-report",
        results=(
            deny_result,
            _scenario(
                "scenario-receipt-accepted",
                SandboxAdversarialScenarioKind.RECEIPT_BUNDLE_ACCEPTANCE,
                passed=True,
            ),
            _scenario(
                "scenario-receipt-rejected",
                SandboxAdversarialScenarioKind.RECEIPT_BUNDLE_REJECTION,
                passed=True,
            ),
            _scenario(
                "scenario-path-escape",
                SandboxAdversarialScenarioKind.PATH_ESCAPE_BLOCK,
                passed=True,
            ),
            _scenario(
                "scenario-symlink-block",
                SandboxAdversarialScenarioKind.SYMLINK_BLOCK,
                passed=True,
            ),
        ),
        metadata={"expected_head_sha": _HEAD_SHA, "wave": "6"},
    )


def _scenario(
    scenario_id: str,
    kind: SandboxAdversarialScenarioKind,
    *,
    passed: bool,
) -> SandboxAdversarialScenarioResult:
    return SandboxAdversarialScenarioResult(
        scenario_id=scenario_id,
        kind=kind,
        outcome=SandboxAdversarialOutcome.DEFENSE_PASSED
        if passed
        else SandboxAdversarialOutcome.DEFENSE_FAILED,
        summary=f"{scenario_id} {'passed' if passed else 'failed'}",
        evidence_digest="a" * 64,
        evaluated_at=_now(),
    )


def _pack(*, artifacts: tuple[EvidenceArtifact, ...]) -> PullRequestEvidencePack:
    return PullRequestEvidencePack(
        pack_id="wave6-sandbox-adversarial-pack",
        pull_request=_identity(),
        created_at=_now(),
        summary="Wave 6 sandbox adversarial PR evidence pack.",
        changed_files=("src/ix_blackfox/sandbox/adversarial.py",),
        requested_checks=("pytest",),
        artifacts=artifacts,
        approvals=(_human_approval(),),
    )


def _identity() -> PullRequestIdentity:
    return PullRequestIdentity(
        provider="github",
        repository="BryceWDesign/IX-BlackFox",
        pull_request_id="pr-7",
        base_ref="main",
        head_ref="wave6-sandbox-adversarial",
        head_sha=_HEAD_SHA,
        author="Bryce Lovell",
    )


def _required_artifacts() -> tuple[EvidenceArtifact, ...]:
    return (
        EvidenceArtifact(
            artifact_id="run-bundle",
            kind=EvidenceArtifactKind.RUN_BUNDLE,
            uri="artifacts/run-bundle.json",
            produced_by="blackfox-runtime",
            sha256="1" * 64,
            size_bytes=512,
            head_sha=_HEAD_SHA,
        ),
        EvidenceArtifact(
            artifact_id="test-report",
            kind=EvidenceArtifactKind.TEST_REPORT,
            uri="artifacts/pytest-report.json",
            produced_by="pytest",
            sha256="2" * 64,
            size_bytes=768,
            head_sha=_HEAD_SHA,
        ),
        EvidenceArtifact(
            artifact_id="governance-receipt",
            kind=EvidenceArtifactKind.GOVERNANCE_RECEIPT,
            uri="artifacts/governance-receipts.json",
            produced_by="blackfox-governance",
            sha256="3" * 64,
            size_bytes=384,
            head_sha=_HEAD_SHA,
        ),
        EvidenceArtifact(
            artifact_id="reliability-report",
            kind=EvidenceArtifactKind.RELIABILITY_REPORT,
            uri="artifacts/wave4-reliability-report.json",
            produced_by="blackfox-reliability-lab",
            sha256="4" * 64,
            size_bytes=1024,
            head_sha=_HEAD_SHA,
        ),
    )


def _adversarial_artifact() -> EvidenceArtifact:
    return sandbox_adversarial_report_to_evidence_artifact(
        pull_request=_identity(),
        adversarial_report=_valid_report(),
        uri="artifacts/wave6/sandbox-adversarial-report.json",
    )


def _human_approval() -> PullRequestApproval:
    return PullRequestApproval(
        approval_id="approval-human-maintainer",
        reviewer_id="maintainer-a",
        reviewer_kind=ReviewerKind.HUMAN,
        decision=ReviewDecision.APPROVED,
        decided_at=_now(),
        note="Human maintainer reviewed Wave 6 sandbox adversarial evidence.",
        evidence_refs=(
            "run-bundle",
            "test-report",
            "governance-receipt",
            "reliability-report",
            "sandbox-adversarial-report",
        ),
        roles=("maintainer",),
    )


def _now() -> datetime:
    return datetime(2026, 5, 16, 12, 0, tzinfo=UTC)
