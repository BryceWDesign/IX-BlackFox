from __future__ import annotations

from datetime import UTC, datetime

from ix_blackfox.sandbox import (
    SandboxArtifactManifest,
    SandboxArtifactRecord,
    SandboxCommandRequest,
    SandboxCommandResult,
    SandboxEgressGuard,
    SandboxEgressRequest,
    SandboxExecutionStatus,
    SandboxReceiptBundle,
    SandboxRunReceiptBuilder,
    default_wave6_container_profile,
    default_wave6_local_audit_profile,
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
    SandboxReceiptEvidenceVerifier,
    sandbox_receipt_bundle_to_evidence_artifact,
)

_SHA256_A = "a" * 64
_SHA256_B = "b" * 64
_HEAD_SHA = "abc1234"


def test_wave6_sandbox_receipt_bundle_converts_to_pr_evidence_artifact() -> None:
    pull_request = _identity()
    bundle = _valid_receipt_bundle()

    artifact = sandbox_receipt_bundle_to_evidence_artifact(
        pull_request=pull_request,
        receipt_bundle=bundle,
        uri="artifacts/wave6/sandbox-receipts.json",
    )

    assert artifact.kind is EvidenceArtifactKind.SANDBOX_RECEIPT_BUNDLE
    assert artifact.sha256 == bundle.digest
    assert artifact.head_sha == pull_request.head_sha
    assert artifact.size_bytes is not None
    assert artifact.metadata["sandbox_receipt_bundle_digest"] == bundle.digest
    assert artifact.metadata["sandbox_receipt_count"] == 1
    assert artifact.metadata["sandbox_passed"] is True


def test_wave6_pr_evidence_validator_can_require_sandbox_receipt_artifact() -> None:
    pack = _pack(artifacts=(*_required_artifacts(), _sandbox_receipt_artifact()))

    report = PullRequestEvidencePackValidator(
        require_sandbox_receipt_bundle=True
    ).validate(pack)

    assert report.passed is True
    assert report.error_count == 0


def test_wave6_pr_evidence_validator_fails_without_required_sandbox_receipt_artifact() -> None:
    pack = _pack(artifacts=_required_artifacts())

    report = PullRequestEvidencePackValidator(
        require_sandbox_receipt_bundle=True
    ).validate(pack)

    assert report.passed is False
    assert "wave5.required_artifact_missing" in report.issue_codes


def test_wave6_sandbox_receipt_verifier_accepts_container_receipts_with_manifest_and_egress() -> None:
    report = SandboxReceiptEvidenceVerifier().verify(
        pull_request=_identity(),
        receipt_bundle=_valid_receipt_bundle(),
    )

    assert report.passed is True
    assert report.error_count == 0
    assert report.issue_codes == ()


def test_wave6_sandbox_receipt_verifier_rejects_local_audit_as_hardened_evidence() -> None:
    request = SandboxCommandRequest(
        request_id="local-audit-request",
        profile=default_wave6_local_audit_profile(),
        argv=("python", "-c", "print('local')"),
        expected_head_sha=_HEAD_SHA,
    )
    result = SandboxCommandResult(
        request_id=request.request_id,
        status=SandboxExecutionStatus.SUCCEEDED,
        exit_code=0,
        duration_ms=10,
        stdout_sha256=_SHA256_A,
        stderr_sha256=_SHA256_B,
    )
    receipt = SandboxRunReceiptBuilder().build(
        request=request,
        result=result,
        receipt_id="receipt-local-audit",
    )
    bundle = SandboxReceiptBundle(
        bundle_id="local-audit-bundle",
        created_at=_now(),
        expected_head_sha=_HEAD_SHA,
        receipts=(receipt,),
    )

    report = SandboxReceiptEvidenceVerifier(
        require_artifact_manifest_digest=False,
        require_egress_audit_bundle_digest=False,
    ).verify(
        pull_request=_identity(),
        receipt_bundle=bundle,
    )

    assert report.passed is False
    assert "wave6.sandbox_receipt_local_audit_not_hardened" in report.issue_codes
    assert "wave6.sandbox_receipt_backend_not_allowed" in report.issue_codes


def test_wave6_sandbox_receipt_verifier_rejects_head_sha_mismatch() -> None:
    bundle = SandboxReceiptBundle(
        bundle_id="stale-bundle",
        created_at=_now(),
        expected_head_sha="def5678",
        receipts=(_valid_receipt(expected_head_sha="def5678"),),
    )

    report = SandboxReceiptEvidenceVerifier().verify(
        pull_request=_identity(),
        receipt_bundle=bundle,
    )

    assert report.passed is False
    assert "wave6.sandbox_receipt_head_sha_mismatch" in report.issue_codes
    assert "wave6.sandbox_receipt_item_head_sha_mismatch" in report.issue_codes


def test_wave6_sandbox_receipt_verifier_rejects_missing_manifest_digest_when_required() -> None:
    request = _container_request()
    egress_bundle = _egress_bundle(request)
    result = _container_result(request, artifact_manifest_sha256=None)
    receipt = SandboxRunReceiptBuilder().build(
        request=request,
        result=result,
        egress_audit_bundle=egress_bundle,
        receipt_id="receipt-no-manifest",
    )
    bundle = SandboxReceiptBundle(
        bundle_id="bundle-no-manifest",
        created_at=_now(),
        expected_head_sha=_HEAD_SHA,
        receipts=(receipt,),
    )

    report = SandboxReceiptEvidenceVerifier().verify(
        pull_request=_identity(),
        receipt_bundle=bundle,
    )

    assert report.passed is False
    assert "wave6.sandbox_receipt_artifact_manifest_missing" in report.issue_codes


def test_wave6_sandbox_receipt_verifier_rejects_missing_egress_audit_when_required() -> None:
    request = _container_request()
    manifest = _manifest(request)
    result = _container_result(request, artifact_manifest_sha256=manifest.digest)
    receipt = SandboxRunReceiptBuilder().build(
        request=request,
        result=result,
        artifact_manifest=manifest,
        receipt_id="receipt-no-egress",
    )
    bundle = SandboxReceiptBundle(
        bundle_id="bundle-no-egress",
        created_at=_now(),
        expected_head_sha=_HEAD_SHA,
        receipts=(receipt,),
    )

    report = SandboxReceiptEvidenceVerifier().verify(
        pull_request=_identity(),
        receipt_bundle=bundle,
    )

    assert report.passed is False
    assert "wave6.sandbox_receipt_egress_audit_missing" in report.issue_codes


def test_wave6_sandbox_receipt_verifier_checks_pack_artifact_digest_binding() -> None:
    bundle = _valid_receipt_bundle()
    good_artifact = sandbox_receipt_bundle_to_evidence_artifact(
        pull_request=_identity(),
        receipt_bundle=bundle,
        uri="artifacts/wave6/sandbox-receipts.json",
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

    report = SandboxReceiptEvidenceVerifier().verify_pack_receipt_artifact(
        pack=pack,
        receipt_bundle=bundle,
    )

    assert report.passed is False
    assert "wave6.sandbox_receipt_artifact_digest_mismatch" in report.issue_codes


def _valid_receipt_bundle() -> SandboxReceiptBundle:
    receipt = _valid_receipt(expected_head_sha=_HEAD_SHA)
    return SandboxReceiptBundle(
        bundle_id="sandbox-receipt-bundle-1",
        created_at=_now(),
        expected_head_sha=_HEAD_SHA,
        receipts=(receipt,),
        metadata={"wave": "6"},
    )


def _valid_receipt(*, expected_head_sha: str) -> object:
    request = _container_request(expected_head_sha=expected_head_sha)
    manifest = _manifest(request)
    egress_bundle = _egress_bundle(request)
    result = _container_result(request, artifact_manifest_sha256=manifest.digest)
    return SandboxRunReceiptBuilder().build(
        request=request,
        result=result,
        artifact_manifest=manifest,
        egress_audit_bundle=egress_bundle,
        receipt_id=f"receipt-{expected_head_sha}",
    )


def _container_request(*, expected_head_sha: str = _HEAD_SHA) -> SandboxCommandRequest:
    return SandboxCommandRequest(
        request_id=f"container-request-{expected_head_sha}",
        profile=default_wave6_container_profile(container_image="python:3.11-slim"),
        argv=("python", "-c", "print('sandbox receipt evidence')"),
        expected_head_sha=expected_head_sha,
    )


def _container_result(
    request: SandboxCommandRequest,
    *,
    artifact_manifest_sha256: str | None,
) -> SandboxCommandResult:
    return SandboxCommandResult(
        request_id=request.request_id,
        status=SandboxExecutionStatus.SUCCEEDED,
        exit_code=0,
        duration_ms=10,
        stdout_sha256=_SHA256_A,
        stderr_sha256=_SHA256_B,
        artifact_manifest_sha256=artifact_manifest_sha256,
    )


def _manifest(request: SandboxCommandRequest) -> SandboxArtifactManifest:
    return SandboxArtifactManifest(
        workspace_id="workspace-1",
        profile_id=request.profile.profile_id,
        profile_digest=request.profile.digest,
        collected_at=_now(),
        sandbox_path="/workspace/out",
        artifacts=(
            SandboxArtifactRecord(
                path="summary.txt",
                sha256=_SHA256_A,
                size_bytes=12,
            ),
        ),
    )


def _egress_bundle(request: SandboxCommandRequest) -> object:
    return SandboxEgressGuard().audit_bundle(
        request.profile,
        (
            SandboxEgressRequest(
                request_id="egress-deny-proof",
                host="pypi.org",
                port=443,
                protocol="https",
                purpose="prove deny-all egress decision is bound into receipt evidence",
            ),
        ),
        bundle_id=f"egress-bundle-{request.request_id}",
    )


def _pack(*, artifacts: tuple[EvidenceArtifact, ...]) -> PullRequestEvidencePack:
    return PullRequestEvidencePack(
        pack_id="wave6-sandbox-receipt-pack",
        pull_request=_identity(),
        created_at=_now(),
        summary="Wave 6 sandbox receipt PR evidence pack.",
        changed_files=("src/ix_blackfox/sandbox/receipt.py",),
        requested_checks=("pytest",),
        artifacts=artifacts,
        approvals=(_human_approval(),),
    )


def _identity() -> PullRequestIdentity:
    return PullRequestIdentity(
        provider="github",
        repository="BryceWDesign/IX-BlackFox",
        pull_request_id="pr-6",
        base_ref="main",
        head_ref="wave6-sandbox-receipts",
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


def _sandbox_receipt_artifact() -> EvidenceArtifact:
    return sandbox_receipt_bundle_to_evidence_artifact(
        pull_request=_identity(),
        receipt_bundle=_valid_receipt_bundle(),
        uri="artifacts/wave6/sandbox-receipts.json",
    )


def _human_approval() -> PullRequestApproval:
    return PullRequestApproval(
        approval_id="approval-human-maintainer",
        reviewer_id="maintainer-a",
        reviewer_kind=ReviewerKind.HUMAN,
        decision=ReviewDecision.APPROVED,
        decided_at=_now(),
        note="Human maintainer reviewed Wave 6 sandbox receipt evidence.",
        evidence_refs=(
            "run-bundle",
            "test-report",
            "governance-receipt",
            "reliability-report",
            "sandbox-receipt-bundle",
        ),
        roles=("maintainer",),
    )


def _now() -> datetime:
    return datetime(2026, 5, 16, 12, 0, tzinfo=UTC)
