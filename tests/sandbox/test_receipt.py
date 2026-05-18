from __future__ import annotations

from datetime import UTC, datetime

import pytest

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
)

_SHA256_A = "a" * 64
_SHA256_B = "b" * 64
_SHA256_C = "c" * 64


def test_wave6_receipt_builder_binds_request_result_profile_network_and_manifest() -> None:
    request = _request()
    manifest = _manifest(request)
    result = _result(request, artifact_manifest_sha256=manifest.digest)

    receipt = SandboxRunReceiptBuilder().build(
        request=request,
        result=result,
        artifact_manifest=manifest,
        receipt_id="receipt-container-success",
    )

    payload = receipt.to_dict()

    assert receipt.passed is True
    assert receipt.request_id == request.request_id
    assert receipt.profile_digest == request.profile.digest
    assert receipt.request_digest == request.digest
    assert receipt.artifact_manifest_digest == manifest.digest
    assert receipt.command_result_digest is not None
    assert receipt.network_policy_digest is not None
    assert receipt.expected_head_sha == "abc1234"
    assert len(receipt.digest) == 64
    assert payload["digest"] == receipt.digest
    assert payload["backend"] == "container"


def test_wave6_receipt_builder_binds_egress_audit_bundle_digest() -> None:
    request = _request()
    result = _result(request)
    egress_bundle = SandboxEgressGuard().audit_bundle(
        request.profile,
        (
            SandboxEgressRequest(
                request_id="egress-denied",
                host="pypi.org",
                port=443,
                protocol="https",
                purpose="prove deny-all egress was evaluated",
            ),
        ),
        bundle_id="egress-bundle-1",
    )

    receipt = SandboxRunReceiptBuilder().build(
        request=request,
        result=result,
        egress_audit_bundle=egress_bundle,
    )

    assert receipt.egress_audit_bundle_digest == egress_bundle.digest
    assert receipt.network_policy_digest == egress_bundle.network_policy_digest
    assert receipt.to_dict()["egress_audit_bundle_digest"] == egress_bundle.digest


def test_wave6_receipt_builder_rejects_result_request_mismatch() -> None:
    request = _request()
    result = SandboxCommandResult(
        request_id="different-request",
        status=SandboxExecutionStatus.SUCCEEDED,
        exit_code=0,
        duration_ms=10,
        stdout_sha256=_SHA256_A,
        stderr_sha256=_SHA256_B,
    )

    with pytest.raises(ValueError, match="request_id"):
        SandboxRunReceiptBuilder().build(request=request, result=result)


def test_wave6_receipt_builder_rejects_manifest_digest_mismatch() -> None:
    request = _request()
    manifest = _manifest(request)
    result = _result(request, artifact_manifest_sha256=_SHA256_C)

    with pytest.raises(ValueError, match="artifact_manifest_sha256"):
        SandboxRunReceiptBuilder().build(
            request=request,
            result=result,
            artifact_manifest=manifest,
        )


def test_wave6_receipt_builder_rejects_manifest_profile_mismatch() -> None:
    request = _request()
    manifest = SandboxArtifactManifest(
        workspace_id="workspace-1",
        profile_id="wrong-profile",
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
    result = _result(request, artifact_manifest_sha256=manifest.digest)

    with pytest.raises(ValueError, match="profile_id"):
        SandboxRunReceiptBuilder().build(
            request=request,
            result=result,
            artifact_manifest=manifest,
        )


def test_wave6_receipt_bundle_summarizes_pass_fail_and_has_stable_digest() -> None:
    request = _request()
    passed_receipt = SandboxRunReceiptBuilder().build(
        request=request,
        result=_result(request),
        receipt_id="receipt-passed",
    )
    failed_receipt = SandboxRunReceiptBuilder().build(
        request=request,
        result=SandboxCommandResult(
            request_id=request.request_id,
            status=SandboxExecutionStatus.FAILED,
            exit_code=1,
            duration_ms=11,
            stdout_sha256=_SHA256_A,
            stderr_sha256=_SHA256_B,
        ),
        receipt_id="receipt-failed",
    )

    bundle = SandboxReceiptBundle(
        bundle_id="receipt-bundle-1",
        created_at=_now(),
        expected_head_sha="abc1234",
        receipts=(passed_receipt, failed_receipt),
        metadata={"wave": "6"},
    )

    assert bundle.passed is False
    assert bundle.receipt_count == 2
    assert bundle.passed_count == 1
    assert bundle.failed_count == 1
    assert len(bundle.digest) == 64
    assert bundle.digest == SandboxReceiptBundle(
        bundle_id="receipt-bundle-1",
        created_at=_now(),
        expected_head_sha="abc1234",
        receipts=(failed_receipt, passed_receipt),
        metadata={"wave": "6"},
    ).digest


def test_wave6_receipt_bundle_rejects_duplicate_receipt_ids() -> None:
    request = _request()
    receipt = SandboxRunReceiptBuilder().build(
        request=request,
        result=_result(request),
        receipt_id="receipt-duplicate",
    )

    with pytest.raises(ValueError, match="duplicate"):
        SandboxReceiptBundle(
            bundle_id="receipt-bundle-duplicate",
            created_at=_now(),
            receipts=(receipt, receipt),
        )


def test_wave6_receipt_bundle_rejects_head_sha_mismatch() -> None:
    request = _request()
    receipt = SandboxRunReceiptBuilder().build(
        request=request,
        result=_result(request),
        receipt_id="receipt-head-bound",
    )

    with pytest.raises(ValueError, match="expected_head_sha"):
        SandboxReceiptBundle(
            bundle_id="receipt-bundle-head-mismatch",
            created_at=_now(),
            expected_head_sha="def5678",
            receipts=(receipt,),
        )


def _request() -> SandboxCommandRequest:
    return SandboxCommandRequest(
        request_id="container-request-1",
        profile=default_wave6_container_profile(container_image="python:3.11-slim"),
        argv=("python", "-c", "print('receipt')"),
        expected_head_sha="abc1234",
    )


def _result(
    request: SandboxCommandRequest,
    *,
    artifact_manifest_sha256: str | None = None,
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


def _now() -> datetime:
    return datetime(2026, 5, 16, 12, 0, tzinfo=UTC)
