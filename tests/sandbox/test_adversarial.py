from __future__ import annotations

from datetime import UTC, datetime

from ix_blackfox.sandbox import (
    SandboxAdversarialHarness,
    SandboxAdversarialOutcome,
    SandboxAdversarialScenarioKind,
    SandboxArtifactManifest,
    SandboxArtifactRecord,
    SandboxCommandRequest,
    SandboxCommandResult,
    SandboxEgressGuard,
    SandboxEgressRequest,
    SandboxExecutionStatus,
    SandboxNetworkAllowRule,
    SandboxNetworkMode,
    SandboxNetworkPolicy,
    SandboxProfile,
    SandboxReceiptBundle,
    SandboxResourceLimits,
    SandboxRunReceiptBuilder,
    default_wave6_container_profile,
    default_wave6_local_audit_profile,
)

_SHA256_A = "a" * 64
_SHA256_B = "b" * 64
_HEAD_SHA = "abc1234"


def test_wave6_adversarial_harness_passes_when_deny_all_egress_is_denied() -> None:
    request = SandboxEgressRequest(
        request_id="egress-denied",
        host="pypi.org",
        port=443,
        protocol="https",
        purpose="adversarial egress probe",
    )
    decision = SandboxEgressGuard().evaluate(
        default_wave6_container_profile(),
        request,
        decision_id="deny-all-decision",
    )

    result = SandboxAdversarialHarness().expect_egress_denied(
        decision,
        scenario_id="scenario-deny-all-egress",
    )

    assert result.passed is True
    assert result.outcome is SandboxAdversarialOutcome.DEFENSE_PASSED
    assert result.findings == ()
    assert len(result.evidence_digest) == 64


def test_wave6_adversarial_harness_fails_when_egress_is_unexpectedly_allowed() -> None:
    profile = _allowlist_container_profile()
    decision = SandboxEgressGuard().evaluate(
        profile,
        SandboxEgressRequest(
            request_id="egress-allowed",
            host="packages.example.test",
            port=443,
            protocol="tcp",
            purpose="allowed mirror request",
        ),
        decision_id="allowlist-decision",
    )

    result = SandboxAdversarialHarness().expect_egress_denied(
        decision,
        scenario_id="scenario-unexpected-egress-allowance",
    )

    assert result.passed is False
    assert result.outcome is SandboxAdversarialOutcome.DEFENSE_FAILED
    assert result.findings[0].code == "wave6.adversarial.egress_unexpectedly_allowed"


def test_wave6_adversarial_harness_accepts_hardened_container_receipt_bundle() -> None:
    bundle = _valid_container_receipt_bundle()

    result = SandboxAdversarialHarness().expect_receipt_bundle_accepted(
        bundle,
        scenario_id="scenario-valid-container-receipts",
    )

    assert result.passed is True
    assert result.findings == ()
    assert result.metadata["bundle_id"] == bundle.bundle_id


def test_wave6_adversarial_harness_rejects_local_audit_as_hardened_evidence() -> None:
    bundle = _local_audit_receipt_bundle()

    result = SandboxAdversarialHarness(
        require_artifact_manifest_digest=False,
        require_egress_audit_bundle_digest=False,
    ).expect_receipt_bundle_rejected(
        bundle,
        scenario_id="scenario-local-audit-rejected",
    )

    assert result.passed is True
    assert "wave6.adversarial.local_audit_not_hardened" in _codes(result)
    assert "wave6.adversarial.backend_not_allowed" in _codes(result)


def test_wave6_adversarial_harness_rejects_failed_receipt_bundle() -> None:
    bundle = _failed_container_receipt_bundle()

    result = SandboxAdversarialHarness(
        require_artifact_manifest_digest=False,
        require_egress_audit_bundle_digest=False,
    ).expect_receipt_bundle_rejected(
        bundle,
        scenario_id="scenario-failed-receipts-rejected",
    )

    assert result.passed is True
    assert "wave6.adversarial.receipt_bundle_failed" in _codes(result)


def test_wave6_adversarial_harness_rejects_missing_artifact_manifest_digest() -> None:
    bundle = _container_receipt_bundle_missing_manifest()

    result = SandboxAdversarialHarness().expect_receipt_bundle_rejected(
        bundle,
        scenario_id="scenario-missing-artifact-manifest",
    )

    assert result.passed is True
    assert "wave6.adversarial.artifact_manifest_missing" in _codes(result)


def test_wave6_adversarial_harness_rejects_missing_egress_audit_digest() -> None:
    bundle = _container_receipt_bundle_missing_egress_audit()

    result = SandboxAdversarialHarness().expect_receipt_bundle_rejected(
        bundle,
        scenario_id="scenario-missing-egress-audit",
    )

    assert result.passed is True
    assert "wave6.adversarial.egress_audit_missing" in _codes(result)


def test_wave6_adversarial_harness_records_expected_path_escape_exception() -> None:
    result = SandboxAdversarialHarness().expect_exception_blocked(
        ValueError("sandbox_path escapes the staged workspace target"),
        scenario_id="scenario-path-escape",
        kind=SandboxAdversarialScenarioKind.PATH_ESCAPE_BLOCK,
        required_message_fragments=("escapes", "workspace"),
    )

    assert result.passed is True
    assert result.findings == ()


def test_wave6_adversarial_harness_fails_when_expected_exception_is_missing() -> None:
    result = SandboxAdversarialHarness().expect_exception_blocked(
        None,
        scenario_id="scenario-missing-symlink-block",
        kind=SandboxAdversarialScenarioKind.SYMLINK_BLOCK,
        required_message_fragments=("symlink",),
    )

    assert result.passed is False
    assert result.findings[0].code == "wave6.adversarial.expected_exception_missing"


def test_wave6_adversarial_report_summarizes_results_and_has_stable_digest() -> None:
    harness = SandboxAdversarialHarness()
    decision = SandboxEgressGuard().evaluate(
        default_wave6_container_profile(),
        SandboxEgressRequest(
            request_id="egress-denied",
            host="pypi.org",
            port=443,
            protocol="https",
        ),
    )
    result = harness.expect_egress_denied(
        decision,
        scenario_id="scenario-deny-all-egress",
    )

    report = harness.report(
        report_id="wave6-adversarial-report",
        results=(result,),
        metadata={"wave": "6"},
    )

    assert report.passed is True
    assert report.scenario_count == 1
    assert report.passed_count == 1
    assert report.failed_count == 0
    assert len(report.digest) == 64
    assert report.to_dict()["digest"] == report.digest


def _valid_container_receipt_bundle() -> SandboxReceiptBundle:
    request = _container_request()
    manifest = _manifest(request)
    egress_bundle = _egress_bundle(request)
    result = _container_result(request, artifact_manifest_sha256=manifest.digest)
    receipt = SandboxRunReceiptBuilder().build(
        request=request,
        result=result,
        artifact_manifest=manifest,
        egress_audit_bundle=egress_bundle,
        receipt_id="receipt-valid-container",
    )
    return SandboxReceiptBundle(
        bundle_id="bundle-valid-container",
        created_at=_now(),
        expected_head_sha=_HEAD_SHA,
        receipts=(receipt,),
    )


def _local_audit_receipt_bundle() -> SandboxReceiptBundle:
    request = SandboxCommandRequest(
        request_id="local-audit-request",
        profile=default_wave6_local_audit_profile(),
        argv=("python", "-c", "print('local audit')"),
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
    return SandboxReceiptBundle(
        bundle_id="bundle-local-audit",
        created_at=_now(),
        expected_head_sha=_HEAD_SHA,
        receipts=(receipt,),
    )


def _failed_container_receipt_bundle() -> SandboxReceiptBundle:
    request = _container_request()
    result = SandboxCommandResult(
        request_id=request.request_id,
        status=SandboxExecutionStatus.FAILED,
        exit_code=1,
        duration_ms=10,
        stdout_sha256=_SHA256_A,
        stderr_sha256=_SHA256_B,
    )
    receipt = SandboxRunReceiptBuilder().build(
        request=request,
        result=result,
        receipt_id="receipt-failed-container",
    )
    return SandboxReceiptBundle(
        bundle_id="bundle-failed-container",
        created_at=_now(),
        expected_head_sha=_HEAD_SHA,
        receipts=(receipt,),
    )


def _container_receipt_bundle_missing_manifest() -> SandboxReceiptBundle:
    request = _container_request()
    egress_bundle = _egress_bundle(request)
    result = _container_result(request, artifact_manifest_sha256=None)
    receipt = SandboxRunReceiptBuilder().build(
        request=request,
        result=result,
        egress_audit_bundle=egress_bundle,
        receipt_id="receipt-missing-manifest",
    )
    return SandboxReceiptBundle(
        bundle_id="bundle-missing-manifest",
        created_at=_now(),
        expected_head_sha=_HEAD_SHA,
        receipts=(receipt,),
    )


def _container_receipt_bundle_missing_egress_audit() -> SandboxReceiptBundle:
    request = _container_request()
    manifest = _manifest(request)
    result = _container_result(request, artifact_manifest_sha256=manifest.digest)
    receipt = SandboxRunReceiptBuilder().build(
        request=request,
        result=result,
        artifact_manifest=manifest,
        receipt_id="receipt-missing-egress",
    )
    return SandboxReceiptBundle(
        bundle_id="bundle-missing-egress",
        created_at=_now(),
        expected_head_sha=_HEAD_SHA,
        receipts=(receipt,),
    )


def _container_request() -> SandboxCommandRequest:
    return SandboxCommandRequest(
        request_id="container-request",
        profile=default_wave6_container_profile(container_image="python:3.11-slim"),
        argv=("python", "-c", "print('adversarial')"),
        expected_head_sha=_HEAD_SHA,
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
        workspace_id="workspace-adversarial",
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
                request_id="egress-denied-proof",
                host="pypi.org",
                port=443,
                protocol="https",
                purpose="adversarial deny-all evidence",
            ),
        ),
        bundle_id="egress-bundle-adversarial",
    )


def _allowlist_container_profile() -> SandboxProfile:
    base = default_wave6_container_profile()
    return SandboxProfile(
        profile_id="wave6.container.allowlist.adversarial",
        backend=base.backend,
        filesystem=base.filesystem,
        resources=SandboxResourceLimits(
            timeout_seconds=30,
            max_memory_mb=256,
            max_processes=16,
            max_output_bytes=65_536,
            max_artifact_bytes=1_048_576,
        ),
        network=SandboxNetworkPolicy(
            mode=SandboxNetworkMode.ALLOWLIST,
            allowlist=(SandboxNetworkAllowRule(host="packages.example.test", port=443),),
        ),
        environment=base.environment,
        allowed_commands=base.allowed_commands,
        metadata=base.metadata,
    )


def _codes(result: object) -> tuple[str, ...]:
    return tuple(finding.code for finding in result.findings)


def _now() -> datetime:
    return datetime(2026, 5, 16, 12, 0, tzinfo=UTC)
