from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ix_blackfox.sandbox import (
    SandboxAdversarialHarness,
    SandboxAdversarialReport,
    SandboxAdversarialScenarioKind,
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
    PullRequestIdentity,
    SandboxAdversarialEvidenceVerifier,
    sandbox_adversarial_report_to_evidence_artifact,
)

_DEFAULT_OUTPUT = Path(".blackfox-artifacts/wave6/wave6-sandbox-ci-report.json")


def build_wave6_ci_report(*, head_sha: str) -> SandboxAdversarialReport:
    harness = SandboxAdversarialHarness()
    deny_decision = SandboxEgressGuard().evaluate(
        default_wave6_container_profile(),
        SandboxEgressRequest(
            request_id="ci-egress-denied-proof",
            host="pypi.org",
            port=443,
            protocol="https",
            purpose="CI adversarial proof that default Wave 6 sandbox policy denies direct egress.",
        ),
        decision_id="ci-deny-all-egress-decision",
    )
    deny_result = harness.expect_egress_denied(
        deny_decision,
        scenario_id="ci-scenario-deny-all-egress",
    )
    receipt_acceptance = harness.expect_receipt_bundle_accepted(
        _valid_container_receipt_bundle(head_sha=head_sha),
        scenario_id="ci-scenario-container-receipts-accepted",
    )
    receipt_rejection = harness.expect_receipt_bundle_rejected(
        _local_audit_receipt_bundle(head_sha=head_sha),
        scenario_id="ci-scenario-local-audit-receipts-rejected",
    )
    path_escape = harness.expect_exception_blocked(
        ValueError("sandbox_path escapes the staged workspace target"),
        scenario_id="ci-scenario-path-escape-blocked",
        kind=SandboxAdversarialScenarioKind.PATH_ESCAPE_BLOCK,
        required_message_fragments=("escapes", "workspace"),
    )
    symlink_block = harness.expect_exception_blocked(
        ValueError("artifact collection refuses symlinked outputs"),
        scenario_id="ci-scenario-symlink-output-blocked",
        kind=SandboxAdversarialScenarioKind.SYMLINK_BLOCK,
        required_message_fragments=("symlink", "outputs"),
    )
    policy_exception = harness.expect_exception_blocked(
        ValueError("combined stdout and stderr exceeded max_output_bytes"),
        scenario_id="ci-scenario-output-policy-blocked",
        kind=SandboxAdversarialScenarioKind.POLICY_EXCEPTION_BLOCK,
        required_message_fragments=("max_output_bytes",),
    )
    return harness.report(
        report_id="wave6-sandbox-ci-adversarial-report",
        results=(
            deny_result,
            receipt_acceptance,
            receipt_rejection,
            path_escape,
            symlink_block,
            policy_exception,
        ),
        metadata={
            "wave": "6",
            "expected_head_sha": head_sha,
            "claim": "ci-unit-evidence-not-production-certification",
        },
    )


def build_ci_payload(*, head_sha: str) -> dict[str, Any]:
    pull_request = _pull_request_identity(head_sha=head_sha)
    adversarial_report = build_wave6_ci_report(head_sha=head_sha)
    adversarial_verification = SandboxAdversarialEvidenceVerifier().verify(
        pull_request=pull_request,
        adversarial_report=adversarial_report,
        pack_id="wave6-sandbox-ci-adversarial-verification",
    )
    adversarial_artifact = sandbox_adversarial_report_to_evidence_artifact(
        pull_request=pull_request,
        adversarial_report=adversarial_report,
        uri="artifacts/wave6/sandbox-adversarial-report.json",
        artifact_id="sandbox-adversarial-report",
        produced_by="blackfox-wave6-ci",
    )
    return {
        "generated_at": datetime.now(tz=UTC).isoformat(),
        "wave": "6",
        "head_sha": head_sha,
        "passed": adversarial_report.passed and adversarial_verification.passed,
        "adversarial_report": adversarial_report.to_dict(),
        "adversarial_verification": adversarial_verification.to_dict(),
        "adversarial_artifact": adversarial_artifact.to_dict(),
        "scope_note": (
            "This CI payload verifies Wave 6 sandbox contracts, egress evidence, "
            "receipt evidence, and adversarial unit scenarios. It is not a production "
            "security certification."
        ),
    }


def write_ci_payload(*, head_sha: str, output_path: Path) -> dict[str, Any]:
    payload = build_ci_payload(head_sha=head_sha)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate Wave 6 sandbox CI evidence for IX-BlackFox."
    )
    parser.add_argument(
        "--head-sha",
        required=True,
        help="The commit SHA that the Wave 6 CI evidence is bound to.",
    )
    parser.add_argument(
        "--output",
        default=str(_DEFAULT_OUTPUT),
        help="Path to write the Wave 6 sandbox CI evidence JSON payload.",
    )
    args = parser.parse_args(argv)

    payload = write_ci_payload(
        head_sha=args.head_sha,
        output_path=Path(args.output),
    )
    print(f"Wave 6 sandbox CI evidence written to {args.output}")
    print(f"Passed: {payload['passed']}")
    return 0 if payload["passed"] else 1


def _valid_container_receipt_bundle(*, head_sha: str) -> SandboxReceiptBundle:
    request = _container_request(head_sha=head_sha)
    manifest = _manifest(request)
    egress_bundle = _egress_bundle(request)
    result = _container_result(request, artifact_manifest_sha256=manifest.digest)
    receipt = SandboxRunReceiptBuilder().build(
        request=request,
        result=result,
        artifact_manifest=manifest,
        egress_audit_bundle=egress_bundle,
        receipt_id="ci-receipt-container-valid",
    )
    return SandboxReceiptBundle(
        bundle_id="ci-receipt-bundle-container-valid",
        created_at=_now(),
        expected_head_sha=head_sha,
        receipts=(receipt,),
        metadata={"wave": "6", "ci": "true"},
    )


def _local_audit_receipt_bundle(*, head_sha: str) -> SandboxReceiptBundle:
    request = SandboxCommandRequest(
        request_id="ci-local-audit-request",
        profile=default_wave6_local_audit_profile(),
        argv=("python", "-c", "print('local audit is not hardened evidence')"),
        expected_head_sha=head_sha,
    )
    result = SandboxCommandResult(
        request_id=request.request_id,
        status=SandboxExecutionStatus.SUCCEEDED,
        exit_code=0,
        duration_ms=10,
        stdout_sha256="a" * 64,
        stderr_sha256="b" * 64,
    )
    receipt = SandboxRunReceiptBuilder().build(
        request=request,
        result=result,
        receipt_id="ci-receipt-local-audit-rejected",
    )
    return SandboxReceiptBundle(
        bundle_id="ci-receipt-bundle-local-audit-rejected",
        created_at=_now(),
        expected_head_sha=head_sha,
        receipts=(receipt,),
        metadata={"wave": "6", "ci": "true"},
    )


def _container_request(*, head_sha: str) -> SandboxCommandRequest:
    return SandboxCommandRequest(
        request_id="ci-container-request",
        profile=default_wave6_container_profile(container_image="python:3.11-slim"),
        argv=("python", "-c", "print('wave6 ci sandbox evidence')"),
        expected_head_sha=head_sha,
        metadata={"ci": "true"},
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
        stdout_sha256="a" * 64,
        stderr_sha256="b" * 64,
        artifact_manifest_sha256=artifact_manifest_sha256,
    )


def _manifest(request: SandboxCommandRequest) -> SandboxArtifactManifest:
    return SandboxArtifactManifest(
        workspace_id="ci-workspace",
        profile_id=request.profile.profile_id,
        profile_digest=request.profile.digest,
        collected_at=_now(),
        sandbox_path="/workspace/out",
        artifacts=(
            SandboxArtifactRecord(
                path="summary.txt",
                sha256="a" * 64,
                size_bytes=12,
            ),
        ),
    )


def _egress_bundle(request: SandboxCommandRequest) -> object:
    return SandboxEgressGuard().audit_bundle(
        request.profile,
        (
            SandboxEgressRequest(
                request_id="ci-egress-deny-proof",
                host="pypi.org",
                port=443,
                protocol="https",
                purpose="CI deny-all egress proof for Wave 6 sandbox evidence.",
            ),
        ),
        bundle_id="ci-egress-audit-bundle",
    )


def _pull_request_identity(*, head_sha: str) -> PullRequestIdentity:
    return PullRequestIdentity(
        provider="github",
        repository="BryceWDesign/IX-BlackFox",
        pull_request_id="ci",
        base_ref="main",
        head_ref="wave6-sandbox-ci",
        head_sha=head_sha,
        author="Bryce Lovell",
    )


def _now() -> datetime:
    return datetime.now(tz=UTC)


if __name__ == "__main__":
    sys.exit(main())
