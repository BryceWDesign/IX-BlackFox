from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime

from ix_blackfox.sandbox import (
    SandboxBackendKind,
    SandboxReceiptBundle,
)
from ix_blackfox.workflow.pr_evidence_pack import (
    EvidenceArtifact,
    EvidenceArtifactKind,
    PullRequestEvidencePack,
    PullRequestIdentity,
    Wave5ValidationIssue,
    Wave5ValidationReport,
    Wave5ValidationSeverity,
)


@dataclass(frozen=True, slots=True)
class SandboxReceiptEvidenceVerifier:
    allowed_backends: tuple[SandboxBackendKind, ...] = (
        SandboxBackendKind.CONTAINER,
        SandboxBackendKind.GVISOR,
        SandboxBackendKind.FIRECRACKER,
    )
    require_artifact_manifest_digest: bool = True
    require_egress_audit_bundle_digest: bool = True

    def verify(
        self,
        *,
        pull_request: PullRequestIdentity,
        receipt_bundle: SandboxReceiptBundle,
        pack_id: str = "wave6-sandbox-receipt-verification",
    ) -> Wave5ValidationReport:
        issues: list[Wave5ValidationIssue] = []
        if not receipt_bundle.receipts:
            issues.append(
                _error(
                    "wave6.sandbox_receipt_bundle_empty",
                    "Sandbox receipt bundle must contain at least one receipt.",
                    "sandbox_receipts.receipts",
                )
            )
        if not receipt_bundle.passed:
            issues.append(
                _error(
                    "wave6.sandbox_receipt_bundle_failed",
                    "Sandbox receipt bundle contains one or more failed receipts.",
                    "sandbox_receipts.passed",
                )
            )
        if receipt_bundle.expected_head_sha is None:
            issues.append(
                _error(
                    "wave6.sandbox_receipt_head_sha_missing",
                    "Sandbox receipt bundle must declare the PR head SHA it was produced for.",
                    "sandbox_receipts.expected_head_sha",
                )
            )
        elif receipt_bundle.expected_head_sha != pull_request.head_sha:
            issues.append(
                _error(
                    "wave6.sandbox_receipt_head_sha_mismatch",
                    f"Sandbox receipt bundle was produced for head SHA '{receipt_bundle.expected_head_sha}', not PR head SHA '{pull_request.head_sha}'.",
                    "sandbox_receipts.expected_head_sha",
                )
            )

        allowed_backend_values = {backend.value for backend in self.allowed_backends}
        for receipt in receipt_bundle.receipts:
            if receipt.backend is SandboxBackendKind.LOCAL_AUDIT:
                issues.append(
                    _error(
                        "wave6.sandbox_receipt_local_audit_not_hardened",
                        f"Receipt '{receipt.receipt_id}' uses local_audit, which is not hardened Wave 6 isolation evidence.",
                        f"sandbox_receipts.{receipt.receipt_id}.backend",
                    )
                )
            if receipt.backend not in self.allowed_backends:
                issues.append(
                    _error(
                        "wave6.sandbox_receipt_backend_not_allowed",
                        f"Receipt '{receipt.receipt_id}' backend '{receipt.backend.value}' is not in the allowed hardened backend set: {sorted(allowed_backend_values)}.",
                        f"sandbox_receipts.{receipt.receipt_id}.backend",
                    )
                )
            if receipt.expected_head_sha != pull_request.head_sha:
                issues.append(
                    _error(
                        "wave6.sandbox_receipt_item_head_sha_mismatch",
                        f"Receipt '{receipt.receipt_id}' head SHA does not match the PR head SHA.",
                        f"sandbox_receipts.{receipt.receipt_id}.expected_head_sha",
                    )
                )
            if self.require_artifact_manifest_digest and receipt.artifact_manifest_digest is None:
                issues.append(
                    _error(
                        "wave6.sandbox_receipt_artifact_manifest_missing",
                        f"Receipt '{receipt.receipt_id}' does not bind an artifact manifest digest.",
                        f"sandbox_receipts.{receipt.receipt_id}.artifact_manifest_digest",
                    )
                )
            if self.require_egress_audit_bundle_digest and receipt.egress_audit_bundle_digest is None:
                issues.append(
                    _error(
                        "wave6.sandbox_receipt_egress_audit_missing",
                        f"Receipt '{receipt.receipt_id}' does not bind an egress audit bundle digest.",
                        f"sandbox_receipts.{receipt.receipt_id}.egress_audit_bundle_digest",
                    )
                )
        return Wave5ValidationReport(
            pack_id=pack_id,
            validated_at=datetime.now(tz=UTC),
            issues=tuple(issues),
        )

    def verify_pack_receipt_artifact(
        self,
        *,
        pack: PullRequestEvidencePack,
        receipt_bundle: SandboxReceiptBundle,
    ) -> Wave5ValidationReport:
        issues = list(
            self.verify(
                pull_request=pack.pull_request,
                receipt_bundle=receipt_bundle,
                pack_id=pack.pack_id,
            ).issues
        )
        matching_artifacts = tuple(
            artifact
            for artifact in pack.artifacts
            if artifact.kind is EvidenceArtifactKind.SANDBOX_RECEIPT_BUNDLE
        )
        if not matching_artifacts:
            issues.append(
                _error(
                    "wave6.sandbox_receipt_artifact_missing",
                    "PR evidence pack does not include a sandbox receipt bundle artifact.",
                    "artifacts",
                )
            )
        for artifact in matching_artifacts:
            if artifact.sha256 != receipt_bundle.digest:
                issues.append(
                    _error(
                        "wave6.sandbox_receipt_artifact_digest_mismatch",
                        f"Sandbox receipt artifact '{artifact.artifact_id}' digest does not match the supplied receipt bundle digest.",
                        f"artifacts.{artifact.artifact_id}.sha256",
                    )
                )
            if artifact.head_sha != pack.pull_request.head_sha:
                issues.append(
                    _error(
                        "wave6.sandbox_receipt_artifact_head_sha_mismatch",
                        f"Sandbox receipt artifact '{artifact.artifact_id}' head SHA does not match the PR head SHA.",
                        f"artifacts.{artifact.artifact_id}.head_sha",
                    )
                )
            if artifact.metadata.get("sandbox_receipt_bundle_digest") != receipt_bundle.digest:
                issues.append(
                    _error(
                        "wave6.sandbox_receipt_artifact_metadata_digest_mismatch",
                        f"Sandbox receipt artifact '{artifact.artifact_id}' metadata does not bind the receipt bundle digest.",
                        f"artifacts.{artifact.artifact_id}.metadata.sandbox_receipt_bundle_digest",
                    )
                )
        return Wave5ValidationReport(
            pack_id=pack.pack_id,
            validated_at=datetime.now(tz=UTC),
            issues=tuple(issues),
        )


def sandbox_receipt_bundle_to_evidence_artifact(
    *,
    pull_request: PullRequestIdentity,
    receipt_bundle: SandboxReceiptBundle,
    uri: str,
    artifact_id: str = "sandbox-receipt-bundle",
    produced_by: str = "blackfox-wave6-sandbox",
) -> EvidenceArtifact:
    payload = json.dumps(receipt_bundle.to_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")
    digest = hashlib.sha256(payload).hexdigest()
    if digest != receipt_bundle.digest:
        raise ValueError("receipt bundle digest does not match deterministic artifact payload digest.")
    return EvidenceArtifact(
        artifact_id=artifact_id,
        kind=EvidenceArtifactKind.SANDBOX_RECEIPT_BUNDLE,
        uri=uri,
        produced_by=produced_by,
        sha256=receipt_bundle.digest,
        size_bytes=len(payload),
        head_sha=pull_request.head_sha,
        metadata={
            "sandbox_receipt_bundle_digest": receipt_bundle.digest,
            "sandbox_receipt_count": receipt_bundle.receipt_count,
            "sandbox_passed": receipt_bundle.passed,
            "sandbox_expected_head_sha": receipt_bundle.expected_head_sha,
            "wave": "6",
        },
    )


def _error(code: str, summary: str, location: str) -> Wave5ValidationIssue:
    return Wave5ValidationIssue(
        code=code,
        severity=Wave5ValidationSeverity.ERROR,
        summary=summary,
        location=location,
    )
