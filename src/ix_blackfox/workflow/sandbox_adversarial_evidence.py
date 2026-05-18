from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime

from ix_blackfox.sandbox import (
    SandboxAdversarialReport,
    SandboxAdversarialScenarioKind,
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
class SandboxAdversarialEvidenceVerifier:
    required_scenario_kinds: tuple[SandboxAdversarialScenarioKind, ...] = (
        SandboxAdversarialScenarioKind.DENY_ALL_EGRESS,
        SandboxAdversarialScenarioKind.RECEIPT_BUNDLE_ACCEPTANCE,
        SandboxAdversarialScenarioKind.RECEIPT_BUNDLE_REJECTION,
        SandboxAdversarialScenarioKind.PATH_ESCAPE_BLOCK,
        SandboxAdversarialScenarioKind.SYMLINK_BLOCK,
    )

    def verify(
        self,
        *,
        pull_request: PullRequestIdentity,
        adversarial_report: SandboxAdversarialReport,
        pack_id: str = "wave6-sandbox-adversarial-verification",
    ) -> Wave5ValidationReport:
        issues: list[Wave5ValidationIssue] = []
        if not adversarial_report.results:
            issues.append(
                _error(
                    "wave6.sandbox_adversarial_report_empty",
                    "Sandbox adversarial report must contain at least one scenario result.",
                    "sandbox_adversarial.results",
                )
            )
        if not adversarial_report.passed:
            issues.append(
                _error(
                    "wave6.sandbox_adversarial_report_failed",
                    "Sandbox adversarial report contains one or more failed scenarios.",
                    "sandbox_adversarial.passed",
                )
            )

        report_head_sha = adversarial_report.metadata.get("expected_head_sha")
        if report_head_sha is None:
            issues.append(
                _error(
                    "wave6.sandbox_adversarial_head_sha_missing",
                    "Sandbox adversarial report metadata must declare the PR head SHA it was produced for.",
                    "sandbox_adversarial.metadata.expected_head_sha",
                )
            )
        elif report_head_sha != pull_request.head_sha:
            issues.append(
                _error(
                    "wave6.sandbox_adversarial_head_sha_mismatch",
                    f"Sandbox adversarial report was produced for head SHA '{report_head_sha}', not PR head SHA '{pull_request.head_sha}'.",
                    "sandbox_adversarial.metadata.expected_head_sha",
                )
            )

        present_kinds = {result.kind for result in adversarial_report.results}
        for required_kind in self.required_scenario_kinds:
            if required_kind not in present_kinds:
                issues.append(
                    _error(
                        "wave6.sandbox_adversarial_required_scenario_missing",
                        f"Required adversarial scenario kind '{required_kind.value}' is missing.",
                        "sandbox_adversarial.results",
                    )
                )

        return Wave5ValidationReport(
            pack_id=pack_id,
            validated_at=datetime.now(tz=UTC),
            issues=tuple(issues),
        )

    def verify_pack_adversarial_artifact(
        self,
        *,
        pack: PullRequestEvidencePack,
        adversarial_report: SandboxAdversarialReport,
    ) -> Wave5ValidationReport:
        issues = list(
            self.verify(
                pull_request=pack.pull_request,
                adversarial_report=adversarial_report,
                pack_id=pack.pack_id,
            ).issues
        )
        matching_artifacts = tuple(
            artifact
            for artifact in pack.artifacts
            if artifact.kind is EvidenceArtifactKind.SANDBOX_ADVERSARIAL_REPORT
        )
        if not matching_artifacts:
            issues.append(
                _error(
                    "wave6.sandbox_adversarial_artifact_missing",
                    "PR evidence pack does not include a sandbox adversarial report artifact.",
                    "artifacts",
                )
            )

        for artifact in matching_artifacts:
            if artifact.sha256 != adversarial_report.digest:
                issues.append(
                    _error(
                        "wave6.sandbox_adversarial_artifact_digest_mismatch",
                        f"Sandbox adversarial artifact '{artifact.artifact_id}' digest does not match the supplied report digest.",
                        f"artifacts.{artifact.artifact_id}.sha256",
                    )
                )
            if artifact.head_sha != pack.pull_request.head_sha:
                issues.append(
                    _error(
                        "wave6.sandbox_adversarial_artifact_head_sha_mismatch",
                        f"Sandbox adversarial artifact '{artifact.artifact_id}' head SHA does not match the PR head SHA.",
                        f"artifacts.{artifact.artifact_id}.head_sha",
                    )
                )
            if artifact.metadata.get("sandbox_adversarial_report_digest") != adversarial_report.digest:
                issues.append(
                    _error(
                        "wave6.sandbox_adversarial_artifact_metadata_digest_mismatch",
                        f"Sandbox adversarial artifact '{artifact.artifact_id}' metadata does not bind the adversarial report digest.",
                        f"artifacts.{artifact.artifact_id}.metadata.sandbox_adversarial_report_digest",
                    )
                )

        return Wave5ValidationReport(
            pack_id=pack.pack_id,
            validated_at=datetime.now(tz=UTC),
            issues=tuple(issues),
        )


def sandbox_adversarial_report_to_evidence_artifact(
    *,
    pull_request: PullRequestIdentity,
    adversarial_report: SandboxAdversarialReport,
    uri: str,
    artifact_id: str = "sandbox-adversarial-report",
    produced_by: str = "blackfox-wave6-adversarial-harness",
) -> EvidenceArtifact:
    payload = json.dumps(adversarial_report.to_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")
    digest = hashlib.sha256(payload).hexdigest()
    if digest != adversarial_report.digest:
        raise ValueError("adversarial report digest does not match deterministic artifact payload digest.")
    return EvidenceArtifact(
        artifact_id=artifact_id,
        kind=EvidenceArtifactKind.SANDBOX_ADVERSARIAL_REPORT,
        uri=uri,
        produced_by=produced_by,
        sha256=adversarial_report.digest,
        size_bytes=len(payload),
        head_sha=pull_request.head_sha,
        metadata={
            "sandbox_adversarial_report_digest": adversarial_report.digest,
            "sandbox_adversarial_scenario_count": adversarial_report.scenario_count,
            "sandbox_adversarial_passed": adversarial_report.passed,
            "sandbox_adversarial_passed_count": adversarial_report.passed_count,
            "sandbox_adversarial_failed_count": adversarial_report.failed_count,
            "sandbox_expected_head_sha": pull_request.head_sha,
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
