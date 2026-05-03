from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum, auto
from pathlib import PurePosixPath
from typing import Any, Self
from uuid import uuid4

from ix_blackfox.authoring.models import (
    AuthoringEvidence,
    AuthoringEvidenceStrength,
    AuthoringFinding,
    AuthoringFindingSeverity,
    AuthoringRiskLevel,
)
from ix_blackfox.authoring.patch_compiler import CompiledPatchCandidate
from ix_blackfox.authoring.response_parser import (
    PatchAuthoringMutation,
    PatchAuthoringProposal,
    PatchMutationType,
)


class AuthoringPolicyDecision(StrEnum):
    """
    Final Wave 3 authoring policy decision.
    """

    ALLOW = auto()
    REQUIRE_REVIEW = auto()
    BLOCK = auto()


class AuthoringPolicyFindingCode(StrEnum):
    """
    Machine-readable Wave 3 authoring policy finding codes.
    """

    ALLOWED_LOW_RISK = auto()
    BLOCKED_PATH = auto()
    SECRET_LIKE_PATH = auto()
    PATH_TRAVERSAL = auto()
    ABSOLUTE_OR_DRIVE_PATH = auto()
    GOVERNANCE_PATH_REQUIRES_REVIEW = auto()
    ACCEPTANCE_LOGIC_REQUIRES_REVIEW = auto()
    RECEIPT_LOGIC_REQUIRES_REVIEW = auto()
    POLICY_FILE_REQUIRES_REVIEW = auto()
    TEST_MUTATION_REQUIRES_REVIEW = auto()
    TEST_WEAKENING_RISK = auto()
    DEPENDENCY_CONFIG_REQUIRES_REVIEW = auto()
    CI_WORKFLOW_REQUIRES_REVIEW = auto()
    EXECUTABLE_SCRIPT_REQUIRES_REVIEW = auto()
    CREATE_FILE_REQUIRES_REVIEW = auto()
    DELETE_LIKE_MUTATION_BLOCKED = auto()
    LARGE_PATCH_REQUIRES_REVIEW = auto()
    LOW_CONFIDENCE_REQUIRES_REVIEW = auto()
    WEAK_EVIDENCE_REQUIRES_REVIEW = auto()
    MISSING_EVIDENCE_REQUIRES_REVIEW = auto()
    UNSAFE_CONTENT_BLOCKED = auto()
    CANDIDATE_PROPOSAL_MISMATCH = auto()
    CANDIDATE_PATCH_PATH_MISMATCH = auto()


@dataclass(frozen=True, slots=True)
class AuthoringPolicyFinding:
    """
    One policy finding for a parsed or compiled Wave 3 patch candidate.
    """

    code: AuthoringPolicyFindingCode
    decision: AuthoringPolicyDecision
    severity: AuthoringFindingSeverity
    summary: str
    path: str | None = None
    risk_level: AuthoringRiskLevel = AuthoringRiskLevel.MODERATE
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "summary", _normalize_text(self.summary, label="summary"))
        object.__setattr__(self, "path", _normalize_optional_relative_path(self.path))
        object.__setattr__(self, "metadata", dict(self.metadata))

    def to_authoring_finding(self) -> AuthoringFinding:
        return AuthoringFinding(
            code=f"authoring.policy.{self.code.value}",
            severity=self.severity,
            summary=self.summary,
            path=self.path,
            metadata={
                "decision": self.decision.value,
                "risk_level": self.risk_level.value,
                **dict(self.metadata),
            },
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code.value,
            "decision": self.decision.value,
            "severity": self.severity.value,
            "summary": self.summary,
            "path": self.path,
            "risk_level": self.risk_level.value,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        return cls(
            code=AuthoringPolicyFindingCode(_require_text(payload, "code")),
            decision=AuthoringPolicyDecision(_require_text(payload, "decision")),
            severity=AuthoringFindingSeverity(_require_text(payload, "severity")),
            summary=_require_text(payload, "summary"),
            path=_optional_text_from_payload(payload, "path"),
            risk_level=AuthoringRiskLevel(_require_text(payload, "risk_level")),
            metadata=_coerce_mapping(payload.get("metadata", {}), field_name="metadata"),
        )


@dataclass(frozen=True, slots=True)
class AuthoringPolicyReport:
    """
    Final Wave 3 authoring policy gate result.

    A report with decision BLOCK must never proceed to Wave 2 execution.
    A report with decision REQUIRE_REVIEW must only proceed when an explicit
    review artifact later satisfies the requirement.
    """

    report_id: str
    decision: AuthoringPolicyDecision
    proposal_id: str
    proposal_digest: str
    affected_paths: tuple[str, ...]
    findings: tuple[AuthoringPolicyFinding, ...] = field(default_factory=tuple)
    candidate_id: str | None = None
    patch_id: str | None = None
    patch_digest: str | None = None
    evidence_strength: AuthoringEvidenceStrength | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "report_id",
            _normalize_identifier(self.report_id, label="report_id"),
        )
        object.__setattr__(
            self,
            "proposal_id",
            _normalize_identifier(self.proposal_id, label="proposal_id"),
        )
        object.__setattr__(self, "proposal_digest", _normalize_sha256(self.proposal_digest))
        object.__setattr__(
            self,
            "affected_paths",
            tuple(_normalize_relative_path(path) for path in self.affected_paths),
        )
        object.__setattr__(self, "findings", tuple(self.findings))
        object.__setattr__(
            self,
            "candidate_id",
            _normalize_optional_identifier(self.candidate_id, label="candidate_id"),
        )
        object.__setattr__(
            self,
            "patch_id",
            _normalize_optional_identifier(self.patch_id, label="patch_id"),
        )
        object.__setattr__(self, "patch_digest", _normalize_optional_sha256(self.patch_digest))
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def blocked(self) -> bool:
        return self.decision is AuthoringPolicyDecision.BLOCK

    @property
    def requires_review(self) -> bool:
        return self.decision is AuthoringPolicyDecision.REQUIRE_REVIEW

    @property
    def allowed(self) -> bool:
        return self.decision is AuthoringPolicyDecision.ALLOW

    @property
    def authoring_findings(self) -> tuple[AuthoringFinding, ...]:
        return tuple(finding.to_authoring_finding() for finding in self.findings)

    @property
    def finding_codes(self) -> tuple[str, ...]:
        return tuple(finding.code.value for finding in self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_id": self.report_id,
            "decision": self.decision.value,
            "blocked": self.blocked,
            "requires_review": self.requires_review,
            "allowed": self.allowed,
            "proposal_id": self.proposal_id,
            "proposal_digest": self.proposal_digest,
            "candidate_id": self.candidate_id,
            "patch_id": self.patch_id,
            "patch_digest": self.patch_digest,
            "affected_paths": list(self.affected_paths),
            "evidence_strength": None if self.evidence_strength is None else self.evidence_strength.value,
            "finding_codes": list(self.finding_codes),
            "findings": [finding.to_dict() for finding in self.findings],
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        evidence_strength_value = payload.get("evidence_strength")
        if evidence_strength_value is not None and not isinstance(evidence_strength_value, str):
            raise TypeError("evidence_strength must be a string or None.")

        return cls(
            report_id=_require_text(payload, "report_id"),
            decision=AuthoringPolicyDecision(_require_text(payload, "decision")),
            proposal_id=_require_text(payload, "proposal_id"),
            proposal_digest=_require_text(payload, "proposal_digest"),
            candidate_id=_optional_text_from_payload(payload, "candidate_id"),
            patch_id=_optional_text_from_payload(payload, "patch_id"),
            patch_digest=_optional_text_from_payload(payload, "patch_digest"),
            affected_paths=_coerce_text_tuple(payload.get("affected_paths", ()), field_name="affected_paths"),
            evidence_strength=None
            if evidence_strength_value is None
            else AuthoringEvidenceStrength(evidence_strength_value),
            findings=_load_findings(payload.get("findings", ())),
            metadata=_coerce_mapping(payload.get("metadata", {}), field_name="metadata"),
        )


@dataclass(frozen=True, slots=True)
class AuthoringPolicyGateConfig:
    """
    Deterministic policy thresholds for Wave 3 authoring proposals.

    This gate is intentionally conservative. It blocks secret/path-escape and
    unsafe-content cases, and escalates sensitive mutations to human review.
    """

    minimum_confidence_for_allow: float = 0.50
    maximum_mutations_for_allow: int = 4
    maximum_changed_paths_for_allow: int = 4
    maximum_total_size_delta_for_allow: int = 8_000
    require_review_for_create_file: bool = True
    require_review_for_test_mutation: bool = True
    require_review_for_governance_paths: bool = True
    require_review_for_dependency_config: bool = True
    require_review_for_ci_workflow: bool = True
    require_review_for_executable_scripts: bool = True
    require_review_for_weak_or_missing_evidence: bool = True
    blocked_roots: tuple[str, ...] = (
        ".git",
        ".hg",
        ".svn",
        ".ssh",
        ".gnupg",
        ".aws",
        ".azure",
        ".docker",
        ".kube",
        "run_bundles",
        "artifacts",
    )
    secret_file_patterns: tuple[str, ...] = (
        ".env",
        ".env.",
        "secret",
        "secrets",
        "credential",
        "credentials",
        "token",
        "private-key",
        "private_key",
        "id_rsa",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "authorized_keys",
    )
    governance_path_patterns: tuple[str, ...] = (
        "policy",
        "approval",
        "acceptance",
        "validator",
        "receipt",
        "workspace",
        "control_plane",
        "manifest",
        "path_policy",
    )
    acceptance_path_patterns: tuple[str, ...] = (
        "acceptance",
        "validator",
        "verification",
    )
    receipt_path_patterns: tuple[str, ...] = (
        "receipt",
        "bundle",
        "summary",
        "evidence",
    )
    test_path_patterns: tuple[str, ...] = (
        "tests/",
        "/tests/",
        "test_",
    )
    dependency_config_patterns: tuple[str, ...] = (
        "pyproject.toml",
        "requirements.txt",
        "requirements-dev.txt",
        "poetry.lock",
        "pdm.lock",
        "uv.lock",
        "package.json",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "dockerfile",
        "compose.yaml",
        "compose.yml",
    )
    ci_workflow_patterns: tuple[str, ...] = (
        ".github/workflows/",
        ".gitlab-ci.yml",
        "azure-pipelines.yml",
        "circleci",
    )
    executable_script_patterns: tuple[str, ...] = (
        ".sh",
        ".bash",
        ".zsh",
        ".ps1",
        ".bat",
        ".cmd",
    )
    unsafe_content_patterns: tuple[str, ...] = (
        "rm -rf",
        "curl ",
        "wget ",
        "powershell",
        "invoke-webrequest",
        "sudo ",
        "chmod ",
        "python -c",
        "python3 -c",
        "subprocess.run",
        "os.system",
        "eval(",
        "exec(",
    )
    test_weakening_patterns: tuple[str, ...] = (
        "pytest.skip",
        "@pytest.mark.skip",
        "@pytest.mark.xfail",
        "assert true",
        "assert 1 == 1",
        "return  # skip",
        "pass  # skip",
    )
    delete_like_phrases: tuple[str, ...] = (
        "delete file",
        "remove file",
        "erase file",
        "drop file",
        "remove assertion",
        "delete assertion",
        "weaken assertion",
    )

    def __post_init__(self) -> None:
        if self.minimum_confidence_for_allow < 0.0 or self.minimum_confidence_for_allow > 1.0:
            raise ValueError("minimum_confidence_for_allow must be between 0.0 and 1.0.")
        if self.maximum_mutations_for_allow <= 0:
            raise ValueError("maximum_mutations_for_allow must be positive.")
        if self.maximum_changed_paths_for_allow <= 0:
            raise ValueError("maximum_changed_paths_for_allow must be positive.")
        if self.maximum_total_size_delta_for_allow <= 0:
            raise ValueError("maximum_total_size_delta_for_allow must be positive.")

        for field_name in (
            "blocked_roots",
            "secret_file_patterns",
            "governance_path_patterns",
            "acceptance_path_patterns",
            "receipt_path_patterns",
            "test_path_patterns",
            "dependency_config_patterns",
            "ci_workflow_patterns",
            "executable_script_patterns",
            "unsafe_content_patterns",
            "test_weakening_patterns",
            "delete_like_phrases",
        ):
            object.__setattr__(
                self,
                field_name,
                _normalize_pattern_tuple(
                    getattr(self, field_name),
                    field_name=field_name,
                ),
            )


@dataclass(frozen=True, slots=True)
class AuthoringPolicyGate:
    """
    Conservative Wave 3 authoring policy gate.

    The gate evaluates parsed proposals and optional compiled patch candidates
    before anything proceeds toward Wave 2 execution.
    """

    config: AuthoringPolicyGateConfig = field(default_factory=AuthoringPolicyGateConfig)

    def evaluate(
        self,
        *,
        proposal: PatchAuthoringProposal,
        candidate: CompiledPatchCandidate | None = None,
        evidence: tuple[AuthoringEvidence, ...] = (),
    ) -> AuthoringPolicyReport:
        if not isinstance(proposal, PatchAuthoringProposal):
            raise TypeError("proposal must be a PatchAuthoringProposal.")

        if candidate is not None and not isinstance(candidate, CompiledPatchCandidate):
            raise TypeError("candidate must be a CompiledPatchCandidate or None.")

        findings: list[AuthoringPolicyFinding] = []
        evidence_strength = _combined_evidence_strength(evidence)

        findings.extend(self._proposal_consistency_findings(proposal=proposal, candidate=candidate))
        findings.extend(self._path_findings(proposal=proposal))
        findings.extend(self._mutation_findings(proposal=proposal))
        findings.extend(self._confidence_findings(proposal=proposal))
        findings.extend(self._evidence_findings(evidence=evidence, evidence_strength=evidence_strength))
        findings.extend(self._patch_size_findings(proposal=proposal))
        findings.extend(self._content_findings(proposal=proposal))

        if not findings:
            findings.append(
                AuthoringPolicyFinding(
                    code=AuthoringPolicyFindingCode.ALLOWED_LOW_RISK,
                    decision=AuthoringPolicyDecision.ALLOW,
                    severity=AuthoringFindingSeverity.INFO,
                    summary="Authoring proposal is low risk under the current Wave 3 policy gate.",
                    risk_level=AuthoringRiskLevel.LOW,
                    metadata={"proposal_id": proposal.proposal_id},
                )
            )

        decision = _final_decision(findings)

        return AuthoringPolicyReport(
            report_id=f"authoring-policy-report-{uuid4().hex}",
            decision=decision,
            proposal_id=proposal.proposal_id,
            proposal_digest=proposal.digest,
            candidate_id=None if candidate is None else candidate.candidate_id,
            patch_id=None if candidate is None else candidate.patch_id,
            patch_digest=None if candidate is None else candidate.patch_digest,
            affected_paths=proposal.affected_paths,
            evidence_strength=evidence_strength,
            findings=_dedupe_findings(findings),
            metadata={
                "gate": "AuthoringPolicyGate",
                "proposal_confidence": proposal.confidence,
                "mutation_count": len(proposal.mutations),
                "changed_path_count": len(proposal.affected_paths),
                "total_size_delta": proposal.total_size_delta,
                "candidate_attached": candidate is not None,
            },
        )

    def _proposal_consistency_findings(
        self,
        *,
        proposal: PatchAuthoringProposal,
        candidate: CompiledPatchCandidate | None,
    ) -> tuple[AuthoringPolicyFinding, ...]:
        if candidate is None:
            return ()

        findings: list[AuthoringPolicyFinding] = []

        if candidate.proposal_id != proposal.proposal_id or candidate.proposal_digest != proposal.digest:
            findings.append(
                AuthoringPolicyFinding(
                    code=AuthoringPolicyFindingCode.CANDIDATE_PROPOSAL_MISMATCH,
                    decision=AuthoringPolicyDecision.BLOCK,
                    severity=AuthoringFindingSeverity.ERROR,
                    summary="Compiled candidate does not match the proposal identity or digest.",
                    risk_level=AuthoringRiskLevel.CRITICAL,
                    metadata={
                        "proposal_id": proposal.proposal_id,
                        "proposal_digest": proposal.digest,
                        "candidate_proposal_id": candidate.proposal_id,
                        "candidate_proposal_digest": candidate.proposal_digest,
                    },
                )
            )

        if set(candidate.changed_paths) != set(proposal.affected_paths):
            findings.append(
                AuthoringPolicyFinding(
                    code=AuthoringPolicyFindingCode.CANDIDATE_PATCH_PATH_MISMATCH,
                    decision=AuthoringPolicyDecision.BLOCK,
                    severity=AuthoringFindingSeverity.ERROR,
                    summary="Compiled candidate changed paths do not match proposal affected paths.",
                    risk_level=AuthoringRiskLevel.CRITICAL,
                    metadata={
                        "proposal_paths": list(proposal.affected_paths),
                        "candidate_paths": list(candidate.changed_paths),
                    },
                )
            )

        return tuple(findings)

    def _path_findings(self, *, proposal: PatchAuthoringProposal) -> tuple[AuthoringPolicyFinding, ...]:
        findings: list[AuthoringPolicyFinding] = []

        for path in proposal.affected_paths:
            if _has_path_traversal(path):
                findings.append(
                    self._finding(
                        code=AuthoringPolicyFindingCode.PATH_TRAVERSAL,
                        decision=AuthoringPolicyDecision.BLOCK,
                        summary="Proposal path contains traversal and must be blocked.",
                        path=path,
                        risk_level=AuthoringRiskLevel.CRITICAL,
                    )
                )
                continue

            if _is_absolute_or_drive_path(path):
                findings.append(
                    self._finding(
                        code=AuthoringPolicyFindingCode.ABSOLUTE_OR_DRIVE_PATH,
                        decision=AuthoringPolicyDecision.BLOCK,
                        summary="Proposal path is not workspace-relative and must be blocked.",
                        path=path,
                        risk_level=AuthoringRiskLevel.CRITICAL,
                    )
                )
                continue

            if self._is_blocked_root(path):
                findings.append(
                    self._finding(
                        code=AuthoringPolicyFindingCode.BLOCKED_PATH,
                        decision=AuthoringPolicyDecision.BLOCK,
                        summary="Proposal targets a blocked root path.",
                        path=path,
                        risk_level=AuthoringRiskLevel.CRITICAL,
                    )
                )

            if self._is_secret_like_path(path):
                findings.append(
                    self._finding(
                        code=AuthoringPolicyFindingCode.SECRET_LIKE_PATH,
                        decision=AuthoringPolicyDecision.BLOCK,
                        summary="Proposal targets a secret-like path.",
                        path=path,
                        risk_level=AuthoringRiskLevel.CRITICAL,
                    )
                )

            if self.config.require_review_for_governance_paths and self._is_governance_path(path):
                findings.append(
                    self._finding(
                        code=AuthoringPolicyFindingCode.GOVERNANCE_PATH_REQUIRES_REVIEW,
                        decision=AuthoringPolicyDecision.REQUIRE_REVIEW,
                        summary="Proposal targets governance-sensitive code and requires review.",
                        path=path,
                        risk_level=AuthoringRiskLevel.HIGH,
                    )
                )

            if self._matches_path(path, self.config.acceptance_path_patterns):
                findings.append(
                    self._finding(
                        code=AuthoringPolicyFindingCode.ACCEPTANCE_LOGIC_REQUIRES_REVIEW,
                        decision=AuthoringPolicyDecision.REQUIRE_REVIEW,
                        summary="Proposal targets acceptance or verification logic and requires review.",
                        path=path,
                        risk_level=AuthoringRiskLevel.HIGH,
                    )
                )

            if self._matches_path(path, self.config.receipt_path_patterns):
                findings.append(
                    self._finding(
                        code=AuthoringPolicyFindingCode.RECEIPT_LOGIC_REQUIRES_REVIEW,
                        decision=AuthoringPolicyDecision.REQUIRE_REVIEW,
                        summary="Proposal targets receipt, bundle, summary, or evidence logic and requires review.",
                        path=path,
                        risk_level=AuthoringRiskLevel.HIGH,
                    )
                )

            if "policy" in path.lower():
                findings.append(
                    self._finding(
                        code=AuthoringPolicyFindingCode.POLICY_FILE_REQUIRES_REVIEW,
                        decision=AuthoringPolicyDecision.REQUIRE_REVIEW,
                        summary="Proposal targets policy-related files and requires review.",
                        path=path,
                        risk_level=AuthoringRiskLevel.HIGH,
                    )
                )

            if self.config.require_review_for_test_mutation and self._is_test_path(path):
                findings.append(
                    self._finding(
                        code=AuthoringPolicyFindingCode.TEST_MUTATION_REQUIRES_REVIEW,
                        decision=AuthoringPolicyDecision.REQUIRE_REVIEW,
                        summary="Proposal mutates tests and requires review to prevent verification weakening.",
                        path=path,
                        risk_level=AuthoringRiskLevel.MODERATE,
                    )
                )

            if self.config.require_review_for_dependency_config and self._is_dependency_config_path(path):
                findings.append(
                    self._finding(
                        code=AuthoringPolicyFindingCode.DEPENDENCY_CONFIG_REQUIRES_REVIEW,
                        decision=AuthoringPolicyDecision.REQUIRE_REVIEW,
                        summary="Proposal mutates dependency or build configuration and requires review.",
                        path=path,
                        risk_level=AuthoringRiskLevel.HIGH,
                    )
                )

            if self.config.require_review_for_ci_workflow and self._is_ci_workflow_path(path):
                findings.append(
                    self._finding(
                        code=AuthoringPolicyFindingCode.CI_WORKFLOW_REQUIRES_REVIEW,
                        decision=AuthoringPolicyDecision.REQUIRE_REVIEW,
                        summary="Proposal mutates CI workflow configuration and requires review.",
                        path=path,
                        risk_level=AuthoringRiskLevel.HIGH,
                    )
                )

            if self.config.require_review_for_executable_scripts and self._is_executable_script_path(path):
                findings.append(
                    self._finding(
                        code=AuthoringPolicyFindingCode.EXECUTABLE_SCRIPT_REQUIRES_REVIEW,
                        decision=AuthoringPolicyDecision.REQUIRE_REVIEW,
                        summary="Proposal mutates executable script content and requires review.",
                        path=path,
                        risk_level=AuthoringRiskLevel.HIGH,
                    )
                )

        return tuple(findings)

    def _mutation_findings(self, *, proposal: PatchAuthoringProposal) -> tuple[AuthoringPolicyFinding, ...]:
        findings: list[AuthoringPolicyFinding] = []

        for mutation in proposal.mutations:
            if self.config.require_review_for_create_file and mutation.mutation_type is PatchMutationType.CREATE_FILE:
                findings.append(
                    self._finding(
                        code=AuthoringPolicyFindingCode.CREATE_FILE_REQUIRES_REVIEW,
                        decision=AuthoringPolicyDecision.REQUIRE_REVIEW,
                        summary="Proposal creates a new file and requires review.",
                        path=mutation.path,
                        risk_level=AuthoringRiskLevel.MODERATE,
                        metadata={"mutation_id": mutation.mutation_id},
                    )
                )

            combined_text = "\n".join(
                (
                    mutation.rationale,
                    mutation.before_text,
                    mutation.after_text,
                    proposal.reasoning_summary,
                    *proposal.risk_notes,
                )
            )

            if _matches_any(combined_text, self.config.delete_like_phrases):
                findings.append(
                    self._finding(
                        code=AuthoringPolicyFindingCode.DELETE_LIKE_MUTATION_BLOCKED,
                        decision=AuthoringPolicyDecision.BLOCK,
                        summary="Proposal contains delete-like mutation language and must be blocked before review.",
                        path=mutation.path,
                        risk_level=AuthoringRiskLevel.CRITICAL,
                        metadata={"mutation_id": mutation.mutation_id},
                    )
                )

            if self._is_test_path(mutation.path) and _looks_like_test_weakening(mutation, self.config.test_weakening_patterns):
                findings.append(
                    self._finding(
                        code=AuthoringPolicyFindingCode.TEST_WEAKENING_RISK,
                        decision=AuthoringPolicyDecision.REQUIRE_REVIEW,
                        summary="Proposal may weaken tests and requires review.",
                        path=mutation.path,
                        risk_level=AuthoringRiskLevel.HIGH,
                        metadata={"mutation_id": mutation.mutation_id},
                    )
                )

        return tuple(findings)

    def _confidence_findings(self, *, proposal: PatchAuthoringProposal) -> tuple[AuthoringPolicyFinding, ...]:
        if proposal.confidence >= self.config.minimum_confidence_for_allow:
            return ()

        return (
            self._finding(
                code=AuthoringPolicyFindingCode.LOW_CONFIDENCE_REQUIRES_REVIEW,
                decision=AuthoringPolicyDecision.REQUIRE_REVIEW,
                summary="Proposal confidence is below the policy allow threshold.",
                risk_level=AuthoringRiskLevel.MODERATE,
                metadata={
                    "confidence": proposal.confidence,
                    "minimum_confidence_for_allow": self.config.minimum_confidence_for_allow,
                },
            ),
        )

    def _evidence_findings(
        self,
        *,
        evidence: tuple[AuthoringEvidence, ...],
        evidence_strength: AuthoringEvidenceStrength | None,
    ) -> tuple[AuthoringPolicyFinding, ...]:
        if not self.config.require_review_for_weak_or_missing_evidence:
            return ()

        if evidence_strength is None:
            return (
                self._finding(
                    code=AuthoringPolicyFindingCode.MISSING_EVIDENCE_REQUIRES_REVIEW,
                    decision=AuthoringPolicyDecision.REQUIRE_REVIEW,
                    summary="No evidence was supplied to the authoring policy gate.",
                    risk_level=AuthoringRiskLevel.MODERATE,
                ),
            )

        if evidence_strength is AuthoringEvidenceStrength.MISSING:
            return (
                self._finding(
                    code=AuthoringPolicyFindingCode.MISSING_EVIDENCE_REQUIRES_REVIEW,
                    decision=AuthoringPolicyDecision.REQUIRE_REVIEW,
                    summary="Supplied evidence is marked missing and requires review.",
                    risk_level=AuthoringRiskLevel.MODERATE,
                    metadata={"evidence_count": len(evidence)},
                ),
            )

        if evidence_strength is AuthoringEvidenceStrength.WEAK:
            return (
                self._finding(
                    code=AuthoringPolicyFindingCode.WEAK_EVIDENCE_REQUIRES_REVIEW,
                    decision=AuthoringPolicyDecision.REQUIRE_REVIEW,
                    summary="Supplied evidence is weak and requires review before authored execution.",
                    risk_level=AuthoringRiskLevel.MODERATE,
                    metadata={"evidence_count": len(evidence)},
                ),
            )

        return ()

    def _patch_size_findings(self, *, proposal: PatchAuthoringProposal) -> tuple[AuthoringPolicyFinding, ...]:
        findings: list[AuthoringPolicyFinding] = []

        if len(proposal.mutations) > self.config.maximum_mutations_for_allow:
            findings.append(
                self._finding(
                    code=AuthoringPolicyFindingCode.LARGE_PATCH_REQUIRES_REVIEW,
                    decision=AuthoringPolicyDecision.REQUIRE_REVIEW,
                    summary="Proposal mutation count exceeds automatic allow threshold.",
                    risk_level=AuthoringRiskLevel.MODERATE,
                    metadata={
                        "mutation_count": len(proposal.mutations),
                        "maximum_mutations_for_allow": self.config.maximum_mutations_for_allow,
                    },
                )
            )

        if len(proposal.affected_paths) > self.config.maximum_changed_paths_for_allow:
            findings.append(
                self._finding(
                    code=AuthoringPolicyFindingCode.LARGE_PATCH_REQUIRES_REVIEW,
                    decision=AuthoringPolicyDecision.REQUIRE_REVIEW,
                    summary="Proposal changed path count exceeds automatic allow threshold.",
                    risk_level=AuthoringRiskLevel.MODERATE,
                    metadata={
                        "changed_path_count": len(proposal.affected_paths),
                        "maximum_changed_paths_for_allow": self.config.maximum_changed_paths_for_allow,
                    },
                )
            )

        if abs(proposal.total_size_delta) > self.config.maximum_total_size_delta_for_allow:
            findings.append(
                self._finding(
                    code=AuthoringPolicyFindingCode.LARGE_PATCH_REQUIRES_REVIEW,
                    decision=AuthoringPolicyDecision.REQUIRE_REVIEW,
                    summary="Proposal size delta exceeds automatic allow threshold.",
                    risk_level=AuthoringRiskLevel.MODERATE,
                    metadata={
                        "total_size_delta": proposal.total_size_delta,
                        "maximum_total_size_delta_for_allow": self.config.maximum_total_size_delta_for_allow,
                    },
                )
            )

        return tuple(findings)

    def _content_findings(self, *, proposal: PatchAuthoringProposal) -> tuple[AuthoringPolicyFinding, ...]:
        findings: list[AuthoringPolicyFinding] = []

        for mutation in proposal.mutations:
            combined_text = "\n".join(
                (
                    mutation.before_text,
                    mutation.after_text,
                    mutation.rationale,
                    proposal.objective_summary,
                    proposal.reasoning_summary,
                    *proposal.assumptions,
                    *proposal.risk_notes,
                    *proposal.expected_tests,
                )
            )
            unsafe_matches = _matching_patterns(combined_text, self.config.unsafe_content_patterns)
            if unsafe_matches:
                findings.append(
                    self._finding(
                        code=AuthoringPolicyFindingCode.UNSAFE_CONTENT_BLOCKED,
                        decision=AuthoringPolicyDecision.BLOCK,
                        summary="Proposal contains unsafe command or dynamic-execution content.",
                        path=mutation.path,
                        risk_level=AuthoringRiskLevel.CRITICAL,
                        metadata={
                            "mutation_id": mutation.mutation_id,
                            "matches": list(unsafe_matches),
                        },
                    )
                )

        return tuple(findings)

    def _finding(
        self,
        *,
        code: AuthoringPolicyFindingCode,
        decision: AuthoringPolicyDecision,
        summary: str,
        risk_level: AuthoringRiskLevel,
        path: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> AuthoringPolicyFinding:
        severity = (
            AuthoringFindingSeverity.ERROR
            if decision is AuthoringPolicyDecision.BLOCK
            else AuthoringFindingSeverity.WARNING
            if decision is AuthoringPolicyDecision.REQUIRE_REVIEW
            else AuthoringFindingSeverity.INFO
        )
        return AuthoringPolicyFinding(
            code=code,
            decision=decision,
            severity=severity,
            summary=summary,
            path=path,
            risk_level=risk_level,
            metadata=dict(metadata or {}),
        )

    def _is_blocked_root(self, path: str) -> bool:
        path_parts = tuple(PurePosixPath(path.lower()).parts)
        for blocked_root in self.config.blocked_roots:
            blocked_parts = tuple(PurePosixPath(blocked_root).parts)
            if _path_parts_start_with(path_parts, blocked_parts):
                return True
        return False

    def _is_secret_like_path(self, path: str) -> bool:
        lowered = path.lower().replace("\\", "/")
        name = PurePosixPath(lowered).name
        return any(pattern in lowered or pattern in name for pattern in self.config.secret_file_patterns)

    def _is_governance_path(self, path: str) -> bool:
        return self._matches_path(path, self.config.governance_path_patterns)

    def _is_test_path(self, path: str) -> bool:
        return self._matches_path(path, self.config.test_path_patterns)

    def _is_dependency_config_path(self, path: str) -> bool:
        return self._matches_path(path, self.config.dependency_config_patterns)

    def _is_ci_workflow_path(self, path: str) -> bool:
        return self._matches_path(path, self.config.ci_workflow_patterns)

    def _is_executable_script_path(self, path: str) -> bool:
        lowered = path.lower().replace("\\", "/")
        return any(lowered.endswith(pattern) or pattern in lowered for pattern in self.config.executable_script_patterns)

    def _matches_path(self, path: str, patterns: tuple[str, ...]) -> bool:
        lowered = path.lower().replace("\\", "/")
        return any(pattern in lowered for pattern in patterns)


def _combined_evidence_strength(
    evidence: tuple[AuthoringEvidence, ...],
) -> AuthoringEvidenceStrength | None:
    if not evidence:
        return None

    if any(item.strength is AuthoringEvidenceStrength.DIRECT for item in evidence):
        return AuthoringEvidenceStrength.DIRECT

    if any(item.strength is AuthoringEvidenceStrength.WEAK for item in evidence):
        return AuthoringEvidenceStrength.WEAK

    return AuthoringEvidenceStrength.MISSING


def _final_decision(findings: Iterable[AuthoringPolicyFinding]) -> AuthoringPolicyDecision:
    decisions = tuple(finding.decision for finding in findings)

    if AuthoringPolicyDecision.BLOCK in decisions:
        return AuthoringPolicyDecision.BLOCK

    if AuthoringPolicyDecision.REQUIRE_REVIEW in decisions:
        return AuthoringPolicyDecision.REQUIRE_REVIEW

    return AuthoringPolicyDecision.ALLOW


def _dedupe_findings(
    findings: Iterable[AuthoringPolicyFinding],
) -> tuple[AuthoringPolicyFinding, ...]:
    deduped: list[AuthoringPolicyFinding] = []
    seen: set[tuple[str, str | None, str]] = set()

    for finding in findings:
        key = (finding.code.value, finding.path, finding.summary)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)

    return tuple(deduped)


def _looks_like_test_weakening(
    mutation: PatchAuthoringMutation,
    patterns: tuple[str, ...],
) -> bool:
    before_lower = mutation.before_text.lower()
    after_lower = mutation.after_text.lower()
    rationale_lower = mutation.rationale.lower()

    if _matches_any(after_lower, patterns):
        return True

    if "assert " in before_lower and "assert " not in after_lower:
        return True

    if "pytest.raises" in before_lower and "pytest.raises" not in after_lower:
        return True

    if "remove assertion" in rationale_lower or "delete assertion" in rationale_lower:
        return True

    return False


def _matches_any(text: str, patterns: tuple[str, ...]) -> bool:
    return bool(_matching_patterns(text, patterns))


def _matching_patterns(text: str, patterns: tuple[str, ...]) -> tuple[str, ...]:
    lowered = text.lower()
    matches: list[str] = []
    for pattern in patterns:
        if pattern in lowered:
            matches.append(pattern)
    return tuple(matches)


def _has_path_traversal(path: str) -> bool:
    return any(part == ".." for part in PurePosixPath(path.replace("\\", "/")).parts)


def _is_absolute_or_drive_path(path: str) -> bool:
    cleaned = path.strip().replace("\\", "/")
    return cleaned.startswith(("/", "~")) or bool(re.match(r"^[a-zA-Z]:", cleaned))


def _path_parts_start_with(path_parts: tuple[str, ...], root_parts: tuple[str, ...]) -> bool:
    if not root_parts:
        return False
    if len(path_parts) < len(root_parts):
        return False
    return path_parts[: len(root_parts)] == root_parts


def _load_findings(value: Any) -> tuple[AuthoringPolicyFinding, ...]:
    if isinstance(value, str) or not isinstance(value, Iterable):
        raise TypeError("findings must be an iterable of mappings.")

    findings: list[AuthoringPolicyFinding] = []
    for item in value:
        if not isinstance(item, Mapping):
            raise TypeError("findings must contain only mappings.")
        findings.append(AuthoringPolicyFinding.from_dict(item))
    return tuple(findings)


def _normalize_identifier(value: str, *, label: str) -> str:
    cleaned = value.strip().lower().replace(" ", "-")
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_optional_identifier(value: str | None, *, label: str) -> str | None:
    if value is None:
        return None
    return _normalize_identifier(value, label=label)


def _normalize_text(value: str, *, label: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_optional_relative_path(value: str | None) -> str | None:
    if value is None:
        return None
    return _normalize_relative_path(value)


def _normalize_relative_path(value: str) -> str:
    cleaned = value.strip().replace("\\", "/")
    if not cleaned:
        raise ValueError("relative path must not be empty.")
    if cleaned.startswith(("/", "~")) or ":" in cleaned.split("/")[0]:
        raise ValueError(f"path must be relative: {value!r}")

    parts: list[str] = []
    for raw_part in cleaned.split("/"):
        part = raw_part.strip()
        if part in {"", "."}:
            continue
        if part == "..":
            raise ValueError(f"path traversal is not allowed: {value!r}")
        parts.append(part)

    if not parts:
        raise ValueError("relative path must not resolve to workspace root.")
    return "/".join(parts)


def _normalize_sha256(value: str) -> str:
    cleaned = value.strip().lower()
    if len(cleaned) != 64 or any(char not in "0123456789abcdef" for char in cleaned):
        raise ValueError("sha256 must be a 64-character lowercase hexadecimal digest.")
    return cleaned


def _normalize_optional_sha256(value: str | None) -> str | None:
    if value is None:
        return None
    return _normalize_sha256(value)


def _normalize_pattern_tuple(values: Iterable[str], *, field_name: str) -> tuple[str, ...]:
    normalized: list[str] = []
    for value in values:
        if not isinstance(value, str):
            raise TypeError(f"{field_name} must contain only strings.")
        cleaned = value.strip().lower().replace("\\", "/")
        if not cleaned:
            raise ValueError(f"{field_name} must not contain empty values.")
        normalized.append(cleaned)
    return tuple(normalized)


def _coerce_mapping(value: Any, *, field_name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{field_name} must be a mapping.")
    return dict(value)


def _coerce_text_tuple(value: Any, *, field_name: str) -> tuple[str, ...]:
    if isinstance(value, str) or not isinstance(value, Iterable):
        raise TypeError(f"{field_name} must be an iterable of strings.")

    result: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise TypeError(f"{field_name} must contain only strings.")
        result.append(item)
    return tuple(result)


def _require_text(payload: Mapping[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str):
        raise TypeError(f"Field {key!r} must be a string.")
    return value


def _optional_text_from_payload(payload: Mapping[str, Any], key: str) -> str | None:
    value = payload.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError(f"Field {key!r} must be a string or None.")
    return value
