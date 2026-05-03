from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum, auto
from typing import Any, Self
from uuid import uuid4

from ix_blackfox.authoring.hypotheses import (
    RepairFailureClass,
    RepairHypothesisReport,
    RepairShape,
)
from ix_blackfox.authoring.models import (
    AuthoringEvidence,
    AuthoringEvidenceStrength,
    AuthoringFinding,
    AuthoringFindingSeverity,
    AuthoringRiskLevel,
)
from ix_blackfox.authoring.patch_compiler import CompiledPatchCandidate
from ix_blackfox.authoring.policy import (
    AuthoringPolicyDecision,
    AuthoringPolicyReport,
)
from ix_blackfox.authoring.response_parser import PatchAuthoringProposal


class CandidateDisposition(StrEnum):
    """
    Final ranking disposition for one Wave 3 authored repair candidate.
    """

    SELECTED = auto()
    AVAILABLE = auto()
    REQUIRES_REVIEW = auto()
    REJECTED = auto()
    BLOCKED = auto()


class CandidateRejectionReason(StrEnum):
    """
    Machine-readable reason for not selecting an authored repair candidate.
    """

    BLOCKED_BY_POLICY = auto()
    REVIEW_REQUIRED = auto()
    PROPOSAL_NOT_FOUND = auto()
    PROPOSAL_DIGEST_MISMATCH = auto()
    POLICY_NOT_FOUND = auto()
    POLICY_PROPOSAL_MISMATCH = auto()
    PATCH_DIGEST_DUPLICATE = auto()
    PATH_RISK_TOO_HIGH = auto()
    PATCH_TOO_LARGE = auto()
    LOW_CONFIDENCE = auto()
    LOW_SCORE = auto()
    NOT_TOP_RANKED = auto()
    NO_AUTHORABLE_HYPOTHESIS = auto()


@dataclass(frozen=True, slots=True)
class CandidateScoreBreakdown:
    """
    Deterministic score components for one authored candidate.

    Higher total_score is better.
    """

    candidate_id: str
    total_score: float
    confidence_score: float
    policy_score: float
    evidence_score: float
    path_risk_score: float
    patch_size_score: float
    hypothesis_score: float
    review_penalty: float
    reasons: tuple[str, ...] = field(default_factory=tuple)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "candidate_id",
            _normalize_identifier(self.candidate_id, label="candidate_id"),
        )
        object.__setattr__(
            self,
            "reasons",
            tuple(_normalize_text(reason, label="reason") for reason in self.reasons),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "total_score": self.total_score,
            "confidence_score": self.confidence_score,
            "policy_score": self.policy_score,
            "evidence_score": self.evidence_score,
            "path_risk_score": self.path_risk_score,
            "patch_size_score": self.patch_size_score,
            "hypothesis_score": self.hypothesis_score,
            "review_penalty": self.review_penalty,
            "reasons": list(self.reasons),
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        return cls(
            candidate_id=_require_text(payload, "candidate_id"),
            total_score=_require_float(payload, "total_score"),
            confidence_score=_require_float(payload, "confidence_score"),
            policy_score=_require_float(payload, "policy_score"),
            evidence_score=_require_float(payload, "evidence_score"),
            path_risk_score=_require_float(payload, "path_risk_score"),
            patch_size_score=_require_float(payload, "patch_size_score"),
            hypothesis_score=_require_float(payload, "hypothesis_score"),
            review_penalty=_require_float(payload, "review_penalty"),
            reasons=_coerce_text_tuple(payload.get("reasons", ()), field_name="reasons"),
            metadata=_coerce_mapping(payload.get("metadata", {}), field_name="metadata"),
        )


@dataclass(frozen=True, slots=True)
class RankedRepairCandidate:
    """
    One candidate after Wave 3 ranking and selection analysis.
    """

    candidate: CompiledPatchCandidate
    score: CandidateScoreBreakdown
    disposition: CandidateDisposition
    rejection_reasons: tuple[CandidateRejectionReason, ...] = field(default_factory=tuple)
    proposal_id: str | None = None
    proposal_digest: str | None = None
    policy_report_id: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "rejection_reasons", tuple(self.rejection_reasons))
        object.__setattr__(
            self,
            "proposal_id",
            _normalize_optional_identifier(self.proposal_id, label="proposal_id"),
        )
        object.__setattr__(
            self,
            "proposal_digest",
            _normalize_optional_sha256(self.proposal_digest),
        )
        object.__setattr__(
            self,
            "policy_report_id",
            _normalize_optional_identifier(self.policy_report_id, label="policy_report_id"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def candidate_id(self) -> str:
        return self.candidate.candidate_id

    @property
    def selected(self) -> bool:
        return self.disposition is CandidateDisposition.SELECTED

    @property
    def rejected(self) -> bool:
        return self.disposition in {
            CandidateDisposition.REJECTED,
            CandidateDisposition.BLOCKED,
            CandidateDisposition.REQUIRES_REVIEW,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "patch_id": self.candidate.patch_id,
            "patch_digest": self.candidate.patch_digest,
            "proposal_id": self.proposal_id,
            "proposal_digest": self.proposal_digest,
            "policy_report_id": self.policy_report_id,
            "disposition": self.disposition.value,
            "selected": self.selected,
            "rejected": self.rejected,
            "rejection_reasons": [reason.value for reason in self.rejection_reasons],
            "changed_paths": list(self.candidate.changed_paths),
            "score": self.score.to_dict(),
            "candidate": self.candidate.to_dict(),
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class RepairCandidateSelectionReport:
    """
    Complete Wave 3 candidate ranking result.

    This report preserves selected, rejected, review-required, blocked, and
    available candidates. It is intentionally reviewable and deterministic.
    """

    report_id: str
    ranked_candidates: tuple[RankedRepairCandidate, ...]
    selected_candidate_id: str | None = None
    findings: tuple[AuthoringFinding, ...] = field(default_factory=tuple)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "report_id",
            _normalize_identifier(self.report_id, label="report_id"),
        )
        candidates = tuple(self.ranked_candidates)
        if not candidates:
            raise ValueError("RepairCandidateSelectionReport requires at least one candidate.")
        object.__setattr__(self, "ranked_candidates", candidates)
        object.__setattr__(
            self,
            "selected_candidate_id",
            _normalize_optional_identifier(self.selected_candidate_id, label="selected_candidate_id"),
        )
        object.__setattr__(self, "findings", tuple(self.findings))
        object.__setattr__(self, "metadata", dict(self.metadata))

        candidate_ids = {candidate.candidate_id for candidate in candidates}
        if len(candidate_ids) != len(candidates):
            raise ValueError("Candidate ids must be unique in a selection report.")

        if self.selected_candidate_id is not None and self.selected_candidate_id not in candidate_ids:
            raise ValueError("selected_candidate_id must match a ranked candidate.")

        selected_count = sum(1 for candidate in candidates if candidate.selected)
        if selected_count > 1:
            raise ValueError("At most one candidate may be marked selected.")

    @property
    def selected_candidate(self) -> RankedRepairCandidate | None:
        if self.selected_candidate_id is None:
            return None
        for candidate in self.ranked_candidates:
            if candidate.candidate_id == self.selected_candidate_id:
                return candidate
        return None

    @property
    def rejected_candidates(self) -> tuple[RankedRepairCandidate, ...]:
        return tuple(candidate for candidate in self.ranked_candidates if candidate.rejected)

    @property
    def blocked_candidates(self) -> tuple[RankedRepairCandidate, ...]:
        return tuple(
            candidate
            for candidate in self.ranked_candidates
            if candidate.disposition is CandidateDisposition.BLOCKED
        )

    @property
    def review_required_candidates(self) -> tuple[RankedRepairCandidate, ...]:
        return tuple(
            candidate
            for candidate in self.ranked_candidates
            if candidate.disposition is CandidateDisposition.REQUIRES_REVIEW
        )

    @property
    def available_candidates(self) -> tuple[RankedRepairCandidate, ...]:
        return tuple(
            candidate
            for candidate in self.ranked_candidates
            if candidate.disposition in {
                CandidateDisposition.SELECTED,
                CandidateDisposition.AVAILABLE,
            }
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_id": self.report_id,
            "selected_candidate_id": self.selected_candidate_id,
            "candidate_count": len(self.ranked_candidates),
            "rejected_count": len(self.rejected_candidates),
            "blocked_count": len(self.blocked_candidates),
            "review_required_count": len(self.review_required_candidates),
            "available_count": len(self.available_candidates),
            "ranked_candidates": [candidate.to_dict() for candidate in self.ranked_candidates],
            "findings": [finding.to_dict() for finding in self.findings],
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class RepairCandidateRankerConfig:
    """
    Deterministic ranking thresholds for Wave 3 authored candidates.
    """

    minimum_selectable_score: float = 40.0
    minimum_selectable_confidence: float = 0.35
    maximum_path_risk_score_for_selection: float = 35.0
    maximum_total_size_delta_for_selection: int = 8_000
    direct_evidence_bonus: float = 15.0
    weak_evidence_bonus: float = 5.0
    missing_evidence_penalty: float = 15.0
    review_required_penalty: float = 20.0
    blocked_penalty: float = 100.0
    governance_path_penalty: float = 30.0
    test_path_penalty: float = 12.0
    dependency_path_penalty: float = 25.0
    create_file_penalty: float = 10.0
    small_patch_bonus: float = 12.0
    source_path_bonus: float = 8.0
    hypothesis_match_bonus: float = 10.0
    no_authorable_hypothesis_penalty: float = 25.0
    governance_path_patterns: tuple[str, ...] = (
        "policy",
        "approval",
        "acceptance",
        "validator",
        "receipt",
        "workspace",
        "control_plane",
        "manifest",
    )
    test_path_patterns: tuple[str, ...] = (
        "tests/",
        "/tests/",
        "test_",
    )
    dependency_path_patterns: tuple[str, ...] = (
        "pyproject.toml",
        "requirements",
        "poetry.lock",
        "pdm.lock",
        "uv.lock",
        "package.json",
        "package-lock.json",
        "dockerfile",
    )

    def __post_init__(self) -> None:
        if self.minimum_selectable_score < 0.0:
            raise ValueError("minimum_selectable_score must be zero or greater.")
        if self.minimum_selectable_confidence < 0.0 or self.minimum_selectable_confidence > 1.0:
            raise ValueError("minimum_selectable_confidence must be between 0.0 and 1.0.")
        if self.maximum_path_risk_score_for_selection < 0.0:
            raise ValueError("maximum_path_risk_score_for_selection must be zero or greater.")
        if self.maximum_total_size_delta_for_selection <= 0:
            raise ValueError("maximum_total_size_delta_for_selection must be positive.")

        for field_name in (
            "governance_path_patterns",
            "test_path_patterns",
            "dependency_path_patterns",
        ):
            object.__setattr__(
                self,
                field_name,
                _normalize_pattern_tuple(getattr(self, field_name), field_name=field_name),
            )


@dataclass(frozen=True, slots=True)
class RepairCandidateRanker:
    """
    Deterministic Wave 3 candidate ranker and selector.

    The ranker does not execute patches. It evaluates already compiled
    candidates, parsed proposals, policy decisions, evidence strength, and
    repair hypotheses to choose the safest candidate that is eligible for
    governed Wave 2 execution.
    """

    config: RepairCandidateRankerConfig = field(default_factory=RepairCandidateRankerConfig)

    def rank(
        self,
        *,
        candidates: Iterable[CompiledPatchCandidate],
        proposals: Iterable[PatchAuthoringProposal],
        policy_reports: Iterable[AuthoringPolicyReport] = (),
        evidence: Iterable[AuthoringEvidence] = (),
        hypotheses: RepairHypothesisReport | None = None,
    ) -> RepairCandidateSelectionReport:
        candidate_tuple = tuple(candidates)
        if not candidate_tuple:
            raise ValueError("At least one compiled candidate is required.")

        proposal_by_id = {proposal.proposal_id: proposal for proposal in proposals}
        policy_by_candidate_id = {
            report.candidate_id: report
            for report in policy_reports
            if report.candidate_id is not None
        }
        evidence_tuple = tuple(evidence)

        scored: list[RankedRepairCandidate] = []
        patch_digests_seen: set[str] = set()

        for candidate in candidate_tuple:
            proposal = proposal_by_id.get(candidate.proposal_id)
            policy_report = policy_by_candidate_id.get(candidate.candidate_id)
            rejection_reasons: list[CandidateRejectionReason] = []

            if proposal is None:
                rejection_reasons.append(CandidateRejectionReason.PROPOSAL_NOT_FOUND)

            if policy_report is None:
                rejection_reasons.append(CandidateRejectionReason.POLICY_NOT_FOUND)

            if proposal is not None and candidate.proposal_digest != proposal.digest:
                rejection_reasons.append(CandidateRejectionReason.PROPOSAL_DIGEST_MISMATCH)

            if policy_report is not None and policy_report.proposal_digest != candidate.proposal_digest:
                rejection_reasons.append(CandidateRejectionReason.POLICY_PROPOSAL_MISMATCH)

            if candidate.patch_digest in patch_digests_seen:
                rejection_reasons.append(CandidateRejectionReason.PATCH_DIGEST_DUPLICATE)
            patch_digests_seen.add(candidate.patch_digest)

            if policy_report is not None:
                if policy_report.decision is AuthoringPolicyDecision.BLOCK:
                    rejection_reasons.append(CandidateRejectionReason.BLOCKED_BY_POLICY)
                elif policy_report.decision is AuthoringPolicyDecision.REQUIRE_REVIEW:
                    rejection_reasons.append(CandidateRejectionReason.REVIEW_REQUIRED)

            if hypotheses is not None and not hypotheses.contains_authorable_hypothesis:
                rejection_reasons.append(CandidateRejectionReason.NO_AUTHORABLE_HYPOTHESIS)

            score = self._score_candidate(
                candidate=candidate,
                proposal=proposal,
                policy_report=policy_report,
                evidence=evidence_tuple,
                hypotheses=hypotheses,
            )

            if proposal is not None and proposal.confidence < self.config.minimum_selectable_confidence:
                rejection_reasons.append(CandidateRejectionReason.LOW_CONFIDENCE)

            if score.path_risk_score > self.config.maximum_path_risk_score_for_selection:
                rejection_reasons.append(CandidateRejectionReason.PATH_RISK_TOO_HIGH)

            if abs(_patch_size_delta(candidate)) > self.config.maximum_total_size_delta_for_selection:
                rejection_reasons.append(CandidateRejectionReason.PATCH_TOO_LARGE)

            disposition = self._initial_disposition(rejection_reasons)

            if (
                disposition is CandidateDisposition.AVAILABLE
                and score.total_score < self.config.minimum_selectable_score
            ):
                rejection_reasons.append(CandidateRejectionReason.LOW_SCORE)
                disposition = CandidateDisposition.REJECTED

            scored.append(
                RankedRepairCandidate(
                    candidate=candidate,
                    score=score,
                    disposition=disposition,
                    rejection_reasons=tuple(_dedupe_rejection_reasons(rejection_reasons)),
                    proposal_id=None if proposal is None else proposal.proposal_id,
                    proposal_digest=None if proposal is None else proposal.digest,
                    policy_report_id=None if policy_report is None else policy_report.report_id,
                    metadata={
                        "proposal_found": proposal is not None,
                        "policy_found": policy_report is not None,
                        "hypotheses_attached": hypotheses is not None,
                    },
                )
            )

        ranked = tuple(
            sorted(
                scored,
                key=lambda item: (
                    _disposition_sort_score(item.disposition),
                    -item.score.total_score,
                    item.score.path_risk_score,
                    abs(item.candidate.patch_diff.total_size_delta),
                    item.candidate.candidate_id,
                ),
            )
        )

        selected_candidate_id: str | None = None
        final_ranked: list[RankedRepairCandidate] = []

        for index, ranked_candidate in enumerate(ranked):
            if index == 0 and ranked_candidate.disposition is CandidateDisposition.AVAILABLE:
                selected_candidate_id = ranked_candidate.candidate_id
                final_ranked.append(
                    _replace_ranked_disposition(
                        ranked_candidate,
                        disposition=CandidateDisposition.SELECTED,
                        rejection_reasons=(),
                    )
                )
                continue

            if ranked_candidate.disposition is CandidateDisposition.AVAILABLE:
                final_ranked.append(
                    _replace_ranked_disposition(
                        ranked_candidate,
                        disposition=CandidateDisposition.REJECTED,
                        rejection_reasons=(
                            CandidateRejectionReason.NOT_TOP_RANKED,
                        ),
                    )
                )
                continue

            final_ranked.append(ranked_candidate)

        findings = self._build_findings(
            ranked_candidates=tuple(final_ranked),
            selected_candidate_id=selected_candidate_id,
        )

        return RepairCandidateSelectionReport(
            report_id=f"candidate-selection-report-{uuid4().hex}",
            ranked_candidates=tuple(final_ranked),
            selected_candidate_id=selected_candidate_id,
            findings=findings,
            metadata={
                "ranker": "RepairCandidateRanker",
                "candidate_count": len(final_ranked),
                "selected": selected_candidate_id is not None,
                "minimum_selectable_score": self.config.minimum_selectable_score,
                "minimum_selectable_confidence": self.config.minimum_selectable_confidence,
            },
        )

    def _score_candidate(
        self,
        *,
        candidate: CompiledPatchCandidate,
        proposal: PatchAuthoringProposal | None,
        policy_report: AuthoringPolicyReport | None,
        evidence: tuple[AuthoringEvidence, ...],
        hypotheses: RepairHypothesisReport | None,
    ) -> CandidateScoreBreakdown:
        reasons: list[str] = []

        confidence_score = 0.0
        if proposal is not None:
            confidence_score = proposal.confidence * 30.0
            reasons.append(f"proposal confidence contributes {confidence_score:.2f}")

        policy_score = 0.0
        review_penalty = 0.0
        if policy_report is None:
            policy_score -= 20.0
            reasons.append("missing policy report penalized")
        elif policy_report.decision is AuthoringPolicyDecision.ALLOW:
            policy_score += 20.0
            reasons.append("policy allow decision rewarded")
        elif policy_report.decision is AuthoringPolicyDecision.REQUIRE_REVIEW:
            review_penalty = self.config.review_required_penalty
            policy_score -= review_penalty
            reasons.append("review-required policy decision penalized")
        elif policy_report.decision is AuthoringPolicyDecision.BLOCK:
            policy_score -= self.config.blocked_penalty
            reasons.append("blocked policy decision heavily penalized")

        evidence_score = self._evidence_score(evidence, reasons=reasons)
        path_risk_score = self._path_risk_score(candidate.changed_paths, reasons=reasons)
        patch_size_score = self._patch_size_score(candidate, proposal, reasons=reasons)
        hypothesis_score = self._hypothesis_score(
            candidate=candidate,
            hypotheses=hypotheses,
            reasons=reasons,
        )

        total_score = (
            50.0
            + confidence_score
            + policy_score
            + evidence_score
            + patch_size_score
            + hypothesis_score
            - path_risk_score
        )

        return CandidateScoreBreakdown(
            candidate_id=candidate.candidate_id,
            total_score=round(total_score, 4),
            confidence_score=round(confidence_score, 4),
            policy_score=round(policy_score, 4),
            evidence_score=round(evidence_score, 4),
            path_risk_score=round(path_risk_score, 4),
            patch_size_score=round(patch_size_score, 4),
            hypothesis_score=round(hypothesis_score, 4),
            review_penalty=round(review_penalty, 4),
            reasons=tuple(reasons),
            metadata={
                "changed_paths": list(candidate.changed_paths),
                "patch_size_delta": candidate.patch_diff.total_size_delta,
            },
        )

    def _evidence_score(
        self,
        evidence: tuple[AuthoringEvidence, ...],
        *,
        reasons: list[str],
    ) -> float:
        if not evidence:
            reasons.append("missing evidence penalized")
            return -self.config.missing_evidence_penalty

        if any(item.strength is AuthoringEvidenceStrength.DIRECT for item in evidence):
            reasons.append("direct evidence rewarded")
            return self.config.direct_evidence_bonus

        if any(item.strength is AuthoringEvidenceStrength.WEAK for item in evidence):
            reasons.append("weak evidence modestly rewarded")
            return self.config.weak_evidence_bonus

        reasons.append("missing-strength evidence penalized")
        return -self.config.missing_evidence_penalty

    def _path_risk_score(
        self,
        changed_paths: tuple[str, ...],
        *,
        reasons: list[str],
    ) -> float:
        score = 0.0

        for path in changed_paths:
            lowered = path.lower().replace("\\", "/")

            if _matches_any(lowered, self.config.governance_path_patterns):
                score += self.config.governance_path_penalty
                reasons.append(f"governance-sensitive path penalized: {path}")

            if _matches_any(lowered, self.config.test_path_patterns):
                score += self.config.test_path_penalty
                reasons.append(f"test path penalized: {path}")

            if _matches_any(lowered, self.config.dependency_path_patterns):
                score += self.config.dependency_path_penalty
                reasons.append(f"dependency/config path penalized: {path}")

            if lowered.startswith("src/"):
                score -= self.config.source_path_bonus
                reasons.append(f"source path rewarded: {path}")

        return max(score, 0.0)

    def _patch_size_score(
        self,
        candidate: CompiledPatchCandidate,
        proposal: PatchAuthoringProposal | None,
        *,
        reasons: list[str],
    ) -> float:
        score = 0.0
        size_delta = abs(candidate.patch_diff.total_size_delta)

        if size_delta <= 400:
            score += self.config.small_patch_bonus
            reasons.append("small patch rewarded")
        elif size_delta > self.config.maximum_total_size_delta_for_selection:
            score -= 20.0
            reasons.append("large patch penalized")

        if proposal is not None:
            create_count = sum(
                1
                for mutation in proposal.mutations
                if mutation.mutation_type.value == "create_file"
            )
            if create_count:
                penalty = create_count * self.config.create_file_penalty
                score -= penalty
                reasons.append(f"create-file mutation penalty applied: {penalty:.2f}")

        return score

    def _hypothesis_score(
        self,
        *,
        candidate: CompiledPatchCandidate,
        hypotheses: RepairHypothesisReport | None,
        reasons: list[str],
    ) -> float:
        if hypotheses is None:
            return 0.0

        selected = hypotheses.selected_hypothesis
        if not hypotheses.contains_authorable_hypothesis:
            reasons.append("no authorable hypothesis penalized")
            return -self.config.no_authorable_hypothesis_penalty

        candidate_paths = set(candidate.changed_paths)
        hypothesis_paths = set(selected.target_paths)
        if candidate_paths and hypothesis_paths and candidate_paths & hypothesis_paths:
            reasons.append("candidate path matches selected hypothesis")
            return self.config.hypothesis_match_bonus

        if selected.failure_class in {
            RepairFailureClass.IMPORT_ERROR,
            RepairFailureClass.MISSING_SYMBOL,
            RepairFailureClass.SYNTAX_ERROR,
            RepairFailureClass.ASSERTION_MISMATCH,
        } and selected.expected_repair_shape not in {
            RepairShape.DO_NOT_AUTHOR_PATCH,
            RepairShape.REQUIRE_HUMAN_REVIEW,
        }:
            reasons.append("authorable hypothesis modestly rewarded")
            return self.config.hypothesis_match_bonus / 2.0

        return 0.0

    def _initial_disposition(
        self,
        rejection_reasons: list[CandidateRejectionReason],
    ) -> CandidateDisposition:
        if CandidateRejectionReason.BLOCKED_BY_POLICY in rejection_reasons:
            return CandidateDisposition.BLOCKED

        if any(
            reason in rejection_reasons
            for reason in (
                CandidateRejectionReason.PROPOSAL_NOT_FOUND,
                CandidateRejectionReason.PROPOSAL_DIGEST_MISMATCH,
                CandidateRejectionReason.POLICY_NOT_FOUND,
                CandidateRejectionReason.POLICY_PROPOSAL_MISMATCH,
                CandidateRejectionReason.PATCH_DIGEST_DUPLICATE,
                CandidateRejectionReason.PATH_RISK_TOO_HIGH,
                CandidateRejectionReason.PATCH_TOO_LARGE,
                CandidateRejectionReason.LOW_CONFIDENCE,
                CandidateRejectionReason.NO_AUTHORABLE_HYPOTHESIS,
            )
        ):
            return CandidateDisposition.REJECTED

        if CandidateRejectionReason.REVIEW_REQUIRED in rejection_reasons:
            return CandidateDisposition.REQUIRES_REVIEW

        return CandidateDisposition.AVAILABLE

    def _build_findings(
        self,
        *,
        ranked_candidates: tuple[RankedRepairCandidate, ...],
        selected_candidate_id: str | None,
    ) -> tuple[AuthoringFinding, ...]:
        findings: list[AuthoringFinding] = []

        if selected_candidate_id is None:
            findings.append(
                AuthoringFinding(
                    code="authoring.candidates.no_candidate_selected",
                    severity=AuthoringFindingSeverity.WARNING,
                    summary="No authored repair candidate was selectable under the ranking policy.",
                    metadata={
                        "candidate_count": len(ranked_candidates),
                        "blocked_count": sum(
                            1
                            for candidate in ranked_candidates
                            if candidate.disposition is CandidateDisposition.BLOCKED
                        ),
                        "review_required_count": sum(
                            1
                            for candidate in ranked_candidates
                            if candidate.disposition is CandidateDisposition.REQUIRES_REVIEW
                        ),
                    },
                )
            )
        else:
            findings.append(
                AuthoringFinding(
                    code="authoring.candidates.candidate_selected",
                    severity=AuthoringFindingSeverity.INFO,
                    summary="A Wave 3 authored repair candidate was selected for governed handoff.",
                    metadata={
                        "selected_candidate_id": selected_candidate_id,
                    },
                )
            )

        for candidate in ranked_candidates:
            if candidate.rejected:
                findings.append(
                    AuthoringFinding(
                        code="authoring.candidates.candidate_not_selected",
                        severity=AuthoringFindingSeverity.WARNING
                        if candidate.disposition is not CandidateDisposition.BLOCKED
                        else AuthoringFindingSeverity.ERROR,
                        summary="A Wave 3 authored repair candidate was not selected.",
                        metadata={
                            "candidate_id": candidate.candidate_id,
                            "disposition": candidate.disposition.value,
                            "rejection_reasons": [
                                reason.value for reason in candidate.rejection_reasons
                            ],
                        },
                    )
                )

        return _dedupe_authoring_findings(findings)


def _replace_ranked_disposition(
    candidate: RankedRepairCandidate,
    *,
    disposition: CandidateDisposition,
    rejection_reasons: tuple[CandidateRejectionReason, ...],
) -> RankedRepairCandidate:
    return RankedRepairCandidate(
        candidate=candidate.candidate,
        score=candidate.score,
        disposition=disposition,
        rejection_reasons=rejection_reasons,
        proposal_id=candidate.proposal_id,
        proposal_digest=candidate.proposal_digest,
        policy_report_id=candidate.policy_report_id,
        metadata=candidate.metadata,
    )


def _disposition_sort_score(disposition: CandidateDisposition) -> int:
    if disposition is CandidateDisposition.AVAILABLE:
        return 0
    if disposition is CandidateDisposition.REQUIRES_REVIEW:
        return 1
    if disposition is CandidateDisposition.REJECTED:
        return 2
    if disposition is CandidateDisposition.BLOCKED:
        return 3
    if disposition is CandidateDisposition.SELECTED:
        return -1
    return 9


def _dedupe_rejection_reasons(
    reasons: Iterable[CandidateRejectionReason],
) -> tuple[CandidateRejectionReason, ...]:
    deduped: list[CandidateRejectionReason] = []
    seen: set[CandidateRejectionReason] = set()

    for reason in reasons:
        if reason in seen:
            continue
        seen.add(reason)
        deduped.append(reason)

    return tuple(deduped)


def _dedupe_authoring_findings(
    findings: Iterable[AuthoringFinding],
) -> tuple[AuthoringFinding, ...]:
    deduped: list[AuthoringFinding] = []
    seen: set[tuple[str, str | None, str]] = set()

    for finding in findings:
        key = (finding.code, finding.path, finding.summary)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)

    return tuple(deduped)


def _matches_any(text: str, patterns: tuple[str, ...]) -> bool:
    return any(pattern in text for pattern in patterns)


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


def _require_float(payload: Mapping[str, Any], key: str) -> float:
    value = payload.get(key)
    if not isinstance(value, int | float):
        raise TypeError(f"Field {key!r} must be a number.")
    return float(value)
