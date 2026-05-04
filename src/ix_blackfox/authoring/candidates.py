from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum, auto
from typing import Any, Self
from uuid import uuid4

from ix_blackfox.authoring.hypotheses import RepairHypothesisReport
from ix_blackfox.authoring.models import (
    AuthoringEvidence,
    AuthoringEvidenceStrength,
    PatchAuthoringProposal,
)
from ix_blackfox.authoring.policy import (
    AuthoringPolicyDecision,
    AuthoringPolicyReport,
)
from ix_blackfox.tools.patch import PatchDiff


class RepairCandidateDisposition(StrEnum):
    """
    Final ranking disposition for a compiled Wave 3 patch candidate.
    """

    SELECTED = auto()
    ELIGIBLE = auto()
    REQUIRES_REVIEW = auto()
    REJECTED = auto()
    BLOCKED = auto()


class RepairCandidateRejectionReason(StrEnum):
    """
    Normalized reasons a compiled patch candidate cannot be selected automatically.
    """

    POLICY_BLOCKED = auto()
    POLICY_REQUIRES_REVIEW = auto()
    NO_DIRECT_EVIDENCE = auto()
    NO_TESTS = auto()
    TOO_MANY_FILES = auto()
    TOO_LARGE = auto()
    LOW_CONFIDENCE = auto()
    HYPOTHESIS_MISMATCH = auto()
    DUPLICATE_PATCH = auto()


@dataclass(frozen=True, slots=True)
class RepairCandidateScore:
    """
    Deterministic score assigned before candidate selection.
    """

    total: float
    policy_score: float
    evidence_score: float
    test_score: float
    size_score: float
    confidence_score: float
    hypothesis_score: float
    risk_penalty: float
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for field_name in (
            "total",
            "policy_score",
            "evidence_score",
            "test_score",
            "size_score",
            "confidence_score",
            "hypothesis_score",
            "risk_penalty",
        ):
            value = getattr(self, field_name)
            if not isinstance(value, int | float):
                raise TypeError(f"{field_name} must be numeric.")
        object.__setattr__(self, "metadata", dict(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "policy_score": self.policy_score,
            "evidence_score": self.evidence_score,
            "test_score": self.test_score,
            "size_score": self.size_score,
            "confidence_score": self.confidence_score,
            "hypothesis_score": self.hypothesis_score,
            "risk_penalty": self.risk_penalty,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        return cls(
            total=_require_float(payload, "total"),
            policy_score=_require_float(payload, "policy_score"),
            evidence_score=_require_float(payload, "evidence_score"),
            test_score=_require_float(payload, "test_score"),
            size_score=_require_float(payload, "size_score"),
            confidence_score=_require_float(payload, "confidence_score"),
            hypothesis_score=_require_float(payload, "hypothesis_score"),
            risk_penalty=_require_float(payload, "risk_penalty"),
            metadata=_coerce_mapping(
                payload.get("metadata", {}), field_name="metadata"
            ),
        )


@dataclass(frozen=True, slots=True)
class RankedRepairCandidate:
    """
    One compiled patch candidate after scoring and governance disposition.
    """

    rank: int
    candidate_id: str
    proposal_id: str
    patch_id: str
    proposal_digest: str
    policy_report_id: str
    disposition: RepairCandidateDisposition
    score: RepairCandidateScore
    rejection_reasons: tuple[RepairCandidateRejectionReason, ...] = field(
        default_factory=tuple
    )
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.rank <= 0:
            raise ValueError("rank must be positive.")
        object.__setattr__(
            self,
            "candidate_id",
            _normalize_identifier(self.candidate_id, label="candidate_id"),
        )
        object.__setattr__(
            self,
            "proposal_id",
            _normalize_identifier(self.proposal_id, label="proposal_id"),
        )
        object.__setattr__(
            self,
            "patch_id",
            _normalize_identifier(self.patch_id, label="patch_id"),
        )
        object.__setattr__(
            self,
            "proposal_digest",
            _normalize_sha256(self.proposal_digest),
        )
        object.__setattr__(
            self,
            "policy_report_id",
            _normalize_identifier(self.policy_report_id, label="policy_report_id"),
        )
        object.__setattr__(self, "rejection_reasons", tuple(self.rejection_reasons))
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def selectable(self) -> bool:
        return self.disposition is RepairCandidateDisposition.ELIGIBLE

    @property
    def selected(self) -> bool:
        return self.disposition is RepairCandidateDisposition.SELECTED

    @property
    def blocked(self) -> bool:
        return self.disposition is RepairCandidateDisposition.BLOCKED

    @property
    def requires_review(self) -> bool:
        return self.disposition is RepairCandidateDisposition.REQUIRES_REVIEW

    @property
    def candidate(self) -> CompiledPatchCandidate:
        raw_candidate = self.metadata.get("candidate")
        if not isinstance(raw_candidate, CompiledPatchCandidate):
            raise ValueError("Ranked candidate metadata does not contain candidate.")
        return raw_candidate

    def with_rank_and_disposition(
        self,
        *,
        rank: int,
        disposition: RepairCandidateDisposition,
    ) -> Self:
        return type(self)(
            rank=rank,
            candidate_id=self.candidate_id,
            proposal_id=self.proposal_id,
            patch_id=self.patch_id,
            proposal_digest=self.proposal_digest,
            policy_report_id=self.policy_report_id,
            disposition=disposition,
            score=self.score,
            rejection_reasons=self.rejection_reasons,
            metadata=self.metadata,
        )

    def to_dict(self) -> dict[str, Any]:
        metadata = {
            key: value
            for key, value in self.metadata.items()
            if key != "candidate"
        }
        return {
            "rank": self.rank,
            "candidate_id": self.candidate_id,
            "proposal_id": self.proposal_id,
            "patch_id": self.patch_id,
            "proposal_digest": self.proposal_digest,
            "policy_report_id": self.policy_report_id,
            "disposition": self.disposition.value,
            "score": self.score.to_dict(),
            "rejection_reasons": [reason.value for reason in self.rejection_reasons],
            "metadata": metadata,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        score_payload = payload.get("score")
        if not isinstance(score_payload, Mapping):
            raise TypeError("score must be a mapping.")
        return cls(
            rank=_require_int(payload, "rank"),
            candidate_id=_require_text(payload, "candidate_id"),
            proposal_id=_require_text(payload, "proposal_id"),
            patch_id=_require_text(payload, "patch_id"),
            proposal_digest=_require_text(payload, "proposal_digest"),
            policy_report_id=_require_text(payload, "policy_report_id"),
            disposition=RepairCandidateDisposition(_require_text(payload, "disposition")),
            score=RepairCandidateScore.from_dict(score_payload),
            rejection_reasons=_coerce_rejection_reason_tuple(
                payload.get("rejection_reasons", ())
            ),
            metadata=_coerce_mapping(
                payload.get("metadata", {}), field_name="metadata"
            ),
        )


@dataclass(frozen=True, slots=True)
class CompiledPatchCandidate:
    """
    Patch candidate produced from a parsed Wave 3 proposal.
    """

    candidate_id: str
    proposal_id: str
    proposal_digest: str
    patch_diff: PatchDiff
    affected_paths: tuple[str, ...]
    tests_to_run: tuple[str, ...]
    rationale: str
    confidence: float
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "candidate_id",
            _normalize_identifier(self.candidate_id, label="candidate_id"),
        )
        object.__setattr__(
            self,
            "proposal_id",
            _normalize_identifier(self.proposal_id, label="proposal_id"),
        )
        object.__setattr__(
            self,
            "proposal_digest",
            _normalize_sha256(self.proposal_digest),
        )
        object.__setattr__(
            self,
            "affected_paths",
            tuple(_normalize_relative_path(path) for path in self.affected_paths),
        )
        object.__setattr__(
            self,
            "tests_to_run",
            tuple(_normalize_test_command(command) for command in self.tests_to_run),
        )
        object.__setattr__(
            self, "rationale", _normalize_text(self.rationale, label="rationale")
        )
        if self.confidence < 0.0 or self.confidence > 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0.")
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def patch_id(self) -> str:
        return self.patch_diff.patch_id

    @property
    def changed_paths(self) -> tuple[str, ...]:
        return self.patch_diff.changed_paths

    @property
    def total_size_delta(self) -> int:
        return self.patch_diff.total_size_delta

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "proposal_id": self.proposal_id,
            "proposal_digest": self.proposal_digest,
            "patch_id": self.patch_id,
            "changed_paths": list(self.changed_paths),
            "affected_paths": list(self.affected_paths),
            "tests_to_run": list(self.tests_to_run),
            "rationale": self.rationale,
            "confidence": self.confidence,
            "patch_diff": self.patch_diff.to_dict(),
            "total_size_delta": self.total_size_delta,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class RepairCandidateSelectionReport:
    """
    Complete deterministic ranking report for Wave 3 compiled patch candidates.
    """

    report_id: str
    selected_candidate: RankedRepairCandidate | None
    ranked_candidates: tuple[RankedRepairCandidate, ...]
    rejected_candidate_ids: tuple[str, ...] = field(default_factory=tuple)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "report_id",
            _normalize_identifier(self.report_id, label="report_id"),
        )
        object.__setattr__(self, "ranked_candidates", tuple(self.ranked_candidates))
        object.__setattr__(
            self,
            "rejected_candidate_ids",
            tuple(
                _normalize_identifier(item, label="rejected_candidate_id")
                for item in self.rejected_candidate_ids
            ),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def eligible_candidates(self) -> tuple[RankedRepairCandidate, ...]:
        return tuple(
            candidate
            for candidate in self.ranked_candidates
            if candidate.disposition
            in {
                RepairCandidateDisposition.ELIGIBLE,
                RepairCandidateDisposition.SELECTED,
            }
        )

    @property
    def blocked_candidates(self) -> tuple[RankedRepairCandidate, ...]:
        return tuple(
            candidate
            for candidate in self.ranked_candidates
            if candidate.blocked
        )

    @property
    def review_required_candidates(self) -> tuple[RankedRepairCandidate, ...]:
        return tuple(
            candidate
            for candidate in self.ranked_candidates
            if candidate.requires_review
        )

    @property
    def rejected_candidates(self) -> tuple[RankedRepairCandidate, ...]:
        return tuple(
            candidate
            for candidate in self.ranked_candidates
            if candidate.disposition is RepairCandidateDisposition.REJECTED
        )

    @property
    def has_selected_candidate(self) -> bool:
        return self.selected_candidate is not None

    @property
    def selected_candidate_id(self) -> str | None:
        if self.selected_candidate is None:
            return None
        return self.selected_candidate.candidate_id

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_id": self.report_id,
            "selected_candidate_id": self.selected_candidate_id,
            "ranked_candidates": [candidate.to_dict() for candidate in self.ranked_candidates],
            "rejected_candidate_ids": list(self.rejected_candidate_ids),
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class RepairCandidateRankerConfig:
    """
    Deterministic candidate ranking knobs.
    """

    max_auto_select_files: int = 3
    max_auto_select_size_delta: int = 2400
    min_auto_select_confidence: float = 0.45
    require_direct_evidence: bool = False
    require_tests: bool = True
    penalize_large_patches: bool = True
    deduplicate_patch_digests: bool = True

    def __post_init__(self) -> None:
        if self.max_auto_select_files <= 0:
            raise ValueError("max_auto_select_files must be positive.")
        if self.max_auto_select_size_delta <= 0:
            raise ValueError("max_auto_select_size_delta must be positive.")
        if self.min_auto_select_confidence < 0.0 or self.min_auto_select_confidence > 1.0:
            raise ValueError("min_auto_select_confidence must be between 0.0 and 1.0.")


@dataclass(frozen=True, slots=True)
class RepairCandidateRanker:
    """
    Rank compiled patch candidates without trusting model confidence alone.
    """

    config: RepairCandidateRankerConfig = field(default_factory=RepairCandidateRankerConfig)

    def rank(
        self,
        *,
        candidates: Iterable[CompiledPatchCandidate],
        proposals: Iterable[PatchAuthoringProposal],
        policy_reports: Iterable[AuthoringPolicyReport],
        evidence: Iterable[AuthoringEvidence],
        hypotheses: RepairHypothesisReport | None = None,
    ) -> RepairCandidateSelectionReport:
        candidate_tuple = tuple(candidates)
        proposal_by_id = {proposal.proposal_id: proposal for proposal in proposals}
        policy_by_proposal_id = {
            report.proposal_id: report for report in policy_reports
        }
        evidence_tuple = tuple(evidence)

        ranked: list[RankedRepairCandidate] = []
        seen_patch_digests: set[str] = set()

        for candidate in candidate_tuple:
            proposal = proposal_by_id.get(candidate.proposal_id)
            policy_report = policy_by_proposal_id.get(candidate.proposal_id)
            if proposal is None or policy_report is None:
                continue

            rejection_reasons = self._rejection_reasons(
                candidate=candidate,
                proposal=proposal,
                policy_report=policy_report,
                evidence=evidence_tuple,
                hypotheses=hypotheses,
                seen_patch_digests=seen_patch_digests,
            )
            score = self._score(
                candidate=candidate,
                proposal=proposal,
                policy_report=policy_report,
                evidence=evidence_tuple,
                hypotheses=hypotheses,
                rejection_reasons=rejection_reasons,
            )
            disposition = self._disposition(
                policy_report=policy_report,
                rejection_reasons=rejection_reasons,
            )
            ranked.append(
                RankedRepairCandidate(
                    rank=1,
                    candidate_id=candidate.candidate_id,
                    proposal_id=candidate.proposal_id,
                    patch_id=candidate.patch_id,
                    proposal_digest=candidate.proposal_digest,
                    policy_report_id=policy_report.report_id,
                    disposition=disposition,
                    score=score,
                    rejection_reasons=rejection_reasons,
                    metadata={
                        "candidate": candidate,
                        "changed_paths": candidate.changed_paths,
                        "tests_to_run": candidate.tests_to_run,
                    },
                )
            )
            seen_patch_digests.add(candidate.patch_diff.digest)

        ranked_sorted = sorted(
            ranked,
            key=lambda item: (
                _disposition_sort_order(item.disposition),
                -item.score.total,
                item.candidate_id,
            ),
        )
        final_ranked: list[RankedRepairCandidate] = []
        selected: RankedRepairCandidate | None = None
        for index, item in enumerate(ranked_sorted, start=1):
            disposition = item.disposition
            if selected is None and disposition is RepairCandidateDisposition.ELIGIBLE:
                disposition = RepairCandidateDisposition.SELECTED

            ranked_item = item.with_rank_and_disposition(
                rank=index,
                disposition=disposition,
            )
            final_ranked.append(ranked_item)
            if ranked_item.selected:
                selected = ranked_item

        return RepairCandidateSelectionReport(
            report_id=f"repair-candidate-selection-{uuid4().hex}",
            selected_candidate=selected,
            ranked_candidates=tuple(final_ranked),
            rejected_candidate_ids=tuple(
                candidate.candidate_id
                for candidate in final_ranked
                if candidate.disposition
                in {
                    RepairCandidateDisposition.REJECTED,
                    RepairCandidateDisposition.BLOCKED,
                }
            ),
            metadata={
                "candidate_count": len(candidate_tuple),
                "ranked_candidate_count": len(final_ranked),
                "selected_candidate_id": None if selected is None else selected.candidate_id,
            },
        )

    def _rejection_reasons(
        self,
        *,
        candidate: CompiledPatchCandidate,
        proposal: PatchAuthoringProposal,
        policy_report: AuthoringPolicyReport,
        evidence: tuple[AuthoringEvidence, ...],
        hypotheses: RepairHypothesisReport | None,
        seen_patch_digests: set[str],
    ) -> tuple[RepairCandidateRejectionReason, ...]:
        reasons: list[RepairCandidateRejectionReason] = []

        if policy_report.decision is AuthoringPolicyDecision.BLOCK:
            reasons.append(RepairCandidateRejectionReason.POLICY_BLOCKED)
        if policy_report.decision is AuthoringPolicyDecision.REQUIRE_REVIEW:
            reasons.append(RepairCandidateRejectionReason.POLICY_REQUIRES_REVIEW)

        if self.config.require_direct_evidence and not any(
            item.strength is AuthoringEvidenceStrength.DIRECT for item in evidence
        ):
            reasons.append(RepairCandidateRejectionReason.NO_DIRECT_EVIDENCE)

        if self.config.require_tests and not candidate.tests_to_run:
            reasons.append(RepairCandidateRejectionReason.NO_TESTS)

        if len(candidate.changed_paths) > self.config.max_auto_select_files:
            reasons.append(RepairCandidateRejectionReason.TOO_MANY_FILES)

        if abs(candidate.total_size_delta) > self.config.max_auto_select_size_delta:
            reasons.append(RepairCandidateRejectionReason.TOO_LARGE)

        if proposal.confidence < self.config.min_auto_select_confidence:
            reasons.append(RepairCandidateRejectionReason.LOW_CONFIDENCE)

        if self._hypothesis_mismatch(candidate=candidate, hypotheses=hypotheses):
            reasons.append(RepairCandidateRejectionReason.HYPOTHESIS_MISMATCH)

        if (
            self.config.deduplicate_patch_digests
            and candidate.patch_diff.digest in seen_patch_digests
        ):
            reasons.append(RepairCandidateRejectionReason.DUPLICATE_PATCH)

        return tuple(reasons)

    def _score(
        self,
        *,
        candidate: CompiledPatchCandidate,
        proposal: PatchAuthoringProposal,
        policy_report: AuthoringPolicyReport,
        evidence: tuple[AuthoringEvidence, ...],
        hypotheses: RepairHypothesisReport | None,
        rejection_reasons: tuple[RepairCandidateRejectionReason, ...],
    ) -> RepairCandidateScore:
        policy_score = _policy_score(policy_report)
        evidence_score = _evidence_score(evidence)
        test_score = 1.0 if candidate.tests_to_run else 0.0
        size_score = _size_score(
            size_delta=abs(candidate.total_size_delta),
            max_size_delta=self.config.max_auto_select_size_delta,
        )
        confidence_score = proposal.confidence
        hypothesis_score = 1.0 if not self._hypothesis_mismatch(candidate=candidate, hypotheses=hypotheses) else 0.0
        risk_penalty = _risk_penalty(rejection_reasons)

        total = (
            policy_score * 0.28
            + evidence_score * 0.18
            + test_score * 0.18
            + size_score * 0.14
            + confidence_score * 0.14
            + hypothesis_score * 0.08
            - risk_penalty
        )

        return RepairCandidateScore(
            total=round(total, 6),
            policy_score=round(policy_score, 6),
            evidence_score=round(evidence_score, 6),
            test_score=round(test_score, 6),
            size_score=round(size_score, 6),
            confidence_score=round(confidence_score, 6),
            hypothesis_score=round(hypothesis_score, 6),
            risk_penalty=round(risk_penalty, 6),
            metadata={
                "changed_path_count": len(candidate.changed_paths),
                "total_size_delta": candidate.total_size_delta,
                "rejection_reason_count": len(rejection_reasons),
            },
        )

    def _disposition(
        self,
        *,
        policy_report: AuthoringPolicyReport,
        rejection_reasons: tuple[RepairCandidateRejectionReason, ...],
    ) -> RepairCandidateDisposition:
        if RepairCandidateRejectionReason.POLICY_BLOCKED in rejection_reasons:
            return RepairCandidateDisposition.BLOCKED

        if policy_report.decision is AuthoringPolicyDecision.REQUIRE_REVIEW:
            return RepairCandidateDisposition.REQUIRES_REVIEW

        if rejection_reasons:
            return RepairCandidateDisposition.REJECTED

        return RepairCandidateDisposition.ELIGIBLE

    def _hypothesis_mismatch(
        self,
        *,
        candidate: CompiledPatchCandidate,
        hypotheses: RepairHypothesisReport | None,
    ) -> bool:
        if hypotheses is None or not hypotheses.selected_hypothesis:
            return False
        target_paths = set(hypotheses.selected_hypothesis.target_paths)
        if not target_paths:
            return False
        return not bool(target_paths.intersection(candidate.changed_paths))


def _patch_size_delta(patch_diff: PatchDiff) -> int:
    return patch_diff.total_size_delta


def _policy_score(policy_report: AuthoringPolicyReport) -> float:
    if policy_report.decision is AuthoringPolicyDecision.ALLOW:
        return 1.0
    if policy_report.decision is AuthoringPolicyDecision.REQUIRE_REVIEW:
        return 0.35
    return 0.0


def _evidence_score(evidence: tuple[AuthoringEvidence, ...]) -> float:
    if not evidence:
        return 0.0
    if any(item.strength is AuthoringEvidenceStrength.DIRECT for item in evidence):
        return 1.0
    if any(item.strength is AuthoringEvidenceStrength.WEAK for item in evidence):
        return 0.55
    return 0.0


def _size_score(*, size_delta: int, max_size_delta: int) -> float:
    if size_delta <= 0:
        return 1.0
    if size_delta >= max_size_delta:
        return 0.0
    return max(0.0, 1.0 - (size_delta / max_size_delta))


def _risk_penalty(
    rejection_reasons: tuple[RepairCandidateRejectionReason, ...],
) -> float:
    penalty = 0.0
    for reason in rejection_reasons:
        if reason in {
            RepairCandidateRejectionReason.POLICY_BLOCKED,
            RepairCandidateRejectionReason.POLICY_REQUIRES_REVIEW,
        }:
            penalty += 0.65
        elif reason in {
            RepairCandidateRejectionReason.TOO_LARGE,
            RepairCandidateRejectionReason.TOO_MANY_FILES,
        }:
            penalty += 0.25
        else:
            penalty += 0.15
    return penalty


def _disposition_sort_order(disposition: RepairCandidateDisposition) -> int:
    if disposition is RepairCandidateDisposition.ELIGIBLE:
        return 0
    if disposition is RepairCandidateDisposition.REQUIRES_REVIEW:
        return 1
    if disposition is RepairCandidateDisposition.REJECTED:
        return 2
    if disposition is RepairCandidateDisposition.BLOCKED:
        return 3
    if disposition is RepairCandidateDisposition.SELECTED:
        return 0
    return 4


def _normalize_identifier(value: str, *, label: str) -> str:
    cleaned = value.strip().lower().replace(" ", "-")
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_relative_path(value: str) -> str:
    cleaned = value.strip().replace("\\", "/")
    if not cleaned:
        raise ValueError("path must not be empty.")
    if cleaned.startswith(("/", "~")) or ":" in cleaned.split("/")[0]:
        raise ValueError(f"path must be relative: {value!r}.")

    parts: list[str] = []
    for raw_part in cleaned.split("/"):
        part = raw_part.strip()
        if part in {"", "."}:
            continue
        if part == "..":
            raise ValueError(f"path must not contain traversal: {value!r}.")
        parts.append(part)

    if not parts:
        raise ValueError("path must not resolve to the workspace root.")
    return "/".join(parts)


def _normalize_test_command(value: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError("test command must not be empty.")
    return cleaned


def _normalize_sha256(value: str) -> str:
    cleaned = value.strip().lower()
    if len(cleaned) != 64 or any(char not in "0123456789abcdef" for char in cleaned):
        raise ValueError("sha256 must be a 64-character lowercase hexadecimal digest.")
    return cleaned


def _coerce_rejection_reason_tuple(
    value: Any,
) -> tuple[RepairCandidateRejectionReason, ...]:
    if not isinstance(value, Iterable) or isinstance(value, str):
        raise TypeError("rejection_reasons must be an iterable.")
    return tuple(RepairCandidateRejectionReason(item) for item in value)


def _coerce_mapping(value: Any, *, field_name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{field_name} must be a mapping.")
    return dict(value)


def _require_text(payload: Mapping[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str):
        raise TypeError(f"Field {key!r} must be a string.")
    return value


def _require_int(payload: Mapping[str, Any], key: str) -> int:
    value = payload.get(key)
    if not isinstance(value, int):
        raise TypeError(f"Field {key!r} must be an integer.")
    return value


def _require_float(payload: Mapping[str, Any], key: str) -> float:
    value = payload.get(key)
    if not isinstance(value, int | float):
        raise TypeError(f"Field {key!r} must be numeric.")
    return float(value)


def _digest_payload(value: Any) -> str:
    canonical = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()
