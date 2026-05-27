from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from ix_blackfox.authoring import PatchAuthoringPromptContract
from ix_blackfox.brains import (
    BrainComparisonCandidate,
    BrainComparisonDecision,
    BrainComparisonRequest,
    BrainComparisonScore,
    BrainModelComparator,
    BrainModelTribunal,
    BrainRole,
    BrainTribunalAction,
    BrainTribunalAssignment,
    BrainTribunalDecision,
    BrainTribunalDisposition,
    BrainTribunalIdentity,
    BrainTribunalReviewRequest,
    BrainTribunalRoleKind,
)
from ix_blackfox.runtime.authoring_repair import PatchProposalProvider


@dataclass(frozen=True, slots=True)
class BrainRepairCandidateSource:
    """
    One provider-backed Wave 7 repair-candidate source.

    The source wraps any existing patch proposal provider and attaches model
    identity, comparison scoring defaults, and tribunal-origin metadata. It does
    not grant the provider execution, filesystem, approval, or test authority.
    """

    source_id: str
    provider: PatchProposalProvider
    brain_name: str
    provider_name: str
    model_name: str
    role: BrainRole = BrainRole.PRIMARY
    score: BrainComparisonScore = field(default_factory=BrainComparisonScore)
    tribunal_role_id: str = "generator-role"
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "source_id",
            _normalize_identifier(self.source_id, label="source_id"),
        )
        object.__setattr__(
            self,
            "brain_name",
            _normalize_identifier(self.brain_name, label="brain_name"),
        )
        object.__setattr__(
            self,
            "provider_name",
            _normalize_identifier(self.provider_name, label="provider_name"),
        )
        object.__setattr__(self, "model_name", _normalize_model_name(self.model_name))
        object.__setattr__(
            self,
            "tribunal_role_id",
            _normalize_identifier(self.tribunal_role_id, label="tribunal_role_id"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def identity(self) -> BrainTribunalIdentity:
        """
        Return the model identity used by the tribunal self-review guard.
        """
        return BrainTribunalIdentity(
            brain_name=self.brain_name,
            provider_name=self.provider_name,
            model_name=self.model_name,
            metadata={"source_id": self.source_id, **dict(self.metadata)},
        )

    def to_dict(self) -> dict[str, object]:
        """
        Return a JSON-serializable source description.
        """
        return {
            "source_id": self.source_id,
            "brain_name": self.brain_name,
            "provider_name": self.provider_name,
            "model_name": self.model_name,
            "role": self.role.value,
            "score": self.score.to_dict(),
            "tribunal_role_id": self.tribunal_role_id,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class BrainRepairProposalRecord:
    """
    One raw repair proposal emitted by a Wave 7 candidate source.
    """

    source: BrainRepairCandidateSource
    response_index: int
    candidate: BrainComparisonCandidate
    raw_response: str | None = None
    error: str | None = None

    def __post_init__(self) -> None:
        if self.response_index <= 0:
            raise ValueError("response_index must be greater than zero.")
        object.__setattr__(self, "raw_response", _normalize_optional_text(self.raw_response))
        object.__setattr__(self, "error", _normalize_optional_text(self.error))
        if self.candidate.eligible and self.raw_response is None:
            raise ValueError("eligible repair proposal records require raw_response.")
        if not self.candidate.eligible and self.error is None:
            raise ValueError("ineligible repair proposal records require error.")

    def to_dict(self) -> dict[str, object]:
        """
        Return a JSON-serializable proposal record.
        """
        return {
            "source": self.source.to_dict(),
            "response_index": self.response_index,
            "candidate": self.candidate.to_dict(),
            "raw_response_digest": self.candidate.output_digest,
            "error": self.error,
        }


@dataclass(frozen=True, slots=True)
class BrainRepairSelectionReport:
    """
    Wave 7 multi-model repair selection evidence.
    """

    comparison_decision: BrainComparisonDecision
    records: tuple[BrainRepairProposalRecord, ...]
    tribunal_decision: BrainTribunalDecision | None = None
    selected_record: BrainRepairProposalRecord | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "records", tuple(self.records))
        object.__setattr__(self, "metadata", dict(self.metadata))
        if self.selected_record is not None and self.selected_record not in self.records:
            raise ValueError("selected_record must be present in records.")

    @property
    def selected_raw_response(self) -> str | None:
        """
        Return the selected raw proposal response when release is allowed.
        """
        if self.selected_record is None:
            return None
        return self.selected_record.raw_response

    @property
    def review_routed(self) -> bool:
        """
        Return True when tribunal review was either routed or not required.
        """
        if self.tribunal_decision is None:
            return True
        return self.tribunal_decision.disposition is BrainTribunalDisposition.ROUTED

    @property
    def blocked(self) -> bool:
        """
        Return True when no selected raw response may be released.
        """
        return self.selected_raw_response is None

    def to_dict(self) -> dict[str, object]:
        """
        Return a JSON-serializable Wave 7 selection report.
        """
        return {
            "selected_source_id": None
            if self.selected_record is None
            else self.selected_record.source.source_id,
            "selected_brain_name": None
            if self.selected_record is None
            else self.selected_record.source.brain_name,
            "selected_raw_response_digest": None
            if self.selected_record is None
            else self.selected_record.candidate.output_digest,
            "blocked": self.blocked,
            "review_routed": self.review_routed,
            "comparison_decision": self.comparison_decision.to_dict(),
            "tribunal_decision": None
            if self.tribunal_decision is None
            else self.tribunal_decision.to_dict(),
            "records": [record.to_dict() for record in self.records],
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class MultiBrainRepairProposalProvider(PatchProposalProvider):
    """
    Wave 7 proposal provider that compares multiple model repair outputs.

    This class is deliberately a PatchProposalProvider adapter so it can plug
    into the existing AuthoredRepairRuntime. It selects one raw JSON proposal for
    downstream parsing/compilation/policy ranking, but it never edits files, runs
    tests, signs off on evidence, or approves its own output.
    """

    sources: tuple[BrainRepairCandidateSource, ...]
    tribunal_assignments: tuple[BrainTribunalAssignment, ...] = field(default_factory=tuple)
    comparator: BrainModelComparator = field(default_factory=BrainModelComparator)
    tribunal: BrainModelTribunal = field(default_factory=BrainModelTribunal)
    require_tribunal_review: bool = True
    required_reviewer_role_kinds: tuple[BrainTribunalRoleKind, ...] = (
        BrainTribunalRoleKind.CRITIC,
        BrainTribunalRoleKind.SECURITY_REVIEWER,
        BrainTribunalRoleKind.POLICY_REVIEWER,
        BrainTribunalRoleKind.EVIDENCE_REVIEWER,
    )
    max_responses_per_source: int = 1
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.sources:
            raise ValueError("MultiBrainRepairProposalProvider requires at least one source.")
        if self.max_responses_per_source <= 0:
            raise ValueError("max_responses_per_source must be positive.")
        source_ids = [source.source_id for source in self.sources]
        if len(set(source_ids)) != len(source_ids):
            raise ValueError("MultiBrainRepairProposalProvider source_id values must be unique.")
        object.__setattr__(self, "sources", tuple(self.sources))
        object.__setattr__(self, "tribunal_assignments", tuple(self.tribunal_assignments))
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def provider_name(self) -> str:
        """
        Return a stable provider name for existing authoring receipts.
        """
        return "multi-brain-repair-proposal-provider"

    @property
    def model_name(self) -> str:
        """
        Return a stable model name for existing authoring receipts.
        """
        return "wave7-model-comparison"

    def generate(self, contract: PatchAuthoringPromptContract) -> Iterable[str]:
        """
        Return the selected raw proposal response, if one survives Wave 7 gates.
        """
        report = self.select(contract)
        if report.selected_raw_response is None:
            return ()
        return (report.selected_raw_response,)

    def select(self, contract: PatchAuthoringPromptContract) -> BrainRepairSelectionReport:
        """
        Collect source proposals, compare candidates, and enforce tribunal routing.
        """
        records = self._collect_records(contract)
        comparison_request = BrainComparisonRequest.create(
            required_role=BrainRole.PRIMARY,
            task_id=contract.request_id,
            pack_name="programming",
            criteria=(
                "model-agnostic repair candidate quality",
                "evidence-bound patch proposal",
                "safe governance-preserving repair",
            ),
            metadata={
                "runtime": "MultiBrainRepairProposalProvider",
                "wave": 7,
                "authoring_contract_id": contract.contract_id,
                "authoring_contract_digest": contract.digest,
                **dict(self.metadata),
            },
        )
        comparison_decision = self.comparator.compare(
            comparison_request,
            tuple(record.candidate for record in records),
        )
        selected_record = self._selected_record(
            records=records,
            comparison_decision=comparison_decision,
        )
        tribunal_decision = self._tribunal_decision(selected_record, contract)

        if self.require_tribunal_review:
            if tribunal_decision is None:
                selected_record = None
            elif tribunal_decision.disposition is not BrainTribunalDisposition.ROUTED:
                selected_record = None

        return BrainRepairSelectionReport(
            comparison_decision=comparison_decision,
            records=records,
            tribunal_decision=tribunal_decision,
            selected_record=selected_record,
            metadata={
                "runtime": "MultiBrainRepairProposalProvider",
                "wave": 7,
                "source_count": len(self.sources),
                "record_count": len(records),
                "tribunal_review_required": self.require_tribunal_review,
                **dict(self.metadata),
            },
        )

    def _collect_records(
        self,
        contract: PatchAuthoringPromptContract,
    ) -> tuple[BrainRepairProposalRecord, ...]:
        records: list[BrainRepairProposalRecord] = []
        for source in self.sources:
            try:
                raw_responses = tuple(
                    response.strip()
                    for response in source.provider.generate(contract)
                    if response.strip()
                )[: self.max_responses_per_source]
            except Exception as exc:
                records.append(_failed_record(source=source, error=str(exc)))
                continue

            if not raw_responses:
                records.append(
                    _failed_record(
                        source=source,
                        error="source produced no raw proposal responses",
                    )
                )
                continue

            for index, raw_response in enumerate(raw_responses, start=1):
                records.append(
                    BrainRepairProposalRecord(
                        source=source,
                        response_index=index,
                        raw_response=raw_response,
                        candidate=BrainComparisonCandidate(
                            brain_name=_candidate_name(source=source, index=index),
                            provider_name=source.provider_name,
                            model_name=source.model_name,
                            role=source.role,
                            score=source.score,
                            output_text=raw_response,
                            invocation_id=f"{source.source_id}-response-{index}",
                            metadata={
                                "source_id": source.source_id,
                                "response_index": index,
                                "origin_brain_name": source.brain_name,
                                **dict(source.metadata),
                            },
                        ),
                    )
                )
        return tuple(records)

    def _selected_record(
        self,
        *,
        records: tuple[BrainRepairProposalRecord, ...],
        comparison_decision: BrainComparisonDecision,
    ) -> BrainRepairProposalRecord | None:
        selected_result = comparison_decision.selected
        if selected_result is None:
            return None
        for record in records:
            if record.candidate == selected_result.candidate:
                return record
        return None

    def _tribunal_decision(
        self,
        selected_record: BrainRepairProposalRecord | None,
        contract: PatchAuthoringPromptContract,
    ) -> BrainTribunalDecision | None:
        if not self.require_tribunal_review or selected_record is None:
            return None
        request = BrainTribunalReviewRequest(
            request_id=f"{contract.request_id}-wave7-review",
            generated_by=selected_record.source.identity,
            action=BrainTribunalAction.REVIEW,
            originating_role_id=selected_record.source.tribunal_role_id,
            required_role_kinds=self.required_reviewer_role_kinds,
            metadata={
                "authoring_contract_id": contract.contract_id,
                "selected_source_id": selected_record.source.source_id,
                "selected_candidate_brain_name": selected_record.candidate.brain_name,
                "selected_candidate_digest": selected_record.candidate.output_digest,
            },
        )
        return self.tribunal.route_review(request, self.tribunal_assignments)


def _failed_record(
    *,
    source: BrainRepairCandidateSource,
    error: str,
) -> BrainRepairProposalRecord:
    return BrainRepairProposalRecord(
        source=source,
        response_index=1,
        error=error,
        candidate=BrainComparisonCandidate(
            brain_name=_candidate_name(source=source, index=1),
            provider_name=source.provider_name,
            model_name=source.model_name,
            role=source.role,
            score=source.score,
            eligible=False,
            reasons=(error,),
            metadata={
                "source_id": source.source_id,
                "origin_brain_name": source.brain_name,
            },
        ),
    )


def _candidate_name(*, source: BrainRepairCandidateSource, index: int) -> str:
    return f"{source.source_id}-proposal-{index}"


def _normalize_identifier(value: str, *, label: str) -> str:
    cleaned = value.strip().lower().replace(" ", "-")
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_model_name(value: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError("model_name must not be empty.")
    return cleaned


def _normalize_optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    return cleaned or None
