from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum, auto
from typing import Any

from ix_blackfox.operating.models import (
    OperatingArtifactKind,
    OperatingDisposition,
    OperatingDomain,
    OperatingEnvelope,
    OperatingFinding,
    OperatingSeverity,
    normalize_identifier,
    normalize_optional_text,
    normalize_text,
)
from ix_blackfox.operating.registry import (
    normalize_identifier_tuple,
    normalize_text_tuple,
)


class NegativeControlType(StrEnum):
    """Negative-control families used to prove Wave 10 blocks unsafe states."""

    MISSING_EVIDENCE = auto()
    TAMPERED_ARTIFACT = auto()
    SELF_APPROVAL = auto()
    MODEL_APPROVAL = auto()
    SYSTEM_APPROVAL = auto()
    POLICY_BYPASS = auto()
    REPLAY_MISMATCH = auto()
    UNTRUSTED_EVIDENCE = auto()
    TRACEABILITY_GAP = auto()
    CLAIM_OVERREACH = auto()
    UNRESOLVED_BLOCKER = auto()


class NegativeControlOutcome(StrEnum):
    """Observed outcome for one negative-control run."""

    PASSED = auto()
    FAILED = auto()
    NOT_RUN = auto()


class KillCriterionStatus(StrEnum):
    """Evaluation state for a kill criterion."""

    NOT_TRIGGERED = auto()
    TRIGGERED = auto()
    WAIVED_BY_HUMAN_REVIEW = auto()
    NOT_EVALUATED = auto()


@dataclass(frozen=True, slots=True)
class NegativeControlCase:
    """A deliberate bad-state test that Wave 10 must block."""

    case_id: str
    control_type: NegativeControlType
    title: str
    description: str
    domains: tuple[OperatingDomain, ...]
    expected_blocking_finding_codes: tuple[str, ...]
    required_artifact_ids: tuple[str, ...] = ()
    required: bool = True
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "case_id", normalize_identifier(self.case_id, label="case_id"))
        object.__setattr__(self, "title", normalize_text(self.title, label="title"))
        object.__setattr__(self, "description", normalize_text(self.description, label="description"))
        if not self.domains:
            raise ValueError("NegativeControlCase domains must not be empty.")
        if not self.expected_blocking_finding_codes:
            raise ValueError(
                "NegativeControlCase expected_blocking_finding_codes must not be empty."
            )
        object.__setattr__(self, "domains", unique_sorted_domains(self.domains))
        object.__setattr__(
            self,
            "expected_blocking_finding_codes",
            normalize_code_tuple(
                self.expected_blocking_finding_codes,
                label="expected_blocking_finding_codes",
            ),
        )
        object.__setattr__(
            self,
            "required_artifact_ids",
            normalize_identifier_tuple(self.required_artifact_ids, label="required_artifact_ids"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "control_type": self.control_type.value,
            "title": self.title,
            "description": self.description,
            "domains": [domain.value for domain in self.domains],
            "expected_blocking_finding_codes": list(self.expected_blocking_finding_codes),
            "required_artifact_ids": list(self.required_artifact_ids),
            "required": self.required,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class NegativeControlResult:
    """Observed evidence that a negative control was run and blocked as expected."""

    result_id: str
    case_id: str
    outcome: NegativeControlOutcome
    observed_blocking: bool
    observed_finding_codes: tuple[str, ...]
    evidence_artifact_ids: tuple[str, ...]
    checked_by: str
    notes: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "result_id",
            normalize_identifier(self.result_id, label="result_id"),
        )
        object.__setattr__(self, "case_id", normalize_identifier(self.case_id, label="case_id"))
        object.__setattr__(
            self,
            "observed_finding_codes",
            normalize_code_tuple(self.observed_finding_codes, label="observed_finding_codes"),
        )
        object.__setattr__(
            self,
            "evidence_artifact_ids",
            normalize_identifier_tuple(self.evidence_artifact_ids, label="evidence_artifact_ids"),
        )
        object.__setattr__(self, "checked_by", normalize_text(self.checked_by, label="checked_by"))
        object.__setattr__(self, "notes", normalize_text_tuple(self.notes, label="notes"))
        object.__setattr__(self, "metadata", dict(self.metadata))

    def expected_finding_gaps(self, case: NegativeControlCase) -> tuple[str, ...]:
        return tuple(
            sorted(
                set(case.expected_blocking_finding_codes)
                - set(self.observed_finding_codes)
            )
        )

    def missing_required_artifacts(self, case: NegativeControlCase) -> tuple[str, ...]:
        return tuple(
            sorted(set(case.required_artifact_ids) - set(self.evidence_artifact_ids))
        )

    def passed_for(self, case: NegativeControlCase) -> bool:
        return (
            self.outcome is NegativeControlOutcome.PASSED
            and self.observed_blocking
            and not self.expected_finding_gaps(case)
            and not self.missing_required_artifacts(case)
            and bool(self.evidence_artifact_ids)
        )

    def to_dict(self, *, case: NegativeControlCase | None = None) -> dict[str, Any]:
        payload = {
            "result_id": self.result_id,
            "case_id": self.case_id,
            "outcome": self.outcome.value,
            "observed_blocking": self.observed_blocking,
            "observed_finding_codes": list(self.observed_finding_codes),
            "evidence_artifact_ids": list(self.evidence_artifact_ids),
            "checked_by": self.checked_by,
            "notes": list(self.notes),
            "metadata": dict(self.metadata),
        }
        if case is not None:
            payload["expected_finding_gaps"] = list(self.expected_finding_gaps(case))
            payload["missing_required_artifacts"] = list(self.missing_required_artifacts(case))
            payload["passed_for_case"] = self.passed_for(case)
        return payload


@dataclass(frozen=True, slots=True)
class KillCriterion:
    """Hard-stop condition that prevents false Wave 10 readiness."""

    criterion_id: str
    title: str
    description: str
    severity: OperatingSeverity
    status: KillCriterionStatus
    trigger_finding_codes: tuple[str, ...]
    repository_ids: tuple[str, ...]
    owner_team_id: str
    evidence_artifact_ids: tuple[str, ...] = ()
    waived_by_human_review_id: str = ""
    waiver_rationale: str = ""
    mandatory: bool = True
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "criterion_id",
            normalize_identifier(self.criterion_id, label="criterion_id"),
        )
        object.__setattr__(self, "title", normalize_text(self.title, label="title"))
        object.__setattr__(self, "description", normalize_text(self.description, label="description"))
        if not self.trigger_finding_codes:
            raise ValueError("KillCriterion trigger_finding_codes must not be empty.")
        if not self.repository_ids:
            raise ValueError("KillCriterion repository_ids must not be empty.")
        object.__setattr__(
            self,
            "trigger_finding_codes",
            normalize_code_tuple(self.trigger_finding_codes, label="trigger_finding_codes"),
        )
        object.__setattr__(
            self,
            "repository_ids",
            normalize_identifier_tuple(self.repository_ids, label="repository_ids"),
        )
        object.__setattr__(
            self,
            "owner_team_id",
            normalize_identifier(self.owner_team_id, label="owner_team_id"),
        )
        object.__setattr__(
            self,
            "evidence_artifact_ids",
            normalize_identifier_tuple(self.evidence_artifact_ids, label="evidence_artifact_ids"),
        )
        object.__setattr__(
            self,
            "waived_by_human_review_id",
            normalize_optional_identifier(
                self.waived_by_human_review_id,
                label="waived_by_human_review_id",
            ),
        )
        object.__setattr__(
            self,
            "waiver_rationale",
            normalize_optional_text(self.waiver_rationale, label="waiver_rationale"),
        )
        if self.status is KillCriterionStatus.WAIVED_BY_HUMAN_REVIEW:
            if not self.waived_by_human_review_id or not self.waiver_rationale:
                raise ValueError(
                    "waived kill criteria must include human review id and waiver rationale."
                )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def triggered(self) -> bool:
        return self.status is KillCriterionStatus.TRIGGERED

    @property
    def waived(self) -> bool:
        return self.status is KillCriterionStatus.WAIVED_BY_HUMAN_REVIEW

    @property
    def evaluated(self) -> bool:
        return self.status is not KillCriterionStatus.NOT_EVALUATED

    @property
    def evidence_bound(self) -> bool:
        return bool(self.evidence_artifact_ids)

    @property
    def blocks_gate(self) -> bool:
        if not self.mandatory:
            return False
        return self.triggered or self.status is KillCriterionStatus.NOT_EVALUATED

    @property
    def warns_gate(self) -> bool:
        return self.waived or (self.triggered and not self.mandatory)

    def to_dict(self) -> dict[str, Any]:
        return {
            "criterion_id": self.criterion_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "status": self.status.value,
            "trigger_finding_codes": list(self.trigger_finding_codes),
            "repository_ids": list(self.repository_ids),
            "owner_team_id": self.owner_team_id,
            "evidence_artifact_ids": list(self.evidence_artifact_ids),
            "waived_by_human_review_id": self.waived_by_human_review_id,
            "waiver_rationale": self.waiver_rationale,
            "mandatory": self.mandatory,
            "triggered": self.triggered,
            "waived": self.waived,
            "evaluated": self.evaluated,
            "evidence_bound": self.evidence_bound,
            "blocks_gate": self.blocks_gate,
            "warns_gate": self.warns_gate,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class FalsificationGate:
    """Fail-closed Wave 10 gate for negative controls and kill criteria."""

    gate_id: str
    target_id: str
    negative_control_cases: tuple[NegativeControlCase, ...]
    negative_control_results: tuple[NegativeControlResult, ...]
    kill_criteria: tuple[KillCriterion, ...]
    required_artifact_ids: tuple[str, ...]
    observed_artifact_ids: tuple[str, ...]
    generated_by: str = "IX-BlackFox Wave 10 falsification gate"
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "gate_id", normalize_identifier(self.gate_id, label="gate_id"))
        object.__setattr__(self, "target_id", normalize_identifier(self.target_id, label="target_id"))
        if not self.negative_control_cases:
            raise ValueError("FalsificationGate negative_control_cases must not be empty.")
        cases = tuple(sorted(self.negative_control_cases, key=lambda case: case.case_id))
        case_ids = [case.case_id for case in cases]
        if len(case_ids) != len(set(case_ids)):
            raise ValueError("FalsificationGate case_id values must be unique.")
        object.__setattr__(self, "negative_control_cases", cases)

        results = tuple(sorted(self.negative_control_results, key=lambda result: result.result_id))
        result_ids = [result.result_id for result in results]
        if len(result_ids) != len(set(result_ids)):
            raise ValueError("FalsificationGate result_id values must be unique.")
        unknown_cases = {result.case_id for result in results} - set(case_ids)
        if unknown_cases:
            unknown = ", ".join(sorted(unknown_cases))
            raise ValueError(f"negative control result references unknown case: {unknown}")
        object.__setattr__(self, "negative_control_results", results)

        criteria = tuple(sorted(self.kill_criteria, key=lambda criterion: criterion.criterion_id))
        criterion_ids = [criterion.criterion_id for criterion in criteria]
        if len(criterion_ids) != len(set(criterion_ids)):
            raise ValueError("FalsificationGate criterion_id values must be unique.")
        object.__setattr__(self, "kill_criteria", criteria)

        object.__setattr__(
            self,
            "required_artifact_ids",
            normalize_identifier_tuple(self.required_artifact_ids, label="required_artifact_ids"),
        )
        object.__setattr__(
            self,
            "observed_artifact_ids",
            normalize_identifier_tuple(self.observed_artifact_ids, label="observed_artifact_ids"),
        )
        object.__setattr__(
            self,
            "generated_by",
            normalize_text(self.generated_by, label="generated_by"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def case_ids(self) -> tuple[str, ...]:
        return tuple(case.case_id for case in self.negative_control_cases)

    @property
    def result_ids(self) -> tuple[str, ...]:
        return tuple(result.result_id for result in self.negative_control_results)

    @property
    def missing_required_artifact_ids(self) -> tuple[str, ...]:
        return tuple(sorted(set(self.required_artifact_ids) - set(self.observed_artifact_ids)))

    @property
    def required_case_ids_without_results(self) -> tuple[str, ...]:
        result_case_ids = {result.case_id for result in self.negative_control_results}
        return tuple(
            case.case_id
            for case in self.negative_control_cases
            if case.required and case.case_id not in result_case_ids
        )

    @property
    def failed_case_ids(self) -> tuple[str, ...]:
        results_by_case = {result.case_id: result for result in self.negative_control_results}
        failed: list[str] = []
        for case in self.negative_control_cases:
            result = results_by_case.get(case.case_id)
            if result is None:
                continue
            if not result.passed_for(case):
                failed.append(case.case_id)
        return tuple(sorted(failed))

    @property
    def triggered_kill_criterion_ids(self) -> tuple[str, ...]:
        return tuple(
            criterion.criterion_id for criterion in self.kill_criteria if criterion.triggered
        )

    @property
    def blocking_kill_criterion_ids(self) -> tuple[str, ...]:
        return tuple(
            criterion.criterion_id for criterion in self.kill_criteria if criterion.blocks_gate
        )

    @property
    def warning_kill_criterion_ids(self) -> tuple[str, ...]:
        return tuple(
            criterion.criterion_id for criterion in self.kill_criteria if criterion.warns_gate
        )

    @property
    def findings(self) -> tuple[OperatingFinding, ...]:
        findings: list[OperatingFinding] = []

        for artifact_id in self.missing_required_artifact_ids:
            findings.append(
                self._finding(
                    code="operating.falsification.missing-required-artifact",
                    severity=OperatingSeverity.CRITICAL,
                    summary=f"Falsification gate {self.gate_id} is missing required artifact {artifact_id}.",
                    blocking=True,
                    metadata={"artifact_id": artifact_id},
                )
            )

        for case_id in self.required_case_ids_without_results:
            findings.append(
                self._finding(
                    code="operating.falsification.required-negative-control-not-run",
                    severity=OperatingSeverity.CRITICAL,
                    summary=f"Required negative control {case_id} has no result.",
                    blocking=True,
                    metadata={"case_id": case_id},
                )
            )

        case_by_id = {case.case_id: case for case in self.negative_control_cases}
        result_by_case = {result.case_id: result for result in self.negative_control_results}
        for case_id in self.failed_case_ids:
            case = case_by_id[case_id]
            result = result_by_case[case_id]
            findings.append(
                self._finding(
                    code="operating.falsification.negative-control-failed",
                    severity=OperatingSeverity.CRITICAL if case.required else OperatingSeverity.HIGH,
                    summary=f"Negative control {case_id} did not block as expected.",
                    blocking=case.required,
                    metadata={
                        "case_id": case_id,
                        "result_id": result.result_id,
                        "outcome": result.outcome.value,
                        "observed_blocking": result.observed_blocking,
                        "expected_finding_gaps": list(result.expected_finding_gaps(case)),
                        "missing_required_artifacts": list(
                            result.missing_required_artifacts(case)
                        ),
                    },
                )
            )

        for criterion in self.kill_criteria:
            if criterion.blocks_gate:
                findings.append(
                    self._finding(
                        code="operating.falsification.kill-criterion-blocked",
                        severity=criterion.severity,
                        summary=f"Kill criterion {criterion.criterion_id} blocks the gate.",
                        blocking=True,
                        metadata={
                            "criterion_id": criterion.criterion_id,
                            "status": criterion.status.value,
                            "trigger_finding_codes": list(criterion.trigger_finding_codes),
                        },
                    )
                )
            elif criterion.warns_gate:
                findings.append(
                    self._finding(
                        code="operating.falsification.kill-criterion-warning",
                        severity=criterion.severity,
                        summary=f"Kill criterion {criterion.criterion_id} requires reviewer attention.",
                        blocking=False,
                        metadata={
                            "criterion_id": criterion.criterion_id,
                            "status": criterion.status.value,
                            "waived_by_human_review_id": criterion.waived_by_human_review_id,
                        },
                    )
                )

        return tuple(sorted(findings, key=lambda finding: (finding.code, finding.summary)))

    @property
    def disposition(self) -> OperatingDisposition:
        if any(finding.blocking for finding in self.findings):
            return OperatingDisposition.BLOCKED
        if self.findings:
            return OperatingDisposition.WARNING
        return OperatingDisposition.READY

    def to_envelope(self) -> OperatingEnvelope:
        return OperatingEnvelope(
            envelope_id=f"{self.gate_id}-falsification-gate-envelope",
            artifact_kind=OperatingArtifactKind.POLICY_EVALUATION,
            subject=f"Wave 10 falsification gate {self.gate_id}",
            domains=(
                OperatingDomain.POLICY_GOVERNED,
                OperatingDomain.MEASURABLE,
                OperatingDomain.REVIEWABLE,
            ),
            findings=self.findings,
            metadata={
                "gate_id": self.gate_id,
                "target_id": self.target_id,
                "case_ids": list(self.case_ids),
                "result_ids": list(self.result_ids),
                "required_artifact_ids": list(self.required_artifact_ids),
                "observed_artifact_ids": list(self.observed_artifact_ids),
                "missing_required_artifact_ids": list(self.missing_required_artifact_ids),
                "required_case_ids_without_results": list(self.required_case_ids_without_results),
                "failed_case_ids": list(self.failed_case_ids),
                "triggered_kill_criterion_ids": list(self.triggered_kill_criterion_ids),
                "blocking_kill_criterion_ids": list(self.blocking_kill_criterion_ids),
                "warning_kill_criterion_ids": list(self.warning_kill_criterion_ids),
                "disposition": self.disposition.value,
            },
        )

    def to_dict(self) -> dict[str, Any]:
        case_by_id = {case.case_id: case for case in self.negative_control_cases}
        envelope = self.to_envelope()
        return {
            "gate_id": self.gate_id,
            "target_id": self.target_id,
            "negative_control_cases": [case.to_dict() for case in self.negative_control_cases],
            "negative_control_results": [
                result.to_dict(case=case_by_id.get(result.case_id))
                for result in self.negative_control_results
            ],
            "kill_criteria": [criterion.to_dict() for criterion in self.kill_criteria],
            "required_artifact_ids": list(self.required_artifact_ids),
            "observed_artifact_ids": list(self.observed_artifact_ids),
            "missing_required_artifact_ids": list(self.missing_required_artifact_ids),
            "required_case_ids_without_results": list(self.required_case_ids_without_results),
            "failed_case_ids": list(self.failed_case_ids),
            "triggered_kill_criterion_ids": list(self.triggered_kill_criterion_ids),
            "blocking_kill_criterion_ids": list(self.blocking_kill_criterion_ids),
            "warning_kill_criterion_ids": list(self.warning_kill_criterion_ids),
            "findings": [finding.to_dict() for finding in self.findings],
            "disposition": self.disposition.value,
            "digest": envelope.digest,
            "generated_by": self.generated_by,
            "metadata": dict(self.metadata),
        }

    def _finding(
        self,
        *,
        code: str,
        severity: OperatingSeverity,
        summary: str,
        blocking: bool,
        metadata: Mapping[str, Any] | None = None,
    ) -> OperatingFinding:
        return OperatingFinding(
            code=code,
            severity=severity,
            summary=summary,
            domains=(
                OperatingDomain.POLICY_GOVERNED,
                OperatingDomain.MEASURABLE,
                OperatingDomain.REVIEWABLE,
            ),
            blocking=blocking,
            metadata={"gate_id": self.gate_id, **dict(metadata or {})},
        )


def normalize_code_tuple(values: Sequence[str], *, label: str) -> tuple[str, ...]:
    normalized: list[str] = []
    seen: set[str] = set()
    for value in values:
        item = normalize_text(value, label=label)
        if item not in seen:
            normalized.append(item)
            seen.add(item)
    return tuple(sorted(normalized))


def normalize_optional_identifier(value: str, *, label: str) -> str:
    if not value.strip():
        return ""
    return normalize_identifier(value, label=label)


def unique_sorted_domains(values: Sequence[OperatingDomain]) -> tuple[OperatingDomain, ...]:
    by_value: dict[str, OperatingDomain] = {}
    for value in values:
        by_value[value.value] = value
    return tuple(by_value[key] for key in sorted(by_value))
