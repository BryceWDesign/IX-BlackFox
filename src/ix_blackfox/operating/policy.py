from __future__ import annotations

from collections.abc import Mapping
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
    unique_sorted_enum_tuple,
)
from ix_blackfox.operating.registry import (
    normalize_identifier_tuple,
    normalize_text_tuple,
)


class OperatingControlEffect(StrEnum):
    """Decision effect produced by a Wave 10 operating control."""

    ALLOW = auto()
    BLOCK = auto()
    WARN = auto()
    REQUIRE_REVIEW = auto()
    REQUIRE_EVIDENCE = auto()
    REQUIRE_REPLAY = auto()
    REQUIRE_TRACEABILITY = auto()


class OperatingControlResultStatus(StrEnum):
    """Evaluation result for one policy control."""

    PASSED = auto()
    WARNING = auto()
    FAILED = auto()
    NOT_APPLICABLE = auto()


@dataclass(frozen=True, slots=True)
class OperatingPolicyContext:
    """Evidence facts available to the Wave 10 policy evaluation layer."""

    context_id: str
    repository_ids: tuple[str, ...]
    domains: tuple[OperatingDomain, ...]
    artifact_ids: tuple[str, ...] = ()
    authoritative_approval_count: int = 0
    replay_passed: bool = False
    traceability_passed: bool = False
    review_bundle_disposition: OperatingDisposition = OperatingDisposition.BLOCKED
    evidence_inventory_disposition: OperatingDisposition = OperatingDisposition.BLOCKED
    campaign_disposition: OperatingDisposition = OperatingDisposition.BLOCKED
    registry_disposition: OperatingDisposition = OperatingDisposition.BLOCKED
    unresolved_blocker_ids: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "context_id",
            normalize_identifier(self.context_id, label="context_id"),
        )
        if not self.repository_ids:
            raise ValueError("OperatingPolicyContext repository_ids must not be empty.")
        if not self.domains:
            raise ValueError("OperatingPolicyContext domains must not be empty.")
        object.__setattr__(
            self,
            "repository_ids",
            normalize_identifier_tuple(self.repository_ids, label="repository_ids"),
        )
        object.__setattr__(self, "domains", unique_sorted_enum_tuple(self.domains))
        object.__setattr__(
            self,
            "artifact_ids",
            normalize_identifier_tuple(self.artifact_ids, label="artifact_ids"),
        )
        if self.authoritative_approval_count < 0:
            raise ValueError("authoritative_approval_count must not be negative.")
        object.__setattr__(
            self,
            "unresolved_blocker_ids",
            normalize_identifier_tuple(
                self.unresolved_blocker_ids,
                label="unresolved_blocker_ids",
            ),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def review_bundle_ready(self) -> bool:
        return self.review_bundle_disposition is OperatingDisposition.READY

    @property
    def evidence_inventory_ready(self) -> bool:
        return self.evidence_inventory_disposition is OperatingDisposition.READY

    @property
    def campaign_ready(self) -> bool:
        return self.campaign_disposition is OperatingDisposition.READY

    @property
    def registry_ready(self) -> bool:
        return self.registry_disposition is OperatingDisposition.READY

    @property
    def no_unresolved_blockers(self) -> bool:
        return not self.unresolved_blocker_ids

    def to_dict(self) -> dict[str, Any]:
        return {
            "context_id": self.context_id,
            "repository_ids": list(self.repository_ids),
            "domains": [domain.value for domain in self.domains],
            "artifact_ids": list(self.artifact_ids),
            "authoritative_approval_count": self.authoritative_approval_count,
            "replay_passed": self.replay_passed,
            "traceability_passed": self.traceability_passed,
            "review_bundle_disposition": self.review_bundle_disposition.value,
            "evidence_inventory_disposition": self.evidence_inventory_disposition.value,
            "campaign_disposition": self.campaign_disposition.value,
            "registry_disposition": self.registry_disposition.value,
            "review_bundle_ready": self.review_bundle_ready,
            "evidence_inventory_ready": self.evidence_inventory_ready,
            "campaign_ready": self.campaign_ready,
            "registry_ready": self.registry_ready,
            "unresolved_blocker_ids": list(self.unresolved_blocker_ids),
            "no_unresolved_blockers": self.no_unresolved_blockers,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class OperatingControl:
    """One fail-closed policy control for Wave 10 operating gates."""

    control_id: str
    title: str
    intent: str
    effect: OperatingControlEffect
    domains: tuple[OperatingDomain, ...]
    severity: OperatingSeverity = OperatingSeverity.CRITICAL
    required_repository_ids: tuple[str, ...] = ()
    required_artifact_ids: tuple[str, ...] = ()
    minimum_human_approvals: int = 0
    require_replay_passed: bool = False
    require_traceability_passed: bool = False
    require_review_bundle_ready: bool = False
    require_evidence_inventory_ready: bool = False
    require_campaign_ready: bool = False
    require_registry_ready: bool = False
    require_no_unresolved_blockers: bool = False
    mandatory: bool = True
    references: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "control_id",
            normalize_identifier(self.control_id, label="control_id"),
        )
        object.__setattr__(self, "title", normalize_text(self.title, label="title"))
        object.__setattr__(self, "intent", normalize_text(self.intent, label="intent"))
        if not self.domains:
            raise ValueError("OperatingControl domains must not be empty.")
        object.__setattr__(self, "domains", unique_sorted_enum_tuple(self.domains))
        object.__setattr__(
            self,
            "required_repository_ids",
            normalize_identifier_tuple(
                self.required_repository_ids,
                label="required_repository_ids",
            ),
        )
        object.__setattr__(
            self,
            "required_artifact_ids",
            normalize_identifier_tuple(
                self.required_artifact_ids,
                label="required_artifact_ids",
            ),
        )
        if self.minimum_human_approvals < 0:
            raise ValueError("minimum_human_approvals must not be negative.")
        object.__setattr__(
            self,
            "references",
            normalize_text_tuple(self.references, label="references"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    def applies_to(self, context: OperatingPolicyContext) -> bool:
        return bool(set(self.domains) & set(context.domains))

    def evaluate(self, context: OperatingPolicyContext) -> OperatingControlResult:
        if not self.applies_to(context):
            return OperatingControlResult(
                control_id=self.control_id,
                status=OperatingControlResultStatus.NOT_APPLICABLE,
                severity=OperatingSeverity.INFO,
                summary=f"Control {self.control_id} is outside this context domain scope.",
                effect=self.effect,
                missing_repository_ids=(),
                missing_artifact_ids=(),
                blocking=False,
            )

        missing_repositories = tuple(
            sorted(set(self.required_repository_ids) - set(context.repository_ids))
        )
        missing_artifacts = tuple(
            sorted(set(self.required_artifact_ids) - set(context.artifact_ids))
        )
        gaps: list[str] = []
        if missing_repositories:
            gaps.append("missing required repositories")
        if missing_artifacts:
            gaps.append("missing required artifacts")
        if context.authoritative_approval_count < self.minimum_human_approvals:
            gaps.append("insufficient authoritative human approvals")
        if self.require_replay_passed and not context.replay_passed:
            gaps.append("replay validation did not pass")
        if self.require_traceability_passed and not context.traceability_passed:
            gaps.append("traceability validation did not pass")
        if self.require_review_bundle_ready and not context.review_bundle_ready:
            gaps.append("review bundle is not ready")
        if self.require_evidence_inventory_ready and not context.evidence_inventory_ready:
            gaps.append("evidence inventory is not ready")
        if self.require_campaign_ready and not context.campaign_ready:
            gaps.append("campaign is not ready")
        if self.require_registry_ready and not context.registry_ready:
            gaps.append("registry is not ready")
        if self.require_no_unresolved_blockers and not context.no_unresolved_blockers:
            gaps.append("unresolved blockers are present")

        if gaps:
            status = (
                OperatingControlResultStatus.FAILED
                if self.mandatory
                else OperatingControlResultStatus.WARNING
            )
            return OperatingControlResult(
                control_id=self.control_id,
                status=status,
                severity=self.severity,
                summary=f"Control {self.control_id} failed: {', '.join(gaps)}.",
                effect=self.effect,
                missing_repository_ids=missing_repositories,
                missing_artifact_ids=missing_artifacts,
                blocking=self.mandatory,
                metadata={"gaps": gaps},
            )

        return OperatingControlResult(
            control_id=self.control_id,
            status=OperatingControlResultStatus.PASSED,
            severity=OperatingSeverity.INFO,
            summary=f"Control {self.control_id} passed for context {context.context_id}.",
            effect=OperatingControlEffect.ALLOW,
            missing_repository_ids=(),
            missing_artifact_ids=(),
            blocking=False,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "control_id": self.control_id,
            "title": self.title,
            "intent": self.intent,
            "effect": self.effect.value,
            "domains": [domain.value for domain in self.domains],
            "severity": self.severity.value,
            "required_repository_ids": list(self.required_repository_ids),
            "required_artifact_ids": list(self.required_artifact_ids),
            "minimum_human_approvals": self.minimum_human_approvals,
            "require_replay_passed": self.require_replay_passed,
            "require_traceability_passed": self.require_traceability_passed,
            "require_review_bundle_ready": self.require_review_bundle_ready,
            "require_evidence_inventory_ready": self.require_evidence_inventory_ready,
            "require_campaign_ready": self.require_campaign_ready,
            "require_registry_ready": self.require_registry_ready,
            "require_no_unresolved_blockers": self.require_no_unresolved_blockers,
            "mandatory": self.mandatory,
            "references": list(self.references),
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class OperatingControlResult:
    """Result emitted by one operating control evaluation."""

    control_id: str
    status: OperatingControlResultStatus
    severity: OperatingSeverity
    summary: str
    effect: OperatingControlEffect
    missing_repository_ids: tuple[str, ...] = ()
    missing_artifact_ids: tuple[str, ...] = ()
    blocking: bool = False
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "control_id",
            normalize_identifier(self.control_id, label="control_id"),
        )
        object.__setattr__(self, "summary", normalize_text(self.summary, label="summary"))
        object.__setattr__(
            self,
            "missing_repository_ids",
            normalize_identifier_tuple(
                self.missing_repository_ids,
                label="missing_repository_ids",
            ),
        )
        object.__setattr__(
            self,
            "missing_artifact_ids",
            normalize_identifier_tuple(
                self.missing_artifact_ids,
                label="missing_artifact_ids",
            ),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def passed(self) -> bool:
        return self.status is OperatingControlResultStatus.PASSED

    def to_finding(
        self,
        *,
        policy_pack_id: str,
        evaluation_id: str,
    ) -> OperatingFinding | None:
        if self.status in {
            OperatingControlResultStatus.PASSED,
            OperatingControlResultStatus.NOT_APPLICABLE,
        }:
            return None
        return OperatingFinding(
            code=f"operating.policy.{self.status.value}.{self.control_id}",
            severity=self.severity,
            summary=self.summary,
            domains=(OperatingDomain.POLICY_GOVERNED, OperatingDomain.MEASURABLE),
            blocking=self.blocking,
            metadata={
                "policy_pack_id": policy_pack_id,
                "evaluation_id": evaluation_id,
                "control_id": self.control_id,
                "status": self.status.value,
                "effect": self.effect.value,
                "missing_repository_ids": list(self.missing_repository_ids),
                "missing_artifact_ids": list(self.missing_artifact_ids),
                **dict(self.metadata),
            },
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "control_id": self.control_id,
            "status": self.status.value,
            "severity": self.severity.value,
            "summary": self.summary,
            "effect": self.effect.value,
            "missing_repository_ids": list(self.missing_repository_ids),
            "missing_artifact_ids": list(self.missing_artifact_ids),
            "blocking": self.blocking,
            "passed": self.passed,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class OperatingPolicyPack:
    """Versioned collection of controls used by Wave 10 operating gates."""

    policy_pack_id: str
    name: str
    version: str
    controls: tuple[OperatingControl, ...]
    required_for_domains: tuple[OperatingDomain, ...]
    description: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "policy_pack_id",
            normalize_identifier(self.policy_pack_id, label="policy_pack_id"),
        )
        object.__setattr__(self, "name", normalize_text(self.name, label="name"))
        object.__setattr__(self, "version", normalize_text(self.version, label="version"))
        if not self.controls:
            raise ValueError("OperatingPolicyPack controls must not be empty.")
        controls = tuple(sorted(self.controls, key=lambda control: control.control_id))
        control_ids = [control.control_id for control in controls]
        if len(control_ids) != len(set(control_ids)):
            raise ValueError("OperatingPolicyPack control_id values must be unique.")
        object.__setattr__(self, "controls", controls)
        if not self.required_for_domains:
            raise ValueError("OperatingPolicyPack required_for_domains must not be empty.")
        object.__setattr__(
            self,
            "required_for_domains",
            unique_sorted_enum_tuple(self.required_for_domains),
        )
        object.__setattr__(
            self,
            "description",
            normalize_optional_text(self.description, label="description"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    def evaluate(
        self,
        context: OperatingPolicyContext,
        *,
        evaluation_id: str,
    ) -> OperatingPolicyEvaluation:
        return OperatingPolicyEvaluation(
            evaluation_id=evaluation_id,
            policy_pack=self,
            context=context,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_pack_id": self.policy_pack_id,
            "name": self.name,
            "version": self.version,
            "controls": [control.to_dict() for control in self.controls],
            "required_for_domains": [domain.value for domain in self.required_for_domains],
            "description": self.description,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class OperatingPolicyEvaluation:
    """Evaluation of one policy pack against one operating context."""

    evaluation_id: str
    policy_pack: OperatingPolicyPack
    context: OperatingPolicyContext
    generated_by: str = "IX-BlackFox Wave 10 operating policy evaluator"
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "evaluation_id",
            normalize_identifier(self.evaluation_id, label="evaluation_id"),
        )
        object.__setattr__(
            self,
            "generated_by",
            normalize_text(self.generated_by, label="generated_by"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def results(self) -> tuple[OperatingControlResult, ...]:
        return tuple(control.evaluate(self.context) for control in self.policy_pack.controls)

    @property
    def failed_control_ids(self) -> tuple[str, ...]:
        return tuple(result.control_id for result in self.results if result.blocking)

    @property
    def warning_control_ids(self) -> tuple[str, ...]:
        return tuple(
            result.control_id
            for result in self.results
            if result.status is OperatingControlResultStatus.WARNING
        )

    @property
    def findings(self) -> tuple[OperatingFinding, ...]:
        findings = tuple(
            finding
            for result in self.results
            if (
                finding := result.to_finding(
                    policy_pack_id=self.policy_pack.policy_pack_id,
                    evaluation_id=self.evaluation_id,
                )
            )
            is not None
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
            envelope_id=f"{self.evaluation_id}-policy-evaluation-envelope",
            artifact_kind=OperatingArtifactKind.POLICY_EVALUATION,
            subject=f"Wave 10 policy evaluation {self.evaluation_id}",
            domains=(OperatingDomain.POLICY_GOVERNED, OperatingDomain.MEASURABLE),
            findings=self.findings,
            metadata={
                "evaluation_id": self.evaluation_id,
                "policy_pack_id": self.policy_pack.policy_pack_id,
                "context_id": self.context.context_id,
                "failed_control_ids": list(self.failed_control_ids),
                "warning_control_ids": list(self.warning_control_ids),
                "disposition": self.disposition.value,
            },
        )

    def to_dict(self) -> dict[str, Any]:
        envelope = self.to_envelope()
        return {
            "evaluation_id": self.evaluation_id,
            "policy_pack": self.policy_pack.to_dict(),
            "context": self.context.to_dict(),
            "results": [result.to_dict() for result in self.results],
            "failed_control_ids": list(self.failed_control_ids),
            "warning_control_ids": list(self.warning_control_ids),
            "findings": [finding.to_dict() for finding in self.findings],
            "disposition": self.disposition.value,
            "digest": envelope.digest,
            "generated_by": self.generated_by,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class OperatingGateDecision:
    """Fail-closed gate decision across one or more policy evaluations."""

    gate_id: str
    evaluations: tuple[OperatingPolicyEvaluation, ...]
    required_evaluation_ids: tuple[str, ...]
    decided_by: str
    rationale: str
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "gate_id",
            normalize_identifier(self.gate_id, label="gate_id"),
        )
        if not self.evaluations:
            raise ValueError("OperatingGateDecision evaluations must not be empty.")
        evaluations = tuple(sorted(self.evaluations, key=lambda item: item.evaluation_id))
        evaluation_ids = [evaluation.evaluation_id for evaluation in evaluations]
        if len(evaluation_ids) != len(set(evaluation_ids)):
            raise ValueError("OperatingGateDecision evaluation_id values must be unique.")
        object.__setattr__(self, "evaluations", evaluations)
        if not self.required_evaluation_ids:
            raise ValueError("OperatingGateDecision required_evaluation_ids must not be empty.")
        object.__setattr__(
            self,
            "required_evaluation_ids",
            normalize_identifier_tuple(
                self.required_evaluation_ids,
                label="required_evaluation_ids",
            ),
        )
        missing = set(self.required_evaluation_ids) - set(evaluation_ids)
        if missing:
            missing_text = ", ".join(sorted(missing))
            raise ValueError(f"required evaluations are not present: {missing_text}")
        object.__setattr__(
            self,
            "decided_by",
            normalize_text(self.decided_by, label="decided_by"),
        )
        object.__setattr__(
            self,
            "rationale",
            normalize_text(self.rationale, label="rationale"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def evaluation_ids(self) -> tuple[str, ...]:
        return tuple(evaluation.evaluation_id for evaluation in self.evaluations)

    @property
    def blocking_evaluation_ids(self) -> tuple[str, ...]:
        return tuple(
            evaluation.evaluation_id
            for evaluation in self.evaluations
            if evaluation.disposition is OperatingDisposition.BLOCKED
        )

    @property
    def warning_evaluation_ids(self) -> tuple[str, ...]:
        return tuple(
            evaluation.evaluation_id
            for evaluation in self.evaluations
            if evaluation.disposition is OperatingDisposition.WARNING
        )

    @property
    def findings(self) -> tuple[OperatingFinding, ...]:
        findings: list[OperatingFinding] = []
        for evaluation in self.evaluations:
            findings.extend(evaluation.findings)
        for evaluation_id in self.blocking_evaluation_ids:
            findings.append(
                OperatingFinding(
                    code="operating.gate.blocked-policy-evaluation",
                    severity=OperatingSeverity.CRITICAL,
                    summary=f"Operating gate is blocked by policy evaluation {evaluation_id}.",
                    domains=(OperatingDomain.POLICY_GOVERNED, OperatingDomain.REVIEWABLE),
                    blocking=True,
                    metadata={"gate_id": self.gate_id, "evaluation_id": evaluation_id},
                )
            )
        return tuple(sorted(findings, key=lambda finding: (finding.code, finding.summary)))

    @property
    def disposition(self) -> OperatingDisposition:
        if self.blocking_evaluation_ids:
            return OperatingDisposition.BLOCKED
        if self.warning_evaluation_ids:
            return OperatingDisposition.WARNING
        return OperatingDisposition.READY

    @property
    def can_proceed(self) -> bool:
        return self.disposition is OperatingDisposition.READY

    def to_envelope(self) -> OperatingEnvelope:
        return OperatingEnvelope(
            envelope_id=f"{self.gate_id}-operating-gate-envelope",
            artifact_kind=OperatingArtifactKind.POLICY_EVALUATION,
            subject=f"Wave 10 operating gate {self.gate_id}",
            domains=(OperatingDomain.POLICY_GOVERNED, OperatingDomain.REVIEWABLE),
            findings=self.findings,
            metadata={
                "gate_id": self.gate_id,
                "evaluation_ids": list(self.evaluation_ids),
                "required_evaluation_ids": list(self.required_evaluation_ids),
                "blocking_evaluation_ids": list(self.blocking_evaluation_ids),
                "warning_evaluation_ids": list(self.warning_evaluation_ids),
                "decided_by": self.decided_by,
                "can_proceed": self.can_proceed,
                "disposition": self.disposition.value,
            },
        )

    def to_dict(self) -> dict[str, Any]:
        envelope = self.to_envelope()
        return {
            "gate_id": self.gate_id,
            "evaluations": [evaluation.to_dict() for evaluation in self.evaluations],
            "evaluation_ids": list(self.evaluation_ids),
            "required_evaluation_ids": list(self.required_evaluation_ids),
            "blocking_evaluation_ids": list(self.blocking_evaluation_ids),
            "warning_evaluation_ids": list(self.warning_evaluation_ids),
            "decided_by": self.decided_by,
            "rationale": self.rationale,
            "findings": [finding.to_dict() for finding in self.findings],
            "disposition": self.disposition.value,
            "can_proceed": self.can_proceed,
            "digest": envelope.digest,
            "metadata": dict(self.metadata),
        }
