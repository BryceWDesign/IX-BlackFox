from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum, auto
from typing import Any

from ix_blackfox.agents.authority import AuthorityEvaluation
from ix_blackfox.agents.authorization import (
    AgentAuthorizationDecision,
    AgentAuthorizationStatus,
)
from ix_blackfox.agents.models import AgentKind, AgentTrustTier
from ix_blackfox.agents.provenance import AgentProvenanceLedger
from ix_blackfox.agents.registry import AgentRegistry, AgentRegistrySnapshot
from ix_blackfox.operating.models import (
    digest_payload,
    normalize_identifier,
    normalize_text,
)


class AgentReadinessStatus(StrEnum):
    """Overall Wave 11 readiness status."""

    READY = auto()
    WARNING = auto()
    BLOCKED = auto()


class AgentReadinessFindingCode(StrEnum):
    """Deterministic finding codes for the Wave 11 agent readiness report."""

    NO_REGISTERED_AGENTS = auto()
    NO_ACTIVE_HUMAN_AUTHORITY = auto()
    REGISTRY_POLICY_BLOCKED = auto()
    REVIEW_DECISION_WITHOUT_AUTHORITY_EVALUATION = auto()
    AUTHORITY_NOT_PRESERVED = auto()
    DECISION_WITHOUT_PROVENANCE = auto()
    PROVENANCE_CHAIN_INVALID = auto()
    BLOCKED_AUTHORIZATION_DECISION_RECORDED = auto()
    REVIEW_AUTHORIZATION_DECISION_RECORDED = auto()
    SUSPENDED_OR_REVOKED_AGENT_PRESENT = auto()


@dataclass(frozen=True, slots=True)
class AgentReadinessFinding:
    """One readiness finding produced by the Wave 11 report."""

    code: AgentReadinessFindingCode
    summary: str
    blocking: bool = False
    agent_id: str = ""
    decision_id: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "agent_id",
            normalize_identifier(self.agent_id, label="agent_id")
            if self.agent_id
            else "",
        )
        object.__setattr__(
            self,
            "decision_id",
            normalize_identifier(self.decision_id, label="decision_id")
            if self.decision_id
            else "",
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "code": self.code.value,
            "summary": self.summary,
            "blocking": self.blocking,
            "agent_id": self.agent_id,
            "decision_id": self.decision_id,
        }


@dataclass(frozen=True, slots=True)
class AgentReadinessReport:
    """Digest-bound Wave 11 readiness report.

    The report answers whether the registry, authorization decisions, human
    authority checks, and provenance chain are coherent enough to treat Wave 11
    agent identity governance as ready.
    """

    report_id: str
    registry_snapshot: AgentRegistrySnapshot
    authorization_decisions: tuple[AgentAuthorizationDecision, ...] = ()
    authority_evaluations: tuple[AuthorityEvaluation, ...] = ()
    provenance_ledger: AgentProvenanceLedger | None = None
    generated_at: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "report_id",
            normalize_identifier(self.report_id, label="report_id"),
        )
        object.__setattr__(
            self,
            "authorization_decisions",
            tuple(
                sorted(
                    self.authorization_decisions,
                    key=lambda decision: decision.decision_id,
                )
            ),
        )
        object.__setattr__(
            self,
            "authority_evaluations",
            tuple(
                sorted(
                    self.authority_evaluations,
                    key=lambda evaluation: (
                        evaluation.decision_id,
                        evaluation.requester_agent_id,
                    ),
                )
            ),
        )
        object.__setattr__(
            self,
            "generated_at",
            normalize_text(self.generated_at, label="generated_at"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def findings(self) -> tuple[AgentReadinessFinding, ...]:
        findings: list[AgentReadinessFinding] = []
        findings.extend(_registry_findings(self.registry_snapshot))
        findings.extend(
            _decision_findings(
                decisions=self.authorization_decisions,
                evaluations=self.authority_evaluations,
                provenance_ledger=self.provenance_ledger,
            )
        )
        if self.provenance_ledger is not None and not self.provenance_ledger.chain_valid:
            findings.append(
                AgentReadinessFinding(
                    code=AgentReadinessFindingCode.PROVENANCE_CHAIN_INVALID,
                    summary="Agent provenance ledger chain validation failed.",
                    blocking=True,
                )
            )
        return tuple(sorted(findings, key=lambda finding: finding.code.value))

    @property
    def blocking_findings(self) -> tuple[AgentReadinessFinding, ...]:
        return tuple(finding for finding in self.findings if finding.blocking)

    @property
    def warning_findings(self) -> tuple[AgentReadinessFinding, ...]:
        return tuple(finding for finding in self.findings if not finding.blocking)

    @property
    def status(self) -> AgentReadinessStatus:
        if self.blocking_findings:
            return AgentReadinessStatus.BLOCKED
        if self.warning_findings:
            return AgentReadinessStatus.WARNING
        return AgentReadinessStatus.READY

    @property
    def ready(self) -> bool:
        return self.status is AgentReadinessStatus.READY

    @property
    def digest(self) -> str:
        return digest_payload(self.to_dict(include_digest=False))

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "report_id": self.report_id,
            "status": self.status.value,
            "ready": self.ready,
            "generated_at": self.generated_at,
            "registry_snapshot_digest": self.registry_snapshot.digest,
            "registry_id": self.registry_snapshot.registry_id,
            "active_agent_count": self.registry_snapshot.active_agent_count,
            "revoked_agent_count": self.registry_snapshot.revoked_agent_count,
            "authorization_decision_count": len(self.authorization_decisions),
            "authority_evaluation_count": len(self.authority_evaluations),
            "provenance_record_count": (
                self.provenance_ledger.record_count if self.provenance_ledger else 0
            ),
            "provenance_head_digest": (
                self.provenance_ledger.head_digest if self.provenance_ledger else ""
            ),
            "blocking_finding_count": len(self.blocking_findings),
            "warning_finding_count": len(self.warning_findings),
            "findings": [finding.to_dict() for finding in self.findings],
            "authorization_decisions": [
                decision.to_dict() for decision in self.authorization_decisions
            ],
            "authority_evaluations": [
                evaluation.to_dict() for evaluation in self.authority_evaluations
            ],
            "metadata": dict(self.metadata),
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload


def build_agent_readiness_report(
    *,
    registry: AgentRegistry,
    report_id: str = "wave-11-agent-readiness",
    authorization_decisions: Sequence[AgentAuthorizationDecision] = (),
    authority_evaluations: Sequence[AuthorityEvaluation] = (),
    provenance_ledger: AgentProvenanceLedger | None = None,
    generated_at: str,
    metadata: Mapping[str, Any] | None = None,
) -> AgentReadinessReport:
    """Build a Wave 11 readiness report from current agent-governance state."""

    return AgentReadinessReport(
        report_id=report_id,
        registry_snapshot=registry.snapshot(),
        authorization_decisions=tuple(authorization_decisions),
        authority_evaluations=tuple(authority_evaluations),
        provenance_ledger=provenance_ledger,
        generated_at=generated_at,
        metadata={} if metadata is None else dict(metadata),
    )


def _registry_findings(
    snapshot: AgentRegistrySnapshot,
) -> tuple[AgentReadinessFinding, ...]:
    findings: list[AgentReadinessFinding] = []

    if not snapshot.agents:
        findings.append(
            AgentReadinessFinding(
                code=AgentReadinessFindingCode.NO_REGISTERED_AGENTS,
                summary="Wave 11 registry contains no registered agents.",
                blocking=True,
            )
        )

    if not any(
        agent.active
        and agent.kind is AgentKind.HUMAN_OPERATOR
        and agent.trust_tier is AgentTrustTier.HUMAN_AUTHORITY
        for agent in snapshot.agents
    ):
        findings.append(
            AgentReadinessFinding(
                code=AgentReadinessFindingCode.NO_ACTIVE_HUMAN_AUTHORITY,
                summary=(
                    "Wave 11 registry has no active human authority agent for "
                    "review-required decisions."
                ),
                blocking=True,
            )
        )

    if snapshot.revoked_agent_count:
        findings.append(
            AgentReadinessFinding(
                code=AgentReadinessFindingCode.SUSPENDED_OR_REVOKED_AGENT_PRESENT,
                summary="Wave 11 registry contains revoked agents.",
                blocking=False,
            )
        )

    for result in snapshot.policy_results:
        for finding in result.blocking_findings:
            findings.append(
                AgentReadinessFinding(
                    code=AgentReadinessFindingCode.REGISTRY_POLICY_BLOCKED,
                    summary=finding.summary,
                    blocking=True,
                    agent_id=result.agent_id,
                )
            )

    return tuple(findings)


def _decision_findings(
    *,
    decisions: tuple[AgentAuthorizationDecision, ...],
    evaluations: tuple[AuthorityEvaluation, ...],
    provenance_ledger: AgentProvenanceLedger | None,
) -> tuple[AgentReadinessFinding, ...]:
    findings: list[AgentReadinessFinding] = []
    evaluation_by_decision = {
        evaluation.decision_id: evaluation for evaluation in evaluations
    }
    provenance_decision_ids = (
        {
            record.decision.decision_id
            for record in provenance_ledger.records
        }
        if provenance_ledger
        else set()
    )

    for decision in decisions:
        if decision.status is AgentAuthorizationStatus.BLOCK:
            findings.append(
                AgentReadinessFinding(
                    code=AgentReadinessFindingCode.BLOCKED_AUTHORIZATION_DECISION_RECORDED,
                    summary="Wave 11 recorded a blocked authorization decision.",
                    blocking=False,
                    agent_id=decision.request.agent_id,
                    decision_id=decision.decision_id,
                )
            )

        if decision.status is AgentAuthorizationStatus.REQUIRE_REVIEW:
            findings.append(
                AgentReadinessFinding(
                    code=AgentReadinessFindingCode.REVIEW_AUTHORIZATION_DECISION_RECORDED,
                    summary="Wave 11 recorded a review-required authorization decision.",
                    blocking=False,
                    agent_id=decision.request.agent_id,
                    decision_id=decision.decision_id,
                )
            )
            evaluation = evaluation_by_decision.get(decision.decision_id)
            if evaluation is None:
                findings.append(
                    AgentReadinessFinding(
                        code=(
                            AgentReadinessFindingCode.REVIEW_DECISION_WITHOUT_AUTHORITY_EVALUATION
                        ),
                        summary=(
                            "Review-required decision does not have a matching "
                            "human-authority evaluation."
                        ),
                        blocking=True,
                        agent_id=decision.request.agent_id,
                        decision_id=decision.decision_id,
                    )
                )
            elif not evaluation.authority_preserved:
                findings.append(
                    AgentReadinessFinding(
                        code=AgentReadinessFindingCode.AUTHORITY_NOT_PRESERVED,
                        summary=(
                            "Human authority was not preserved for a "
                            "review-required authorization decision."
                        ),
                        blocking=True,
                        agent_id=decision.request.agent_id,
                        decision_id=decision.decision_id,
                    )
                )

        if decision.decision_id not in provenance_decision_ids:
            findings.append(
                AgentReadinessFinding(
                    code=AgentReadinessFindingCode.DECISION_WITHOUT_PROVENANCE,
                    summary=(
                        "Authorization decision is not represented in the "
                        "agent provenance ledger."
                    ),
                    blocking=True,
                    agent_id=decision.request.agent_id,
                    decision_id=decision.decision_id,
                )
            )

    return tuple(findings)
