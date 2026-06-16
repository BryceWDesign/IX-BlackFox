from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum, auto
from typing import Any

from ix_blackfox.agents.authorization import (
    AgentAuthorizationDecision,
    AgentAuthorizationRequest,
)
from ix_blackfox.agents.capabilities import capability_is_human_only
from ix_blackfox.agents.models import AgentIdentity
from ix_blackfox.agents.registry import AgentRegistry
from ix_blackfox.operating.models import digest_payload, normalize_identifier


class AuthorityFindingCode(StrEnum):
    """Human-authority and self-approval finding codes for Wave 11."""

    HUMAN_REVIEW_NOT_REQUIRED = auto()
    HUMAN_REVIEW_SATISFIED = auto()
    REVIEWER_MISSING = auto()
    REVIEWER_UNKNOWN = auto()
    REVIEWER_NOT_HUMAN_AUTHORITY = auto()
    SELF_APPROVAL_BLOCKED = auto()
    HUMAN_ONLY_CAPABILITY_BLOCKED = auto()
    REQUESTER_UNKNOWN = auto()


@dataclass(frozen=True, slots=True)
class AuthorityFinding:
    """One finding from human-authority validation."""

    code: AuthorityFindingCode
    summary: str
    blocking: bool = False
    agent_id: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "agent_id",
            normalize_identifier(self.agent_id, label="agent_id")
            if self.agent_id
            else "",
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "code": self.code.value,
            "summary": self.summary,
            "blocking": self.blocking,
            "agent_id": self.agent_id,
        }


@dataclass(frozen=True, slots=True)
class AuthorityEvaluation:
    """Digest-bound result proving whether human authority was preserved."""

    request_id: str
    decision_id: str
    requester_agent_id: str
    reviewer_agent_id: str
    findings: tuple[AuthorityFinding, ...]
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "request_id",
            normalize_identifier(self.request_id, label="request_id"),
        )
        object.__setattr__(
            self,
            "decision_id",
            normalize_identifier(self.decision_id, label="decision_id"),
        )
        object.__setattr__(
            self,
            "requester_agent_id",
            normalize_identifier(self.requester_agent_id, label="requester_agent_id"),
        )
        object.__setattr__(
            self,
            "reviewer_agent_id",
            normalize_identifier(self.reviewer_agent_id, label="reviewer_agent_id")
            if self.reviewer_agent_id
            else "",
        )
        object.__setattr__(
            self,
            "findings",
            tuple(sorted(self.findings, key=lambda finding: finding.code.value)),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def blocking_findings(self) -> tuple[AuthorityFinding, ...]:
        return tuple(finding for finding in self.findings if finding.blocking)

    @property
    def authority_preserved(self) -> bool:
        return not self.blocking_findings

    @property
    def digest(self) -> str:
        return digest_payload(self.to_dict(include_digest=False))

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "request_id": self.request_id,
            "decision_id": self.decision_id,
            "requester_agent_id": self.requester_agent_id,
            "reviewer_agent_id": self.reviewer_agent_id,
            "authority_preserved": self.authority_preserved,
            "blocking_finding_count": len(self.blocking_findings),
            "findings": [finding.to_dict() for finding in self.findings],
            "metadata": dict(self.metadata),
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload


def evaluate_human_authority(
    *,
    registry: AgentRegistry,
    request: AgentAuthorizationRequest,
    decision: AgentAuthorizationDecision,
) -> AuthorityEvaluation:
    """Validate human-authority preservation for one decision.

    This check is intentionally separate from authorization evaluation so reports,
    CI scripts, and adapters can prove that review did not become self-approval.
    """

    findings: list[AuthorityFinding] = []
    requester = registry.lookup(request.agent_id)
    reviewer = _lookup_reviewer(registry, decision.reviewer_agent_id)

    if requester is None:
        findings.append(
            AuthorityFinding(
                code=AuthorityFindingCode.REQUESTER_UNKNOWN,
                summary="Requesting agent is not registered.",
                blocking=True,
                agent_id=request.agent_id,
            )
        )

    if decision.requires_review:
        findings.extend(_review_findings(request, decision, requester, reviewer))
    else:
        findings.append(
            AuthorityFinding(
                code=AuthorityFindingCode.HUMAN_REVIEW_NOT_REQUIRED,
                summary="Decision does not require a human reviewer.",
            )
        )

    if capability_is_human_only(request.capability) and (
        requester is None or not requester.can_hold_human_authority
    ):
        findings.append(
            AuthorityFinding(
                code=AuthorityFindingCode.HUMAN_ONLY_CAPABILITY_BLOCKED,
                summary=(
                    "Human-only capability was requested by a non-human "
                    "authority agent."
                ),
                blocking=True,
                agent_id=request.agent_id,
            )
        )

    return AuthorityEvaluation(
        request_id=request.request_id,
        decision_id=decision.decision_id,
        requester_agent_id=request.agent_id,
        reviewer_agent_id=decision.reviewer_agent_id,
        findings=tuple(findings),
        metadata={"decision_status": decision.status.value},
    )


def _review_findings(
    request: AgentAuthorizationRequest,
    decision: AgentAuthorizationDecision,
    requester: AgentIdentity | None,
    reviewer: AgentIdentity | None,
) -> tuple[AuthorityFinding, ...]:
    findings: list[AuthorityFinding] = []

    if not decision.reviewer_agent_id:
        findings.append(
            AuthorityFinding(
                code=AuthorityFindingCode.REVIEWER_MISSING,
                summary="Review-required decision does not identify a reviewer.",
                blocking=True,
            )
        )
        return tuple(findings)

    if reviewer is None:
        findings.append(
            AuthorityFinding(
                code=AuthorityFindingCode.REVIEWER_UNKNOWN,
                summary="Reviewer agent is not registered.",
                blocking=True,
                agent_id=decision.reviewer_agent_id,
            )
        )
        return tuple(findings)

    if requester is not None and reviewer.agent_id == requester.agent_id:
        findings.append(
            AuthorityFinding(
                code=AuthorityFindingCode.SELF_APPROVAL_BLOCKED,
                summary="Requester cannot serve as its own human authority reviewer.",
                blocking=True,
                agent_id=reviewer.agent_id,
            )
        )

    if not reviewer.can_hold_human_authority:
        findings.append(
            AuthorityFinding(
                code=AuthorityFindingCode.REVIEWER_NOT_HUMAN_AUTHORITY,
                summary="Reviewer is not an active human authority agent.",
                blocking=True,
                agent_id=reviewer.agent_id,
            )
        )

    if not any(finding.blocking for finding in findings):
        findings.append(
            AuthorityFinding(
                code=AuthorityFindingCode.HUMAN_REVIEW_SATISFIED,
                summary=(
                    "Review-required decision names a separate active human "
                    "authority reviewer."
                ),
                agent_id=reviewer.agent_id,
            )
        )

    return tuple(findings)


def _lookup_reviewer(
    registry: AgentRegistry,
    reviewer_agent_id: str,
) -> AgentIdentity | None:
    if not reviewer_agent_id:
        return None
    return registry.lookup(reviewer_agent_id)
