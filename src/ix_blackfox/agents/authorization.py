from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum, auto
from typing import Any

from ix_blackfox.agents.models import AgentCapability, CapabilityRiskTier
from ix_blackfox.operating.models import (
    OperatingDomain,
    digest_payload,
    normalize_identifier,
    normalize_optional_text,
    normalize_path_tuple,
    normalize_text,
)
from ix_blackfox.operating.registry import normalize_identifier_tuple


class AgentAction(StrEnum):
    """Action families that can be requested by a registered actor."""

    PROPOSE = auto()
    REVIEW = auto()
    APPLY = auto()
    RUN = auto()
    READ = auto()
    WRITE = auto()
    INSPECT = auto()
    EXPORT = auto()
    APPROVE = auto()
    MUTATE = auto()
    ACCESS = auto()
    REGISTER = auto()
    DELEGATE = auto()
    REVOKE = auto()


class AgentAuthorizationStatus(StrEnum):
    """Top-level authorization result."""

    ALLOW = auto()
    REQUIRE_REVIEW = auto()
    BLOCK = auto()


class AgentAuthorizationReason(StrEnum):
    """Deterministic reason codes for Wave 11 authorization decisions."""

    ALLOWED = auto()
    REVIEW_REQUIRED_BY_SCOPE = auto()
    UNKNOWN_AGENT = auto()
    REVOKED_AGENT = auto()
    SUSPENDED_AGENT = auto()
    MISSING_CAPABILITY = auto()
    CAPABILITY_OUT_OF_SCOPE = auto()
    HUMAN_AUTHORITY_REQUIRED = auto()
    MODEL_SELF_APPROVAL_BLOCKED = auto()
    SYSTEM_SELF_APPROVAL_BLOCKED = auto()
    TOOL_CAPABILITY_NOT_DECLARED = auto()
    EVIDENCE_MISSING = auto()
    DELEGATION_INVALID = auto()
    EXPIRED_GRANT = auto()
    RESTRICTED_DOMAIN = auto()
    POLICY_FINDING_BLOCKED = auto()


@dataclass(frozen=True, slots=True)
class AgentAuthorizationTarget:
    """Normalized target scope for an authorization request."""

    repository_id: str = ""
    domain: OperatingDomain | None = None
    tool_id: str = ""
    pack_id: str = ""
    path: str = ""
    work_package_id: str = ""
    artifact_ids: tuple[str, ...] = ()
    risk_tier: CapabilityRiskTier = CapabilityRiskTier.MEDIUM
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "repository_id",
            normalize_optional_text(self.repository_id, label="repository_id"),
        )
        object.__setattr__(
            self,
            "tool_id",
            normalize_optional_text(self.tool_id, label="tool_id"),
        )
        object.__setattr__(
            self,
            "pack_id",
            normalize_optional_text(self.pack_id, label="pack_id"),
        )
        normalized_path = ""
        if self.path:
            normalized_path = normalize_path_tuple((self.path,), label="path")[0]
        object.__setattr__(self, "path", normalized_path)
        object.__setattr__(
            self,
            "work_package_id",
            normalize_optional_text(
                self.work_package_id,
                label="work_package_id",
            ),
        )
        object.__setattr__(
            self,
            "artifact_ids",
            normalize_identifier_tuple(self.artifact_ids, label="artifact_ids"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def bounded(self) -> bool:
        return bool(
            self.repository_id
            or self.domain is not None
            or self.tool_id
            or self.pack_id
            or self.path
            or self.work_package_id
            or self.artifact_ids
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "repository_id": self.repository_id,
            "domain": self.domain.value if self.domain else "",
            "tool_id": self.tool_id,
            "pack_id": self.pack_id,
            "path": self.path,
            "work_package_id": self.work_package_id,
            "artifact_ids": list(self.artifact_ids),
            "risk_tier": self.risk_tier.value,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class AgentAuthorizationRequest:
    """One action request made by one registered actor."""

    request_id: str
    agent_id: str
    action: AgentAction
    capability: AgentCapability
    target: AgentAuthorizationTarget
    requested_at: str
    evidence_artifact_ids: tuple[str, ...] = ()
    justification: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "request_id",
            normalize_identifier(self.request_id, label="request_id"),
        )
        object.__setattr__(
            self,
            "agent_id",
            normalize_identifier(self.agent_id, label="agent_id"),
        )
        object.__setattr__(
            self,
            "requested_at",
            normalize_text(self.requested_at, label="requested_at"),
        )
        object.__setattr__(
            self,
            "evidence_artifact_ids",
            normalize_identifier_tuple(
                self.evidence_artifact_ids,
                label="evidence_artifact_ids",
            ),
        )
        object.__setattr__(
            self,
            "justification",
            normalize_optional_text(self.justification, label="justification"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))
        if not self.target.bounded:
            raise ValueError("AgentAuthorizationRequest target must be bounded.")

    @property
    def digest(self) -> str:
        return digest_payload(self.to_dict(include_digest=False))

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "request_id": self.request_id,
            "agent_id": self.agent_id,
            "action": self.action.value,
            "capability": self.capability.value,
            "target": self.target.to_dict(),
            "requested_at": self.requested_at,
            "evidence_artifact_ids": list(self.evidence_artifact_ids),
            "justification": self.justification,
            "metadata": dict(self.metadata),
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload


@dataclass(frozen=True, slots=True)
class AgentAuthorizationDecision:
    """Evidence-bound decision for one Wave 11 authorization request."""

    decision_id: str
    request: AgentAuthorizationRequest
    status: AgentAuthorizationStatus
    reasons: tuple[AgentAuthorizationReason, ...]
    decided_at: str
    reviewer_agent_id: str = ""
    evidence_artifact_ids: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "decision_id",
            normalize_identifier(self.decision_id, label="decision_id"),
        )
        object.__setattr__(
            self,
            "reasons",
            tuple(sorted(set(self.reasons), key=lambda reason: reason.value)),
        )
        object.__setattr__(
            self,
            "decided_at",
            normalize_text(self.decided_at, label="decided_at"),
        )
        object.__setattr__(
            self,
            "reviewer_agent_id",
            normalize_optional_text(
                self.reviewer_agent_id,
                label="reviewer_agent_id",
            ),
        )
        object.__setattr__(
            self,
            "evidence_artifact_ids",
            normalize_identifier_tuple(
                self.evidence_artifact_ids,
                label="evidence_artifact_ids",
            ),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))
        if not self.reasons:
            raise ValueError("AgentAuthorizationDecision reasons must not be empty.")
        if self.status is AgentAuthorizationStatus.ALLOW and self.reviewer_agent_id:
            raise ValueError("ALLOW decisions must not imply human review authority.")
        if (
            self.status is AgentAuthorizationStatus.REQUIRE_REVIEW
            and not self.reviewer_agent_id
        ):
            raise ValueError("REQUIRE_REVIEW decisions must name a reviewer agent id.")

    @property
    def allowed(self) -> bool:
        return self.status is AgentAuthorizationStatus.ALLOW

    @property
    def requires_review(self) -> bool:
        return self.status is AgentAuthorizationStatus.REQUIRE_REVIEW

    @property
    def blocked(self) -> bool:
        return self.status is AgentAuthorizationStatus.BLOCK

    @property
    def digest(self) -> str:
        return digest_payload(self.to_dict(include_digest=False))

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "decision_id": self.decision_id,
            "request": self.request.to_dict(),
            "status": self.status.value,
            "reasons": [reason.value for reason in self.reasons],
            "decided_at": self.decided_at,
            "reviewer_agent_id": self.reviewer_agent_id,
            "evidence_artifact_ids": list(self.evidence_artifact_ids),
            "allowed": self.allowed,
            "requires_review": self.requires_review,
            "blocked": self.blocked,
            "metadata": dict(self.metadata),
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload


def build_decision_id(request: AgentAuthorizationRequest, status: AgentAuthorizationStatus) -> str:
    """Build a stable decision id for deterministic tests and reports."""

    digest = digest_payload(
        {
            "request_digest": request.digest,
            "status": status.value,
        }
    )
    return f"agent-auth-{digest[:24]}"
