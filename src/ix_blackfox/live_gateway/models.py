from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum, auto
from typing import Any

from ix_blackfox.agents.authorization import AgentAuthorizationDecision
from ix_blackfox.operating.models import (
    digest_payload,
    normalize_optional_text,
    normalize_relative_path,
    normalize_text,
)

WAVE14_AUTHORITY_SUBJECT_SCHEMA_VERSION = "wave14.authority_subject.v1"
WAVE14_DECISION_SCHEMA_VERSION = "wave14.live_authority_decision.v1"
WAVE14_RECEIPT_SCHEMA_VERSION = "wave14.authority_receipt.v1"
WAVE14_EVIDENCE_SCHEMA_VERSION = "wave14.authority_evidence.v1"


class LiveAuthorityStatus(StrEnum):
    """Final Wave 14 pre-tool authority disposition."""

    ALLOW = auto()
    BLOCK = auto()
    REVIEW_REQUIRED = auto()
    EVIDENCE_REQUIRED = auto()


@dataclass(frozen=True, slots=True)
class AuthoritySubject:
    """Exact action subject to which Wave 14 evidence and authority bind."""

    agent_id: str
    tool_name: str
    capability: str
    repository_id: str
    revision: str
    path: str
    arguments_digest: str
    authority_context_digest: str
    protocol: str
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "agent_id", normalize_text(self.agent_id, label="agent_id"))
        object.__setattr__(self, "tool_name", normalize_text(self.tool_name, label="tool_name"))
        object.__setattr__(self, "capability", normalize_text(self.capability, label="capability"))
        object.__setattr__(
            self,
            "repository_id",
            normalize_optional_text(self.repository_id, label="repository_id"),
        )
        object.__setattr__(
            self,
            "revision",
            normalize_optional_text(self.revision, label="revision"),
        )
        normalized_path = normalize_relative_path(self.path) if self.path.strip() else ""
        object.__setattr__(self, "path", normalized_path)
        object.__setattr__(self, "arguments_digest", normalize_text(self.arguments_digest, label="arguments_digest"))
        object.__setattr__(
            self,
            "authority_context_digest",
            normalize_text(self.authority_context_digest, label="authority_context_digest"),
        )
        for label, value in (
            ("arguments_digest", self.arguments_digest),
            ("authority_context_digest", self.authority_context_digest),
        ):
            if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
                raise ValueError(f"{label} must be a lowercase SHA-256 digest.")
        object.__setattr__(self, "protocol", normalize_text(self.protocol, label="protocol"))
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def digest(self) -> str:
        return digest_payload(self.to_dict(include_digest=False))

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": WAVE14_AUTHORITY_SUBJECT_SCHEMA_VERSION,
            "agent_id": self.agent_id,
            "tool_name": self.tool_name,
            "capability": self.capability,
            "repository_id": self.repository_id,
            "revision": self.revision,
            "path": self.path,
            "arguments_digest": self.arguments_digest,
            "authority_context_digest": self.authority_context_digest,
            "protocol": self.protocol,
            "metadata": dict(self.metadata),
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload


@dataclass(frozen=True, slots=True)
class EvidenceIssue:
    """One fail-closed evidence verification issue."""

    code: str
    summary: str
    evidence_id: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "summary": self.summary,
            "evidence_id": self.evidence_id,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class EvidenceVerification:
    """Verification result for one serialized Wave 14 evidence artifact."""

    evidence_id: str
    kind: str
    issuer: str
    passed: bool
    digest: str = ""
    status: str = ""
    issues: tuple[EvidenceIssue, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "kind": self.kind,
            "issuer": self.issuer,
            "passed": self.passed,
            "digest": self.digest,
            "status": self.status,
            "issue_count": len(self.issues),
            "issues": [issue.to_dict() for issue in self.issues],
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class EvidenceEvaluation:
    """Combined evidence-condition result for one exact authority subject."""

    policy_id: str
    required_kinds: tuple[str, ...]
    valid_evidence_ids: tuple[str, ...]
    missing_kinds: tuple[str, ...]
    human_approval_satisfied: bool
    verifications: tuple[EvidenceVerification, ...]
    issues: tuple[EvidenceIssue, ...] = ()

    @property
    def passed(self) -> bool:
        return not self.missing_kinds and not self.issues

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "passed": self.passed,
            "required_kinds": list(self.required_kinds),
            "valid_evidence_ids": list(self.valid_evidence_ids),
            "missing_kinds": list(self.missing_kinds),
            "human_approval_satisfied": self.human_approval_satisfied,
            "verification_count": len(self.verifications),
            "verifications": [item.to_dict() for item in self.verifications],
            "issue_count": len(self.issues),
            "issues": [issue.to_dict() for issue in self.issues],
        }


@dataclass(frozen=True, slots=True)
class LiveAuthorityDecision:
    """Final Wave 14 decision combining identity scope and evidence conditions."""

    subject: AuthoritySubject
    status: LiveAuthorityStatus
    reason_codes: tuple[str, ...]
    agent_authorization: AgentAuthorizationDecision
    evidence: EvidenceEvaluation
    decided_at: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "reason_codes", tuple(sorted(set(self.reason_codes))))
        object.__setattr__(self, "decided_at", normalize_text(self.decided_at, label="decided_at"))
        if not self.reason_codes:
            raise ValueError("LiveAuthorityDecision reason_codes must not be empty.")

    @property
    def allowed(self) -> bool:
        return self.status is LiveAuthorityStatus.ALLOW

    @property
    def digest(self) -> str:
        return digest_payload(self.to_dict(include_digest=False))

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": WAVE14_DECISION_SCHEMA_VERSION,
            "subject": self.subject.to_dict(),
            "status": self.status.value,
            "reason_codes": list(self.reason_codes),
            "agent_authorization": self.agent_authorization.to_dict(),
            "evidence": self.evidence.to_dict(),
            "decided_at": self.decided_at,
            "allowed": self.allowed,
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload
