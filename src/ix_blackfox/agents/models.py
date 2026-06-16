from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum, auto
from typing import Any

from ix_blackfox.operating.models import (
    OperatingDomain,
    digest_payload,
    normalize_identifier,
    normalize_optional_text,
    normalize_path_tuple,
    normalize_text,
    unique_sorted_enum_tuple,
)
from ix_blackfox.operating.registry import normalize_identifier_tuple

WAVE11_AGENT_IDENTITY_SCHEMA_VERSION = "wave11.agent_identity_registry.v1"


class AgentKind(StrEnum):
    """Actor categories governed by the Wave 11 identity registry."""

    HUMAN_OPERATOR = auto()
    MODEL_BRAIN = auto()
    TOOL = auto()
    SYSTEM_SERVICE = auto()
    CI_RUNNER = auto()
    POLICY_ENGINE = auto()
    REPOSITORY = auto()
    EXTERNAL_AGENT = auto()
    UNKNOWN = auto()


class AgentTrustTier(StrEnum):
    """Trust tier assigned to a registered actor before action authorization."""

    HUMAN_AUTHORITY = auto()
    GOVERNED_AUTOMATION = auto()
    REGISTERED_TOOL = auto()
    REGISTERED_REPOSITORY = auto()
    OBSERVER = auto()
    UNKNOWN = auto()


class AgentLifecycleState(StrEnum):
    """Lifecycle state used to prevent revoked actors from acting as active."""

    ACTIVE = auto()
    SUSPENDED = auto()
    REVOKED = auto()


class CapabilityRiskTier(StrEnum):
    """Risk tier for one delegated capability grant."""

    LOW = auto()
    MEDIUM = auto()
    HIGH = auto()
    CRITICAL = auto()


class AgentCapability(StrEnum):
    """Capability families that can be granted to a Wave 11 actor."""

    PROPOSE_PATCH = auto()
    REVIEW_PATCH = auto()
    APPLY_PATCH = auto()
    RUN_TESTS = auto()
    RUN_PROCESS = auto()
    READ_WORKSPACE = auto()
    WRITE_WORKSPACE = auto()
    INSPECT_POLICY = auto()
    EXPORT_EVIDENCE = auto()
    APPROVE_RELEASE = auto()
    APPROVE_SECURITY = auto()
    APPROVE_COMPLIANCE = auto()
    APPROVE_SANDBOX_EGRESS = auto()
    MUTATE_SYSTEM = auto()
    ACCESS_SECRET = auto()
    ACCESS_NETWORK = auto()
    REGISTER_AGENT = auto()
    DELEGATE_CAPABILITY = auto()
    REVOKE_AGENT = auto()


@dataclass(frozen=True, slots=True)
class AgentCapabilityScope:
    """Scope boundary for one capability grant.

    A grant must be bounded by at least one repository, operating domain, tool,
    pack, path root, or evidence artifact so broad authority cannot be implied.
    """

    repository_ids: tuple[str, ...] = ()
    domains: tuple[OperatingDomain, ...] = ()
    tool_ids: tuple[str, ...] = ()
    pack_ids: tuple[str, ...] = ()
    path_roots: tuple[str, ...] = ()
    max_risk_tier: CapabilityRiskTier = CapabilityRiskTier.MEDIUM
    requires_human_review: bool = False
    evidence_artifact_ids: tuple[str, ...] = ()
    delegated_by: str = ""
    expires_at: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "repository_ids",
            normalize_identifier_tuple(self.repository_ids, label="repository_ids"),
        )
        object.__setattr__(self, "domains", unique_sorted_enum_tuple(self.domains))
        object.__setattr__(
            self,
            "tool_ids",
            normalize_identifier_tuple(self.tool_ids, label="tool_ids"),
        )
        object.__setattr__(
            self,
            "pack_ids",
            normalize_identifier_tuple(self.pack_ids, label="pack_ids"),
        )
        object.__setattr__(
            self,
            "path_roots",
            normalize_path_tuple(self.path_roots, label="path_roots"),
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
            "delegated_by",
            normalize_optional_text(self.delegated_by, label="delegated_by"),
        )
        object.__setattr__(
            self,
            "expires_at",
            normalize_optional_text(self.expires_at, label="expires_at"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))
        if not self.has_boundary:
            raise ValueError("AgentCapabilityScope must include at least one boundary.")

    @property
    def has_boundary(self) -> bool:
        return bool(
            self.repository_ids
            or self.domains
            or self.tool_ids
            or self.pack_ids
            or self.path_roots
            or self.evidence_artifact_ids
        )

    def covers_repository(self, repository_id: str) -> bool:
        if not self.repository_ids:
            return True
        normalized = normalize_identifier(repository_id, label="repository_id")
        return normalized in self.repository_ids

    def covers_domain(self, domain: OperatingDomain) -> bool:
        return not self.domains or domain in self.domains

    def to_dict(self) -> dict[str, Any]:
        return {
            "repository_ids": list(self.repository_ids),
            "domains": [domain.value for domain in self.domains],
            "tool_ids": list(self.tool_ids),
            "pack_ids": list(self.pack_ids),
            "path_roots": list(self.path_roots),
            "max_risk_tier": self.max_risk_tier.value,
            "requires_human_review": self.requires_human_review,
            "evidence_artifact_ids": list(self.evidence_artifact_ids),
            "delegated_by": self.delegated_by,
            "expires_at": self.expires_at,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class AgentCapabilityGrant:
    """One explicit capability granted to one registered actor."""

    grant_id: str
    capability: AgentCapability
    scope: AgentCapabilityScope
    active: bool = True
    rationale: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "grant_id",
            normalize_identifier(self.grant_id, label="grant_id"),
        )
        object.__setattr__(
            self,
            "rationale",
            normalize_optional_text(self.rationale, label="rationale"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def digest(self) -> str:
        return digest_payload(self.to_dict(include_digest=False))

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "grant_id": self.grant_id,
            "capability": self.capability.value,
            "scope": self.scope.to_dict(),
            "active": self.active,
            "rationale": self.rationale,
            "metadata": dict(self.metadata),
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload


@dataclass(frozen=True, slots=True)
class AgentIdentity:
    """Registered Wave 11 actor with explicit scoped capabilities."""

    agent_id: str
    display_name: str
    kind: AgentKind
    trust_tier: AgentTrustTier
    capability_grants: tuple[AgentCapabilityGrant, ...]
    lifecycle_state: AgentLifecycleState = AgentLifecycleState.ACTIVE
    issuer: str = ""
    subject: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "agent_id",
            normalize_identifier(self.agent_id, label="agent_id"),
        )
        object.__setattr__(
            self,
            "display_name",
            normalize_text(self.display_name, label="display_name"),
        )
        if not self.capability_grants:
            raise ValueError("AgentIdentity capability_grants must not be empty.")
        grants = tuple(sorted(self.capability_grants, key=lambda grant: grant.grant_id))
        grant_ids = [grant.grant_id for grant in grants]
        if len(grant_ids) != len(set(grant_ids)):
            raise ValueError("AgentIdentity grant_id values must be unique.")
        object.__setattr__(self, "capability_grants", grants)
        object.__setattr__(
            self,
            "issuer",
            normalize_optional_text(self.issuer, label="issuer"),
        )
        object.__setattr__(
            self,
            "subject",
            normalize_optional_text(self.subject, label="subject"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))
        self._validate_identity_boundary()

    @property
    def active(self) -> bool:
        return self.lifecycle_state is AgentLifecycleState.ACTIVE

    @property
    def can_hold_human_authority(self) -> bool:
        return self.active and self.kind is AgentKind.HUMAN_OPERATOR

    @property
    def active_grants(self) -> tuple[AgentCapabilityGrant, ...]:
        return tuple(grant for grant in self.capability_grants if grant.active)

    @property
    def capabilities(self) -> tuple[AgentCapability, ...]:
        return unique_sorted_enum_tuple(
            tuple(grant.capability for grant in self.active_grants)
        )

    @property
    def digest(self) -> str:
        return digest_payload(self.to_dict(include_digest=False))

    def has_capability(self, capability: AgentCapability) -> bool:
        return capability in self.capabilities

    def grants_for(self, capability: AgentCapability) -> tuple[AgentCapabilityGrant, ...]:
        return tuple(grant for grant in self.active_grants if grant.capability is capability)

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "agent_id": self.agent_id,
            "display_name": self.display_name,
            "kind": self.kind.value,
            "trust_tier": self.trust_tier.value,
            "lifecycle_state": self.lifecycle_state.value,
            "issuer": self.issuer,
            "subject": self.subject,
            "active": self.active,
            "can_hold_human_authority": self.can_hold_human_authority,
            "capabilities": [capability.value for capability in self.capabilities],
            "capability_grants": [grant.to_dict() for grant in self.capability_grants],
            "metadata": dict(self.metadata),
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload

    def _validate_identity_boundary(self) -> None:
        if self.kind is AgentKind.UNKNOWN and self.trust_tier is not AgentTrustTier.UNKNOWN:
            raise ValueError("UNKNOWN agent kind must use UNKNOWN trust tier.")
        if (
            self.kind is not AgentKind.HUMAN_OPERATOR
            and self.trust_tier is AgentTrustTier.HUMAN_AUTHORITY
        ):
            raise ValueError("Only human operators may hold HUMAN_AUTHORITY trust tier.")
        if self.lifecycle_state is AgentLifecycleState.REVOKED and self.active_grants:
            raise ValueError("Revoked agents must not retain active grants.")


def normalize_capability_grants(
    grants: Sequence[AgentCapabilityGrant],
) -> tuple[AgentCapabilityGrant, ...]:
    """Return grants sorted by grant id with duplicate ids rejected."""

    normalized = tuple(sorted(grants, key=lambda grant: grant.grant_id))
    grant_ids = [grant.grant_id for grant in normalized]
    if len(grant_ids) != len(set(grant_ids)):
        raise ValueError("capability grant_id values must be unique.")
    return normalized
