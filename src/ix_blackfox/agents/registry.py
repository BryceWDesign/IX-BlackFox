from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from ix_blackfox.agents.capabilities import (
    CapabilityPolicyResult,
    validate_agent_capability_posture,
)
from ix_blackfox.agents.models import (
    WAVE11_AGENT_IDENTITY_SCHEMA_VERSION,
    AgentCapability,
    AgentIdentity,
    AgentKind,
    AgentLifecycleState,
)
from ix_blackfox.operating.models import digest_payload, normalize_identifier


@dataclass(frozen=True, slots=True)
class AgentRegistrySnapshot:
    """Digest-bound snapshot of the Wave 11 agent registry."""

    schema_version: str
    registry_id: str
    agents: tuple[AgentIdentity, ...]
    policy_results: tuple[CapabilityPolicyResult, ...]
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "registry_id",
            normalize_identifier(self.registry_id, label="registry_id"),
        )
        agents = tuple(sorted(self.agents, key=lambda agent: agent.agent_id))
        agent_ids = [agent.agent_id for agent in agents]
        if len(agent_ids) != len(set(agent_ids)):
            raise ValueError("AgentRegistrySnapshot agent_id values must be unique.")
        object.__setattr__(self, "agents", agents)
        results = tuple(sorted(self.policy_results, key=lambda result: result.agent_id))
        result_ids = [result.agent_id for result in results]
        if tuple(agent_ids) != tuple(result_ids):
            raise ValueError("AgentRegistrySnapshot policy results must match agents.")
        object.__setattr__(self, "policy_results", results)
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def active_agent_count(self) -> int:
        return sum(1 for agent in self.agents if agent.active)

    @property
    def revoked_agent_count(self) -> int:
        return sum(
            1
            for agent in self.agents
            if agent.lifecycle_state is AgentLifecycleState.REVOKED
        )

    @property
    def blocking_finding_count(self) -> int:
        return sum(len(result.blocking_findings) for result in self.policy_results)

    @property
    def ready(self) -> bool:
        return self.blocking_finding_count == 0

    @property
    def digest(self) -> str:
        return digest_payload(self.to_dict(include_digest=False))

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": self.schema_version,
            "registry_id": self.registry_id,
            "ready": self.ready,
            "active_agent_count": self.active_agent_count,
            "revoked_agent_count": self.revoked_agent_count,
            "blocking_finding_count": self.blocking_finding_count,
            "agents": [agent.to_dict() for agent in self.agents],
            "policy_results": [result.to_dict() for result in self.policy_results],
            "metadata": dict(self.metadata),
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload


@dataclass(frozen=True, slots=True)
class AgentRegistry:
    """Authoritative Wave 11 registry of identity-bound actors."""

    registry_id: str
    agents: tuple[AgentIdentity, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "registry_id",
            normalize_identifier(self.registry_id, label="registry_id"),
        )
        agents = tuple(sorted(self.agents, key=lambda agent: agent.agent_id))
        agent_ids = [agent.agent_id for agent in agents]
        if len(agent_ids) != len(set(agent_ids)):
            raise ValueError("AgentRegistry agent_id values must be unique.")
        object.__setattr__(self, "agents", agents)
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def agent_ids(self) -> tuple[str, ...]:
        return tuple(agent.agent_id for agent in self.agents)

    @property
    def active_agents(self) -> tuple[AgentIdentity, ...]:
        return tuple(agent for agent in self.agents if agent.active)

    @property
    def revoked_agents(self) -> tuple[AgentIdentity, ...]:
        return tuple(
            agent
            for agent in self.agents
            if agent.lifecycle_state is AgentLifecycleState.REVOKED
        )

    @property
    def digest(self) -> str:
        return digest_payload(self.to_dict(include_digest=False))

    def register(self, agent: AgentIdentity) -> AgentRegistry:
        """Return a registry with a new agent added.

        Duplicate agent ids are blocked. Use replace() for explicit updates.
        """

        if agent.agent_id in self.agent_ids:
            raise ValueError(f"agent already registered: {agent.agent_id}")
        return AgentRegistry(
            registry_id=self.registry_id,
            agents=(*self.agents, agent),
            metadata=self.metadata,
        )

    def replace(self, agent: AgentIdentity) -> AgentRegistry:
        """Return a registry with an existing agent replaced."""

        if agent.agent_id not in self.agent_ids:
            raise ValueError(f"agent is not registered: {agent.agent_id}")
        return AgentRegistry(
            registry_id=self.registry_id,
            agents=tuple(
                agent if current.agent_id == agent.agent_id else current
                for current in self.agents
            ),
            metadata=self.metadata,
        )

    def lookup(self, agent_id: str) -> AgentIdentity | None:
        normalized = normalize_identifier(agent_id, label="agent_id")
        return next(
            (agent for agent in self.agents if agent.agent_id == normalized), None
        )

    def require(self, agent_id: str) -> AgentIdentity:
        agent = self.lookup(agent_id)
        if agent is None:
            normalized = normalize_identifier(agent_id, label="agent_id")
            raise KeyError(f"agent is not registered: {normalized}")
        return agent

    def find_by_kind(self, kind: AgentKind) -> tuple[AgentIdentity, ...]:
        return tuple(agent for agent in self.agents if agent.kind is kind)

    def find_by_capability(
        self,
        capability: AgentCapability,
        *,
        active_only: bool = True,
    ) -> tuple[AgentIdentity, ...]:
        candidates = self.active_agents if active_only else self.agents
        return tuple(agent for agent in candidates if agent.has_capability(capability))

    def snapshot(self) -> AgentRegistrySnapshot:
        return AgentRegistrySnapshot(
            schema_version=WAVE11_AGENT_IDENTITY_SCHEMA_VERSION,
            registry_id=self.registry_id,
            agents=self.agents,
            policy_results=tuple(
                validate_agent_capability_posture(agent) for agent in self.agents
            ),
            metadata=self.metadata,
        )

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "registry_id": self.registry_id,
            "agent_ids": list(self.agent_ids),
            "active_agent_count": len(self.active_agents),
            "revoked_agent_count": len(self.revoked_agents),
            "agents": [agent.to_dict() for agent in self.agents],
            "metadata": dict(self.metadata),
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload


def build_agent_registry(
    registry_id: str,
    agents: Iterable[AgentIdentity],
    *,
    metadata: Mapping[str, Any] | None = None,
) -> AgentRegistry:
    """Build a registry from an iterable while preserving duplicate checks."""

    return AgentRegistry(
        registry_id=registry_id,
        agents=tuple(agents),
        metadata={} if metadata is None else dict(metadata),
    )
