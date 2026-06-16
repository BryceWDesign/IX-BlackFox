from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from ix_blackfox.agents.capabilities import (
    capability_default_risk_tier,
    capability_requires_human_review,
)
from ix_blackfox.agents.models import (
    AgentCapability,
    AgentCapabilityGrant,
    AgentCapabilityScope,
    AgentIdentity,
    AgentKind,
    AgentLifecycleState,
    AgentTrustTier,
)
from ix_blackfox.agents.registry import AgentRegistry, build_agent_registry
from ix_blackfox.brains.contracts import BrainCapability
from ix_blackfox.brains.manifest import BrainManifest, BrainManifestSnapshot
from ix_blackfox.operating.authority import (
    ReviewBoard,
    ReviewerAuthority,
    ReviewerKind,
    TeamRole,
)
from ix_blackfox.operating.models import OperatingDomain, normalize_identifier
from ix_blackfox.tools.manifest import (
    ToolApprovalMode,
    ToolCapability,
    ToolManifest,
    ToolManifestRegistry,
    ToolSideEffect,
)


_BRAIN_CAPABILITY_MAP: dict[BrainCapability, tuple[AgentCapability, ...]] = {
    BrainCapability.TEXT_GENERATION: (AgentCapability.PROPOSE_PATCH,),
    BrainCapability.CODE_GENERATION: (AgentCapability.PROPOSE_PATCH,),
    BrainCapability.STRUCTURED_OUTPUT: (AgentCapability.INSPECT_POLICY,),
    BrainCapability.SAFETY_CLASSIFICATION: (AgentCapability.REVIEW_PATCH,),
    BrainCapability.TOOL_PLANNING: (AgentCapability.RUN_TESTS,),
    BrainCapability.LONG_CONTEXT_REASONING: (AgentCapability.READ_WORKSPACE,),
    BrainCapability.VISION_ANALYSIS: (AgentCapability.READ_WORKSPACE,),
}

_TOOL_CAPABILITY_MAP: dict[ToolCapability, tuple[AgentCapability, ...]] = {
    ToolCapability.FILE_READ: (AgentCapability.READ_WORKSPACE,),
    ToolCapability.FILE_WRITE: (AgentCapability.WRITE_WORKSPACE,),
    ToolCapability.DIRECTORY_LIST: (AgentCapability.READ_WORKSPACE,),
    ToolCapability.PATCH_PLAN: (AgentCapability.PROPOSE_PATCH,),
    ToolCapability.PATCH_APPLY: (AgentCapability.APPLY_PATCH,),
    ToolCapability.COMMAND_EXECUTION: (AgentCapability.RUN_PROCESS,),
    ToolCapability.TEST_EXECUTION: (AgentCapability.RUN_TESTS,),
    ToolCapability.STATIC_ANALYSIS: (AgentCapability.INSPECT_POLICY,),
    ToolCapability.REPORT_GENERATION: (AgentCapability.EXPORT_EVIDENCE,),
    ToolCapability.POLICY_INSPECTION: (AgentCapability.INSPECT_POLICY,),
    ToolCapability.ARTIFACT_EXPORT: (AgentCapability.EXPORT_EVIDENCE,),
}

_TOOL_SIDE_EFFECT_MAP: dict[ToolSideEffect, tuple[AgentCapability, ...]] = {
    ToolSideEffect.NONE: (),
    ToolSideEffect.READ_WORKSPACE: (AgentCapability.READ_WORKSPACE,),
    ToolSideEffect.WRITE_WORKSPACE: (AgentCapability.WRITE_WORKSPACE,),
    ToolSideEffect.RUN_PROCESS: (AgentCapability.RUN_PROCESS,),
    ToolSideEffect.ACCESS_NETWORK: (AgentCapability.ACCESS_NETWORK,),
    ToolSideEffect.MUTATE_SYSTEM: (AgentCapability.MUTATE_SYSTEM,),
}

_TEAM_ROLE_CAPABILITY_MAP: dict[TeamRole, tuple[AgentCapability, ...]] = {
    TeamRole.PLATFORM_OWNER: (
        AgentCapability.REVIEW_PATCH,
        AgentCapability.APPROVE_RELEASE,
        AgentCapability.APPROVE_SECURITY,
        AgentCapability.DELEGATE_CAPABILITY,
    ),
    TeamRole.SECURITY_REVIEWER: (
        AgentCapability.REVIEW_PATCH,
        AgentCapability.APPROVE_SECURITY,
        AgentCapability.APPROVE_SANDBOX_EGRESS,
    ),
    TeamRole.DEVSECOPS_OPERATOR: (
        AgentCapability.REVIEW_PATCH,
        AgentCapability.RUN_TESTS,
        AgentCapability.RUN_PROCESS,
        AgentCapability.EXPORT_EVIDENCE,
    ),
    TeamRole.QA_VERIFIER: (
        AgentCapability.REVIEW_PATCH,
        AgentCapability.RUN_TESTS,
    ),
    TeamRole.COMPLIANCE_REVIEWER: (
        AgentCapability.REVIEW_PATCH,
        AgentCapability.APPROVE_COMPLIANCE,
        AgentCapability.EXPORT_EVIDENCE,
    ),
    TeamRole.RELEASE_MANAGER: (
        AgentCapability.REVIEW_PATCH,
        AgentCapability.APPROVE_RELEASE,
    ),
    TeamRole.INCIDENT_COMMANDER: (
        AgentCapability.REVIEW_PATCH,
        AgentCapability.APPROVE_SANDBOX_EGRESS,
        AgentCapability.ACCESS_NETWORK,
        AgentCapability.EXPORT_EVIDENCE,
    ),
    TeamRole.OBSERVER: (
        AgentCapability.READ_WORKSPACE,
        AgentCapability.INSPECT_POLICY,
    ),
}


def brain_manifest_to_agent_identity(
    manifest: BrainManifest,
    *,
    repository_ids: Sequence[str] = ("ix-blackfox",),
    domains: Sequence[OperatingDomain] = (
        OperatingDomain.POLICY_GOVERNED,
        OperatingDomain.REVIEWABLE,
    ),
    path_roots: Sequence[str] = ("src/ix_blackfox",),
    evidence_artifact_ids: Sequence[str] = (),
) -> AgentIdentity:
    """Convert a Wave 7 brain manifest into a Wave 11 model-brain agent.

    The adapter is intentionally conservative. A model brain may receive
    proposal, review, inspection, test-planning, or read-style capabilities
    derived from its declared BrainCapability values. It never receives human
    approval, patch-application, secret, mutation, registration, delegation, or
    revocation authority from a BrainManifest.
    """

    capabilities = _agent_capabilities_from_brain_manifest(manifest)
    evidence_ids = tuple(evidence_artifact_ids) or (
        f"brain-manifest-{manifest.brain_name}",
    )
    grants = tuple(
        _grant_for_brain_capability(
            manifest=manifest,
            capability=capability,
            repository_ids=repository_ids,
            domains=domains,
            path_roots=path_roots,
            evidence_artifact_ids=evidence_ids,
        )
        for capability in capabilities
    )

    return AgentIdentity(
        agent_id=f"brain-{manifest.brain_name}",
        display_name=f"Brain: {manifest.brain_name}",
        kind=AgentKind.MODEL_BRAIN,
        trust_tier=AgentTrustTier.GOVERNED_AUTOMATION,
        capability_grants=grants,
        issuer=manifest.provider_name,
        subject=manifest.model_name,
        metadata={
            "adapter": "brain-manifest",
            "brain_name": manifest.brain_name,
            "provider_name": manifest.provider_name,
            "model_name": manifest.model_name,
            "version": manifest.version,
            "roles": [role.value for role in manifest.roles],
            "brain_capabilities": [
                capability.value for capability in manifest.capabilities
            ],
            "labels": list(manifest.labels),
            "preferred_packs": list(manifest.preferred_packs),
            "is_default": manifest.is_default,
        },
    )


def brain_snapshot_to_agent_registry(
    snapshot: BrainManifestSnapshot,
    *,
    registry_id: str = "wave-11-brain-agents",
    repository_ids: Sequence[str] = ("ix-blackfox",),
    domains: Sequence[OperatingDomain] = (
        OperatingDomain.POLICY_GOVERNED,
        OperatingDomain.REVIEWABLE,
    ),
    path_roots: Sequence[str] = ("src/ix_blackfox",),
    evidence_artifact_ids: Sequence[str] = (),
) -> AgentRegistry:
    """Convert a BrainManifestSnapshot into a Wave 11 AgentRegistry."""

    return build_agent_registry(
        registry_id,
        (
            brain_manifest_to_agent_identity(
                manifest,
                repository_ids=repository_ids,
                domains=domains,
                path_roots=path_roots,
                evidence_artifact_ids=evidence_artifact_ids,
            )
            for manifest in snapshot.manifests
        ),
        metadata={
            "adapter": "brain-manifest-snapshot",
            "brain_count": len(snapshot.manifests),
        },
    )


def tool_manifest_to_agent_identity(
    manifest: ToolManifest,
    *,
    repository_ids: Sequence[str] = ("ix-blackfox",),
    domains: Sequence[OperatingDomain] = (OperatingDomain.POLICY_GOVERNED,),
    path_roots: Sequence[str] = ("src/ix_blackfox",),
    evidence_artifact_ids: Sequence[str] = (),
) -> AgentIdentity:
    """Convert a governed ToolManifest into a Wave 11 tool agent.

    The adapter maps declared tool capabilities and side effects into scoped
    BlackFox agent capabilities. It does not grant approval, delegation,
    registration, revocation, or human authority to a tool. Risky side effects
    are still visible as grants so capability posture validation and
    authorization evaluation can block or require review deterministically.
    """

    capabilities = _agent_capabilities_from_tool_manifest(manifest)
    evidence_ids = tuple(evidence_artifact_ids) or (
        f"tool-manifest-{manifest.tool_id}",
    )
    roots = tuple(path_roots)
    if manifest.path_policy and manifest.path_policy.allowed_roots:
        roots = manifest.path_policy.allowed_roots
    grants = tuple(
        _grant_for_tool_capability(
            manifest=manifest,
            capability=capability,
            repository_ids=repository_ids,
            domains=domains,
            path_roots=roots,
            evidence_artifact_ids=evidence_ids,
        )
        for capability in capabilities
    )

    return AgentIdentity(
        agent_id=f"tool-{manifest.tool_id}",
        display_name=f"Tool: {manifest.name}",
        kind=AgentKind.TOOL,
        trust_tier=AgentTrustTier.REGISTERED_TOOL,
        capability_grants=grants,
        issuer="tool-manifest-registry",
        subject=manifest.tool_id,
        metadata={
            "adapter": "tool-manifest",
            "tool_id": manifest.tool_id,
            "name": manifest.name,
            "version": manifest.version,
            "summary": manifest.summary,
            "tool_capabilities": [
                capability.value for capability in manifest.capabilities
            ],
            "side_effects": [effect.value for effect in manifest.side_effects],
            "approval_mode": manifest.approval_mode.value,
            "tags": list(manifest.tags),
            "has_side_effects": manifest.has_side_effects,
        },
    )


def tool_registry_to_agent_registry(
    registry: ToolManifestRegistry,
    *,
    registry_id: str = "wave-11-tool-agents",
    repository_ids: Sequence[str] = ("ix-blackfox",),
    domains: Sequence[OperatingDomain] = (OperatingDomain.POLICY_GOVERNED,),
    path_roots: Sequence[str] = ("src/ix_blackfox",),
    evidence_artifact_ids: Sequence[str] = (),
) -> AgentRegistry:
    """Convert a ToolManifestRegistry into a Wave 11 AgentRegistry."""

    manifests = registry.list_manifests()
    return build_agent_registry(
        registry_id,
        (
            tool_manifest_to_agent_identity(
                manifest,
                repository_ids=repository_ids,
                domains=domains,
                path_roots=path_roots,
                evidence_artifact_ids=evidence_artifact_ids,
            )
            for manifest in manifests
        ),
        metadata={
            "adapter": "tool-manifest-registry",
            "tool_count": len(manifests),
        },
    )


def reviewer_authority_to_agent_identity(
    authority: ReviewerAuthority,
    *,
    path_roots: Sequence[str] = ("src/ix_blackfox",),
    evidence_artifact_ids: Sequence[str] = (),
) -> AgentIdentity:
    """Convert Wave 10 ReviewerAuthority into a Wave 11 agent identity.

    Human reviewers become human-authority agents. Model and system reviewers are
    intentionally preserved as model/system agents so Wave 11 capability posture
    validation can expose any attempted approval authority as blocking evidence.
    """

    capabilities = _agent_capabilities_from_reviewer_authority(authority)
    evidence_ids = tuple(evidence_artifact_ids) or (
        f"reviewer-authority-{authority.reviewer_id}",
    )
    grants = tuple(
        _grant_for_reviewer_capability(
            authority=authority,
            capability=capability,
            path_roots=path_roots,
            evidence_artifact_ids=evidence_ids,
        )
        for capability in capabilities
    )

    return AgentIdentity(
        agent_id=f"reviewer-{authority.reviewer_id}",
        display_name=f"Reviewer: {authority.reviewer_id}",
        kind=_agent_kind_from_reviewer_kind(authority.reviewer_kind),
        trust_tier=_trust_tier_from_reviewer_kind(authority.reviewer_kind),
        lifecycle_state=(
            AgentLifecycleState.ACTIVE
            if authority.active
            else AgentLifecycleState.SUSPENDED
        ),
        capability_grants=grants,
        issuer=authority.delegated_by or authority.team_id,
        subject=authority.reviewer_id,
        metadata={
            "adapter": "reviewer-authority",
            "reviewer_id": authority.reviewer_id,
            "reviewer_kind": authority.reviewer_kind.value,
            "team_id": authority.team_id,
            "roles": [role.value for role in authority.roles],
            "approved_repository_ids": list(authority.approved_repository_ids),
            "approved_domains": [domain.value for domain in authority.approved_domains],
            "active": authority.active,
            "delegated_by": authority.delegated_by,
            "can_issue_authoritative_approval": (
                authority.can_issue_authoritative_approval
            ),
        },
    )


def review_board_to_agent_registry(
    board: ReviewBoard,
    *,
    registry_id: str = "wave-11-reviewer-agents",
    path_roots: Sequence[str] = ("src/ix_blackfox",),
    evidence_artifact_ids: Sequence[str] = (),
) -> AgentRegistry:
    """Convert a Wave 10 ReviewBoard into a Wave 11 reviewer AgentRegistry."""

    return build_agent_registry(
        registry_id,
        (
            reviewer_authority_to_agent_identity(
                authority,
                path_roots=path_roots,
                evidence_artifact_ids=evidence_artifact_ids,
            )
            for authority in board.reviewer_authorities
        ),
        metadata={
            "adapter": "review-board",
            "board_id": board.board_id,
            "team_ids": list(board.team_ids),
            "reviewer_count": len(board.reviewer_authorities),
        },
    )


def _agent_capabilities_from_brain_manifest(
    manifest: BrainManifest,
) -> tuple[AgentCapability, ...]:
    mapped: set[AgentCapability] = set()
    for brain_capability in manifest.capabilities:
        mapped.update(_BRAIN_CAPABILITY_MAP[brain_capability])
    return tuple(sorted(mapped, key=lambda capability: capability.value))


def _agent_capabilities_from_tool_manifest(
    manifest: ToolManifest,
) -> tuple[AgentCapability, ...]:
    mapped: set[AgentCapability] = set()
    for tool_capability in manifest.capabilities:
        mapped.update(_TOOL_CAPABILITY_MAP[tool_capability])
    for side_effect in manifest.side_effects:
        mapped.update(_TOOL_SIDE_EFFECT_MAP[side_effect])
    return tuple(sorted(mapped, key=lambda capability: capability.value))


def _agent_capabilities_from_reviewer_authority(
    authority: ReviewerAuthority,
) -> tuple[AgentCapability, ...]:
    mapped: set[AgentCapability] = set()
    for role in authority.roles:
        mapped.update(_TEAM_ROLE_CAPABILITY_MAP[role])
    if not mapped:
        mapped.add(AgentCapability.READ_WORKSPACE)
    return tuple(sorted(mapped, key=lambda capability: capability.value))


def _grant_for_brain_capability(
    *,
    manifest: BrainManifest,
    capability: AgentCapability,
    repository_ids: Sequence[str],
    domains: Sequence[OperatingDomain],
    path_roots: Sequence[str],
    evidence_artifact_ids: Sequence[str],
) -> AgentCapabilityGrant:
    normalized_capability = normalize_identifier(
        capability.value,
        label="capability",
    )
    metadata: dict[str, Any] = {
        "source_brain_name": manifest.brain_name,
        "source_manifest_version": manifest.version,
        "source_brain_capabilities": [
            brain_capability.value for brain_capability in manifest.capabilities
        ],
    }
    return AgentCapabilityGrant(
        grant_id=f"brain-{manifest.brain_name}-{normalized_capability}",
        capability=capability,
        scope=AgentCapabilityScope(
            repository_ids=tuple(repository_ids),
            domains=tuple(domains),
            pack_ids=manifest.preferred_packs,
            path_roots=tuple(path_roots),
            max_risk_tier=capability_default_risk_tier(capability),
            requires_human_review=capability_requires_human_review(capability),
            evidence_artifact_ids=tuple(evidence_artifact_ids),
            metadata=metadata,
        ),
        rationale=(
            "Derived from a BrainManifest declaration. This grant gives the "
            "model brain scoped participation authority only; it does not grant "
            "human approval, self-approval, mutation, secret, or deployment "
            "authority."
        ),
        metadata=metadata,
    )


def _grant_for_tool_capability(
    *,
    manifest: ToolManifest,
    capability: AgentCapability,
    repository_ids: Sequence[str],
    domains: Sequence[OperatingDomain],
    path_roots: Sequence[str],
    evidence_artifact_ids: Sequence[str],
) -> AgentCapabilityGrant:
    normalized_capability = normalize_identifier(
        capability.value,
        label="capability",
    )
    manifest_requires_review = manifest.approval_mode in {
        ToolApprovalMode.ALWAYS,
        ToolApprovalMode.POLICY,
    }
    metadata: dict[str, Any] = {
        "source_tool_id": manifest.tool_id,
        "source_tool_version": manifest.version,
        "source_tool_capabilities": [
            tool_capability.value for tool_capability in manifest.capabilities
        ],
        "source_tool_side_effects": [
            side_effect.value for side_effect in manifest.side_effects
        ],
        "source_tool_approval_mode": manifest.approval_mode.value,
    }
    return AgentCapabilityGrant(
        grant_id=f"tool-{manifest.tool_id}-{normalized_capability}",
        capability=capability,
        scope=AgentCapabilityScope(
            repository_ids=tuple(repository_ids),
            domains=tuple(domains),
            tool_ids=(manifest.tool_id,),
            path_roots=tuple(path_roots),
            max_risk_tier=capability_default_risk_tier(capability),
            requires_human_review=(
                manifest_requires_review or capability_requires_human_review(capability)
            ),
            evidence_artifact_ids=tuple(evidence_artifact_ids),
            metadata=metadata,
        ),
        rationale=(
            "Derived from a ToolManifest declaration. This grant records the "
            "tool's scoped operational capability for Wave 11 preflight; it "
            "does not grant human approval, delegation, registration, revocation, "
            "or self-approval authority."
        ),
        metadata=metadata,
    )


def _grant_for_reviewer_capability(
    *,
    authority: ReviewerAuthority,
    capability: AgentCapability,
    path_roots: Sequence[str],
    evidence_artifact_ids: Sequence[str],
) -> AgentCapabilityGrant:
    normalized_capability = normalize_identifier(
        capability.value,
        label="capability",
    )
    metadata: dict[str, Any] = {
        "source_reviewer_id": authority.reviewer_id,
        "source_reviewer_kind": authority.reviewer_kind.value,
        "source_team_id": authority.team_id,
        "source_roles": [role.value for role in authority.roles],
        "can_issue_authoritative_approval": authority.can_issue_authoritative_approval,
    }
    return AgentCapabilityGrant(
        grant_id=f"reviewer-{authority.reviewer_id}-{normalized_capability}",
        capability=capability,
        scope=AgentCapabilityScope(
            repository_ids=authority.approved_repository_ids,
            domains=authority.approved_domains,
            path_roots=tuple(path_roots),
            max_risk_tier=capability_default_risk_tier(capability),
            requires_human_review=capability_requires_human_review(capability),
            evidence_artifact_ids=tuple(evidence_artifact_ids),
            delegated_by=authority.delegated_by or authority.team_id,
            metadata=metadata,
        ),
        rationale=(
            "Derived from a Wave 10 ReviewerAuthority record. The grant preserves "
            "the reviewer's repository and domain boundary for Wave 11 "
            "identity-bound authorization."
        ),
        metadata=metadata,
    )


def _agent_kind_from_reviewer_kind(reviewer_kind: ReviewerKind) -> AgentKind:
    if reviewer_kind is ReviewerKind.HUMAN:
        return AgentKind.HUMAN_OPERATOR
    if reviewer_kind is ReviewerKind.MODEL:
        return AgentKind.MODEL_BRAIN
    return AgentKind.SYSTEM_SERVICE


def _trust_tier_from_reviewer_kind(reviewer_kind: ReviewerKind) -> AgentTrustTier:
    if reviewer_kind is ReviewerKind.HUMAN:
        return AgentTrustTier.HUMAN_AUTHORITY
    return AgentTrustTier.GOVERNED_AUTOMATION
