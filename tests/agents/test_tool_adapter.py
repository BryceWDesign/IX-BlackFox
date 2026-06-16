from __future__ import annotations

from ix_blackfox.agents import (
    AgentCapability,
    AgentKind,
    AgentTrustTier,
    tool_manifest_to_agent_identity,
    tool_registry_to_agent_registry,
    validate_agent_capability_posture,
)
from ix_blackfox.operating import OperatingDomain
from ix_blackfox.tools import (
    ToolApprovalMode,
    ToolCapability,
    ToolManifest,
    ToolManifestRegistry,
    ToolPathPolicy,
    ToolSideEffect,
)


def test_tool_manifest_adapter_creates_registered_tool_agent() -> None:
    manifest = ToolManifest(
        tool_id="test_runner",
        name="Test Runner",
        version="1.0",
        summary="Runs allowlisted tests.",
        capabilities=(ToolCapability.TEST_EXECUTION,),
        side_effects=(ToolSideEffect.RUN_PROCESS,),
        approval_mode=ToolApprovalMode.ALWAYS,
        path_policy=ToolPathPolicy(allowed_roots=("tests", "src")),
        tags=("ci", "tests"),
    )

    agent = tool_manifest_to_agent_identity(manifest)

    assert agent.agent_id == "tool-test-runner"
    assert agent.kind is AgentKind.TOOL
    assert agent.trust_tier is AgentTrustTier.REGISTERED_TOOL
    assert agent.issuer == "tool-manifest-registry"
    assert agent.subject == "test_runner"
    assert set(agent.capabilities) == {
        AgentCapability.RUN_PROCESS,
        AgentCapability.RUN_TESTS,
    }
    assert agent.metadata["adapter"] == "tool-manifest"
    assert agent.metadata["approval_mode"] == "always"
    assert validate_agent_capability_posture(agent).allowed
    for grant in agent.capability_grants:
        assert grant.scope.tool_ids == ("test-runner",)
        assert grant.scope.path_roots == ("src", "tests")
        assert grant.scope.requires_human_review is True


def test_tool_manifest_adapter_maps_workspace_and_policy_capabilities() -> None:
    manifest = ToolManifest(
        tool_id="policy_reader",
        name="Policy Reader",
        version="1.0",
        summary="Reads workspace policy files.",
        capabilities=(
            ToolCapability.FILE_READ,
            ToolCapability.DIRECTORY_LIST,
            ToolCapability.POLICY_INSPECTION,
            ToolCapability.STATIC_ANALYSIS,
        ),
        side_effects=(ToolSideEffect.READ_WORKSPACE,),
        approval_mode=ToolApprovalMode.NEVER,
        path_policy=ToolPathPolicy(allowed_roots=("blackfox.policy.toml", "src")),
        tags=("policy",),
    )

    agent = tool_manifest_to_agent_identity(
        manifest,
        repository_ids=("IX-BlackFox",),
        domains=(OperatingDomain.REVIEWABLE,),
        evidence_artifact_ids=("policy-reader-manifest",),
    )

    assert set(agent.capabilities) == {
        AgentCapability.INSPECT_POLICY,
        AgentCapability.READ_WORKSPACE,
    }
    assert validate_agent_capability_posture(agent).allowed
    for grant in agent.capability_grants:
        assert grant.scope.repository_ids == ("ix-blackfox",)
        assert grant.scope.domains == (OperatingDomain.REVIEWABLE,)
        assert grant.scope.evidence_artifact_ids == ("policy-reader-manifest",)
        assert grant.scope.requires_human_review is False


def test_tool_manifest_adapter_exposes_blocking_posture_for_mutating_tool() -> None:
    manifest = ToolManifest(
        tool_id="system_mutator",
        name="System Mutator",
        version="1.0",
        summary="Declares system mutation side effects for policy testing.",
        capabilities=(ToolCapability.COMMAND_EXECUTION,),
        side_effects=(ToolSideEffect.MUTATE_SYSTEM,),
        approval_mode=ToolApprovalMode.ALWAYS,
        tags=("dangerous",),
    )

    agent = tool_manifest_to_agent_identity(manifest)
    result = validate_agent_capability_posture(agent)

    assert AgentCapability.MUTATE_SYSTEM in agent.capabilities
    assert not result.allowed
    assert result.blocking_findings


def test_tool_registry_adapter_builds_agent_registry() -> None:
    registry = ToolManifestRegistry()
    registry.register(
        ToolManifest(
            tool_id="reader_tool",
            name="Reader Tool",
            version="1.0",
            summary="Reads files.",
            capabilities=(ToolCapability.FILE_READ,),
            side_effects=(ToolSideEffect.READ_WORKSPACE,),
            approval_mode=ToolApprovalMode.NEVER,
        )
    )
    registry.register(
        ToolManifest(
            tool_id="export_tool",
            name="Export Tool",
            version="1.0",
            summary="Exports artifacts.",
            capabilities=(ToolCapability.ARTIFACT_EXPORT,),
            side_effects=(ToolSideEffect.NONE,),
            approval_mode=ToolApprovalMode.ALWAYS,
        )
    )

    agent_registry = tool_registry_to_agent_registry(registry)

    assert agent_registry.registry_id == "wave-11-tool-agents"
    assert agent_registry.agent_ids == ("tool-export-tool", "tool-reader-tool")
    assert agent_registry.find_by_capability(AgentCapability.READ_WORKSPACE)
    assert agent_registry.find_by_capability(AgentCapability.EXPORT_EVIDENCE)
    assert agent_registry.metadata["adapter"] == "tool-manifest-registry"
    assert agent_registry.metadata["tool_count"] == 2
