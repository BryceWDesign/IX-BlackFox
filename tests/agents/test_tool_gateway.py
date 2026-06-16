from __future__ import annotations

from dataclasses import dataclass

from ix_blackfox.agents import (
    AgentAuthorizedToolGateway,
    AgentAuthorizationEvaluator,
    AgentAuthorizationReason,
    AgentAuthorizationStatus,
    AgentCapability,
    AgentCapabilityGrant,
    AgentCapabilityScope,
    AgentIdentity,
    AgentKind,
    AgentRegistry,
    AgentTrustTier,
    CapabilityRiskTier,
    agent_action_for_tool_capability,
    agent_capability_for_tool_capability,
    build_tool_authorization_request,
)
from ix_blackfox.operating import OperatingDomain
from ix_blackfox.tools import (
    GovernedToolGateway,
    ToolCapability,
    ToolInvocationRequest,
    ToolInvocationResult,
    ToolInvocationStatus,
    ToolManifest,
    ToolSideEffect,
)


@dataclass(slots=True)
class FakeToolInvoker:
    manifest: ToolManifest
    invoked: bool = False

    def invoke(self, request: ToolInvocationRequest) -> ToolInvocationResult:
        self.invoked = True
        return ToolInvocationResult.succeeded(
            request=request,
            output={"ok": True, "tool_id": request.tool_id},
        )


def test_tool_authorization_request_maps_tool_invocation_scope() -> None:
    request = _tool_request(
        tool_id="reader_tool",
        capability=ToolCapability.FILE_READ,
        arguments={"path": "src/ix_blackfox/agents/models.py"},
    )

    auth_request = build_tool_authorization_request(
        agent_id="reader-agent",
        request=request,
    )

    assert auth_request.agent_id == "reader-agent"
    assert auth_request.capability is AgentCapability.READ_WORKSPACE
    assert auth_request.action is agent_action_for_tool_capability(
        ToolCapability.FILE_READ
    )
    assert auth_request.target.tool_id == "reader-tool"
    assert auth_request.target.path == "src/ix_blackfox/agents/models.py"
    assert auth_request.target.repository_id == "ix-blackfox"
    assert auth_request.target.domain is OperatingDomain.POLICY_GOVERNED
    assert auth_request.target.risk_tier is CapabilityRiskTier.LOW
    assert agent_capability_for_tool_capability(ToolCapability.TEST_EXECUTION) is (
        AgentCapability.RUN_TESTS
    )


def test_agent_authorized_tool_gateway_invokes_existing_gateway_when_allowed() -> None:
    invoker = FakeToolInvoker(
        manifest=ToolManifest(
            tool_id="reader_tool",
            name="Reader Tool",
            version="1.0",
            summary="Reads workspace files.",
            capabilities=(ToolCapability.FILE_READ,),
            side_effects=(ToolSideEffect.READ_WORKSPACE,),
        )
    )
    gateway = GovernedToolGateway()
    gateway.register_tool(invoker)
    wrapper = AgentAuthorizedToolGateway(
        gateway=gateway,
        authorization_evaluator=AgentAuthorizationEvaluator(
            registry=AgentRegistry(
                registry_id="wave-11",
                agents=(
                    _agent(
                        "reader-agent",
                        AgentKind.TOOL,
                        AgentTrustTier.REGISTERED_TOOL,
                        AgentCapability.READ_WORKSPACE,
                        CapabilityRiskTier.LOW,
                        tool_ids=("reader-tool",),
                    ),
                ),
            )
        ),
    )

    report = wrapper.authorize_and_invoke(
        agent_id="reader-agent",
        request=_tool_request("reader_tool", ToolCapability.FILE_READ),
        decided_at="2026-06-15T12:01:00Z",
    )

    assert report.allowed_by_agent_authorization is True
    assert report.executed_gateway is True
    assert report.gateway_report is not None
    assert report.result.status is ToolInvocationStatus.SUCCEEDED
    assert invoker.invoked is True
    assert report.to_dict()["gateway_report"] is not None


def test_agent_authorized_tool_gateway_blocks_before_tool_gateway_for_unknown_agent() -> None:
    invoker = FakeToolInvoker(
        manifest=ToolManifest(
            tool_id="reader_tool",
            name="Reader Tool",
            version="1.0",
            summary="Reads workspace files.",
            capabilities=(ToolCapability.FILE_READ,),
        )
    )
    gateway = GovernedToolGateway()
    gateway.register_tool(invoker)
    wrapper = AgentAuthorizedToolGateway(
        gateway=gateway,
        authorization_evaluator=AgentAuthorizationEvaluator(
            registry=AgentRegistry(registry_id="wave-11")
        ),
    )

    report = wrapper.authorize_and_invoke(
        agent_id="missing-agent",
        request=_tool_request("reader_tool", ToolCapability.FILE_READ),
        decided_at="2026-06-15T12:01:00Z",
    )

    assert report.blocked_by_agent_authorization is True
    assert report.executed_gateway is False
    assert report.gateway_report is None
    assert report.result.status is ToolInvocationStatus.BLOCKED
    assert report.authorization_decision.reasons == (
        AgentAuthorizationReason.UNKNOWN_AGENT,
    )
    assert invoker.invoked is False


def test_agent_authorized_tool_gateway_requires_review_before_gateway_execution() -> None:
    invoker = FakeToolInvoker(
        manifest=ToolManifest(
            tool_id="writer_tool",
            name="Writer Tool",
            version="1.0",
            summary="Writes workspace files.",
            capabilities=(ToolCapability.FILE_WRITE,),
            side_effects=(ToolSideEffect.WRITE_WORKSPACE,),
        )
    )
    gateway = GovernedToolGateway()
    gateway.register_tool(invoker)
    wrapper = AgentAuthorizedToolGateway(
        gateway=gateway,
        authorization_evaluator=AgentAuthorizationEvaluator(
            registry=AgentRegistry(
                registry_id="wave-11",
                agents=(
                    _agent(
                        "writer-agent",
                        AgentKind.TOOL,
                        AgentTrustTier.REGISTERED_TOOL,
                        AgentCapability.WRITE_WORKSPACE,
                        CapabilityRiskTier.HIGH,
                        requires_review=True,
                        tool_ids=("writer-tool",),
                    ),
                ),
            )
        ),
    )

    report = wrapper.authorize_and_invoke(
        agent_id="writer-agent",
        request=_tool_request(
            "writer_tool",
            ToolCapability.FILE_WRITE,
            arguments={"path": "src/ix_blackfox/generated.py"},
            metadata={"agent_risk_tier": "high"},
        ),
        decided_at="2026-06-15T12:01:00Z",
        reviewer_agent_id="release-owner",
    )

    assert report.review_required_by_agent_authorization is True
    assert report.authorization_decision.status is (
        AgentAuthorizationStatus.REQUIRE_REVIEW
    )
    assert report.executed_gateway is False
    assert report.result.status is ToolInvocationStatus.REVIEW_REQUIRED
    assert report.result.failure is not None
    assert report.result.failure.kind.value == "approval_required"
    assert invoker.invoked is False


def test_agent_authorized_tool_gateway_blocks_out_of_scope_tool_grant() -> None:
    invoker = FakeToolInvoker(
        manifest=ToolManifest(
            tool_id="other_tool",
            name="Other Tool",
            version="1.0",
            summary="Reads files.",
            capabilities=(ToolCapability.FILE_READ,),
        )
    )
    gateway = GovernedToolGateway()
    gateway.register_tool(invoker)
    wrapper = AgentAuthorizedToolGateway(
        gateway=gateway,
        authorization_evaluator=AgentAuthorizationEvaluator(
            registry=AgentRegistry(
                registry_id="wave-11",
                agents=(
                    _agent(
                        "reader-agent",
                        AgentKind.TOOL,
                        AgentTrustTier.REGISTERED_TOOL,
                        AgentCapability.READ_WORKSPACE,
                        CapabilityRiskTier.LOW,
                        tool_ids=("reader-tool",),
                    ),
                ),
            )
        ),
    )

    report = wrapper.authorize_and_invoke(
        agent_id="reader-agent",
        request=_tool_request("other_tool", ToolCapability.FILE_READ),
        decided_at="2026-06-15T12:01:00Z",
    )

    assert report.blocked_by_agent_authorization is True
    assert report.authorization_decision.reasons == (
        AgentAuthorizationReason.CAPABILITY_OUT_OF_SCOPE,
    )
    assert report.executed_gateway is False
    assert invoker.invoked is False


def _agent(
    agent_id: str,
    kind: AgentKind,
    trust_tier: AgentTrustTier,
    capability: AgentCapability,
    tier: CapabilityRiskTier,
    *,
    requires_review: bool = False,
    tool_ids: tuple[str, ...] = (),
) -> AgentIdentity:
    return AgentIdentity(
        agent_id=agent_id,
        display_name=agent_id,
        kind=kind,
        trust_tier=trust_tier,
        capability_grants=(
            AgentCapabilityGrant(
                grant_id=f"{agent_id}-{capability.value}",
                capability=capability,
                scope=AgentCapabilityScope(
                    repository_ids=("ix-blackfox",),
                    domains=(OperatingDomain.POLICY_GOVERNED,),
                    tool_ids=tool_ids,
                    path_roots=("src/ix_blackfox",),
                    max_risk_tier=tier,
                    requires_human_review=requires_review,
                    evidence_artifact_ids=("wave-11-tool-gateway-test",),
                ),
            ),
        ),
    )


def _tool_request(
    tool_id: str,
    capability: ToolCapability,
    *,
    arguments: dict[str, object] | None = None,
    metadata: dict[str, object] | None = None,
) -> ToolInvocationRequest:
    return ToolInvocationRequest.create(
        tool_id=tool_id,
        capability=capability,
        arguments={} if arguments is None else arguments,
        requested_by="wave-11-test",
        metadata={"repository_id": "ix-blackfox", **dict(metadata or {})},
    )
