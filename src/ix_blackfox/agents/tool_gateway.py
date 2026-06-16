from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from ix_blackfox.agents.authorization import (
    AgentAction,
    AgentAuthorizationDecision,
    AgentAuthorizationEvaluator,
    AgentAuthorizationRequest,
    AgentAuthorizationStatus,
    AgentAuthorizationTarget,
)
from ix_blackfox.agents.capabilities import capability_default_risk_tier
from ix_blackfox.agents.models import AgentCapability, CapabilityRiskTier
from ix_blackfox.operating.models import OperatingDomain
from ix_blackfox.tools.contracts import (
    ToolFailure,
    ToolFailureKind,
    ToolInvocationRequest,
    ToolInvocationResult,
    ToolInvocationStatus,
)
from ix_blackfox.tools.gateway import GovernedToolGateway, ToolGatewayInvocationReport
from ix_blackfox.tools.manifest import ToolCapability


@dataclass(frozen=True, slots=True)
class AgentAuthorizedToolInvocationReport:
    """Wave 11 wrapper report for one agent-authorized tool invocation."""

    agent_id: str
    request: ToolInvocationRequest
    authorization_request: AgentAuthorizationRequest
    authorization_decision: AgentAuthorizationDecision
    gateway_report: ToolGatewayInvocationReport | None
    result: ToolInvocationResult
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def allowed_by_agent_authorization(self) -> bool:
        return self.authorization_decision.status is AgentAuthorizationStatus.ALLOW

    @property
    def blocked_by_agent_authorization(self) -> bool:
        return self.authorization_decision.status is AgentAuthorizationStatus.BLOCK

    @property
    def review_required_by_agent_authorization(self) -> bool:
        return (
            self.authorization_decision.status
            is AgentAuthorizationStatus.REQUIRE_REVIEW
        )

    @property
    def executed_gateway(self) -> bool:
        return self.gateway_report is not None

    @property
    def succeeded(self) -> bool:
        return self.result.status is ToolInvocationStatus.SUCCEEDED

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "request": self.request.to_dict(),
            "authorization_request": self.authorization_request.to_dict(),
            "authorization_decision": self.authorization_decision.to_dict(),
            "gateway_report": (
                self.gateway_report.to_dict() if self.gateway_report else None
            ),
            "result": self.result.to_dict(),
            "allowed_by_agent_authorization": self.allowed_by_agent_authorization,
            "blocked_by_agent_authorization": self.blocked_by_agent_authorization,
            "review_required_by_agent_authorization": (
                self.review_required_by_agent_authorization
            ),
            "executed_gateway": self.executed_gateway,
            "succeeded": self.succeeded,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class AgentAuthorizedToolGateway:
    """Preflight wrapper around the existing governed tool gateway.

    The wrapper does not replace GovernedToolGateway. It adds a Wave 11
    identity/capability authorization decision before the existing tool policy
    and receipt flow is allowed to run.
    """

    gateway: GovernedToolGateway
    authorization_evaluator: AgentAuthorizationEvaluator

    def authorize_and_invoke(
        self,
        *,
        agent_id: str,
        request: ToolInvocationRequest,
        decided_at: str,
        reviewer_agent_id: str = "",
        evidence_artifact_ids: Sequence[str] = (),
        metadata: Mapping[str, Any] | None = None,
    ) -> AgentAuthorizedToolInvocationReport:
        authorization_request = build_tool_authorization_request(
            agent_id=agent_id,
            request=request,
        )
        authorization_decision = self.authorization_evaluator.evaluate(
            authorization_request,
            decided_at=decided_at,
            reviewer_agent_id=reviewer_agent_id,
            evidence_artifact_ids=evidence_artifact_ids,
        )

        if authorization_decision.status is AgentAuthorizationStatus.BLOCK:
            result = _agent_blocked_result(
                request=request,
                decision=authorization_decision,
            )
            return AgentAuthorizedToolInvocationReport(
                agent_id=authorization_request.agent_id,
                request=request,
                authorization_request=authorization_request,
                authorization_decision=authorization_decision,
                gateway_report=None,
                result=result,
                metadata={"gateway_executed": False, **dict(metadata or {})},
            )

        if authorization_decision.status is AgentAuthorizationStatus.REQUIRE_REVIEW:
            result = _agent_review_required_result(
                request=request,
                decision=authorization_decision,
            )
            return AgentAuthorizedToolInvocationReport(
                agent_id=authorization_request.agent_id,
                request=request,
                authorization_request=authorization_request,
                authorization_decision=authorization_decision,
                gateway_report=None,
                result=result,
                metadata={"gateway_executed": False, **dict(metadata or {})},
            )

        gateway_report = self.gateway.invoke(request)
        return AgentAuthorizedToolInvocationReport(
            agent_id=authorization_request.agent_id,
            request=request,
            authorization_request=authorization_request,
            authorization_decision=authorization_decision,
            gateway_report=gateway_report,
            result=gateway_report.result,
            metadata={"gateway_executed": True, **dict(metadata or {})},
        )


def build_tool_authorization_request(
    *,
    agent_id: str,
    request: ToolInvocationRequest,
) -> AgentAuthorizationRequest:
    """Build the Wave 11 authorization request for a tool invocation."""

    capability = agent_capability_for_tool_capability(request.capability)
    return AgentAuthorizationRequest(
        request_id=f"tool-auth-{request.invocation_id}",
        agent_id=agent_id,
        action=agent_action_for_tool_capability(request.capability),
        capability=capability,
        target=AgentAuthorizationTarget(
            repository_id=_repository_id_from_metadata(request.metadata),
            domain=_domain_from_metadata(request.metadata),
            tool_id=request.tool_id,
            path=_path_from_arguments(request.arguments),
            work_package_id=request.task_id or "",
            artifact_ids=(
                (request.run_id,) if request.run_id is not None else ()
            ),
            risk_tier=_risk_tier_from_metadata(
                request.metadata,
                default=capability_default_risk_tier(capability),
            ),
            metadata={
                "tool_invocation_id": request.invocation_id,
                "tool_capability": request.capability.value,
                "tool_id": request.tool_id,
            },
        ),
        requested_at=request.created_at.isoformat(),
        evidence_artifact_ids=(
            f"tool-invocation-{request.invocation_id}",
            f"tool-manifest-{request.tool_id}",
        ),
        justification=(
            "Wave 11 agent authorization preflight for governed tool invocation."
        ),
        metadata={
            "tool_invocation_id": request.invocation_id,
            "tool_id": request.tool_id,
            "tool_capability": request.capability.value,
            "requested_by": request.requested_by or "",
        },
    )


def agent_capability_for_tool_capability(
    capability: ToolCapability,
) -> AgentCapability:
    """Map a ToolCapability into the corresponding Wave 11 AgentCapability."""

    mapping = {
        ToolCapability.FILE_READ: AgentCapability.READ_WORKSPACE,
        ToolCapability.FILE_WRITE: AgentCapability.WRITE_WORKSPACE,
        ToolCapability.DIRECTORY_LIST: AgentCapability.READ_WORKSPACE,
        ToolCapability.PATCH_PLAN: AgentCapability.PROPOSE_PATCH,
        ToolCapability.PATCH_APPLY: AgentCapability.APPLY_PATCH,
        ToolCapability.COMMAND_EXECUTION: AgentCapability.RUN_PROCESS,
        ToolCapability.TEST_EXECUTION: AgentCapability.RUN_TESTS,
        ToolCapability.STATIC_ANALYSIS: AgentCapability.INSPECT_POLICY,
        ToolCapability.REPORT_GENERATION: AgentCapability.EXPORT_EVIDENCE,
        ToolCapability.POLICY_INSPECTION: AgentCapability.INSPECT_POLICY,
        ToolCapability.ARTIFACT_EXPORT: AgentCapability.EXPORT_EVIDENCE,
    }
    return mapping[capability]


def agent_action_for_tool_capability(capability: ToolCapability) -> AgentAction:
    """Map a ToolCapability into the requested Wave 11 action family."""

    mapping = {
        ToolCapability.FILE_READ: AgentAction.READ,
        ToolCapability.FILE_WRITE: AgentAction.WRITE,
        ToolCapability.DIRECTORY_LIST: AgentAction.READ,
        ToolCapability.PATCH_PLAN: AgentAction.PROPOSE,
        ToolCapability.PATCH_APPLY: AgentAction.APPLY,
        ToolCapability.COMMAND_EXECUTION: AgentAction.RUN,
        ToolCapability.TEST_EXECUTION: AgentAction.RUN,
        ToolCapability.STATIC_ANALYSIS: AgentAction.INSPECT,
        ToolCapability.REPORT_GENERATION: AgentAction.EXPORT,
        ToolCapability.POLICY_INSPECTION: AgentAction.INSPECT,
        ToolCapability.ARTIFACT_EXPORT: AgentAction.EXPORT,
    }
    return mapping[capability]


def _agent_blocked_result(
    *,
    request: ToolInvocationRequest,
    decision: AgentAuthorizationDecision,
) -> ToolInvocationResult:
    return ToolInvocationResult.failed(
        request=request,
        status=ToolInvocationStatus.BLOCKED,
        failure=ToolFailure(
            kind=ToolFailureKind.POLICY_BLOCKED,
            message="Tool invocation blocked by Wave 11 agent authorization.",
            retryable=False,
            metadata=_authorization_failure_metadata(decision),
        ),
        output={
            "agent_authorization_decision": decision.to_dict(),
        },
        metadata={
            "agent_authorization_status": decision.status.value,
            "gateway_executed": False,
        },
    )


def _agent_review_required_result(
    *,
    request: ToolInvocationRequest,
    decision: AgentAuthorizationDecision,
) -> ToolInvocationResult:
    return ToolInvocationResult.failed(
        request=request,
        status=ToolInvocationStatus.REVIEW_REQUIRED,
        failure=ToolFailure(
            kind=ToolFailureKind.APPROVAL_REQUIRED,
            message=(
                "Tool invocation requires human review by Wave 11 agent "
                "authorization."
            ),
            retryable=False,
            metadata=_authorization_failure_metadata(decision),
        ),
        output={
            "agent_authorization_decision": decision.to_dict(),
        },
        metadata={
            "agent_authorization_status": decision.status.value,
            "gateway_executed": False,
        },
    )


def _authorization_failure_metadata(
    decision: AgentAuthorizationDecision,
) -> dict[str, Any]:
    return {
        "decision_id": decision.decision_id,
        "decision_status": decision.status.value,
        "decision_reasons": [reason.value for reason in decision.reasons],
        "decision_digest": decision.digest,
        "reviewer_agent_id": decision.reviewer_agent_id,
    }


def _repository_id_from_metadata(metadata: Mapping[str, Any]) -> str:
    value = metadata.get("repository_id")
    return value if isinstance(value, str) and value.strip() else "ix-blackfox"


def _domain_from_metadata(metadata: Mapping[str, Any]) -> OperatingDomain:
    value = metadata.get("operating_domain")
    if isinstance(value, OperatingDomain):
        return value
    if isinstance(value, str) and value.strip():
        return OperatingDomain(value)
    return OperatingDomain.POLICY_GOVERNED


def _risk_tier_from_metadata(
    metadata: Mapping[str, Any],
    *,
    default: CapabilityRiskTier,
) -> CapabilityRiskTier:
    value = metadata.get("agent_risk_tier", metadata.get("risk_tier"))
    if isinstance(value, CapabilityRiskTier):
        return value
    if isinstance(value, str) and value.strip():
        return CapabilityRiskTier(value)
    return default


def _path_from_arguments(arguments: Mapping[str, Any]) -> str:
    for key in ("path", "file_path", "target_path", "output_path", "root"):
        value = arguments.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return ""
